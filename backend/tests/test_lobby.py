import unittest
try:
    from local_auth.lobby import make_server_header, verify_client_auth
except ImportError:
    make_server_header = verify_client_auth = None

P = bytes.fromhex('c8000000c8000000d2000000d2000000000008002e7360dafd16fae7')


def client_body(title=1002, seed=0, ticket=bytes(128)):
    # Independent fixture writer: bit offsets from exact-build analysis.
    fields = [(0, 8, 7), (8, 1, 1), (9, 5, 8), (14, 32, title),
              (46, 5, 8), (51, 32, seed), (83, 1024, int.from_bytes(ticket, 'little'))]
    result = bytearray(139)
    for offset, width, value in fields:
        for bit in range(width):
            if value & (1 << bit):
                result[(offset + bit) // 8] |= 1 << ((offset + bit) % 8)
    return bytes(result)


class HandshakeTests(unittest.TestCase):
    def test_malformed_negotiation_and_auth_body_are_rejected(self):
        self.assertIsNotNone(make_server_header)
        from local_auth.profiles import Profile
        for initial in (P[:-1], b'\0' * 28, P[:16] + b'\0' * 4 + P[20:]):
            with self.subTest(initial=initial.hex()), self.assertRaises(ValueError):
                make_server_header(initial, server_id=bytes(8), nonce=bytes(8))
        header = make_server_header(P, server_id=bytes(8), nonce=bytes(8))
        player = Profile('Test', 1, bytes(range(24)))
        lookup = lambda token: {'profile': player, 'expires': 200, 'iv_seed': 0, 'title_id': 1002}
        valid = bytes.fromhex('95000000ab82') + client_body() + bytes.fromhex('c9e0d96c734499b1')
        malformed = bytearray(valid)
        malformed[6] = 0
        with self.assertRaisesRegex(ValueError, 'body'):
            verify_client_auth(P, header, bytes(malformed), lookup, now=100)
        with self.assertRaises(ValueError):
            verify_client_auth(P, header, valid[:-1] + b'\0', lookup, now=100)
        with self.assertRaisesRegex(ValueError, 'expired'):
            verify_client_auth(P, header, valid, lookup, now=201)

    def test_fragmented_tcp_handshake_establishes_a_local_session(self):
        import json
        import hashlib
        import hmac
        import socket
        import struct
        import tempfile
        import threading
        import time
        from pathlib import Path
        import local_auth.lobby as lobby
        from unittest.mock import patch
        from local_auth.server import make_server
        from local_auth.profiles import ProfileStore
        self.assertTrue(hasattr(lobby, 'make_lobby_server'), 'TCP handshake service is not implemented')
        with tempfile.TemporaryDirectory() as directory, patch.object(
                lobby, 'STARTGAME_TRIGGER', Path(directory) / 'absent-trigger'):
            player = ProfileStore(Path(directory) / 'profiles.db').get_or_create('SocketTest')
            auth = make_server(player, port=0)
            token = b'T' * 128
            auth.sessions[token] = {'profile': player, 'expires': time.time() + 300,
                                    'iv_seed': 42, 'title_id': 1002}
            events = []
            server = lobby.make_lobby_server(auth, port=0, event=lambda kind, **kw: events.append((kind, kw)),
                                             game_server=None)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            def read_exact(conn, length):
                result = b''
                while len(result) < length:
                    chunk = conn.recv(length - len(result))
                    self.assertTrue(chunk, 'Premature TCP close')
                    result += chunk
                return result
            try:
                with socket.create_connection(server.server_address, timeout=3) as conn:
                    conn.sendall(P[:3]); conn.sendall(P[3:])
                    header = read_exact(conn, 26)
                    prefix = bytes.fromhex('95000000ab82') + client_body(seed=42, ticket=token)
                    th = hashlib.sha1(P[8:] + header + prefix).digest()
                    prk = hmac.digest(th, player.auth_key, 'sha1')
                    challenge = hmac.digest(prk, b'CLIENTCHAL\x01', 'sha1')[:16]
                    packet = prefix + challenge[:8]
                    conn.sendall(packet[:19]); conn.sendall(packet[19:])
                    response = read_exact(conn, 14)
                    self.assertEqual(response, bytes.fromhex('0a000000ab83') + challenge[8:])
                    # Send a real AES/HMAC application frame after the handshake.
                    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                    previous = b''; material = b''
                    for counter in range(1, 5):
                        previous = hmac.digest(prk, previous + b'BDDATA' + bytes([counter]), 'sha1')
                        material += previous
                    private_args = b'private-request-canary'
                    application = bytes([71, 3, 4]) + private_args
                    plain = struct.pack('<I', len(application)) + b'\x86' + application
                    plain += bytes((-len(plain)) % 16)
                    iv = bytes(16)
                    cipher = Cipher(algorithms.AES(material[40:56]), modes.CBC(iv)).encryptor()
                    encrypted = cipher.update(plain) + cipher.finalize()
                    prefix = struct.pack('<I', 30 + len(encrypted)) + b'\xab\x85' + struct.pack('<I', 1) + iv + encrypted
                    frame = prefix + hmac.digest(material[:20], prefix, 'sha1')[:8]
                    conn.sendall(frame)
                    # Reading the complete response synchronizes with reply construction.
                    response_prefix = read_exact(conn, 4)
                    response = response_prefix + read_exact(conn, struct.unpack('<I', response_prefix)[0])
                    from local_auth.frames import decode_server_data
                    keys = lobby.Keys(material[:20], material[20:40], material[40:56], material[56:72])
                    reply_type, reply_body = decode_server_data(response, keys, expected_counter=1)
                    self.assertEqual(reply_type, 1)
                    self.assertIn(b'encrypted_codoid', reply_body)
                    observed = dict(events)
                    self.assertIn('lobby_authenticated', observed)
                    self.assertEqual(observed['lobby_keys_derived'], {})
                    self.assertEqual(observed['lobby_service_received'], {
                        'player': 'SocketTest', 'service': 71, 'task': 4,
                        'application_bytes': len(application), 'args_bytes': len(private_args)})
                    self.assertEqual(observed['lobby_reply_built'], {
                        'player': 'SocketTest', 'service': 71, 'task': 4,
                        'transaction_id': 1, 'reply_type': 1, 'reply_bytes': len(reply_body)})
                    serialized = json.dumps(events)
                    for secret in (private_args, reply_body, token, player.auth_key,
                                   keys.c2s_mac, keys.s2c_mac, keys.c2s_aes, keys.s2c_aes):
                        self.assertNotIn(secret.hex(), serialized)
                    self.assertNotIn(private_args.decode(), serialized)
            finally:
                server.shutdown(); server.server_close(); thread.join(3)
                auth.server_close()

    def test_header_and_proofs_match_static_reference_vector(self):
        self.assertIsNotNone(make_server_header, 'QA lobby handshake is not implemented')
        from local_auth.profiles import Profile
        header = make_server_header(P, server_id=bytes(8), nonce=bytes(8))
        self.assertEqual(header.hex(), '16000000ab81d200000000000000000000000000000000000000')
        packet = bytes.fromhex('95000000ab82') + client_body() + bytes.fromhex('c9e0d96c734499b1')
        player = Profile('VectorTest', 1, bytes(range(24)))
        lookup = lambda token: {'profile': player, 'expires': 200, 'iv_seed': 0, 'title_id': 1002} if token == bytes(128) else None
        events = []
        reply, keys, profile = verify_client_auth(
            P, header, packet, lookup, now=100, log=lambda kind, **fields: events.append((kind, fields)))
        self.assertEqual(events, [('lobby_keys_derived', {})])
        self.assertEqual(reply.hex(), '0a000000ab83a2793099a8a2bfe2')
        self.assertEqual(keys.c2s_mac.hex(), '96c0700290f791c4dc2c87edd2eabd542b619323')
        self.assertEqual(keys.s2c_mac.hex(), '14a87ea7bcab3fe0c08c5b8e33e85fd7b5ad6e55')
        # Report line wraps are not byte/key boundaries: concatenate first.
        expected_data = bytes.fromhex(
            '96c0700290f791c4dc2c87edd2eabd542b619323'
            '14a87ea7bcab3fe0c08c5b8e33e85fd7b5ad6e55'
            '178d505fc426ac71d9b323786748173d5'
            '78d3806830cfe81ef3428b1911cd101')
        self.assertEqual(keys.c2s_aes, expected_data[40:56])
        self.assertEqual(keys.s2c_aes, expected_data[56:72])
        self.assertEqual(profile, player)


    def test_startgame_keeps_session_material_on_wire_out_of_diagnostics(self):
        import json
        import socket
        import struct
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        from local_auth import lobby
        from local_auth.frames import decode_server_data, parse_args
        from local_auth.rooms import build_startgame_record, ROOM_PUSH

        keys = lobby.Keys(b'A' * 20, b'B' * 20, b'C' * 16, b'D' * 16)
        session_id, security_key = bytes(range(8)), bytes(range(16, 32))
        events = []
        sender, receiver = socket.socketpair()
        with sender, receiver, tempfile.TemporaryDirectory() as directory:
            receiver.settimeout(3)
            handler = object.__new__(lobby.LobbyHandler)
            handler.request = sender
            handler.server = SimpleNamespace(game_server=('127.0.0.1', 28960), join_password='private-password')
            handler.start_at = 0
            handler.channel_id = 69421
            with patch.object(lobby, 'STARTGAME_TRIGGER', Path(directory) / 'absent'), \
                    patch('local_auth.matchkey.fetch_match_key', return_value=(security_key, session_id)) as fetch:
                counter = handler._send_queued_startgame(
                    keys, 7, SimpleNamespace(name='StartTest'),
                    lambda kind, **fields: events.append((kind, fields)))
            fetch.assert_called_once_with('127.0.0.1', 28960, 'private-password')
            self.assertEqual(counter, 8)
            self.assertIsNone(handler.start_at)
            stream = receiver.makefile('rb')
            with stream:
                prefix = stream.read(4)
                frame = prefix + stream.read(struct.unpack('<I', prefix)[0])
            kind, application = decode_server_data(frame, keys, expected_counter=7)
            self.assertEqual(kind, ROOM_PUSH)
            record = build_startgame_record('127.0.0.1', 28960, session_id, security_key)
            self.assertEqual(parse_args(application + b'\0')[4], (19, struct.pack('<I', len(record)) + record))
            self.assertEqual(dict(events)['room_startgame_pushed'], {
                'player': 'StartTest', 'host': '127.0.0.1:28960',
                'record_bytes': len(record), 'frame_bytes': len(frame)})
            serialized = json.dumps(events)
            for secret in (session_id, security_key, record, application):
                self.assertNotIn(secret.hex(), serialized)
            self.assertNotIn('private-password', serialized)


if __name__ == '__main__':
    unittest.main()
