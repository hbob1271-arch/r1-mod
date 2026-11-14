import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from local_auth import lobby
from local_auth.matchkey import MatchKeyRefused, build_request, fetch_match_key, parse_reply

KEY = bytes(range(16))
SESSION = bytes([70, 0, 0, 0, 0, 0, 0, 0])
REPLY = b'\xff\xff\xff\xffmatchkey ' + KEY.hex().encode() + b' ' + SESSION.hex().encode()


class FakeServer(threading.Thread):
    """Answers each getmatchkey with `reply(request)`, like r1-server's SVC_MatchKey."""

    def __init__(self, reply):
        super().__init__(daemon=True)
        self.reply = reply
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.settimeout(5)
        self.port = self.sock.getsockname()[1]
        self.requests = []

    def run(self):
        try:
            data, source = self.sock.recvfrom(2048)
        except OSError:
            return
        self.requests.append(data)
        answer = self.reply(data)
        if answer is not None:
            self.sock.sendto(answer, source)

    def close(self):
        self.sock.close()


class MatchKeyProtocol(unittest.TestCase):
    def test_request_carries_the_password_quoted(self):
        self.assertEqual(build_request(), b'\xff\xff\xff\xffgetmatchkey')
        self.assertEqual(build_request('hunter 2'), b'\xff\xff\xff\xffgetmatchkey "hunter 2"')

    def test_reply_gives_key_and_security_id(self):
        self.assertEqual(parse_reply(REPLY), (KEY, SESSION))

    def test_refusals_raise(self):
        with self.assertRaisesRegex(MatchKeyRefused, 'password'):
            parse_reply(b'\xff\xff\xff\xffmatchkey refused')
        with self.assertRaisesRegex(MatchKeyRefused, 'no match key'):
            parse_reply(b'\xff\xff\xff\xffmatchkey unavailable')

    def test_other_packets_are_not_replies(self):
        for data in (b'matchkey 00', b'\xff\xff\xff\xffstatusResponse\n', b'\xff\xff\xff\xffmatchkey abc def'):
            with self.assertRaises(ValueError):
                parse_reply(data)

    def test_fetch_over_udp(self):
        server = FakeServer(lambda request: REPLY)
        server.start()
        try:
            self.assertEqual(fetch_match_key('127.0.0.1', server.port, 'pw', timeout=2, tries=1), (KEY, SESSION))
        finally:
            server.join(5); server.close()
        self.assertEqual(server.requests, [build_request('pw')])

    def test_fetch_without_an_answer_is_none(self):
        server = FakeServer(lambda request: None)
        server.start()
        try:
            self.assertIsNone(fetch_match_key('127.0.0.1', server.port, timeout=0.2, tries=1))
        finally:
            server.join(5); server.close()

    def test_wrong_ip_same_port_cannot_supply_match_key(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
            target.bind(('127.0.0.1', 0))
            target.settimeout(2)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
                other.bind(('127.0.0.2', target.getsockname()[1]))
                failures = []
                def respond():
                    try:
                        _, source = target.recvfrom(2048)
                        other.sendto(REPLY, source)
                    except OSError as error:
                        failures.append(error)
                worker = threading.Thread(target=respond)
                worker.start()
                try:
                    self.assertIsNone(fetch_match_key('127.0.0.1', target.getsockname()[1],
                                                      timeout=0.1, tries=1))
                finally:
                    worker.join(3)
                self.assertFalse(worker.is_alive())
                self.assertEqual(failures, [])

    def test_invalid_packets_do_not_extend_attempt_deadline(self):
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        sock.recvfrom.return_value = (b'garbage', ('127.0.0.1', 28960))
        with mock.patch('local_auth.matchkey.socket.socket', return_value=sock), \
             mock.patch('local_auth.matchkey.socket.gethostbyname', return_value='127.0.0.1'), \
             mock.patch('local_auth.matchkey.time.monotonic', side_effect=[0, 0.2, 0.9, 1.1]):
            self.assertIsNone(fetch_match_key('localhost', 28960, timeout=1, tries=1))
        self.assertEqual(sock.recvfrom.call_count, 2)
        self.assertEqual(sock.sendto.call_args.args[1], ('127.0.0.1', 28960))


class MatchSession(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.event = lambda kind, **fields: self.events.append(kind)
        self.dir = tempfile.TemporaryDirectory()
        self.key_file = Path(self.dir.name) / 'state' / 'securitykey.bin'
        patcher = mock.patch.object(lobby, 'SECURITY_KEY_FILE', self.key_file)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.dir.cleanup)

    def test_server_key_is_used_and_no_key_file_written(self):
        session = lobby.match_session('203.0.113.5', 28960, '', self.event, fetch=lambda *a: (KEY, SESSION))
        self.assertEqual(session, (SESSION, KEY))
        self.assertFalse(self.key_file.exists())
        self.assertIn('matchkey_received', self.events)

    def test_remote_server_without_an_answer_is_not_joined(self):
        with mock.patch('builtins.print'):
            self.assertIsNone(lobby.match_session('203.0.113.5', 28960, '', self.event, fetch=lambda *a: None))
        self.assertIn('startgame_no_matchkey', self.events)

    def test_refusal_is_not_joined(self):
        def refuse(*a):
            raise MatchKeyRefused('wrong join password')
        with mock.patch('builtins.print'):
            self.assertIsNone(lobby.match_session('203.0.113.5', 28960, 'x', self.event, fetch=refuse))
        self.assertIn('startgame_refused', self.events)

    def test_local_server_without_an_answer_gets_a_written_key(self):
        session = lobby.match_session('127.0.0.1', 28960, '', self.event, fetch=lambda *a: None)
        self.assertEqual(session[0], lobby.STARTGAME_SESSION_ID)
        self.assertEqual(self.key_file.read_bytes(), session[1])
        self.assertEqual(len(session[1]), 16)


if __name__ == '__main__':
    unittest.main()
