import base64
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from local_auth.profiles import ProfileStore
try:
    from local_auth.server import make_server
except ImportError:
    make_server = None


def make_test_certificates(directory):
    """Ephemeral loopback PKI; never read or replace a developer's certificates."""
    from datetime import datetime, timedelta, timezone
    from ipaddress import ip_address
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Ephemeral test CA')])
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '127.0.0.1')])

    def builder(subject, public_key):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
                .public_key(public_key).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                               critical=False))

    ca_cert = (builder(ca_name, ca_key.public_key())
               .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
               .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                              critical=True).sign(ca_key, hashes.SHA256()))
    server_cert = (builder(server_name, server_key.public_key())
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False),
                                  critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                   .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip_address('127.0.0.1'))]),
                                  critical=False).sign(ca_key, hashes.SHA256()))
    ca = directory / 'ca.pem'
    certificate = directory / 'server.pem'
    ca.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    certificate.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM) + server_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return certificate, ca


class ServerTests(unittest.TestCase):
    def test_invalid_requests_do_not_issue_sessions(self):
        self.assertIsNotNone(make_server)
        with tempfile.TemporaryDirectory() as directory:
            player = ProfileStore(Path(directory) / 'profiles.db').get_or_create('Tester')
            server = make_server(player, port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for method, path, body, expected in [
                    ('POST', '/auth/', '{', 400),
                    ('POST', '/auth/', '[]', 400),
                    ('POST', '/auth/', json.dumps({'auth_task': '29', 'title_id': '1002', 'iv_seed': '1'}), 400),
                    ('POST', '/wrong', '{}', 404),
                    ('GET', '/wrong', None, 404),
                ]:
                    with self.subTest(method=method, path=path, body=body):
                        conn = http.client.HTTPConnection(*server.server_address, timeout=3)
                        try:
                            conn.request(method, path, body)
                            response = conn.getresponse()
                            self.assertEqual(response.status, expected)
                            response.read()
                        finally:
                            conn.close()
                self.assertEqual(len(server.sessions), 0)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(3)

    def test_tls_accepts_qa_style_expect_continue_request(self):
        import ssl
        import warnings
        with tempfile.TemporaryDirectory() as directory:
            certificate, ca = make_test_certificates(Path(directory))
            player = ProfileStore(Path(directory) / 'profiles.db').get_or_create('TLSPlayer')
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', DeprecationWarning)
                server = make_server(player, port=0, certfile=str(certificate))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            context = ssl.create_default_context(cafile=str(ca))
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            conn = http.client.HTTPSConnection(*server.server_address, context=context, timeout=3)
            try:
                conn.request('POST', '/auth/', json.dumps({'auth_task': '10', 'title_id': '1002', 'iv_seed': '42'}),
                             {'Content-Type': 'application/json', 'Expect': '100-continue'})
                response = conn.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(json.loads(response.read())['code'], '700')
            finally:
                conn.close()
                server.shutdown()
                server.server_close()
                thread.join(3)

    def test_auth_over_http_issues_selected_local_name(self):
        self.assertIsNotNone(make_server, 'HTTP auth service is not implemented')
        with tempfile.TemporaryDirectory() as directory:
            player = ProfileStore(Path(directory) / 'profiles.db').get_or_create('MenuTester')
            server = make_server(player, port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            conn = http.client.HTTPConnection(*server.server_address, timeout=3)
            try:
                conn.request('POST', '/auth/', json.dumps({'auth_task': '10', 'title_id': '1002', 'iv_seed': '42'}),
                             {'Content-Type': 'application/json'})
                response = conn.getresponse()
                self.assertEqual(response.status, 200)
                result = json.loads(response.read())
                self.assertEqual(result['auth_task'], '11')
                ticket = base64.b64decode(result['client_ticket'])
                self.assertEqual(ticket[33:97].rstrip(b'\0'), b'MenuTester')
                self.assertEqual(len(server.sessions), 1)
                session = next(iter(server.sessions.values()))
                self.assertEqual(session['iv_seed'], 42)
                self.assertEqual(session['title_id'], 1002)
            finally:
                conn.close()
                server.shutdown()
                server.server_close()
                thread.join(3)


if __name__ == '__main__':
    unittest.main()
