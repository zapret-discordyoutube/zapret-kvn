"""Real local Hysteria server with a deliberately silent HTTPS destination.

Windows release gates use the pinned bundled core. Linux can opt in with
HYSTERIA_TEST_BINARY. All listeners and all data traffic stay on loopback.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from PyQt6.QtCore import QCoreApplication, QProcess
from xray_fluent.constants import HYSTERIA_PATH_DEFAULT
from xray_fluent.engines.hysteria.manager import HysteriaManager
from xray_fluent.engines.socks_probe import open_socks_connection

_APP = QCoreApplication.instance() or QCoreApplication([])
_BINARY = os.environ.get('HYSTERIA_TEST_BINARY', str(HYSTERIA_PATH_DEFAULT) if os.name == 'nt' else '')


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


@unittest.skipUnless(_BINARY and Path(_BINARY).is_file(), 'requires pinned Hysteria test binary')
class LiveHysteriaReadinessTests(unittest.TestCase):
    def test_authenticated_core_stays_running_when_https_destinations_are_silent(self):
        with tempfile.TemporaryDirectory(prefix='hy-health-') as directory:
            root = Path(directory)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
            now = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
                        x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
                    .sign(key, hashes.SHA256()))
            (root/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            (root/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            (root/'key.pem').chmod(0o600)
            server_port = free_port(socket.SOCK_DGRAM)
            server_config = {'listen': f'127.0.0.1:{server_port}',
                'tls': {'cert': str(root/'cert.pem'), 'key': str(root/'key.pem')},
                'auth': {'type': 'password', 'password': 'local-test-only'},
                'obfs': {'type': 'salamander', 'salamander': {'password': 'local-obfs-only'}}}
            (root/'server.json').write_text(json.dumps(server_config))
            stop = threading.Event()
            accepted = []
            blackhole = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            blackhole.bind(('127.0.0.1', 0)); blackhole.listen(); blackhole.settimeout(0.1)
            target_port = blackhole.getsockname()[1]
            def accept_silent_connections():
                while not stop.is_set():
                    try:
                        conn, _ = blackhole.accept(); accepted.append(conn)
                    except socket.timeout:
                        pass
                    except OSError:
                        break
            accept_thread = threading.Thread(target=accept_silent_connections, daemon=True)
            accept_thread.start()
            manager = None
            with (root/'server.log').open('wb') as server_log:
                server = subprocess.Popen([str(Path(_BINARY).resolve()), '--config', str(root/'server.json'),
                    '--disable-update-check', '--log-level', 'info', 'server'],
                    stdout=server_log, stderr=subprocess.STDOUT,
                    creationflags=0x08000000 if os.name == 'nt' else 0)
                try:
                    deadline = time.monotonic() + 10
                    while 'server up and running' not in (root/'server.log').read_text(errors='replace'):
                        if server.poll() is not None or time.monotonic() > deadline:
                            self.fail('local Hysteria server did not start: ' + (root/'server.log').read_text(errors='replace'))
                        time.sleep(0.02)
                    with patch('xray_fluent.engines.hysteria.manager.HYSTERIA_PATH_DEFAULT', Path(_BINARY)), \
                         patch('xray_fluent.engines.hysteria.manager.HYSTERIA_CONFIG_FILE', root/'client.json'), \
                         patch('xray_fluent.engines.hysteria.manager.RUNTIME_DIR', root):
                        manager = HysteriaManager()
                        warnings, errors = [], []
                        manager.warning.connect(warnings.append)
                        manager.error.connect(errors.append)
                        relay_port = free_port(socket.SOCK_STREAM)
                        client_config = {'server': f'127.0.0.1:{server_port}', 'auth': 'local-test-only', 'lazy': True,
                            'quic': {'disableChromeParrot': True}, 'obfs': server_config['obfs'],
                            'tls': {'sni': 'localhost', 'insecure': True,
                                'pinSHA256': hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()},
                            'socks5': {'listen': f'127.0.0.1:{relay_port}', 'username': 'local', 'password': 'test'}}
                        def blocked_https(port, *, username, password, **_):
                            raw = open_socks_connection(port, username=username, password=password,
                                timeout=0.5, target_host='127.0.0.1', target_port=target_port)
                            try:
                                with ssl.create_default_context().wrap_socket(raw, server_hostname='localhost'):
                                    raise AssertionError('silent peer unexpectedly completed TLS')
                            finally:
                                raw.close()
                        with patch.object(manager, '_probe_remote_endpoint', side_effect=blocked_https):
                            self.assertTrue(manager.start(client_config, relay_port, process_generation=17, allow_parallel=True),
                                            "\n".join(manager._last_output_lines))
                            deadline = time.monotonic() + 5
                            while not warnings and time.monotonic() < deadline:
                                _APP.processEvents(); time.sleep(0.01)
                        self.assertTrue(accepted, 'the probe must actually traverse the real Hysteria server')
                        self.assertEqual(errors, [])
                        self.assertEqual(len(warnings), 1)
                        self.assertTrue(manager.is_running)
                        self.assertEqual(manager._process.state(), QProcess.ProcessState.Running)
                        self.assertEqual(manager.stats, {'remote_authenticated': True, 'https_check': 'warning'})
                finally:
                    if manager is not None:
                        manager.stop(); manager.deleteLater(); _APP.processEvents()
                    server.terminate()
                    try:
                        server.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        server.kill(); server.wait(timeout=3)
                    stop.set(); blackhole.close(); accept_thread.join(timeout=1)
                    for conn in accepted:
                        conn.close()
