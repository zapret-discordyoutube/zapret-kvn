"""The path check after a failure (schema 3): only facts, a minimal ladder, no hand-made packets.

Owner 2026-11-19: «make sure there are no unnecessary checks that could trigger DPI», «check as rarely as possible
and only if it's really necessary». The same ladder as Android ``BlockProbeTest.kt``.
"""

from __future__ import annotations

import datetime
import errno
import random
import socket
import ssl
import tempfile
import threading
import unittest
from pathlib import Path

from xray_fluent.client_reports import checks as k
from xray_fluent.client_reports.probe import (
    BlockProbe,
    NoDataProbe,
    ProbeTarget,
    Relay,
    measure_flow,
    needs_path_check,
    result_of,
    system_hello,
)
from xray_fluent.client_reports.reporter import probe_target_for

FRONT = "161.104.89.59"
SERVER = "203.0.113.10"
NEUTRAL = "77.88.44.242"


class _Sock:
    def close(self) -> None:
        pass


class LadderTests(unittest.TestCase):
    """A scripted network: (ip, port) -> connect result, (ip, port, name) -> TLS result."""

    def _probe(self, connects=None, hellos=None, *, system=None, doh=None):
        connects, hellos = connects or {}, hellos or {}
        self.wire: list[tuple] = []

        def connect(address, _timeout):
            self.wire.append(("tcp",) + tuple(address))
            result = connects.get(tuple(address))
            if isinstance(result, Exception):
                raise result
            sock = _Sock()
            sock.address = tuple(address)
            return sock

        def hello(sock, name):
            self.wire.append(("tls",) + sock.address + (name,))
            return hellos.get(sock.address + (name,), k.ANSWERED)

        def system_lookup(host):
            self.wire.append(("dns_system", host))
            if host.endswith("fuckingspeedtest.com"):
                return {FRONT}
            if host in ("ya.ru", "vk.com", "www.gosuslugi.ru", "ozon.ru", "www.wildberries.ru"):
                return {NEUTRAL}
            if isinstance(system, Exception):
                raise system
            return set(system if system is not None else {SERVER})

        def doh_lookup(host):
            self.wire.append(("dns_doh", host))
            if isinstance(doh, Exception):
                raise doh
            return set(doh if doh is not None else {SERVER})

        self.pauses: list[float] = []
        return BlockProbe(lambda: ["oeifnxndqq.fuckingspeedtest.com"], rng=random.Random(1), connect=connect,
                          system_lookup=system_lookup, doh_lookup=doh_lookup, hello=hello,
                          clock=iter(range(0, 10_000, 1)).__next__, pause=self.pauses.append)

    def _server_wire(self):
        return [step for step in self.wire if SERVER in step]

    def test_sni_block_shows_as_facts_and_the_front_never_hears_the_servers_name(self) -> None:
        silence = socket.timeout("timed out")
        probe = self._probe(hellos={(SERVER, 8443, "www.microsoft.com"): k.TIMEOUT})
        facts = probe.run(ProbeTarget("nl.node.example", 8443, "www.microsoft.com", True, False))
        self.assertEqual({"control_front": "answered", "dns_doh": "answered", "tcp_target": "answered",
                          "tls_real": "timeout", "tls_neutral": "answered"},
                         {probe: check.r for probe, check in facts.checks.items()})
        self.assertEqual(SERVER, facts.probed_address)
        self.assertFalse(any(step[0] == "tls" and step[1] == FRONT for step in self.wire))
        self.assertNotIn("tls_front", facts.checks)
        self.assertFalse(any(step[0] == "dns_system" and step[1] == "nl.node.example" for step in self.wire))
        self.assertTrue(all(0.15 <= gap <= 0.7 for gap in self.pauses))
        del silence

    def test_the_address_the_start_used_needs_no_dns_probe(self) -> None:
        probe = self._probe()
        facts = probe.run(ProbeTarget("nl.node.example", 443, None, False, False), known_address=SERVER)
        self.assertEqual(["control_front", "tcp_target"], list(facts.checks))

    def test_the_system_resolver_only_when_doh_did_not_answer(self) -> None:
        probe = self._probe(doh=OSError("doh blocked"))
        facts = probe.run(ProbeTarget("nl.node.example", 443, None, False, False))
        self.assertEqual(("unknown", "answered"), (facts.checks["dns_doh"].r, facts.checks["dns_system"].r))

    def test_a_silent_port_asks_443_and_a_refused_one_does_not(self) -> None:
        silence = socket.timeout("timed out")
        probe = self._probe({(SERVER, 8443): silence, (SERVER, 443): silence})
        facts = probe.run(ProbeTarget("nl.node.example", 8443, None, True, False), known_address=SERVER)
        self.assertEqual(("timeout", "timeout"), (facts.checks["tcp_target"].r, facts.checks["tcp_443"].r))
        probe = self._probe({(SERVER, 8443): ConnectionRefusedError(errno.ECONNREFUSED, "refused")})
        facts = probe.run(ProbeTarget("nl.node.example", 8443, None, True, False), known_address=SERVER)
        self.assertEqual("refused", facts.checks["tcp_target"].r)
        self.assertNotIn("tcp_443", facts.checks)          # the address answered: nothing more to learn

    def test_no_network_stops_after_the_neutral_control(self) -> None:
        silence = socket.timeout("timed out")
        probe = self._probe({(FRONT, 443): silence, (NEUTRAL, 443): silence})
        facts = probe.run(ProbeTarget("nl.node.example", 8443, None, True, False))
        self.assertEqual(["control_front", "control_neutral"], list(facts.checks))
        self.assertEqual([], self._server_wire())           # the server is never touched

    def test_a_udp_line_gets_no_probe_of_the_server(self) -> None:
        probe = self._probe()
        facts = probe.run(ProbeTarget("hy.node.example", 443, "hy.node.example", False, True, carrier="udp"),
                          known_address=SERVER)
        self.assertEqual(["control_front"], list(facts.checks))
        self.assertEqual([], self._server_wire())

    def test_a_code_that_proves_the_server_answered_needs_no_check(self) -> None:
        self.assertFalse(needs_path_check("TARGET_AUTH_REJECTED"))
        self.assertFalse(needs_path_check("TARGET_TLS_REJECTED"))
        self.assertFalse(needs_path_check("LOCAL_BIND_COLLISION"))
        self.assertFalse(needs_path_check("NETWORK_LOST"))
        self.assertTrue(needs_path_check("TARGET_NETWORK_TIMEOUT"))
        self.assertTrue(needs_path_check(""))

    def test_errors_before_and_after_connect(self) -> None:
        self.assertEqual("refused", result_of(ConnectionRefusedError(), connected=False))
        self.assertEqual("reset", result_of(ConnectionResetError(), connected=True))
        self.assertEqual("timeout", result_of(socket.timeout(), connected=False))
        self.assertEqual("unknown", result_of(OSError(errno.ENETUNREACH, "unreachable"), connected=False))


def _self_signed(folder: Path) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    cert_path, key_path = folder / "cert.pem", folder / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


class SystemHelloTests(unittest.TestCase):
    """The real system TLS stack against local servers that answer, stay silent or hang up."""

    def _serve(self, behaviour):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        self.addCleanup(listener.close)

        def run():
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            try:
                behaviour(conn)
            except (OSError, ssl.SSLError):
                pass
            finally:
                conn.close()

        threading.Thread(target=run, daemon=True).start()
        return socket.create_connection(listener.getsockname(), timeout=2)

    def test_an_untrusted_certificate_is_an_answer(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        cert, key = _self_signed(Path(folder.name))
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert, key)

        def tls(conn):
            with server_context.wrap_socket(conn, server_side=True) as wrapped:
                wrapped.recv(1)

        self.assertEqual("answered", system_hello(self._serve(tls), "www.microsoft.com", timeout=2))

    def test_a_hang_up_is_a_reset_and_silence_a_timeout(self) -> None:
        self.assertEqual("reset", system_hello(self._serve(lambda conn: conn.recv(4096)), "ya.ru", timeout=2))
        stop = threading.Event()
        self.addCleanup(stop.set)
        self.assertEqual("timeout", system_hello(self._serve(lambda conn: stop.wait(3)), "ya.ru", timeout=0.3))


class TargetTests(unittest.TestCase):
    def test_target_of_a_node_names_its_carrier(self) -> None:
        node = type("Node", (), {})()
        node.server, node.port, node.scheme = "nl.node.example", 8443, "vless"
        node.outbound = {"streamSettings": {"security": "reality", "realitySettings": {"serverName": "www.microsoft.com"}}}
        target = probe_target_for(node)
        self.assertEqual(("www.microsoft.com", True, False, "tcp", "reality", "tcp"),
                         (target.server_name, target.uses_tls, target.udp, target.transport, target.security, target.carrier))
        node.outbound = {"streamSettings": {"network": "xhttp", "security": "tls",
                                            "tlsSettings": {"serverName": "a.example", "alpn": ["h3"]}}}
        self.assertEqual(("xhttp", "udp"), (probe_target_for(node).transport, probe_target_for(node).carrier))
        node.scheme, node.outbound = "hysteria2", {"tls": {"server_name": "hy.example"}}
        self.assertEqual(("quic", "udp", True), (probe_target_for(node).transport, probe_target_for(node).carrier,
                                                 probe_target_for(node).udp))
        node.port = 0
        self.assertIsNone(probe_target_for(node))


class FlowTests(unittest.TestCase):
    def _opener(self, chunks, stall: bool):
        class Response:
            status = 206

            def __init__(self):
                self.chunks = list(chunks)

            def read(self, _size):
                if self.chunks:
                    return self.chunks.pop(0)
                if stall:
                    raise TimeoutError("The read operation timed out")
                return b""

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        class Opener:
            def open(self, _request, timeout=None):
                return Response()

        return Opener()

    def test_a_stall_reports_the_bytes_and_a_full_read_answers(self) -> None:
        stalled = measure_flow(None, opener=self._opener([b"x" * 8192, b"x" * 8192], stall=True))
        self.assertEqual(("timeout", 16_384), (stalled.r, stalled.b))
        full = measure_flow(None, opener=self._opener([b"x" * 8192] * 8, stall=False))
        self.assertEqual(("answered", 65_536), (full.r, full.b))
        self.assertIsNone(measure_flow(None))   # no session proxy: not run


class NoDataTests(unittest.TestCase):
    def test_tunnel_by_address_and_name_then_direct_only_when_direct(self) -> None:
        calls: list[tuple] = []

        def through(relay, target, name, _path, _timeout):
            calls.append(("tunnel", target, name))
            raise socket.timeout("timed out")

        def direct(target, name, _path, _timeout):
            calls.append(("direct", target, name))

        probe = NoDataProbe(rng=random.Random(3), doh_lookup=lambda _name: {"142.250.1.1"}, through_relay=through,
                            direct=direct, pause=lambda _s: None)
        found = probe.run(Relay(1080, "u", "p"), direct_allowed=True)
        self.assertEqual({"tunnel_a": "timeout", "tunnel_b": "timeout", "direct_a": "answered", "direct_b": "answered"},
                         {probe: check.r for probe, check in found.items()})
        self.assertIn(("tunnel", "142.250.1.1", calls[0][2]), calls)       # tunnel_a: a literal address, no DNS
        calls.clear()
        found = NoDataProbe(rng=random.Random(3), doh_lookup=lambda _name: {"142.250.1.1"}, through_relay=through,
                            direct=direct, pause=lambda _s: None).run(Relay(1080, "u", "p"), direct_allowed=False)
        self.assertEqual({"tunnel_a", "tunnel_b"}, set(found))
        self.assertFalse(any(kind == "direct" for kind, *_ in calls))


if __name__ == "__main__":
    unittest.main()
