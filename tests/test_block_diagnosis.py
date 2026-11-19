"""Block diagnosis (owner decision 2026-11-19): the pure decision, the ClientHello and the probe steps.

The same cases as Android ``BlockDiagnosisTest.kt``; the ClientHello is byte-identical to Android's.
"""

from __future__ import annotations

import errno
import hashlib
import random
import socket
import unittest

from xray_fluent.client_reports import contract as c
from xray_fluent.client_reports import diagnosis as d
from xray_fluent.client_reports.probe import BlockProbe, ProbeTarget, measure_freeze
from xray_fluent.client_reports.reporter import probe_target_for

OK, SILENT, RESET, UNKNOWN = d.ProbeResult.ANSWERED, d.ProbeResult.TIMEOUT, d.ProbeResult.RESET, d.ProbeResult.UNKNOWN


def code(**facts):
    facts.setdefault("control", OK)
    found = d.diagnose(d.DiagnosisFacts(**facts))
    return (found.failed_step, found.detail) if found else None


class DecisionTests(unittest.TestCase):
    def test_tcp_swap_tells_a_port_block_from_a_whole_ip_block(self) -> None:
        self.assertEqual(("connect", "port_blocked"), code(tcp_target=SILENT, tcp_other_port=OK))
        self.assertEqual(("connect", "ip_blocked"), code(tcp_target=SILENT, tcp_other_port=SILENT))
        # A reset: someone answered, the address is alive.
        self.assertEqual(("connect", "tcp_reset"), code(tcp_target=RESET, tcp_other_port=SILENT))
        self.assertEqual(("connect", "port_blocked"), code(tcp_target=SILENT, tcp_other_port=RESET))
        self.assertEqual(("connect", "tcp_timeout"), code(tcp_target=SILENT))

    def test_tls_swap_tells_an_sni_block_from_an_ip_level_tls_block(self) -> None:
        base = dict(tcp_target=OK, uses_tls=True, tls_real_name=SILENT)
        self.assertEqual(("handshake", "sni_blocked"), code(**base, tls_neutral_name=OK))
        self.assertEqual(("handshake", "sni_blocked_everywhere"), code(**base, tls_neutral_name=OK, tls_real_name_elsewhere=SILENT))
        # Our front closes the connection without an answer for a foreign name (seen 2026-11-19): not a filter.
        self.assertEqual(("handshake", "sni_blocked"), code(**base, tls_neutral_name=OK, tls_real_name_elsewhere=RESET))
        self.assertEqual(("handshake", "tls_blocked"), code(**base, tls_neutral_name=SILENT))
        self.assertIsNone(code(**base, tls_neutral_name=RESET))
        self.assertIsNone(code(**base))
        self.assertIsNone(code(tcp_target=OK, uses_tls=True, tls_real_name=OK, tls_neutral_name=OK))

    def test_freeze_is_named_only_near_sixteen_kilobytes(self) -> None:
        up = dict(tcp_target=OK, uses_tls=True, tls_real_name=OK)
        self.assertEqual(("request", "freeze_16k"), code(**up, stalled_after_bytes=16_384))
        self.assertEqual(("request", "freeze_16k"), code(**up, stalled_after_bytes=4_800))
        self.assertIsNone(code(**up, stalled_after_bytes=200_000))
        self.assertIsNone(code(**up, stalled_after_bytes=0))
        self.assertIsNone(d.freeze(65_536))
        verdict = c.classify(c.AttemptFacts(succeeded=True), d.freeze(16_000))
        self.assertEqual((c.Outcome.FAILED, "request", "freeze_16k"), (verdict.outcome, verdict.failed_step, verdict.detail))
        self.assertEqual(c.Outcome.CONNECTED, c.classify(c.AttemptFacts(succeeded=True), d.Diagnosis("connect", "ip_blocked")).outcome)

    def test_dns_is_named_only_when_nothing_below_it_is_closed(self) -> None:
        poisoned = dict(system_dns=frozenset({"10.10.34.35"}), doh_dns=frozenset({"185.1.2.3"}))
        self.assertEqual(("resolve", "dns_poisoned"), code(**poisoned))
        self.assertEqual(("resolve", "dns_no_answer"), code(system_dns=frozenset(), doh_dns=frozenset({"185.1.2.3"})))
        self.assertEqual(("resolve", "dns_nxdomain"), code(doh_name_missing=True, system_dns=frozenset()))
        self.assertIsNone(code(system_dns=frozenset({"185.1.2.3", "185.1.2.4"}), doh_dns=frozenset({"185.1.2.3"})))
        self.assertEqual(("handshake", "tls_blocked"), code(**poisoned, tcp_target=OK, uses_tls=True,
                                                            tls_real_name=SILENT, tls_neutral_name=SILENT))

    def test_no_verdict_when_the_pcs_own_network_is_down(self) -> None:
        dead = d.DiagnosisFacts(control=SILENT, tcp_target=SILENT, tcp_other_port=SILENT)
        self.assertIsNone(d.diagnose(dead))
        self.assertIsNone(d.diagnose_udp(dead))
        self.assertIn("сеть компьютера", d.describe(None, dead))

    def test_udp_servers_are_judged_by_their_ip_only(self) -> None:
        self.assertEqual("ip_blocked", d.diagnose_udp(d.DiagnosisFacts(control=OK, udp_transport=True, tcp_other_port=SILENT)).detail)
        self.assertIsNone(d.diagnose_udp(d.DiagnosisFacts(control=OK, udp_transport=True, tcp_other_port=RESET)))
        self.assertIsNone(code(udp_transport=True, uses_tls=True, tcp_target=OK, tls_real_name=SILENT, tls_neutral_name=SILENT))

    def test_the_button_sends_local_errors_marked(self) -> None:
        sni = d.Diagnosis("handshake", "sni_blocked")
        self.assertEqual("sni_blocked", c.classify(c.AttemptFacts(core_code="TARGET_NETWORK_TIMEOUT"), sni).detail)
        self.assertEqual("sni_blocked", c.classify(c.AttemptFacts(), sni).detail)
        self.assertIsNone(c.classify(c.AttemptFacts(core_code="LOCAL_BIND_COLLISION"), sni))
        self.assertEqual("local_bind_collision", c.classify_forced(c.AttemptFacts(core_code="LOCAL_BIND_COLLISION")).detail)
        self.assertEqual("local_network", c.classify_forced(c.AttemptFacts(network_lost=True)).detail)
        self.assertEqual(("connect", "local_unknown"), (c.classify_forced(c.AttemptFacts()).failed_step, c.classify_forced(c.AttemptFacts()).detail))
        self.assertEqual(c.Outcome.CONNECTED, c.classify_forced(c.AttemptFacts(succeeded=True)).outcome)
        long = c.local_code("LOCAL_" + "X" * 80)
        record = c.AttemptRecord("x1", "vless", c.Outcome.FAILED, "connect", long, 1, 1_795_000_000_000, "")
        self.assertTrue(len(long) <= 48 and c.is_valid(record))

    def test_the_notice_says_what_was_found(self) -> None:
        self.assertEqual("Закрыто имя сервера (SNI): с другим именем тот же адрес отвечает.",
                         d.describe(d.Diagnosis("handshake", "sni_blocked"), None))
        self.assertEqual("Путь до сервера открыт: адрес, порт и имя отвечают.",
                         d.describe(None, d.DiagnosisFacts(control=OK, tcp_target=OK, uses_tls=True, tls_real_name=OK)))


class _Zero(random.Random):
    def getrandbits(self, k: int) -> int:
        return 0


class ClientHelloTests(unittest.TestCase):
    def test_byte_identical_to_android(self) -> None:
        hello = d.client_hello("vpn.example.com", _Zero())
        self.assertEqual(248, len(hello))
        self.assertEqual("6dc7b9266543b53282983212404e292e840180a17d9a13e7e009202ccdcd5f66", hashlib.sha256(hello).hexdigest())

    def test_well_formed_record_with_the_chosen_name(self) -> None:
        hello = d.client_hello("vpn.example.com")
        self.assertEqual(0x16, hello[0])
        self.assertEqual(len(hello) - 5, int.from_bytes(hello[3:5], "big"))
        self.assertEqual(1, hello[5])
        self.assertEqual(len(hello) - 9, int.from_bytes(hello[6:9], "big"))
        self.assertEqual("vpn.example.com", d.server_name_of(hello))
        self.assertEqual("ya.ru", d.server_name_of(d.client_hello("ya.ru.")))
        self.assertNotEqual(hello, d.client_hello("vpn.example.com"))
        self.assertEqual(OK, d.judge_first_byte(0x15))
        self.assertEqual(RESET, d.judge_first_byte(-1))


class _Sock:
    def __init__(self, answer: bytes | Exception) -> None:
        self.answer = answer
        self.sent = b""

    def settimeout(self, _value) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, _size: int) -> bytes:
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer

    def close(self) -> None:
        pass


class ProbeTests(unittest.TestCase):
    """The network steps with a scripted network: (ip, port) → connect result, SNI → TLS answer."""

    FRONT = "161.104.89.59"
    SERVER = "203.0.113.10"

    def _probe(self, connect_map, tls_by_name=None, *, system=None, doh=None):
        tls_by_name = tls_by_name or {}
        sockets: list[_Sock] = []

        def connect(address, _timeout):
            result = connect_map.get(address, OK)
            if isinstance(result, Exception):
                raise result
            sock = _Sock(b"")
            original = sock.recv

            def recv(size):
                name = d.server_name_of(sock.sent)
                answer = tls_by_name.get((address, name), b"\x16")
                sock.answer = answer
                return original(size)

            sock.recv = recv
            sockets.append(sock)
            return sock

        def system_lookup(host):
            if host.endswith("fuckingspeedtest.com") or host.endswith("osjcpjzipyb.click"):
                return {self.FRONT}
            if isinstance(system, Exception):
                raise system
            return set(system if system is not None else {self.SERVER})

        def doh_lookup(_host):
            return set(doh if doh is not None else {self.SERVER})

        probe = BlockProbe(lambda: ["oeifnxndqq.fuckingspeedtest.com"], rng=random.Random(1), connect=connect,
                           system_lookup=system_lookup, doh_lookup=doh_lookup)
        return probe

    def test_sni_block_is_found_by_swapping_the_name(self) -> None:
        target = ProbeTarget("nl.node.example", 8443, "www.microsoft.com", uses_tls=True, udp=False)
        silence = socket.timeout("timed out")
        probe = self._probe({}, {((self.SERVER, 8443), "www.microsoft.com"): silence})
        facts = probe.run(target)
        self.assertEqual((OK, OK, SILENT, OK), (facts.control, facts.tcp_target, facts.tls_real_name, facts.tls_neutral_name))
        self.assertEqual("sni_blocked", d.diagnose(facts).detail)

    def test_a_silent_ip_is_ip_blocked(self) -> None:
        silence = socket.timeout("timed out")
        probe = self._probe({(self.SERVER, 8443): silence, (self.SERVER, 443): silence})
        facts = probe.run(ProbeTarget("nl.node.example", 8443, None, uses_tls=True, udp=False))
        self.assertEqual("ip_blocked", d.diagnose(facts).detail)

    def test_a_refused_port_is_a_reset(self) -> None:
        probe = self._probe({(self.SERVER, 8443): ConnectionRefusedError(errno.ECONNREFUSED, "refused")})
        self.assertEqual("tcp_reset", d.diagnose(probe.run(ProbeTarget("203.0.113.10", 8443, None, True, False))).detail)

    def test_no_network_means_no_verdict(self) -> None:
        silence = socket.timeout("timed out")
        probe = self._probe({(self.FRONT, 443): silence, (self.SERVER, 8443): silence, (self.SERVER, 443): silence})
        facts = probe.run(ProbeTarget("nl.node.example", 8443, None, uses_tls=True, udp=False))
        self.assertEqual(SILENT, facts.control)
        self.assertIsNone(d.diagnose(facts))

    def test_udp_server_checks_only_its_ip(self) -> None:
        probe = self._probe({(self.SERVER, 443): socket.timeout("timed out")})
        facts = probe.run(ProbeTarget("hy.node.example", 443, "hy.node.example", uses_tls=False, udp=True))
        self.assertEqual("ip_blocked", d.diagnose_udp(facts).detail)

    def test_poisoned_system_dns(self) -> None:
        probe = self._probe({}, system={"10.10.34.35"})
        facts = probe.run(ProbeTarget("nl.node.example", 443, None, uses_tls=False, udp=False))
        self.assertEqual("dns_poisoned", d.diagnose(facts).detail)


class TargetTests(unittest.TestCase):
    def test_target_of_a_reality_node_uses_its_server_name(self) -> None:
        node = type("Node", (), {})()
        node.server, node.port, node.scheme = "nl.node.example", 8443, "vless"
        node.outbound = {"streamSettings": {"security": "reality", "realitySettings": {"serverName": "www.microsoft.com"}}}
        self.assertEqual(ProbeTarget("nl.node.example", 8443, "www.microsoft.com", True, False, "vless", "tcp", "reality"),
                         probe_target_for(node))
        node.outbound = {"streamSettings": {"network": "xhttp", "security": "tls", "tlsSettings": {"serverName": "a.example"}}}
        self.assertEqual(("xhttp", "tls"), (probe_target_for(node).transport, probe_target_for(node).security))
        node.scheme, node.outbound = "hysteria2", {"tls": {"server_name": "hy.example"}}
        self.assertEqual(ProbeTarget("nl.node.example", 8443, "hy.example", False, True, "hysteria2", "quic", "tls"),
                         probe_target_for(node))
        node.port = 0
        self.assertIsNone(probe_target_for(node))


class FreezeTests(unittest.TestCase):
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

    def test_a_stall_reports_the_bytes_and_a_full_read_reports_nothing(self) -> None:
        self.assertEqual(16_384, measure_freeze(None, opener=self._opener([b"x" * 8192, b"x" * 8192], stall=True)))
        self.assertIsNone(measure_freeze(None, opener=self._opener([b"x" * 8192] * 8, stall=False)))
        self.assertIsNone(measure_freeze(None))   # no session proxy: nothing to measure


if __name__ == "__main__":
    unittest.main()
