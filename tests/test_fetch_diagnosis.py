from __future__ import annotations

import socket
import threading
import unittest
from types import SimpleNamespace

from xray_fluent.network import fetch_diagnosis as fd
from xray_fluent.network.fetch_diagnosis import (
    CULPRIT_BLOCK,
    CULPRIT_NETWORK,
    CULPRIT_REFUSED,
    CULPRIT_SERVER,
    CULPRIT_VPN,
    Evidence,
    HostProbe,
    blame_for_http,
    host_tag,
    judge,
    mask_host,
    redact_host,
)

OK = HostProbe(True)
HOST = "url.globalinetforall.example.com"


def fail(stage: str, how: str = "timeout", detail: str = "") -> HostProbe:
    return HostProbe(False, stage, how, (("dns", 5),), detail)


class MaskingTests(unittest.TestCase):
    def test_host_is_recognisable_but_not_complete(self) -> None:
        self.assertEqual(mask_host("url.globalinetforall.example.com"), "url.gl***.ex***.com")
        self.assertEqual(mask_host("203.0.113.9"), "203.0.*.*")
        self.assertEqual(mask_host("sub.zapret.moe"), "sub.za***.moe")

    def test_tag_has_stable_fingerprint_and_no_full_host(self) -> None:
        tag = host_tag(HOST, 443)
        self.assertEqual(tag, host_tag(HOST.upper(), 443))
        self.assertNotIn("globalinetforall", tag)
        self.assertRegex(tag, r":443#[0-9a-f]{6}$")
        self.assertNotEqual(tag, host_tag("other.example.com", 443))

    def test_raw_error_text_loses_the_host(self) -> None:
        text = redact_host(f"connect to {HOST} failed", HOST)
        self.assertNotIn(HOST, text)
        self.assertIn("#", text)


class JudgeTests(unittest.TestCase):
    def verdict(self, direct, vpn=None):
        return judge(Evidence(HOST, 443, direct, vpn))

    def test_tls_hang_with_vpn_working_is_a_block(self) -> None:
        d = self.verdict((fail("tls"), OK), (OK, OK))
        self.assertEqual((d.culprit, d.certain), (CULPRIT_BLOCK, True))
        self.assertIn("SNI", d.where)

    def test_tls_hang_without_vpn_is_a_probable_block_with_hint(self) -> None:
        d = self.verdict((fail("tls", "reset"), OK))
        self.assertEqual((d.culprit, d.certain), (CULPRIT_BLOCK, False))
        self.assertIn("Через VPN не пробовали", d.advice)
        self.assertIn("(вероятно)", d.message())

    def test_probable_block_with_servers_says_to_connect_to_any_server_and_keeps_the_note(self) -> None:
        d = judge(Evidence(HOST, 443, (fail("tls"), OK), None, servers_available=True))
        self.assertIn("Подключитесь к любому серверу", d.advice)
        self.assertIn("повторять, пока не получится", d.advice)
        self.assertIn("Через VPN не пробовали", d.advice)

    def test_probable_block_without_any_server_asks_for_a_single_key_not_a_vpn(self) -> None:
        d = judge(Evidence(HOST, 443, (fail("tls"), OK), None, servers_available=False))
        self.assertEqual((d.culprit, d.certain), (CULPRIT_BLOCK, False))
        self.assertIn("хотя бы один сервер", d.advice)
        self.assertIn("одиночный ключ", d.advice)
        self.assertIn("не подписку", d.advice)
        self.assertIn("Ctrl+V", d.advice)
        self.assertIn("загрузится сама через этот сервер", d.advice)
        self.assertNotIn("Включите VPN", d.advice)
        self.assertNotIn("Через VPN не пробовали", d.advice)

    def test_the_server_flag_changes_nothing_once_the_vpn_is_connected(self) -> None:
        with_flag = judge(Evidence(HOST, 443, (fail("tls"), OK), (OK, OK), servers_available=True))
        without_flag = judge(Evidence(HOST, 443, (fail("tls"), OK), (OK, OK), servers_available=False))
        self.assertEqual(with_flag.advice, without_flag.advice)
        self.assertEqual((with_flag.culprit, with_flag.certain), (CULPRIT_BLOCK, True))

    def test_the_server_flag_does_not_touch_other_verdicts(self) -> None:
        for flag in (True, False):
            d = judge(Evidence(HOST, 443, (fail("tcp"), OK), (fail("tcp"), OK), servers_available=flag))
            self.assertEqual((d.culprit, d.certain), (CULPRIT_SERVER, True))

    def test_collect_evidence_carries_the_server_flag(self) -> None:
        def direct(host, port):
            return OK

        ev = fd.collect_evidence(HOST, 443, tunnel_port=None, direct_probe=direct, servers_available=False)
        self.assertFalse(ev.servers_available)
        self.assertTrue(fd.collect_evidence(HOST, 443, tunnel_port=None, direct_probe=direct).servers_available)

    def test_vpn_connected_but_control_fails_is_vpn(self) -> None:
        d = self.verdict((fail("tcp"), OK), (fail("proxy", "status", "ответ прокси 502"), fail("proxy", "status", "ответ прокси 502")))
        self.assertEqual((d.culprit, d.certain), (CULPRIT_VPN, True))

    def test_everything_down_is_the_users_network(self) -> None:
        d = self.verdict((fail("dns", "dns"), fail("dns", "dns")), (fail("proxy_local", "refused"), fail("proxy_local", "refused")))
        self.assertEqual(d.culprit, CULPRIT_NETWORK)

    def test_server_down_everywhere_is_the_bot(self) -> None:
        d = self.verdict((fail("tcp"), OK), (fail("tcp"), OK))
        self.assertEqual((d.culprit, d.certain), (CULPRIT_SERVER, True))
        self.assertIn("и напрямую, и через VPN", d.advice)

    def test_handshake_ok_but_no_answer_is_a_silent_server(self) -> None:
        d = self.verdict((OK, OK), (OK, OK))
        self.assertEqual((d.culprit, d.certain), (CULPRIT_SERVER, False))
        self.assertIn("ответа на запрос нет", d.where)

    def test_direct_internet_dead_but_vpn_reaches_server_is_a_block(self) -> None:
        d = self.verdict((fail("tcp"), fail("tcp")), (OK, OK))
        self.assertEqual(d.culprit, CULPRIT_BLOCK)

    def test_log_names_masked_host_and_every_probe_without_the_full_address(self) -> None:
        d = self.verdict((fail("tls"), OK), (OK, OK))
        joined = "\n".join(d.log_lines)
        self.assertIn(host_tag(HOST, 443), joined)
        self.assertNotIn("globalinetforall", joined)
        self.assertIn("напрямую, сервер: сбой на tls", joined)
        self.assertIn("через VPN, контроль: ok", joined)
        self.assertIn("вердикт block", joined)


class HttpBlameTests(unittest.TestCase):
    def test_codes_map_to_culprits(self) -> None:
        self.assertEqual(blame_for_http(403, "Провайдер отклонил запрос клиента (HTTP 403)")[0], CULPRIT_REFUSED)
        self.assertEqual(blame_for_http(200, "Достигнут лимит устройств подписки")[0], CULPRIT_REFUSED)
        self.assertEqual(blame_for_http(404)[0], CULPRIT_SERVER)
        self.assertIn("недействительна", blame_for_http(404)[1])
        self.assertIn("сломан", blame_for_http(503)[1])


class CollectEvidenceTests(unittest.TestCase):
    def test_probes_server_and_control_on_every_route_and_skips_vpn_when_down(self) -> None:
        calls: list[tuple] = []

        def direct(host, port):
            calls.append(("direct", host))
            return OK

        def proxy(port, host, target_port):
            calls.append(("vpn", host, port))
            return OK

        ev = fd.collect_evidence(HOST, 443, tunnel_port=None, direct_probe=direct, proxy_probe=proxy)
        self.assertIsNone(ev.vpn)
        self.assertEqual({c[1] for c in calls}, {HOST, fd.CONTROL_HOST})
        calls.clear()
        ev = fd.collect_evidence(HOST, 443, tunnel_port=1080, direct_probe=direct, proxy_probe=proxy)
        self.assertIsNotNone(ev.vpn)
        self.assertEqual(len(calls), 4)


class RealProbeStageTests(unittest.TestCase):
    def test_dns_failure(self) -> None:
        probe = fd.probe_direct("no-such-host.invalid", 443, timeout=3)
        self.assertEqual((probe.ok, probe.failed, probe.how), (False, "dns", "dns"))

    def test_tcp_refused(self) -> None:
        with socket.socket() as probe_socket:
            probe_socket.bind(("127.0.0.1", 0))
            port = probe_socket.getsockname()[1]
        probe = fd.probe_direct("127.0.0.1", port, timeout=3)
        self.assertEqual((probe.failed, probe.how), ("tcp", "refused"))

    def test_tls_hang_after_tcp_connect_is_reported_as_tls_timeout(self) -> None:
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        held: list[socket.socket] = []

        def accept() -> None:
            conn, _ = server.accept()
            held.append(conn)  # принять и молчать, как фильтр, замораживающий рукопожатие

        threading.Thread(target=accept, daemon=True).start()
        try:
            probe = fd.probe_direct("127.0.0.1", server.getsockname()[1], timeout=1.0)
        finally:
            for conn in held:
                conn.close()
            server.close()
        self.assertEqual((probe.failed, probe.how), ("tls", "timeout"))
        self.assertEqual([name for name, _ in probe.ms], ["dns", "tcp"])

    def test_proxy_rejecting_connect_is_reported_with_its_status(self) -> None:
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)

        def serve() -> None:
            conn, _ = server.accept()
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            conn.close()

        threading.Thread(target=serve, daemon=True).start()
        try:
            probe = fd.probe_via_proxy(server.getsockname()[1], "example.com", 443, timeout=2.0)
        finally:
            server.close()
        self.assertEqual((probe.failed, probe.how), ("proxy", "status"))
        self.assertIn("502", probe.detail)


if __name__ == "__main__":
    unittest.main()


class HttpStageTests(unittest.TestCase):
    """Стадия «настоящий запрос»: TLS проходит, а отвечает ли сервер на HTTP."""

    def run_stage(self, server_action):
        left, right = socket.socketpair()
        try:
            threading.Thread(target=server_action, args=(right,), daemon=True).start()
            fd._http_stage(left, "sub.example.com", fd.time.monotonic() + 0.3)
        finally:
            left.close()
            right.close()

    def setUp(self) -> None:
        self._budget = fd._HTTP_MIN_BUDGET
        fd._HTTP_MIN_BUDGET = 0.3

    def tearDown(self) -> None:
        fd._HTTP_MIN_BUDGET = self._budget

    def test_any_http_answer_counts_even_a_404(self) -> None:
        def answer(conn):
            conn.recv(512)
            conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")

        self.run_stage(answer)  # не бросает

    def test_silence_after_the_request_is_a_timeout(self) -> None:
        def silent(conn):
            conn.recv(512)
            threading.Event().wait(1.0)

        with self.assertRaises(TimeoutError):
            self.run_stage(silent)

    def test_close_without_an_answer_is_a_reset(self) -> None:
        def close(conn):
            conn.recv(512)
            conn.close()

        with self.assertRaises(ConnectionResetError):
            self.run_stage(close)

    def test_non_http_bytes_are_refused(self) -> None:
        def garbage(conn):
            conn.recv(512)
            conn.sendall(b"\x16\x03\x01 not http at all")

        with self.assertRaises(OSError):
            self.run_stage(garbage)

    def test_request_never_carries_a_subscription_path(self) -> None:
        seen: list[bytes] = []

        def answer(conn):
            seen.append(conn.recv(1024))
            conn.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")

        self.run_stage(answer)
        request = seen[0].decode()
        self.assertTrue(request.startswith("GET / HTTP/1.1\r\nHost: sub.example.com\r\n"), request)
        self.assertEqual(fd._http_path(fd.CONTROL_HOST), "/generate_204")


class HttpProbeTests(unittest.TestCase):
    def test_a_silent_http_stage_becomes_a_probe_failure_on_stage_http(self) -> None:
        class Secure:
            closed = False

            def close(self):
                self.closed = True

        secure = Secure()

        def fake_stage(sock, host, deadline):
            raise TimeoutError("молчит")

        original = fd._http_stage
        fd._http_stage = fake_stage
        try:
            probe = fd._http_probe(secure, "sub.example.com", fd.time.monotonic() + 1, [("dns", 5), ("tcp", 8), ("tls", 40)])
        finally:
            fd._http_stage = original
        self.assertEqual((probe.ok, probe.failed, probe.how), (False, "http", "timeout"))
        self.assertTrue(secure.closed)
        self.assertEqual([name for name, _ in probe.ms], ["dns", "tcp", "tls"])


class VpnAcceptsTlsButServerIsSilentTests(unittest.TestCase):
    def test_the_verdict_does_not_claim_the_vpn_route_opens_when_it_does_not(self) -> None:
        ok = fd.HostProbe(True)
        direct_target = fd.HostProbe(False, "tcp", "timeout")
        vpn_target = fd.HostProbe(False, "http", "timeout")
        d = fd.judge(fd.Evidence("sub.example.com", 443, (direct_target, ok), (vpn_target, ok)))
        self.assertEqual(d.culprit, fd.CULPRIT_SERVER)
        self.assertTrue(d.certain)
        self.assertNotIn("открывается: обновите подписку при включённом VPN", d.advice)
        self.assertIn("на запрос он не отвечает", d.advice)
        self.assertIn("через VPN соединение и TLS проходят", d.where)
        self.assertIn("другому серверу", d.advice)

    def test_describe_failure_words_for_the_http_stage(self) -> None:
        silent = fd.describe_failure(fd.HostProbe(False, "http", "timeout"), "через VPN")
        reset = fd.describe_failure(fd.HostProbe(False, "http", "reset"), "через VPN")
        self.assertIn("на запрос сайта ответа нет", silent)
        self.assertIn("оборвалось", reset)


class RouteOutcomesTests(unittest.TestCase):
    def test_real_download_results_are_listed_per_route(self) -> None:
        from xray_fluent.network.background_workers import _route_outcomes

        failures = (
            SimpleNamespace(via_proxy=False, reason="сервер не ответил за 15 с"),
            SimpleNamespace(via_proxy=True, reason="соединение оборвалось — похоже на блокировку"),
        )
        text = _route_outcomes(failures)
        self.assertEqual(
            text,
            " Итог самой загрузки: напрямую — сервер не ответил за 15 с; через VPN — соединение оборвалось — похоже на блокировку.",
        )
        self.assertEqual(_route_outcomes(()), "")
