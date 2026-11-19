"""Connection reports for status.zapret.moe (S4, owner decisions 15–19.11.2026).

The contract must match vpnbot ``client_reports/contract.py`` exactly: one field outside
it refuses the whole batch. The same cases as the Android module ``client-reports``.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import threading
import unittest
import urllib.request
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from xray_fluent.application.subscription_service import reconcile_subscription
from xray_fluent.client_reports import contract as c
from xray_fluent.client_reports import reporter as r
from xray_fluent.importer.subscription_http import SERVICE_HEADER, SubscriptionFetchResult
from xray_fluent.importer.subscription_parser import parse_subscription_payload
from xray_fluent.profiles.models import AppState, Node, Subscription

NOW = 1_795_000_000_000
APP = c.AppIdentity("zapret-kvn", "0.8.88", "windows")
INSTALL = "0123456789abcdef0123456789abcdef"


def record(outcome=c.Outcome.FAILED, step="handshake", detail="udp_no_answer", at=NOW - 1000, token=""):
    return c.AttemptRecord("hiphopgen", "hysteria2", outcome, step, detail, 4200, at, token)


def header(mapping: dict) -> str:
    return base64.urlsafe_b64encode(zlib.compress(json.dumps(mapping).encode())).decode().rstrip("=")


class ContractTests(unittest.TestCase):
    def test_batch_carries_exactly_the_contract_fields(self) -> None:
        body = json.loads(c.batch_json(INSTALL, APP, [record(token="v1.abc.def")], c.SENT_TUNNEL))
        report = body["reports"][0]
        self.assertEqual(
            {"schema", "install_id", "app", "server_id", "product", "outcome", "failed_step", "detail",
             "elapsed_ms", "attempted_at", "sent_via", "network_token"},
            set(report),
        )
        self.assertEqual({"name", "version", "platform"}, set(report["app"]))
        self.assertEqual(2, report["schema"])
        self.assertRegex(report["attempted_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    DETAILS = c.AttemptDetails(
        server_ip="185.1.2.3", port=443, transport="tcp", security="reality", network_type="ethernet",
        settings=c.ReportSettings(mode="tun", masking="off"),
        versions=(("os", "10.0.19045"), ("xray", "26.11.9")),
    )

    def test_schema_two_carries_the_details_and_omits_the_unknown(self) -> None:
        import dataclasses

        report = json.loads(c.batch_json(INSTALL, APP, [dataclasses.replace(record(), details=self.DETAILS)], c.SENT_DIRECT))["reports"][0]
        self.assertEqual(("185.1.2.3", 443, "reality", "ethernet"),
                         (report["server_ip"], report["port"], report["security"], report["network_type"]))
        self.assertEqual({"mode": "tun", "masking": "off"}, report["settings"])
        self.assertEqual({"os": "10.0.19045", "xray": "26.11.9"}, report["versions"])
        bare = json.loads(c.batch_json(INSTALL, APP, [record()], c.SENT_DIRECT))["reports"][0]
        self.assertFalse({"settings", "versions", "server_ip", "port"} & set(bare))

    def test_a_foreign_server_replaces_the_catalogue_id_and_its_name_is_cleaned(self) -> None:
        foreign = c.ForeignServer.of("NL.Example.COM", "vless", "Мой\u200b сервер\u0007 🇳🇱")
        self.assertEqual(c.ForeignServer("nl.example.com", "vless", "Мой сервер 🇳🇱"), foreign)
        item = c.AttemptRecord("", "", c.Outcome.FAILED, "handshake", "sni_blocked", 900, NOW - 1000, "", foreign, self.DETAILS)
        self.assertTrue(c.is_valid(item))
        report = json.loads(c.batch_json(INSTALL, APP, [item], c.SENT_DIRECT))["reports"][0]
        self.assertNotIn("server_id", report)
        self.assertEqual({"host": "nl.example.com", "protocol": "vless", "name": "Мой сервер 🇳🇱"}, report["foreign"])
        import dataclasses
        self.assertFalse(c.is_valid(dataclasses.replace(item, server_id="hipnl", product="vless")))
        self.assertFalse(c.is_valid(dataclasses.replace(item, foreign=None)))
        self.assertIsNone(c.ForeignServer.of("fe80::1%eth0", "vless", "x"))
        self.assertIsNone(c.ForeignServer.of("bad host", "vless", "x"))
        self.assertEqual("2001:db8::7", c.ForeignServer.of("[2001:db8::7]", "hysteria2", "").host)
        self.assertEqual(64, len(c.ForeignServer.of("a.example", "vless", "🇳🇱" * 40).name))

    def test_bad_detail_values_drop_out_instead_of_losing_the_report(self) -> None:
        dirty = c.AttemptDetails(
            server_ip="fe80::1%eth0", port=70_000, transport="Web Socket", security="TLS", network_type="satellite",
            settings=c.ReportSettings(mode="vpn", dns="Свой"),
            versions=(("os", "10"), ("kernel", "6.1"), ("xray", "x" * 40)),
        ).cleaned()
        self.assertEqual(c.AttemptDetails(security="tls", versions=(("os", "10"),)), dirty)
        self.assertEqual("1.260327.1-676eaf66f8f0",
                         c.short_version("github.com/xtls/xray-core@v1.260327.1-0.20261109052709-676eaf66f8f0"))
        self.assertEqual("2.14.0", c.short_version("app/v2.14.0"))

    def test_queue_keeps_schema_two_and_reads_old_lines(self) -> None:
        import dataclasses

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "queue.jsonl"
            path.write_text('{"v":1,"s":"hipnl","p":"vless","o":"connected","f":"","d":"","e":900,"t":%d,"n":""}\n' % (NOW - 5000))
            queue = c.ReportQueue(path)
            foreign = c.AttemptRecord("", "", c.Outcome.FAILED, "connect", "ip_blocked", 900, NOW - 1000, "",
                                      c.ForeignServer.of("x.example", "vless", "Сервер"), self.DETAILS)
            queue.add(dataclasses.replace(record(), details=self.DETAILS))
            queue.add(foreign)
            pending = c.ReportQueue(path).pending(NOW)
            self.assertEqual(3, len(pending))
            self.assertEqual("hipnl", pending[0].server_id)
            self.assertEqual(self.DETAILS, pending[1].details)
            self.assertEqual(foreign, pending[2])

    def test_connected_report_has_no_step_token_or_detail(self) -> None:
        body = json.loads(c.batch_json(INSTALL, APP, [record(c.Outcome.CONNECTED, "", "")], c.SENT_DIRECT))
        report = body["reports"][0]
        self.assertNotIn("failed_step", report)
        self.assertNotIn("network_token", report)
        self.assertNotIn("detail", report)

    def test_invalid_records_never_reach_the_queue(self) -> None:
        self.assertFalse(c.is_valid(record(step="")))
        self.assertFalse(c.is_valid(record(step="dns")))
        self.assertFalse(c.is_valid(record(c.Outcome.CONNECTED)))
        self.assertFalse(c.is_valid(c.AttemptRecord("Hip NL", "vless", c.Outcome.CONNECTED, "", "", 1, NOW, "")))
        self.assertFalse(c.is_valid(c.AttemptRecord("x", "vless_fragment", c.Outcome.CONNECTED, "", "", 1, NOW, "")))
        self.assertFalse(c.is_valid(c.AttemptRecord("x", "vless", c.Outcome.CONNECTED, "", "", 600_001, NOW, "")))
        self.assertTrue(c.is_valid(record()))
        with self.assertRaises(ValueError):
            c.batch_json(INSTALL, APP, [record(step="dns")], c.SENT_DIRECT)

    def test_freshness_follows_the_ingest_window(self) -> None:
        self.assertTrue(c.is_fresh(record(at=NOW - 6 * 24 * 3600 * 1000), NOW))
        self.assertFalse(c.is_fresh(record(at=NOW - 7 * 24 * 3600 * 1000), NOW))
        self.assertFalse(c.is_fresh(record(at=NOW + 11 * 60 * 1000), NOW))

    def test_header_keeps_only_contract_entries(self) -> None:
        value = header({
            "🇳🇱 Velnor": {"server_id": "hipnl", "product": "vless"},
            "Bad id": {"server_id": "Hip NL", "product": "vless"},
            "Bad product": {"server_id": "x1", "product": "vless_fragment"},
            "Extra": "plain",
        })
        self.assertEqual({"🇳🇱 Velnor": c.ServerRef("hipnl", "vless")}, c.parse_server_ids(value))
        plain = base64.urlsafe_b64encode(json.dumps({"A": {"server_id": "a", "product": "vless"}}).encode()).decode()
        self.assertEqual({}, c.parse_server_ids(plain.rstrip("=")))
        bomb = base64.urlsafe_b64encode(zlib.compress(b"[" + b" " * (c.MAX_INFLATED_BYTES + 10) + b"]")).decode()
        self.assertEqual({}, c.parse_server_ids(bomb))
        self.assertEqual(frozenset({"vless"}), c.products_for_scheme("trojan"))
        self.assertEqual({}, c.parse_server_ids("not base64 !!"))
        self.assertEqual({}, c.parse_server_ids(None))
        self.assertEqual({}, c.parse_server_ids("A" * (c.MAX_HEADER_CHARS + 1)))

    def test_classifier_maps_core_codes_onto_the_ladder(self) -> None:
        def step(**facts):
            verdict = c.classify(c.AttemptFacts(**facts))
            return None if verdict is None else (verdict.failed_step, verdict.detail)

        self.assertEqual(("auth", "auth_rejected"), step(core_code="TARGET_AUTH_REJECTED"))
        self.assertEqual(("handshake", "tls_failed"), step(core_code="TARGET_PIN_MISMATCH"))
        self.assertEqual(("handshake", "udp_no_answer"), step(core_code="TARGET_NETWORK_TIMEOUT", udp_transport=True))
        self.assertEqual(("handshake", "handshake_timeout"), step(core_code="TARGET_NETWORK_TIMEOUT"))
        self.assertEqual(("connect", "connection_refused"), step(core_code="TARGET_CONNECTION_REFUSED"))
        self.assertEqual(("request", "no_response"), step(traffic_failed=True))
        self.assertIsNone(step(core_code="LOCAL_BIND_COLLISION", traffic_failed=True))
        self.assertIsNone(step(network_lost=True, traffic_failed=True))
        self.assertIsNone(step())
        self.assertEqual(c.Outcome.CANCELLED, c.classify(c.AttemptFacts(cancelled=True)).outcome)

    def test_queue_orders_prunes_and_survives_restart(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "queue.jsonl"
            queue = c.ReportQueue(path, capacity=3)
            a, b = record(at=NOW - 3000), record(c.Outcome.CONNECTED, "", "", at=NOW - 2000)
            queue.add(record(at=NOW - 8 * 24 * 3600 * 1000))
            queue.add(a)
            queue.add(record(step="bogus"))
            queue.add(b)
            self.assertEqual([a, b], queue.pending(NOW))
            queue.remove([a])
            self.assertEqual([b], c.ReportQueue(path).pending(NOW))
            queue.remove([b])
            self.assertFalse(path.exists())

    def test_token_ages_out(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            cache = c.NetworkTokenCache(Path(folder) / "token")
            self.assertTrue(cache.needs_refresh(NOW))
            cache.store(c.NetworkToken("v1.payload.mac", NOW))
            fresh = c.NetworkTokenCache(Path(folder) / "token")
            self.assertEqual("v1.payload.mac", fresh.current(NOW + 1000))
            self.assertFalse(fresh.needs_refresh(NOW + 1000))
            self.assertTrue(fresh.needs_refresh(NOW + 3600 * 1000))
            self.assertEqual("", fresh.current(NOW + 2 * 3600 * 1000))

    def test_send_policy(self) -> None:
        self.assertIs(c.SendAction.REMOVE, c.after_response(202))
        self.assertIs(c.SendAction.DROP, c.after_response(400))
        self.assertIs(c.SendAction.KEEP_AND_STOP, c.after_response(429))
        self.assertIs(c.SendAction.TRY_OTHER_PATH, c.after_response(None))


class SubscriptionMapTests(unittest.TestCase):
    VLESS = "vless://11111111-1111-1111-1111-111111111111@203.0.113.5:443?security=tls#Velnor"

    def test_header_fills_the_map_only_for_the_service(self) -> None:
        subscription = Subscription(id="sub", url="https://sub.example/token")
        state = AppState(subscriptions=[subscription])
        parsed = parse_subscription_payload(self.VLESS)
        ids = header({"Velnor": {"server_id": "hipnl", "product": "vless"}})

        reconcile_subscription(
            state, subscription, parsed,
            SubscriptionFetchResult(headers={SERVICE_HEADER: "1", c.SERVER_IDS_HEADER: ids}),
        )
        self.assertEqual({"Velnor": {"server_id": "hipnl", "product": "vless"}}, subscription.server_ids)
        restored = Subscription.from_dict(subscription.to_dict())
        self.assertEqual(subscription.server_ids, restored.server_ids)

        node = state.nodes[0]
        self.assertEqual(c.ServerRef("hipnl", "vless"), r.server_ref_for(node, state.subscriptions))
        # The same name in a Hysteria 2 node is another product: not this server.
        other = Node(name="Velnor", scheme="hysteria2", subscription_id="sub", provider_name="Velnor")
        self.assertIsNone(r.server_ref_for(other, state.subscriptions))

        # A 304 carrying the header refreshes the map; one without it keeps the map.
        from xray_fluent.application.subscription_service import apply_not_modified

        apply_not_modified(subscription, SubscriptionFetchResult(headers={}, status=304, not_modified=True))
        self.assertIn("Velnor", subscription.server_ids)
        newer = header({"Velnor": {"server_id": "hipnl2", "product": "vless"}})
        apply_not_modified(subscription, SubscriptionFetchResult(
            headers={SERVICE_HEADER: "1", c.SERVER_IDS_HEADER: newer}, status=304, not_modified=True))
        self.assertEqual("hipnl2", subscription.server_ids["Velnor"]["server_id"])

        # Another provider (no service header) never gets a map, even with the header.
        reconcile_subscription(state, subscription, parsed, SubscriptionFetchResult(headers={c.SERVER_IDS_HEADER: ids}))
        self.assertEqual({}, subscription.server_ids)
        self.assertIsNone(r.server_ref_for(state.nodes[0], state.subscriptions))


class _Ingest(BaseHTTPRequestHandler):
    received: list[dict] = []
    status = 202

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        type(self).received.append(json.loads(self.rfile.read(length)))
        self.send_response(type(self).status)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    feed: dict = {"schema": 1, "domains": ["fuckingspeedtest.com", "osjcpjzipyb.click"],
                  "services": {"reports": {"hosts": ["newnamexyz.osjcpjzipyb.click"]}}}

    def do_GET(self) -> None:  # noqa: N802
        if not self.path.startswith("/v1/network"):
            body = json.dumps(type(self).feed).encode()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        body = json.dumps({"ok": True, "asn": 1, "region": "RU-MOW", "network_token": "v1.tok.mac"}).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        pass


class ReporterTests(unittest.TestCase):
    def setUp(self) -> None:
        _Ingest.received = []
        _Ingest.status = 202
        self.server = HTTPServer(("127.0.0.1", 0), _Ingest)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]
        self.tried: list[tuple[str, bool]] = []   # (host, through the tunnel)
        self.dead: set[str] = set()

    def _opener(self, via_proxy, _proxy_port):
        """Every https://<name>/... goes to the local ingest; a name in ``dead`` does not answer."""
        test = self

        class Opener:
            def open(self, request, timeout=None):
                from urllib.parse import urlsplit
                parts = urlsplit(request.full_url)
                test.tried.append((parts.hostname, via_proxy))
                if parts.hostname in test.dead:
                    raise OSError("no answer")
                local = urllib.request.Request(
                    f"http://127.0.0.1:{test.port}{parts.path}" + (f"?{parts.query}" if parts.query else ""),
                    data=request.data, method=request.get_method(), headers=dict(request.header_items()),
                )
                return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(local, timeout=timeout)

        return Opener()

    def _reporter(self, tunnel_port=None, *, tun=False):
        return r.ClientReporter(Path(self.folder.name), "0.8.88", tunnel_proxy_port=lambda: tunnel_port,
                                direct_is_direct=lambda: not tun, now_ms=lambda: NOW, opener=self._opener)

    def test_in_tun_mode_reports_go_only_through_the_tunnel_and_no_token_is_asked(self) -> None:
        # A TUN session captures the app's own "direct" requests: they could leave from the VPN server.
        reporter = self._reporter(tunnel_port=8080, tun=True)
        reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(succeeded=True), 900, NOW - 5000, None)
        self.assertEqual("tunnel", _Ingest.received[0]["reports"][0]["sent_via"])
        self.assertTrue(all(via for host, via in self.tried if host not in ("script.google.com", "gist.githubusercontent.com")))
        self.assertFalse(any("/v1/network" in host for host, _ in self.tried))
        self.assertNotIn("network_token", _Ingest.received[0]["reports"][0])

    def test_tun_without_a_local_proxy_still_sends_through_the_tun(self) -> None:
        reporter = self._reporter(tunnel_port=None, tun=True)
        reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(succeeded=True), 900, NOW - 5000, None)
        self.assertEqual("tunnel", _Ingest.received[0]["reports"][0]["sent_via"])

    def test_token_is_prefetched_only_while_requests_are_direct(self) -> None:
        tun = self._reporter(tun=True)
        tun.prefetch_token()
        self.assertEqual([], self.tried)
        direct = self._reporter()
        direct._refresh_token()          # what prefetch_token runs on its thread
        self.assertEqual("v1.tok.mac", c.NetworkTokenCache(Path(self.folder.name) / "network-token").current(NOW))
        self.assertTrue(all(not via for _host, via in self.tried))

    def test_attempt_is_sent_directly_with_token_and_install_id(self) -> None:
        reporter = self._reporter()
        reporter._attempt(c.ServerRef("hiphopgen", "hysteria2"), "hysteria2",
                         c.AttemptFacts(core_code="TARGET_NETWORK_TIMEOUT"), 4200, NOW - 5000, None)
        report = _Ingest.received[0]["reports"][0]
        self.assertEqual("direct", report["sent_via"])
        self.assertEqual("v1.tok.mac", report["network_token"])
        self.assertEqual(("failed", "handshake", "udp_no_answer"),
                         (report["outcome"], report["failed_step"], report["detail"]))
        self.assertTrue(c.is_install_id(report["install_id"]))
        self.assertEqual(report["install_id"], (Path(self.folder.name) / "install-id").read_text())
        self.assertEqual(0, c.ReportQueue(Path(self.folder.name) / "queue.jsonl").size())

    def test_rate_limit_keeps_the_queue(self) -> None:
        _Ingest.status = 429
        reporter = self._reporter()
        reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(succeeded=True), 900, NOW - 5000, None)
        self.assertEqual(1, c.ReportQueue(Path(self.folder.name) / "queue.jsonl").size())

    def test_vless_relay_probe_decides_the_outcome(self) -> None:
        from unittest.mock import patch

        reporter = self._reporter()
        with patch.object(r, "probe_relay", return_value=False) as probe:
            reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(succeeded=True),
                             900, NOW - 5000, (1234, "u", "p"))
        probe.assert_called_once_with(1234, "u", "p")
        report = _Ingest.received[0]["reports"][0]
        self.assertEqual(("failed", "request", "no_response"),
                         (report["outcome"], report["failed_step"], report["detail"]))

    def test_not_about_the_server_is_not_reported(self) -> None:
        reporter = self._reporter()
        reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(core_code="LOCAL_BIND_COLLISION"),
                         900, NOW - 5000, None)
        self.assertEqual([], _Ingest.received)


    def _diagnosing(self, facts, *, freeze_bytes=None):
        from xray_fluent.client_reports import diagnosis as d

        class Probe:
            def run(self, _target):
                return facts

        seen: list = []
        reporter = r.ClientReporter(
            Path(self.folder.name), "0.8.91", tunnel_proxy_port=lambda: 8080, now_ms=lambda: NOW, opener=self._opener,
            probe=Probe(), freeze_probe=lambda _port: freeze_bytes, on_failure_changed=seen.append,
        )
        return reporter, seen, d

    def test_a_failure_is_checked_and_reported_with_the_kind_of_block(self) -> None:
        from xray_fluent.client_reports.diagnosis import DiagnosisFacts, ProbeResult as P
        from xray_fluent.client_reports.probe import ProbeTarget

        facts = DiagnosisFacts(control=P.ANSWERED, tcp_target=P.ANSWERED, uses_tls=True,
                               tls_real_name=P.TIMEOUT, tls_neutral_name=P.ANSWERED)
        reporter, seen, _d = self._diagnosing(facts)
        target = ProbeTarget("nl.node.example", 443, "www.microsoft.com", True, False)
        # Xray gives no code for the server: before the path check such a failure was never reported.
        reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(), 900, NOW - 5000, None, target, 7)
        report = _Ingest.received[0]["reports"][0]
        self.assertEqual(("failed", "handshake", "sni_blocked"), (report["outcome"], report["failed_step"], report["detail"]))
        self.assertTrue(seen[1].checking)
        self.assertEqual("Закрыто имя сервера (SNI): с другим именем тот же адрес отвечает.", seen[-1].diagnosis_text)
        self.assertEqual(r.SendStatus.SENT, seen[-1].status)

    def test_the_button_sends_a_local_failure_marked_local(self) -> None:
        reporter, seen, _d = self._diagnosing(None)
        reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(core_code="LOCAL_BIND_COLLISION"),
                          900, NOW - 5000, None, None, 3)
        self.assertEqual([], _Ingest.received)
        self.assertEqual(r.SendStatus.AVAILABLE, seen[-1].status)
        reporter._force(reporter._failure)
        self.assertEqual("local_bind_collision", _Ingest.received[0]["reports"][0]["detail"])
        self.assertEqual(r.SendStatus.SENT, seen[-1].status)

    def test_a_foreign_server_is_reported_in_full_only_by_the_button(self) -> None:
        from xray_fluent.client_reports.diagnosis import DiagnosisFacts, ProbeResult as P
        from xray_fluent.client_reports.probe import ProbeTarget

        facts = DiagnosisFacts(control=P.ANSWERED, tcp_target=P.TIMEOUT, tcp_other_port=P.TIMEOUT, probed_address="203.0.113.10")
        reporter, seen, _d = self._diagnosing(facts)
        target = ProbeTarget("x.example", 8443, None, True, False, protocol="vless", transport="ws", security="tls")
        reporter._attempt(None, "vless", c.AttemptFacts(), 900, NOW - 5000, None, target, 1, "Мой сервер 🇳🇱")
        self.assertEqual([], _Ingest.received)                      # nothing goes out by itself
        self.assertEqual(r.SendStatus.AVAILABLE, seen[-1].status)
        self.assertEqual("Адрес сервера закрыт целиком: не отвечают ни его порт, ни порт 443.", seen[-1].diagnosis_text)
        reporter._force(reporter._failure)
        report = _Ingest.received[0]["reports"][0]
        self.assertEqual({"host": "x.example", "protocol": "vless", "name": "Мой сервер 🇳🇱"}, report["foreign"])
        self.assertEqual(("203.0.113.10", 8443, "ws", "tls", "ip_blocked"),
                         (report["server_ip"], report["port"], report["transport"], report["security"], report["detail"]))
        self.assertEqual(r.SendStatus.SENT, seen[-1].status)
        # Without an address there is nothing to send: no button.
        reporter._attempt(None, "vless", c.AttemptFacts(), 900, NOW - 4000, None, None, 2)
        self.assertEqual(r.SendStatus.NOT_OURS, seen[-1].status)

    def test_a_freeze_after_success_is_reported_as_a_failure_and_checked_rarely(self) -> None:
        from xray_fluent.client_reports.probe import ProbeTarget

        reporter, seen, _d = self._diagnosing(None, freeze_bytes=14_000)
        target = ProbeTarget("nl.node.example", 443, None, True, False)
        reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(succeeded=True), 900, NOW - 5000, None, target, 1)
        reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(succeeded=True), 900, NOW - 4000, None, target, 2)
        details = [item["reports"][0]["detail"] if "detail" in item["reports"][0] else "" for item in _Ingest.received]
        self.assertEqual(["freeze_16k", ""], details)   # the second success is within 10 minutes: not measured

    def test_names_come_from_the_feed_and_a_silent_name_is_skipped(self) -> None:
        reporter = self._reporter()
        self.dead = {"newnamexyz.osjcpjzipyb.click", "oeifnxndqq.fuckingspeedtest.com"}
        reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(succeeded=True), 900, NOW - 5000, None)
        self.assertEqual(1, len(_Ingest.received))
        hosts = [h for h, _ in self.tried]
        self.assertIn("script.google.com", hosts)                               # the feed was asked first (no names yet)
        posted = [h for h in hosts if h not in ("script.google.com", "gist.githubusercontent.com")]
        self.assertNotIn(c.INGEST_FIXED, posted[:-1])                            # the cut name is never tried before a pool name
        self.assertEqual(["newnamexyz.osjcpjzipyb.click"], c.IngestHostCache(Path(self.folder.name) / "ingest-hosts").hosts())

    def test_nothing_answers_directly_so_the_tunnel_carries_the_batch(self) -> None:
        reporter = self._reporter(tunnel_port=8080)
        self.dead = set(c.INGEST_SEED) | {"newnamexyz.osjcpjzipyb.click"}
        reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(succeeded=True), 900, NOW - 5000, None)
        self.assertEqual([], _Ingest.received)                                    # every name is dead on both paths
        self.assertEqual(1, c.ReportQueue(Path(self.folder.name) / "queue.jsonl").size())
        self.assertTrue(any(via for _h, via in self.tried))                       # the tunnel was tried too
        self.dead = set()
        reporter._flush()
        self.assertEqual("direct", _Ingest.received[0]["reports"][0]["sent_via"])

    def test_a_long_queue_goes_in_small_requests(self) -> None:
        queue = c.ReportQueue(Path(self.folder.name) / "queue.jsonl")
        for i in range(60):
            queue.add(c.AttemptRecord("hipnl", "vless", c.Outcome.FAILED, "handshake", "handshake_timeout", 15000,
                                      NOW - 10000 + i, "v1." + "a" * 120 + "." + "b" * 43))
        self._reporter()._flush()
        self.assertGreaterEqual(len(_Ingest.received), 3)
        self.assertEqual(60, sum(len(batch["reports"]) for batch in _Ingest.received))
        for batch in _Ingest.received:
            self.assertLessEqual(len(json.dumps(batch).encode()), c.MAX_BODY_BYTES + 512)


class IngestNamesTests(unittest.TestCase):
    def test_feed_names_only_under_its_domains(self) -> None:
        text = json.dumps({"domains": ["fuckingspeedtest.com"], "services": {"reports": {"hosts": [
            "ok.fuckingspeedtest.com", "evil.example.org", "fuckingspeedtest.com.evil.org", "Bad Name", 7]}}})
        self.assertEqual(["ok.fuckingspeedtest.com"], c.parse_ingest_feed(text))
        self.assertEqual([], c.parse_ingest_feed('{"schema": 1, "families": {}}'))
        self.assertEqual([], c.parse_ingest_feed("<html>"))

    def test_order_alternates_domains_and_keeps_the_cut_name_last(self) -> None:
        import random as rnd

        learned = ["aaaaaaaaaa.fuckingspeedtest.com", "bbbbbbbbbb.fuckingspeedtest.com", "cccccccccc.osjcpjzipyb.click"]
        for seed in range(20):
            order = c.ingest_order(learned, set(), rnd.Random(seed))
            self.assertEqual(c.INGEST_FIXED, order[-1])
            self.assertNotEqual(c.domain_of(order[0]), c.domain_of(order[1]))
        order = c.ingest_order([], {"oeifnxndqq.fuckingspeedtest.com", c.INGEST_FIXED}, rnd.Random(1))
        self.assertEqual("wkjjjdcycb.osjcpjzipyb.click", order[0])

    def test_take_batch_respects_bytes_and_count(self) -> None:
        records = list(range(50))
        self.assertEqual(20, len(c.take_batch(records, 50, c.MAX_BODY_BYTES, lambda xs: len(xs) * 400)))
        self.assertEqual([0], c.take_batch(records, 50, 100, lambda xs: len(xs) * 1000))

    def test_cache_feed_due_daily_or_after_silence_at_most_hourly(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            cache = c.IngestHostCache(Path(folder) / "ingest-hosts")
            self.assertTrue(cache.feed_due(NOW, nothing_answered=False))
            cache.note_feed_attempt(NOW)
            self.assertFalse(cache.feed_due(NOW + 60_000, nothing_answered=True))
            cache.store(["x1.osjcpjzipyb.click"], NOW)
            again = c.IngestHostCache(Path(folder) / "ingest-hosts")
            self.assertEqual(["x1.osjcpjzipyb.click"], again.hosts())
            self.assertFalse(again.feed_due(NOW + 3_600_000, nothing_answered=False))
            self.assertTrue(again.feed_due(NOW + 3_600_000, nothing_answered=True))
            self.assertTrue(again.feed_due(NOW + c.FEED_MAX_AGE_MS, nothing_answered=False))


class ControllerHookTests(unittest.TestCase):
    """``_report_transition_attempt``: which transition ends become reports."""

    def _controller(self, scheme: str, *, relay_port: int = 0, failure=None):
        from xray_fluent.application.controller import AppController

        calls: list[tuple] = []
        sub = Subscription(id="sub", service=True, server_ids={"Velnor": {"server_id": "hipnl", "product": "vless"},
                                                              "Hiphopgen": {"server_id": "hiphopgen", "product": "hysteria2"}})
        name = "Velnor" if scheme == "vless" else "Hiphopgen"
        node = Node(name=name, scheme=scheme, subscription_id="sub", provider_name=name)
        fake = SimpleNamespace(
            state=SimpleNamespace(subscriptions=[sub]),
            _runtime_selected_node=lambda: node,
            _client_report_started_ms=NOW - 3000,
            _client_report_relay=(relay_port, "u", "p") if relay_port else None,
            _active_session=SimpleNamespace(sidecar_relay_port=relay_port),
            hysteria=SimpleNamespace(last_failure_code=failure),
            client_reporter=SimpleNamespace(on_attempt=lambda *args, **kwargs: calls.append((args, kwargs))),
            _logger=SimpleNamespace(info=lambda _line: None),
            _client_report_attempt=5,
            amnezia=SimpleNamespace(last_failure=None),
        )
        fake._client_report_failure_code = lambda scheme: AppController._client_report_failure_code(fake, scheme)
        return AppController._report_transition_attempt, fake, calls

    def test_vless_success_asks_for_the_relay_probe(self) -> None:
        hook, fake, calls = self._controller("vless", relay_port=1234)
        hook(fake, "connect", SimpleNamespace(result=True, error=None), False)
        (_args, kwargs), = calls
        self.assertEqual((1234, "u", "p"), kwargs["relay"])

    def test_vless_without_relay_is_not_reported(self) -> None:
        hook, fake, calls = self._controller("vless")
        hook(fake, "connect", SimpleNamespace(result=True, error=None), False)
        self.assertEqual([], calls)

    def test_every_failure_goes_to_the_reporter_with_the_core_code_when_there_is_one(self) -> None:
        # Without a code the reporter still checks the path; it reports only what the check or a code names.
        hook, fake, calls = self._controller("hysteria2")
        hook(fake, "connect", SimpleNamespace(result=False, error=None), False)
        (args, kwargs), = calls
        self.assertIsNone(args[2].core_code)
        self.assertEqual(5, kwargs["attempt"])
        hook, fake, calls = self._controller("hysteria2", failure=SimpleNamespace(name="TARGET_NETWORK_TIMEOUT"))
        hook(fake, "connect", SimpleNamespace(result=False, error=None), False)
        (args, _kwargs), = calls
        self.assertEqual("TARGET_NETWORK_TIMEOUT", args[2].core_code)

    def test_awg_handshake_silence_is_a_udp_timeout(self) -> None:
        hook, fake, calls = self._controller("awg")
        fake.amnezia = SimpleNamespace(last_failure=("handshake_readiness", "no handshake"))
        hook(fake, "connect", SimpleNamespace(result=False, error=None), False)
        self.assertEqual("TARGET_NETWORK_TIMEOUT", calls[0][0][2].core_code)

    def test_superseded_is_cancelled_and_cleanup_is_ignored(self) -> None:
        hook, fake, calls = self._controller("hysteria2")
        hook(fake, "connect", SimpleNamespace(result=False, error=None), True)
        self.assertTrue(calls[0][0][2].cancelled)
        hook(fake, "cleanup", SimpleNamespace(result=True, error=None), False)
        hook(fake, "disconnect", SimpleNamespace(result=True, error=None), False)
        self.assertEqual(1, len(calls))


if __name__ == "__main__":
    unittest.main()
