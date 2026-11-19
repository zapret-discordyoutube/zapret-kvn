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
import zlib
import unittest
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
        self.assertEqual(1, report["schema"])
        self.assertRegex(report["attempted_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

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

    def do_GET(self) -> None:  # noqa: N802
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
        self.addCleanup(self.server.shutdown)
        port = self.server.server_address[1]
        self.original = r.ENDPOINT
        r.ENDPOINT = f"http://127.0.0.1:{port}"
        self.addCleanup(lambda: setattr(r, "ENDPOINT", self.original))

    def _reporter(self, tunnel_port=None):
        return r.ClientReporter(Path(self.folder.name), "0.8.88", tunnel_proxy_port=lambda: tunnel_port, now_ms=lambda: NOW)

    def test_attempt_is_sent_directly_with_token_and_install_id(self) -> None:
        reporter = self._reporter()
        reporter._record(c.ServerRef("hiphopgen", "hysteria2"), "hysteria2",
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
        reporter._record(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(succeeded=True), 900, NOW - 5000, None)
        self.assertEqual(1, c.ReportQueue(Path(self.folder.name) / "queue.jsonl").size())

    def test_vless_relay_probe_decides_the_outcome(self) -> None:
        from unittest.mock import patch

        reporter = self._reporter()
        with patch.object(r, "probe_relay", return_value=False) as probe:
            reporter._record(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(succeeded=True),
                             900, NOW - 5000, (1234, "u", "p"))
        probe.assert_called_once_with(1234, "u", "p")
        report = _Ingest.received[0]["reports"][0]
        self.assertEqual(("failed", "request", "no_response"),
                         (report["outcome"], report["failed_step"], report["detail"]))

    def test_not_about_the_server_is_not_reported(self) -> None:
        reporter = self._reporter()
        reporter._record(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(core_code="LOCAL_BIND_COLLISION"),
                         900, NOW - 5000, None)
        self.assertEqual([], _Ingest.received)


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
        )
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

    def test_hysteria_failure_needs_the_core_code(self) -> None:
        hook, fake, calls = self._controller("hysteria2")
        hook(fake, "connect", SimpleNamespace(result=False, error=None), False)
        self.assertEqual([], calls)
        hook, fake, calls = self._controller("hysteria2", failure=SimpleNamespace(name="TARGET_NETWORK_TIMEOUT"))
        hook(fake, "connect", SimpleNamespace(result=False, error=None), False)
        (args, _kwargs), = calls
        self.assertEqual("TARGET_NETWORK_TIMEOUT", args[2].core_code)

    def test_superseded_is_cancelled_and_cleanup_is_ignored(self) -> None:
        hook, fake, calls = self._controller("hysteria2")
        hook(fake, "connect", SimpleNamespace(result=False, error=None), True)
        self.assertTrue(calls[0][0][2].cancelled)
        hook(fake, "cleanup", SimpleNamespace(result=True, error=None), False)
        hook(fake, "disconnect", SimpleNamespace(result=True, error=None), False)
        self.assertEqual(1, len(calls))


if __name__ == "__main__":
    unittest.main()
