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

    def test_report_id_is_made_once_and_survives_the_queue(self) -> None:
        # vpnbot «report_id live» 2026-11-19: one attempt, one id, the same in every re-send.
        import dataclasses

        first, second = c.new_report_id(), c.new_report_id()
        self.assertRegex(first, r"^[0-9a-f]{32}$")
        self.assertNotEqual(first, second)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "queue.jsonl"
            c.ReportQueue(path).add(dataclasses.replace(record(), report_id=first))
            again = c.ReportQueue(path).pending(NOW)
            self.assertEqual(first, again[0].report_id)
            body = json.loads(c.batch_json(INSTALL, APP, again, c.SENT_DIRECT))
            self.assertEqual(first, body["reports"][0]["report_id"])
        # A line written before report_id goes out without one; a malformed id never reaches the queue.
        self.assertNotIn("report_id", json.loads(c.batch_json(INSTALL, APP, [record()], c.SENT_DIRECT))["reports"][0])
        for bad in ("ABCDEF" * 6, "0" * 31, "g" * 32):
            self.assertFalse(c.is_valid(dataclasses.replace(record(), report_id=bad)))

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

    def test_the_attempt_is_a_fact_not_a_verdict(self) -> None:
        # Schema 3: no app verdict; a lost network is a code the server knows, others only in the contract's shape.
        self.assertEqual(c.Outcome.FAILED, c.outcome_of(c.AttemptFacts(core_code="TARGET_AUTH_REJECTED")))
        self.assertEqual(c.Outcome.CANCELLED, c.outcome_of(c.AttemptFacts(cancelled=True)))
        self.assertEqual(c.Outcome.CONNECTED, c.outcome_of(c.AttemptFacts(succeeded=True)))
        self.assertEqual("NETWORK_LOST", c.attempt_core_code(c.AttemptFacts(network_lost=True, core_code="TARGET_X")))
        self.assertEqual("LOCAL_BIND_COLLISION", c.attempt_core_code(c.AttemptFacts(core_code="LOCAL_BIND_COLLISION")))
        self.assertEqual("", c.attempt_core_code(c.AttemptFacts(core_code="CORE_UNCLASSIFIED")))

    def test_schema_3_report_carries_facts_and_no_app_verdict(self) -> None:
        from xray_fluent.client_reports.checks import Check

        checks = (("control_front", Check("answered", 41)), ("tcp_target", Check("refused", 12)))
        record3 = c.AttemptRecord("hiphopgen", "hysteria2", c.Outcome.FAILED, "", "", 4200, NOW - 1000, "",
                                  carrier="udp", core_code="TARGET_NETWORK_TIMEOUT", checks=checks, report_id="ab" * 16)
        report = json.loads(c.batch_json(INSTALL, APP, [record3], "direct"))["reports"][0]
        self.assertEqual(3, report["schema"])
        self.assertNotIn("failed_step", report)
        self.assertNotIn("detail", report)
        self.assertEqual(("udp", "TARGET_NETWORK_TIMEOUT"), (report["carrier"], report["core_code"]))
        self.assertEqual({"control_front": {"r": "answered", "ms": 41}, "tcp_target": {"r": "refused", "ms": 12}},
                         report["checks"])
        # A schema 2 line still in the queue goes as schema 2.
        self.assertEqual(2, json.loads(c.batch_json(INSTALL, APP, [record()], "direct"))["reports"][0]["schema"])
        # Schema 3 never carries an app verdict; schema 2 never carries facts.
        self.assertFalse(c.is_valid(c.AttemptRecord("hiphopgen", "hysteria2", c.Outcome.FAILED, "handshake", "x", 1, NOW, "",
                                                    carrier="udp")))
        self.assertFalse(c.is_valid(c.AttemptRecord("hiphopgen", "hysteria2", c.Outcome.FAILED, "handshake", "x", 1, NOW, "",
                                                    core_code="TARGET_NETWORK_TIMEOUT")))

    def test_schema_3_line_survives_the_queue(self) -> None:
        from xray_fluent.client_reports.checks import Check

        with tempfile.TemporaryDirectory() as folder:
            queue = c.ReportQueue(Path(folder) / "queue.jsonl")
            line = c.AttemptRecord("hiphopgen", "hysteria2", c.Outcome.CONNECTED, "", "", 900, NOW - 1000, "",
                                   carrier="tcp", checks=(("flow", Check("timeout", 5000, b=14_000)),))
            queue.add(line)
            queue.add(record())
            self.assertEqual([line, record()], c.ReportQueue(Path(folder) / "queue.jsonl").pending(NOW))

    def test_an_unsent_first_copy_gives_way_to_its_completion(self) -> None:
        from xray_fluent.client_reports.checks import Check

        with tempfile.TemporaryDirectory() as folder:
            queue = c.ReportQueue(Path(folder) / "queue.jsonl")
            first = c.AttemptRecord("hiphopgen", "hysteria2", c.Outcome.FAILED, "", "", 900, NOW - 1000, "",
                                    report_id="cd" * 16, carrier="udp", complete=False)
            whole = c.AttemptRecord("hiphopgen", "hysteria2", c.Outcome.FAILED, "", "", 900, NOW - 1000, "",
                                    report_id="cd" * 16, carrier="udp", complete=True,
                                    checks=(("quic_neutral", Check("timeout", 3000)),))
            queue.add(first)
            queue.add(whole)
            self.assertEqual([whole], queue.pending(NOW))
            self.assertTrue(json.loads(c.batch_json(INSTALL, APP, [whole], "direct"))["reports"][0]["complete"])
            # complete needs a report_id and exists only in schema 3.
            self.assertFalse(c.is_valid(c.AttemptRecord("hiphopgen", "hysteria2", c.Outcome.FAILED, "", "", 1, NOW, "",
                                                        carrier="udp", complete=True)))

    def test_reply_verdicts_in_batch_order_and_anything_odd_is_none(self) -> None:
        good = {"detail": "ip_blocked", "level": "ip", "confidence": "proven", "text": "Адрес закрыт.\u0007"}
        got = c.parse_reply(json.dumps({"ok": True, "verdicts": [good, None, {"detail": 5}]}).encode(), 3)
        self.assertEqual(c.ServerVerdict("ip_blocked", "ip", "proven", "Адрес закрыт."), got[0])
        self.assertEqual([None, None], got[1:])
        self.assertEqual([None, None], c.parse_reply(b'{"ok":true}', 2))
        self.assertEqual([None], c.parse_reply(b"not json", 1))
        self.assertEqual([None], c.parse_reply(json.dumps({"verdicts": [good, good]}).encode(), 1))

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

    def test_relay_line_keeps_its_via_from_header_to_report(self) -> None:
        # vpnbot 2026-11-19: a «… через Россию» line is {"relay_of", "product", "via"} with no server_id, so a parser
        # that does not know via skips it; the report must carry the key, or a relay failure would count against the
        # target itself.
        import dataclasses

        ids = header({
            "Velnor через Россию": {"relay_of": "hipnl", "product": "hysteria2", "via": "3f9a0c21be"},
            "Velnor": {"server_id": "hipnl", "product": "hysteria2"},
            "Broken relay": {"relay_of": "hipnl", "product": "hysteria2", "via": "RU-NODE-1"},
            "Relay without key": {"relay_of": "hipnl", "product": "hysteria2"},
            "Interim shape": {"server_id": "hipnl", "product": "hysteria2", "via": "3f9a0c21be"},
            "Both ids": {"server_id": "hipnl", "relay_of": "hipnl", "product": "hysteria2"},
        })
        parsed = c.parse_server_ids(ids)
        self.assertEqual(c.ServerRef("hipnl", "hysteria2", "3f9a0c21be"), parsed["Velnor через Россию"])
        self.assertEqual(c.ServerRef("hipnl", "hysteria2"), parsed["Velnor"])
        # A relay line that cannot be told apart from the target is never reported as the target.
        for name in ("Broken relay", "Relay without key", "Interim shape", "Both ids"):
            self.assertNotIn(name, parsed)

        subscription = Subscription(id="sub", service=True)
        from xray_fluent.application.subscription_service import learn_server_ids

        learn_server_ids(subscription, SubscriptionFetchResult(headers={c.SERVER_IDS_HEADER: ids}))
        restored = Subscription.from_dict(subscription.to_dict())
        node = Node(name="x", scheme="hysteria2", subscription_id="sub", provider_name="Velnor через Россию")
        ref = r.server_ref_for(node, [restored])
        self.assertEqual("3f9a0c21be", ref.via)

        relayed = dataclasses.replace(record(), via="3f9a0c21be")
        self.assertEqual("3f9a0c21be", json.loads(c.batch_json(INSTALL, APP, [relayed], c.SENT_DIRECT))["reports"][0]["via"])
        self.assertNotIn("via", json.loads(c.batch_json(INSTALL, APP, [record()], c.SENT_DIRECT))["reports"][0])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "queue.jsonl"
            c.ReportQueue(path).add(relayed)
            self.assertEqual("3f9a0c21be", c.ReportQueue(path).pending(NOW)[0].via)
        foreign = c.AttemptRecord("", "", c.Outcome.FAILED, "connect", "ip_blocked", 900, NOW - 1000, "",
                                  c.ForeignServer.of("x.example", "vless", "Сервер"), via="3f9a0c21be")
        self.assertFalse(c.is_valid(foreign))
        self.assertFalse(c.is_valid(dataclasses.replace(record(), via="3F9A0C21BE")))

    def test_map_saved_before_the_relay_shape_is_learned_again(self) -> None:
        # 0.8.94 ignored via: a map saved between vpnbot's two relay-line shapes may list a «через Россию» line as
        # its target, so a map without the current format marker is dropped and the header is asked again.
        from xray_fluent.application.subscription_service import needs_server_ids

        old = Subscription(id="sub", service=True, server_ids={"Velnor через Россию": {"server_id": "hipnl", "product": "hysteria2"}}).to_dict()
        del old["server_ids_format"]
        restored = Subscription.from_dict(old)
        self.assertEqual({}, restored.server_ids)
        self.assertTrue(needs_server_ids(restored))
        current = Subscription(id="sub", service=True, server_ids={"Velnor": {"server_id": "hipnl", "product": "hysteria2"}})
        self.assertEqual(current.server_ids, Subscription.from_dict(current.to_dict()).server_ids)

    def test_service_subscription_without_ids_is_checked_once_even_with_auto_update_off(self) -> None:
        # The owner's archive 2026-11-19: auto-update off, both vpnbot subscriptions fetched before the header
        # existed, so not one report was ever written. A check (server list untouched) learns the ids.
        from xray_fluent.application.controller import AppController
        from xray_fluent.application.subscription_service import learn_server_ids, needs_server_ids

        ours = Subscription(id="ours", service=True)
        other = Subscription(id="other", service=False)
        known = Subscription(id="known", service=True, server_ids={"Velnor": {"server_id": "hipnl", "product": "vless"}})
        self.assertEqual([True, False, False], [needs_server_ids(s) for s in (ours, other, known)])

        ids = header({"Velnor": {"server_id": "hipnl", "product": "hysteria2"}})
        self.assertFalse(learn_server_ids(other, SubscriptionFetchResult(headers={c.SERVER_IDS_HEADER: ids})))
        self.assertEqual({}, other.server_ids)
        self.assertFalse(learn_server_ids(ours, SubscriptionFetchResult(headers={}, status=304, not_modified=True)))
        self.assertTrue(learn_server_ids(ours, SubscriptionFetchResult(headers={c.SERVER_IDS_HEADER: ids}, status=304,
                                                                       not_modified=True)))
        self.assertEqual("hysteria2", ours.server_ids["Velnor"]["product"])

        asked: list[str] = []
        fake = SimpleNamespace(
            locked=False, _server_ids_asked=set(), _log=lambda _line: None,
            state=SimpleNamespace(subscriptions=[Subscription(id="a", service=True), other, known]),
            check_subscription=lambda sid, mode: asked.append(sid),
        )
        AppController._learn_missing_server_ids(fake)
        AppController._learn_missing_server_ids(fake)   # once per run, not on every call
        self.assertEqual(["a"], asked)
        fake.locked, fake._server_ids_asked, asked[:] = True, set(), []
        AppController._learn_missing_server_ids(fake)
        self.assertEqual([], asked)


class _Ingest(BaseHTTPRequestHandler):
    received: list[dict] = []
    status = 202
    #: Optional ``batch -> status``: the ingest's own decision for one batch.
    decide = None

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        batch = json.loads(self.rfile.read(length))
        type(self).received.append(batch)
        decide = type(self).decide
        self.send_response(decide(batch) if decide else type(self).status)
        self.end_headers()
        # vpnbot (schema 3 live 2026-11-19): one verdict per report in batch order, null for schema 1/2.
        verdicts = [dict(type(self).verdict) if item.get("schema") == 3 else None for item in batch["reports"]]
        self.wfile.write(json.dumps({"ok": True, "accepted": len(verdicts), "repeated": 0, "verdicts": verdicts}).encode())

    verdict = {"detail": "sni_blocked", "level": "sni", "confidence": "proven", "text": "Закрыто имя сервера."}

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
                                direct_is_direct=lambda: not tun, now_ms=lambda: NOW, opener=self._opener,
                                enabled=True)

    def test_a_pc_clock_ahead_is_corrected_by_the_ingests_date(self) -> None:
        # vpnbot 2026-11-20: batches refused as client_report_invalid_attempted_at (now + 10 min at most). The local
        # ingest refuses the same way against its real clock; the PC here runs three hours ahead.
        import time
        from datetime import datetime

        def refuse_future(batch: dict) -> int:
            latest = max(datetime.fromisoformat(item["attempted_at"].replace("Z", "+00:00")).timestamp()
                         for item in batch["reports"])
            return 400 if latest > time.time() + 600 else 202

        _Ingest.decide = staticmethod(refuse_future)
        try:
            ahead = int(time.time() * 1000) + 3 * 3600 * 1000
            reporter = r.ClientReporter(Path(self.folder.name), "0.8.88", tunnel_proxy_port=lambda: None,
                                        now_ms=lambda: ahead, opener=self._opener, enabled=True)
            reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(succeeded=True), 900,
                              ahead - 5000, None)
        finally:
            _Ingest.decide = None
        self.assertEqual(2, len(_Ingest.received))
        sent = datetime.fromisoformat(_Ingest.received[1]["reports"][0]["attempted_at"].replace("Z", "+00:00"))
        self.assertLess(abs(sent.timestamp() - time.time()), 120)
        self.assertEqual(0, c.ReportQueue(Path(self.folder.name) / "queue.jsonl").size())

    def test_an_app_error_goes_as_its_own_kind_after_the_reports(self) -> None:
        from xray_fluent.client_reports import app_errors

        reporter = self._reporter()
        reporter.on_app_error(app_errors.AppError("crash", "crash:KeyError", ("xray_fluent.a.b:3",)), NOW - 1000)
        reporter._flush(wait=True)
        items = [item for batch in _Ingest.received for item in batch["reports"]]
        self.assertEqual(1, len(items))
        item = items[0]
        self.assertEqual(("app_error", 1, "crash", "crash:KeyError", 1, ["xray_fluent.a.b:3"]),
                         (item["kind"], item["schema"], item["step"], item["code"], item["count"], item["frames"]))
        self.assertNotIn("server_id", item)
        self.assertNotIn("message", item)

    def test_reports_off_for_test_runs_write_and_send_nothing(self) -> None:
        # The release gate runs the real controller against local test servers: ZAPRET_KVN_CLIENT_REPORTS=off.
        self.assertFalse(r.reports_enabled({"ZAPRET_KVN_CLIENT_REPORTS": "off"}))
        self.assertTrue(r.reports_enabled({}))
        self.assertTrue(r.reports_enabled({"ZAPRET_KVN_CLIENT_REPORTS": "on"}))
        # This very run is off too (tests/conftest.py for pytest, the gate's environment for unittest): a real
        # controller built by any test never sends to the production ingest.
        self.assertFalse(r.reports_enabled())
        lines: list[str] = []
        reporter = r.ClientReporter(Path(self.folder.name), "0.8.98", tunnel_proxy_port=lambda: None,
                                    now_ms=lambda: NOW, opener=self._opener, log=lines.append, enabled=False)
        reporter._attempt(c.ServerRef("hiphopgen", "hysteria2"), "hysteria2",
                          c.AttemptFacts(core_code="TARGET_NETWORK_TIMEOUT"), 4200, NOW - 5000, None)
        reporter.prefetch_token()
        reporter.flush()
        reporter._flush(wait=True)
        self.assertEqual(0, c.ReportQueue(Path(self.folder.name) / "queue.jsonl").size())
        self.assertEqual([], self.tried)
        self.assertEqual([], _Ingest.received)
        self.assertTrue(any("off" in line for line in lines))

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
        self.assertEqual("v1.tok.mac", c.NetworkTokenCache(Path(self.folder.name) / "network-token-2").current(NOW))
        self.assertTrue(all(not via for _host, via in self.tried))

    def test_attempt_is_sent_directly_with_token_and_install_id(self) -> None:
        reporter = self._reporter()
        reporter._attempt(c.ServerRef("hiphopgen", "hysteria2"), "hysteria2",
                         c.AttemptFacts(core_code="TARGET_NETWORK_TIMEOUT"), 4200, NOW - 5000, None)
        report = _Ingest.received[0]["reports"][0]
        self.assertEqual("direct", report["sent_via"])
        self.assertEqual("v1.tok.mac", report["network_token"])
        self.assertRegex(report["report_id"], r"^[0-9a-f]{32}$")
        self.assertEqual((3, "failed", "TARGET_NETWORK_TIMEOUT", "udp"),
                         (report["schema"], report["outcome"], report["core_code"], report["carrier"]))
        self.assertNotIn("detail", report)
        self.assertTrue(c.is_install_id(report["install_id"]))
        self.assertEqual(report["install_id"], (Path(self.folder.name) / "install-id").read_text())
        self.assertEqual(0, c.ReportQueue(Path(self.folder.name) / "queue.jsonl").size())

    def test_rate_limit_keeps_the_queue(self) -> None:
        _Ingest.status = 429
        reporter = self._reporter()
        reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(succeeded=True), 900, NOW - 5000, None)
        self.assertEqual(1, c.ReportQueue(Path(self.folder.name) / "queue.jsonl").size())

    def test_vless_relay_probe_decides_the_outcome_and_only_no_data_probes_run(self) -> None:
        from unittest.mock import patch

        from xray_fluent.client_reports.checks import Check
        from xray_fluent.client_reports.probe import ProbeTarget

        class NoData:
            def __init__(self):
                self.calls = []

            def run(self, relay, *, direct_allowed):
                self.calls.append((relay, direct_allowed))
                return {"tunnel_a": Check("timeout", 8000), "tunnel_b": Check("timeout", 8000),
                        "direct_a": Check("answered", 90), "direct_b": Check("answered", 120)}

        class PathProbe:
            def run(self, _target, **_kw):
                raise AssertionError("the tunnel was up: no probe of the server's path")

        no_data = NoData()
        reporter = r.ClientReporter(Path(self.folder.name), "0.8.98", tunnel_proxy_port=lambda: None, now_ms=lambda: NOW,
                                    opener=self._opener, probe=PathProbe(), no_data_probe=no_data, enabled=True)
        target = ProbeTarget("nl.node.example", 443, "www.microsoft.com", True, False)
        from xray_fluent.client_reports import checks as k
        live = k.PROBES if k.HEALTH_LIVE else k.PROBES + (k.HEALTH,)
        with patch.object(r, "probe_relay", return_value="timeout") as probe, patch.object(k, "PROBES", live):
            reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(succeeded=True),
                              900, NOW - 5000, (1234, "u", "p"), target)
        probe.assert_called_once_with(1234, "u", "p")
        self.assertEqual([(r.Relay(1234, "u", "p"), True)], no_data.calls)
        first, whole = (batch["reports"][0] for batch in _Ingest.received)
        self.assertEqual(("failed", False), (first["outcome"], first["complete"]))
        # The app's own health check is a fact it already has: it goes with the first copy (vpnbot 2026-11-20).
        self.assertEqual(["health"], list(first["checks"]))
        self.assertEqual("timeout", first["checks"]["health"]["r"])
        self.assertEqual(["tunnel_a", "tunnel_b", "direct_a", "direct_b", "health"], list(whole["checks"]))
        self.assertEqual((True, first["report_id"]), (whole["complete"], whole["report_id"]))

    def test_not_about_the_server_goes_with_the_raw_local_code_and_no_probe(self) -> None:
        # Every failure is reported (owner 2026-11-19); vpnbot keeps LOCAL_* out of the server's verdict. The core's
        # code proves nothing about the path, so no probe goes on the wire.
        from xray_fluent.client_reports.probe import ProbeTarget

        class PathProbe:
            def run(self, _target, **_kw):
                raise AssertionError("no probe for a local failure")

        reporter = r.ClientReporter(Path(self.folder.name), "0.8.98", tunnel_proxy_port=lambda: None, now_ms=lambda: NOW,
                                    opener=self._opener, probe=PathProbe(), enabled=True)
        target = ProbeTarget("nl.node.example", 443, None, True, False)
        reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(core_code="LOCAL_BIND_COLLISION"),
                          900, NOW - 5000, None, target)
        report = _Ingest.received[0]["reports"][0]
        self.assertEqual(("failed", "LOCAL_BIND_COLLISION"), (report["outcome"], report["core_code"]))
        self.assertNotIn("checks", report)

    def test_a_core_code_that_proves_the_server_answered_skips_the_path_check(self) -> None:
        from xray_fluent.client_reports.probe import ProbeTarget

        class PathProbe:
            def run(self, _target, **_kw):
                raise AssertionError("the core already proved the address answers")

        reporter = r.ClientReporter(Path(self.folder.name), "0.8.98", tunnel_proxy_port=lambda: None, now_ms=lambda: NOW,
                                    opener=self._opener, probe=PathProbe(), enabled=True)
        target = ProbeTarget("de.node.example", 443, None, False, True, carrier="udp")
        reporter._attempt(c.ServerRef("hiphopgen", "hysteria2"), "hysteria2",
                          c.AttemptFacts(core_code="TARGET_AUTH_REJECTED"), 900, NOW - 5000, None, target)
        self.assertEqual("TARGET_AUTH_REJECTED", _Ingest.received[0]["reports"][0]["core_code"])

    def test_a_failure_without_any_code_is_reported_too(self) -> None:
        # The owner's Hosonl failure (2026-11-19) showed a notice but never reached the panel: no core code, no proof.
        reporter = self._reporter()
        reporter._attempt(c.ServerRef("hosonl", "hysteria2", "3af0bdfa97"), "hysteria2", c.AttemptFacts(), 900, NOW - 5000, None)
        report = _Ingest.received[0]["reports"][0]
        self.assertEqual(("failed", "udp", "3af0bdfa97"), (report["outcome"], report["carrier"], report["via"]))
        self.assertNotIn("core_code", report)

    def _diagnosing(self, path, *, flow=None):
        from xray_fluent.client_reports.probe import PathFacts

        class Probe:
            def __init__(self):
                self.calls = 0

            def run(self, _target, **_kw):
                self.calls += 1
                return path or PathFacts()

        seen: list = []
        probe = Probe()
        reporter = r.ClientReporter(
            Path(self.folder.name), "0.8.91", tunnel_proxy_port=lambda: 8080, now_ms=lambda: NOW, opener=self._opener,
            probe=probe, flow_probe=lambda _port: flow, on_failure_changed=seen.append, enabled=True,
        )
        return reporter, seen, probe

    def test_a_failure_is_checked_and_the_notice_shows_vpnbots_text(self) -> None:
        from xray_fluent.client_reports.checks import Check
        from xray_fluent.client_reports.probe import PathFacts, ProbeTarget

        path = PathFacts({"control_front": Check("answered", 40), "tcp_target": Check("answered", 60),
                          "tls_real": Check("timeout", 5000), "tls_neutral": Check("answered", 70)}, "203.0.113.7")
        reporter, seen, _probe = self._diagnosing(path)
        target = ProbeTarget("nl.node.example", 443, "www.microsoft.com", True, False)
        reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(), 900, NOW - 5000, None, target, 7)
        # Completion: the failure goes at once (no checks yet), the same report whole after the check.
        first, report = (batch["reports"][0] for batch in _Ingest.received)
        self.assertEqual((False, None), (first["complete"], first.get("checks")))
        self.assertEqual((True, first["report_id"], first["attempted_at"]),
                         (report["complete"], report["report_id"], report["attempted_at"]))
        self.assertEqual(["control_front", "tcp_target", "tls_real", "tls_neutral"], list(report["checks"]))
        self.assertEqual("203.0.113.7", report["server_ip"])
        self.assertTrue(any(item.checking for item in seen))
        self.assertEqual("Закрыто имя сервера.", seen[-1].diagnosis_text)     # vpnbot's text, the app has none
        self.assertEqual("sni_blocked", seen[-1].detail)
        self.assertEqual(r.SendStatus.SENT, seen[-1].status)

    def test_without_an_answer_the_notice_waits_and_the_button_adds_nothing(self) -> None:
        _Ingest.status = 429
        reporter, seen, _probe = self._diagnosing(None)
        reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(core_code="TARGET_NETWORK_TIMEOUT"),
                          900, NOW - 5000, None, None, 3)
        self.assertEqual(r.SendStatus.QUEUED, seen[-1].status)
        self.assertEqual(r.WAITING_TEXT, seen[-1].diagnosis_text)
        _Ingest.status = 202
        reporter._force(reporter._failure)
        self.assertEqual(1, len(_Ingest.received[-1]["reports"]))           # the same report, not a second
        self.assertEqual("Закрыто имя сервера.", seen[-1].diagnosis_text)

    def test_a_foreign_server_is_reported_in_full_by_itself(self) -> None:
        # Owner 2026-11-19: «send everything we possibly can automatically, even without the button», own servers
        # in full (address too); the button only sends at once and never writes a second report.
        from xray_fluent.client_reports.checks import Check
        from xray_fluent.client_reports.probe import PathFacts, ProbeTarget

        path = PathFacts({"control_front": Check("answered", 40), "tcp_target": Check("timeout", 4000),
                          "tcp_443": Check("timeout", 4000)}, "203.0.113.10")
        reporter, seen, _probe = self._diagnosing(path)
        target = ProbeTarget("x.example", 8443, None, True, False, protocol="vless", transport="ws", security="tls")
        reporter._attempt(None, "vless", c.AttemptFacts(), 900, NOW - 5000, None, target, 1, "Мой сервер 🇳🇱")
        self.assertEqual(r.SendStatus.SENT, seen[-1].status)              # went out by itself
        reporter._force(reporter._failure)
        # The first copy and its completion; the button writes nothing new.
        self.assertEqual(2, sum(len(batch["reports"]) for batch in _Ingest.received))
        report = _Ingest.received[1]["reports"][0]
        self.assertEqual({"host": "x.example", "protocol": "vless", "name": "Мой сервер 🇳🇱"}, report["foreign"])
        self.assertEqual(("203.0.113.10", 8443, "ws", "tls", "tcp"),
                         (report["server_ip"], report["port"], report["transport"], report["security"], report["carrier"]))
        # Without an address there is nothing to send: no button.
        reporter._attempt(None, "vless", c.AttemptFacts(), 900, NOW - 4000, None, None, 2)
        self.assertEqual(r.SendStatus.NOT_OURS, seen[-1].status)

    def test_one_check_per_server_and_per_address_in_ten_minutes(self) -> None:
        from xray_fluent.client_reports.probe import ProbeTarget

        reporter, _seen, probe = self._diagnosing(None)
        reporter._server_address = lambda host: "203.0.113.20"
        ref = c.ServerRef("hipnl", "vless")
        reporter._attempt(ref, "vless", c.AttemptFacts(), 900, NOW - 5000, None, ProbeTarget("a.example", 443, None, True, False))
        # Another row on the same address («через Россию» lines share it): no second probe.
        reporter._attempt(ref, "vless", c.AttemptFacts(), 900, NOW - 4000, None, ProbeTarget("b.example", 443, None, True, False))
        self.assertEqual(1, probe.calls)

    def test_one_check_per_install_in_ten_minutes(self) -> None:
        from xray_fluent.client_reports.probe import ProbeTarget

        reporter, _seen, probe = self._diagnosing(None)
        ref = c.ServerRef("hipnl", "vless")
        reporter._attempt(ref, "vless", c.AttemptFacts(), 900, NOW - 5000, None, ProbeTarget("203.0.113.1", 443, None, True, False))
        # The user clicks through servers: another server on another address is not probed within ten minutes.
        reporter._attempt(ref, "vless", c.AttemptFacts(), 900, NOW - 4000, None, ProbeTarget("203.0.113.2", 443, None, True, False))
        self.assertEqual(1, probe.calls)

    def test_flow_after_success_is_a_fact_and_measured_rarely(self) -> None:
        from xray_fluent.client_reports.checks import Check
        from xray_fluent.client_reports.probe import ProbeTarget

        reporter, _seen, _probe = self._diagnosing(None, flow=Check("timeout", 5000, b=14_000))
        target = ProbeTarget("nl.node.example", 443, None, True, False)
        reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(succeeded=True), 900, NOW - 5000, None, target, 1)
        reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(succeeded=True), 900, NOW - 4000, None, target, 2)
        first, second = (item["reports"][0] for item in _Ingest.received)
        self.assertEqual(("connected", {"flow": {"r": "timeout", "ms": 5000, "b": 14_000}}), (first["outcome"], first["checks"]))
        self.assertNotIn("checks", second)       # within 10 minutes: not measured again

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
