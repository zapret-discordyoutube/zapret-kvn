from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import zipfile

from PyQt6.QtGui import QImage

from xray_fluent.application.subscription_service import (
    apply_not_modified,
    hide_subscription_node,
    mark_subscription_failure,
    reconcile_subscription,
    remove_subscription,
    subscription_due,
)
from xray_fluent.constants import (
    STATE_SCHEMA_VERSION,
    SUBSCRIPTION_PARSER_REVISION,
)
from xray_fluent.diagnostics import export_diagnostics
from xray_fluent.models import (
    AppState,
    Node,
    Subscription,
    normalize_subscription_warnings,
)
from xray_fluent.qr_utils import QrDecodeError, decode_subscription_qr
from xray_fluent.storage import StateStorage
from xray_fluent.link_parser import LinkParseError, parse_single
from xray_fluent.subscription_http import (
    SubscriptionFetchError,
    SubscriptionFetchResult,
    _SafeRedirectHandler,
    _device_locale,
    _short_locale,
    _windows_locale_code,
    default_subscription_user_agent,
    describe_http_failure,
    fetch_subscription,
    is_panel_compatible_hwid,
    mask_subscription_url,
    resolve_subscription_source,
    sanitize_fetch_error,
    subscription_request_headers,
)
from xray_fluent.subscription_parser import (
    SubscriptionParseError,
    parse_subscription_payload,
    validate_filter_patterns,
)


VLESS_A = "vless://11111111-1111-1111-1111-111111111111@a.example:443?security=tls#Same"
VLESS_B = "vless://22222222-2222-2222-2222-222222222222@b.example:443?security=tls#Same"


class SubscriptionParserTests(unittest.TestCase):
    def test_mixed_hysteria_subscription_keeps_all_gecko_nodes(self) -> None:
        salamander = [
            f"hy2://auth-{index}@s{index}.example:443/?obfs=salamander&"
            f"obfs-password=cover-{index}#Salamander-{index}"
            for index in range(38)
        ]
        gecko = [
            f"hy2://auth-g{index}@g{index}.example:443/?obfs=gecko&"
            f"obfs-password=cover-g{index}#Gecko-{index}"
            for index in range(4)
        ]

        parsed = parse_subscription_payload("\n".join(salamander + gecko))

        self.assertEqual(len(parsed.nodes), 42)
        self.assertEqual(parsed.skipped, 0)
        self.assertEqual(parsed.warnings, [])
        self.assertEqual(
            sum((node.outbound.get("obfs") or {}).get("type") == "gecko" for node in parsed.nodes),
            4,
        )

    def test_all_supported_link_protocols_and_wireguard_config(self) -> None:
        vmess_json = json.dumps(
            {
                "v": "2",
                "ps": "VMess",
                "add": "vmess.example",
                "port": "443",
                "id": "33333333-3333-3333-3333-333333333333",
                "aid": "0",
                "net": "tcp",
                "tls": "tls",
            },
            separators=(",", ":"),
        )
        vmess = "vmess://" + base64.b64encode(vmess_json.encode()).decode()
        links = [
            VLESS_A,
            vmess,
            "trojan://secret@trojan.example:443#Trojan",
            "ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example:8388#SS",
            "hysteria://hy.example:8443/?auth=secret&upmbps=50&downmbps=100#HY",
            "hy2://secret@hy2.example:443/?insecure=1#HY2",
            "tuic://44444444-4444-4444-4444-444444444444:secret@tuic.example:443#TUIC",
            "socks://user:pass@socks.example:1080#SOCKS",
            "http://user:pass@http.example:8080#HTTP",
        ]
        parsed = parse_subscription_payload("\n".join(links))
        self.assertEqual(
            {node.scheme for node in parsed.nodes},
            {"vless", "vmess", "trojan", "ss", "hysteria", "hysteria2", "tuic", "socks", "http"},
        )

        wireguard = """# WireGuard
[Interface]
PrivateKey = private
Address = 10.0.0.2/32

[Peer]
PublicKey = public
Endpoint = wg.example:51820
AllowedIPs = 0.0.0.0/0
"""
        wg_parsed = parse_subscription_payload(wireguard)
        self.assertEqual(wg_parsed.nodes[0].scheme, "wireguard")
        awg_parsed = parse_subscription_payload(wireguard.replace("Address =", "Jc = 4\nAddress ="))
        self.assertEqual(awg_parsed.nodes[0].scheme, "awg")

    def test_raw_bom_crlf_metadata_partial_errors_and_duplicate_names(self) -> None:
        payload = (
            "\ufeff# profile-title: Demo Provider\r\n"
            "# profile-update-interval: 6\r\n"
            "# subscription-userinfo: upload=10; download=20; totl=100; expire=200\r\n"
            "# profile-web-page-url: https://cabinet.example/user?token=secret\r\n"
            f"{VLESS_A}\r\nnot-a-link\r\n{VLESS_B}\r\n"
        )

        parsed = parse_subscription_payload(payload, source_url="https://sub.example/list")

        self.assertEqual([node.provider_name for node in parsed.nodes], ["Same", "Same"])
        self.assertEqual(len({node.source_key for node in parsed.nodes}), 2)
        self.assertEqual(parsed.metadata.title, "Demo Provider")
        self.assertEqual(parsed.metadata.provider_interval_hours, 6)
        self.assertEqual(parsed.metadata.info.used, 30)
        self.assertEqual(parsed.metadata.info.total, 100)
        self.assertEqual(parsed.skipped, 1)
        self.assertTrue(parsed.warnings)

    def test_once_encoded_urlsafe_base64_and_header_priority(self) -> None:
        encoded = base64.urlsafe_b64encode(VLESS_A.encode()).decode().rstrip("=")
        parsed = parse_subscription_payload(
            encoded,
            headers={"Profile-Title": "Header title"},
            source_url="https://example.com/file.txt#fragment-title",
        )
        self.assertEqual(len(parsed.nodes), 1)
        self.assertEqual(parsed.metadata.title, "Header title")

    def test_filters_are_case_insensitive_and_hidden_keys_are_stable(self) -> None:
        both = parse_subscription_payload(f"{VLESS_A}\n{VLESS_B}")
        hidden = both.nodes[0].source_key
        parsed = parse_subscription_payload(
            f"{VLESS_A}\n{VLESS_B}",
            include_pattern="same",
            hidden_source_keys={hidden},
        )
        self.assertEqual([node.server for node in parsed.nodes], ["b.example"])
        with self.assertRaises(SubscriptionParseError):
            validate_filter_patterns("(", "")

    def test_exact_duplicates_are_removed_but_same_names_are_allowed(self) -> None:
        parsed = parse_subscription_payload(f"{VLESS_A}\n{VLESS_A}\n{VLESS_B}")
        self.assertEqual(len(parsed.nodes), 2)
        self.assertEqual(parsed.skipped, 1)

        renamed_same_outbound = VLESS_A.rsplit("#", 1)[0] + "#Another name"
        aliases = parse_subscription_payload(f"{VLESS_A}\n{renamed_same_outbound}")
        self.assertEqual(len(aliases.nodes), 2)
        self.assertEqual(aliases.nodes[0].source_key, aliases.nodes[1].source_key)

    def test_full_json_extracts_only_independent_supported_proxies(self) -> None:
        document = {
            "dns": {"servers": ["1.1.1.1"]},
            "routing": {"rules": [{"type": "field"}]},
            "inbounds": [{"protocol": "socks"}],
            "outbounds": [
                {"protocol": "freedom", "tag": "direct"},
                {
                    "protocol": "trojan",
                    "tag": "Xray proxy",
                    "settings": {"servers": [{"address": "x.example", "port": 443, "password": "p"}]},
                },
                {
                    "type": "hysteria2",
                    "tag": "Dependent",
                    "server": "d.example",
                    "server_port": 443,
                    "password": "p",
                    "detour": "other",
                },
                {"type": "selector", "tag": "select", "outbounds": ["proxy"]},
                {"type": "mystery", "tag": "unknown", "server": "u.example", "server_port": 1},
            ],
            "endpoints": [
                {
                    "type": "wireguard",
                    "tag": "WG",
                    "private_key": "private",
                    "peers": [{"address": "wg.example", "port": 51820, "public_key": "public"}],
                }
            ],
        }

        parsed = parse_subscription_payload(json.dumps(document))

        self.assertEqual({node.provider_name for node in parsed.nodes}, {"Xray proxy", "WG"})
        self.assertGreaterEqual(parsed.skipped, 3)
        self.assertNotIn("dns", {node.scheme for node in parsed.nodes})
        self.assertTrue(any("неподдерживаемый" in warning for warning in parsed.warnings))

    def test_empty_or_over_limit_payload_is_rejected(self) -> None:
        with self.assertRaises(SubscriptionParseError):
            parse_subscription_payload("bad data only")
        with self.assertRaises(SubscriptionParseError):
            parse_subscription_payload(f"{VLESS_A}\n{VLESS_B}", max_nodes=1)

    def test_xray_wireguard_endpoint_is_validated_and_extracted(self) -> None:
        outbound = {
            "protocol": "wireguard",
            "tag": "Xray WG",
            "settings": {
                "secretKey": "private",
                "peers": [
                    {
                        "endpoint": "[2001:db8::1]:51820",
                        "publicKey": "public",
                    }
                ],
            },
        }
        parsed = parse_subscription_payload(json.dumps(outbound))
        self.assertEqual((parsed.nodes[0].server, parsed.nodes[0].port), ("2001:db8::1", 51820))

        outbound["settings"]["peers"][0].pop("publicKey")
        with self.assertRaises(SubscriptionParseError):
            parse_subscription_payload(json.dumps(outbound))


class SubscriptionReconcileTests(unittest.TestCase):
    def _fetch(self, **headers: str) -> SubscriptionFetchResult:
        return SubscriptionFetchResult(headers=headers)

    def test_reconcile_preserves_id_local_fields_history_and_selection(self) -> None:
        subscription = Subscription(id="sub", name="Provider", url="https://sub.example/a")
        first = parse_subscription_payload(VLESS_A)
        state = AppState(subscriptions=[subscription])
        reconcile_subscription(state, subscription, first, self._fetch())
        old = state.nodes[0]
        old.id = "stable-id"
        old.name = "My local name"
        old.group = "My group"
        old.tags = ["favorite"]
        old.ping_ms = 25
        old.speed_mbps = 10.5
        old.ping_history = [("now", 25)]
        state.selected_node_id = old.id

        changed_transport = VLESS_A.replace("security=tls", "security=tls&type=ws&path=%2Fws")
        second = parse_subscription_payload(changed_transport)
        outcome = reconcile_subscription(state, subscription, second, self._fetch())
        current = state.nodes[0]

        self.assertEqual(current.id, "stable-id")
        self.assertEqual(current.name, "My local name")
        self.assertEqual(current.group, "My group")
        self.assertEqual(current.tags, ["favorite"])
        self.assertEqual(current.ping_history, [("now", 25)])
        self.assertEqual(state.selected_node_id, "stable-id")
        self.assertTrue(outcome.selected_node_changed)
        self.assertTrue(outcome.result.reconnect_required)

    def test_failed_parse_is_atomic_and_removed_selection_prefers_same_subscription(self) -> None:
        subscription = Subscription(id="sub", name="Provider", url="https://sub.example/a")
        parsed = parse_subscription_payload(f"{VLESS_A}\n{VLESS_B}")
        state = AppState(subscriptions=[subscription])
        reconcile_subscription(state, subscription, parsed, self._fetch())
        state.selected_node_id = state.nodes[1].id
        snapshot = state.to_dict()

        with self.assertRaises(SubscriptionParseError):
            parse_subscription_payload("totally broken")
        self.assertEqual(state.to_dict(), snapshot)

        outcome = reconcile_subscription(
            state,
            subscription,
            parse_subscription_payload(VLESS_A),
            self._fetch(),
        )
        self.assertTrue(outcome.selected_node_removed)
        self.assertEqual(state.selected_node_id, state.nodes[0].id)

    def test_hide_and_remove_with_keep_local(self) -> None:
        subscription = Subscription(id="sub", name="Provider", url="https://sub.example/a")
        state = AppState(subscriptions=[subscription])
        reconcile_subscription(state, subscription, parse_subscription_payload(VLESS_A), self._fetch())
        node_id = state.nodes[0].id
        state.selected_node_id = node_id

        self.assertEqual(hide_subscription_node(state, node_id), "sub")
        self.assertEqual(state.nodes, [])
        self.assertEqual(len(subscription.hidden_source_keys), 1)

        subscription.hidden_source_keys.clear()
        reconcile_subscription(state, subscription, parse_subscription_payload(VLESS_A), self._fetch())
        self.assertTrue(remove_subscription(state, "sub", keep_nodes=True))
        self.assertEqual(state.subscriptions, [])
        self.assertIsNone(state.nodes[0].subscription_id)
        self.assertEqual(state.nodes[0].source_key, "")

    def test_metadata_redirect_policy_and_cache_headers(self) -> None:
        subscription = Subscription(id="sub", url="https://same.example/old", etag="old")
        state = AppState(subscriptions=[subscription])
        parsed = parse_subscription_payload(
            VLESS_A,
            headers={"moved-permanently-to": "https://same.example/new"},
        )
        reconcile_subscription(state, subscription, parsed, self._fetch(etag="new"))
        self.assertEqual(subscription.url, "https://same.example/new")
        self.assertEqual(subscription.etag, "")

        parsed = parse_subscription_payload(
            VLESS_A,
            headers={"moved-permanently-to": "https://other.example/new"},
        )
        reconcile_subscription(state, subscription, parsed, self._fetch(etag="current"))
        self.assertEqual(subscription.url, "https://same.example/new")
        self.assertEqual(subscription.pending_url, "https://other.example/new")
        self.assertEqual(subscription.etag, "current")

    def test_legacy_snapshot_recovers_gecko_and_stamps_parser_revision(self) -> None:
        old_links = [
            f"hy2://auth-{index}@s{index}.example:443/?obfs=salamander&"
            f"obfs-password=cover-{index}#Server-{index}"
            for index in range(38)
        ]
        gecko_links = [
            f"hy2://auth-g{index}@g{index}.example:443/?obfs=gecko&"
            f"obfs-password=cover-g{index}#Gecko-{index}"
            for index in range(4)
        ]
        subscription = Subscription(id="sub", parser_revision=0, etag='"old"')
        state = AppState(subscriptions=[subscription])
        first = parse_subscription_payload("\n".join(old_links))
        reconcile_subscription(state, subscription, first, self._fetch(etag='"old"'))
        stable_ids = {node.provider_name: node.id for node in state.nodes}
        subscription.parser_revision = 0

        outcome = reconcile_subscription(
            state,
            subscription,
            parse_subscription_payload("\n".join(old_links + gecko_links)),
            self._fetch(etag='"new"'),
        )

        self.assertEqual(len(state.nodes), 42)
        self.assertEqual(outcome.result.added, 4)
        self.assertEqual(outcome.result.removed, 0)
        self.assertEqual(subscription.parser_revision, SUBSCRIPTION_PARSER_REVISION)
        self.assertEqual(subscription.etag, '"new"')
        self.assertEqual(
            {node.provider_name: node.id for node in state.nodes if node.provider_name in stable_ids},
            stable_ids,
        )

    def test_persistent_parse_diagnostics_follow_applied_snapshot(self) -> None:
        subscription = Subscription(id="sub")
        state = AppState(subscriptions=[subscription])
        partial = parse_subscription_payload(f"{VLESS_A}\nnot-a-link")

        reconcile_subscription(state, subscription, partial, self._fetch(etag='"partial"'))

        self.assertEqual(subscription.skipped_count, 1)
        self.assertTrue(subscription.warnings)
        unchanged = apply_not_modified(subscription, self._fetch(etag='"partial"'))
        self.assertEqual(unchanged.skipped, 1)
        self.assertEqual(unchanged.warnings, subscription.warnings)

        reconcile_subscription(
            state,
            subscription,
            parse_subscription_payload(VLESS_A),
            self._fetch(etag='"clean"'),
        )
        self.assertEqual(subscription.skipped_count, 0)
        self.assertEqual(subscription.warnings, [])


class SubscriptionSchedulingAndHttpTests(unittest.TestCase):
    def test_open_client_deep_links_are_unwrapped_and_encrypted_happ_is_rejected(self) -> None:
        target = "https://sub.example/list?token=secret"
        encoded = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
        cases = (
            (target, (target, None)),
            (f"happ://add/{target}", (target, "happ")),
            (f"incy://import/{target}", (target, "incy")),
            (f"incy://import/{encoded}", (target, "incy")),
            (f"v2raytun://import/{target}", (target, "v2raytun")),
        )
        for source, expected in cases:
            with self.subTest(source=source):
                self.assertEqual(resolve_subscription_source(source), expected)
        # happ://crypt* теперь расшифровывается (см. tests/test_happ_crypt.py);
        # непригодная нагрузка обязана давать доменную ошибку, а не трассировку.
        with self.assertRaises(SubscriptionFetchError):
            resolve_subscription_source("happ://crypt3/opaque-payload")

        # Зашифрованные deep links других клиентов по-прежнему не поддерживаются.
        with self.assertRaisesRegex(SubscriptionFetchError, "не расшифровываются"):
            resolve_subscription_source("v2raytun://crypt/opaque-payload")

    def test_client_profiles_send_only_explicit_stable_hwid_headers(self) -> None:
        default_headers = subscription_request_headers(Subscription())
        self.assertEqual(default_headers["User-Agent"], default_subscription_user_agent())
        self.assertNotIn("X-HWID", default_headers)

        subscription = Subscription(
            client_profile="incy",
            send_hwid=True,
            hwid="DEVICE-ID-123",
        )
        headers = subscription_request_headers(subscription)
        self.assertEqual(headers["User-Agent"], "INCY/1.0/Windows")
        self.assertEqual(headers["X-HWID"], "DEVICE-ID-123")
        self.assertEqual(headers["X-Device-ID"], "DEVICE-ID-123")
        self.assertEqual(headers["X-Client"], "INCY")
        self.assertEqual(headers["X-Device-OS"], "Windows")
        self.assertNotIn("X-Real-IP", headers)
        self.assertNotIn("X-Forwarded-For", headers)

        # Набор Happ снят с реального клиента: лишний заголовок выдаёт подделку
        # панели не хуже отсутствующего, поэтому Accept и X-App-Version не шлём.
        happ = subscription_request_headers(
            Subscription(client_profile="happ", send_hwid=True, hwid="DEVICE-ID-123")
        )
        self.assertEqual(happ["User-Agent"], "Happ/3.13.0")
        self.assertNotIn("X-App-Version", happ)
        self.assertNotIn("Accept", happ)
        self.assertEqual(happ["X-Device-Locale"], _short_locale(_device_locale()))
        self.assertNotIn("-", happ["X-Device-Locale"])

        with self.assertRaises(SubscriptionFetchError):
            subscription_request_headers(Subscription(user_agent="bad\r\nInjected: yes"))
        with self.assertRaises(SubscriptionFetchError):
            subscription_request_headers(
                Subscription(send_hwid=True, hwid="bad\nvalue")
            )


    def test_windows_locale_name_becomes_a_language_code(self) -> None:
        # На Windows locale.getlocale() отдаёт Russian_Russia, которое ни один
        # клиент в заголовок не пишет.
        self.assertEqual(_windows_locale_code("Russian_Russia"), "ru_RU")
        self.assertEqual(_short_locale("ru-RU"), "ru")

    def test_forbidden_is_explained_and_separates_the_site_protection(self) -> None:
        panel = describe_http_failure(403, {})
        self.assertIn("профиль клиента", panel)
        protected = describe_http_failure(403, {"CF-Ray": "abc"})
        self.assertIn("прокси", protected)

    def test_panel_compatible_hwid_follows_the_happ_format(self) -> None:
        self.assertTrue(is_panel_compatible_hwid("aaaaaaaaa-537f-4c45-a479-ee0b6cf035f7"))
        self.assertTrue(is_panel_compatible_hwid("aBc123XyZ0"))
        self.assertFalse(is_panel_compatible_hwid("short"))
        self.assertFalse(is_panel_compatible_hwid("has spaces inside"))


    def test_vendor_specific_parameters_do_not_block_the_import(self) -> None:
        # Панели добавляют собственные параметры быстрее, чем их можно перечислить:
        # fm и vcn у 3x-ui появились после spx.
        node = parse_single(
            "vless://11111111-1111-1111-1111-111111111111@a.example:443"
            "?security=tls&sni=a.example&spx=%2F&fm=%7B%22a%22%3A1%7D&vcn=1#Vendor"
        )
        self.assertEqual(node.outbound["protocol"], "vless")

    def test_unknown_security_mode_is_refused(self) -> None:
        with self.assertRaises(LinkParseError):
            parse_single(
                "vless://11111111-1111-1111-1111-111111111111@a.example:443?security=xtls#Bad"
            )


    def test_certificate_pin_next_to_insecure_keeps_the_server(self) -> None:
        # Пин рядом с insecure ничего не добавляет: проверка отключена самой
        # ссылкой, и отказ отнимал бы у пользователя рабочий сервер.
        node = parse_single(
            "hysteria2://secret@a.example:8443"
            "?insecure=1&pinSHA256=0E%3AD6%3A04&obfs=salamander&obfs-password=pw&sni=a.example#Pin"
        )
        self.assertTrue(node.outbound["tls"]["insecure"])

        with self.assertRaises(LinkParseError):
            parse_single("hysteria2://secret@a.example:8443?pinSHA256=0E%3AD6%3A04#Pin")

    def test_interval_override_and_backoff(self) -> None:
        now = datetime.now(timezone.utc)
        subscription = Subscription(
            parser_revision=SUBSCRIPTION_PARSER_REVISION,
            update_interval_hours=2,
            provider_interval_hours=8,
            last_success_at=(now - timedelta(hours=3)).isoformat(),
        )
        self.assertTrue(subscription_due(subscription, now))
        result = mark_subscription_failure(subscription, "failed https://host/path?token=secret")
        self.assertFalse(result.success)
        self.assertNotIn("token=secret", result.message)
        self.assertFalse(subscription_due(subscription, now))
        mark_subscription_failure(subscription, "again")
        self.assertEqual(subscription.failure_count, 2)

        stale = Subscription(
            parser_revision=0,
            last_success_at=now.isoformat(),
        )
        self.assertTrue(subscription_due(stale, now))
        stale.auto_update = False
        self.assertFalse(subscription_due(stale, now))

    def test_auto_fetch_retries_once_through_active_proxy(self) -> None:
        subscription = Subscription(url="https://sub.example/path?token=secret")
        calls: list[tuple[bool, int | None]] = []

        def fake_once(_subscription, **kwargs):
            calls.append((kwargs["via_proxy"], kwargs["proxy_port"]))
            if not kwargs["via_proxy"]:
                raise OSError("direct failed")
            return SubscriptionFetchResult(data=b"ok", via_proxy=True)

        with patch("xray_fluent.subscription_http._fetch_once", side_effect=fake_once):
            result = fetch_subscription(subscription, mode="auto", proxy_port=1391)
        self.assertTrue(result.via_proxy)
        self.assertEqual(calls, [(False, None), (True, 1391)])

    def test_force_refresh_preserves_fallback_and_omits_validators(self) -> None:
        subscription = Subscription(
            url="https://sub.example/list",
            etag='"old"',
            last_modified="Mon, 01 Jan 2024 00:00:00 GMT",
            parser_revision=SUBSCRIPTION_PARSER_REVISION,
        )
        attempts: list[bool] = []

        def fake_once(_subscription, **kwargs):
            attempts.append(bool(kwargs["force_refresh"]))
            if not kwargs["via_proxy"]:
                raise OSError("direct failed")
            return SubscriptionFetchResult(data=b"ok", via_proxy=True)

        with patch("xray_fluent.subscription_http._fetch_once", side_effect=fake_once):
            result = fetch_subscription(
                subscription,
                mode="auto",
                proxy_port=1391,
                force_refresh=True,
            )
        self.assertTrue(result.via_proxy)
        self.assertEqual(attempts, [True, True])

    def test_proxy_mode_requires_port_and_secrets_are_masked(self) -> None:
        subscription = Subscription(url="https://user:pass@sub.example/very-long-token-value?token=secret")
        with self.assertRaises(SubscriptionFetchError):
            fetch_subscription(subscription, mode="proxy", proxy_port=None)
        masked = mask_subscription_url(subscription.url)
        self.assertEqual(masked, "********")
        self.assertNotIn("token=secret", masked)
        self.assertNotIn("very-long-token-value", masked)
        self.assertNotIn("pass", masked)
        self.assertNotIn("pass", sanitize_fetch_error(RuntimeError(subscription.url)))

    def test_cache_headers_user_agent_304_size_limit_and_redirect_scheme(self) -> None:
        subscription = Subscription(
            url="https://sub.example/list",
            etag='"abc"',
            last_modified="Mon, 01 Jan 2024 00:00:00 GMT",
            parser_revision=SUBSCRIPTION_PARSER_REVISION,
        )

        class Response:
            status = 200
            headers = {"ETag": '"next"'}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def geturl(self):
                return subscription.url

            def read(self, _limit):
                return b"payload"

        opener = SimpleNamespace(open=lambda request, timeout: Response())
        with patch("xray_fluent.subscription_http.build_opener", return_value=opener):
            result = fetch_subscription(subscription, mode="direct")
        self.assertEqual(result.headers["etag"], '"next"')
        self.assertEqual(default_subscription_user_agent().split("/", 1)[0], "ZapretKVN")

        captured = []

        def open_and_capture(request, timeout):
            captured.append((request, timeout))
            return Response()

        opener.open = open_and_capture
        with patch("xray_fluent.subscription_http.build_opener", return_value=opener):
            fetch_subscription(subscription, mode="direct")
        request, timeout = captured[0]
        self.assertEqual(request.get_header("If-none-match"), '"abc"')
        self.assertEqual(request.get_header("If-modified-since"), "Mon, 01 Jan 2024 00:00:00 GMT")
        self.assertEqual(request.get_header("User-agent"), default_subscription_user_agent())
        self.assertEqual(timeout, 15)

        class OversizedResponse(Response):
            def read(self, limit):
                return b"x" * limit

        opener.open = lambda _request, timeout: OversizedResponse()
        with patch("xray_fluent.subscription_http.build_opener", return_value=opener):
            with self.assertRaisesRegex(SubscriptionFetchError, "превышает"):
                fetch_subscription(subscription, mode="direct", max_bytes=8)

        http_error = urllib.error.HTTPError(
            subscription.url,
            304,
            "Not Modified",
            {"ETag": '"abc"'},
            None,
        )
        opener.open = lambda _request, timeout: (_ for _ in ()).throw(http_error)
        with patch("xray_fluent.subscription_http.build_opener", return_value=opener):
            not_modified = fetch_subscription(subscription, mode="direct")
        self.assertTrue(not_modified.not_modified)

        stale = Subscription(
            url=subscription.url,
            etag='"abc"',
            last_modified=subscription.last_modified,
            parser_revision=0,
        )
        captured.clear()
        opener.open = open_and_capture
        with patch("xray_fluent.subscription_http.build_opener", return_value=opener):
            fetch_subscription(stale, mode="direct")
        stale_request = captured[0][0]
        self.assertIsNone(stale_request.get_header("If-none-match"))
        self.assertIsNone(stale_request.get_header("If-modified-since"))
        opener.open = lambda _request, timeout: (_ for _ in ()).throw(http_error)
        with patch("xray_fluent.subscription_http.build_opener", return_value=opener):
            with self.assertRaisesRegex(SubscriptionFetchError, "304 без условного"):
                fetch_subscription(stale, mode="direct")

        handler = _SafeRedirectHandler()
        with self.assertRaises(SubscriptionFetchError):
            handler.redirect_request(
                urllib.request.Request(subscription.url),
                None,
                302,
                "Found",
                {},
                "file:///tmp/secret",
            )


class SubscriptionStateAndQrTests(unittest.TestCase):
    def test_v1_migration_and_plain_encrypted_backup_roundtrip(self) -> None:
        legacy = AppState.from_dict(
            {
                "schema_version": 1,
                "nodes": [{"id": "old", "name": "Local", "server": "example.com", "port": 443}],
            }
        )
        self.assertEqual(legacy.schema_version, 1)
        self.assertIsNone(legacy.nodes[0].subscription_id)

        subscription = Subscription(
            id="sub",
            name="Private",
            url="https://sub.example/?token=secret",
            client_profile="happ",
            send_hwid=True,
            hwid="OWN-DEVICE-ID",
            parser_revision=SUBSCRIPTION_PARSER_REVISION,
            skipped_count=4,
            warnings=[
                "hysteria2://auth@example/?obfs-password=secret",
                "PrivateKey=private-value",
            ],
        )
        state = AppState(schema_version=STATE_SCHEMA_VERSION, subscriptions=[subscription])
        state_data = state.to_dict()
        restored = AppState.from_dict(state_data)
        self.assertEqual(restored.subscription_device_id, state.subscription_device_id)
        self.assertEqual(restored.subscriptions[0].client_profile, "happ")
        self.assertTrue(restored.subscriptions[0].send_hwid)
        self.assertEqual(restored.subscriptions[0].hwid, "OWN-DEVICE-ID")
        self.assertEqual(restored.subscriptions[0].parser_revision, SUBSCRIPTION_PARSER_REVISION)
        self.assertEqual(restored.subscriptions[0].skipped_count, 4)
        self.assertNotIn("secret", " ".join(restored.subscriptions[0].warnings))
        self.assertNotIn("private-value", " ".join(restored.subscriptions[0].warnings))
        legacy_subscription = Subscription.from_dict({"url": "https://example.com"})
        self.assertEqual(legacy_subscription.parser_revision, 0)
        self.assertEqual(legacy_subscription.skipped_count, 0)
        self.assertEqual(legacy_subscription.warnings, [])
        self.assertEqual(
            normalize_subscription_warnings("not-a-list"),
            [],
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "state.enc"
            plain_path = Path(temp_dir) / "state-plain.enc"
            backup_path = Path(temp_dir) / "backup.enc"
            plain_storage = StateStorage(plain_path)
            plain_storage.save(state)
            self.assertEqual(plain_storage.load().subscriptions[0].url, subscription.url)
            storage = StateStorage(state_path)
            storage.passphrase = "strong passphrase"
            storage.save(state)
            self.assertNotIn("token=secret", state_path.read_text(encoding="utf-8"))
            loaded = storage.load()
            self.assertEqual(loaded.subscriptions[0].url, subscription.url)
            storage.export_backup(backup_path, "backup passphrase")
            imported = storage.import_backup(backup_path, "backup passphrase")
            self.assertEqual(imported.subscriptions[0].url, subscription.url)

    def test_diagnostics_redact_subscription_urls_node_credentials_and_log_urls(self) -> None:
        state = AppState(
            subscription_device_id="INSTALL-DEVICE-SECRET",
            subscriptions=[
                Subscription(
                    url="https://sub.example/?token=top-secret",
                    send_hwid=True,
                    hwid="SUBSCRIPTION-HWID-SECRET",
                    warnings=[
                        "hy2://auth-secret@example/?obfs-password=cover-secret",
                        "PrivateKey=warning-private-key",
                    ],
                )
            ],
            nodes=[
                Node(
                    link="vless://private-link",
                    outbound={"type": "wireguard", "private_key": "private-key"},
                )
            ],
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = export_diagnostics(
                Path(temp_dir) / "diagnostics.zip",
                state,
                ["failed https://sub.example/path?token=log-secret"],
            )
            with zipfile.ZipFile(archive_path) as archive:
                state_text = archive.read("state_redacted.json").decode()
                logs_text = archive.read("recent_logs.txt").decode()
        self.assertNotIn("top-secret", state_text)
        self.assertNotIn("private-link", state_text)
        self.assertNotIn("private-key", state_text)
        self.assertNotIn("INSTALL-DEVICE-SECRET", state_text)
        self.assertNotIn("SUBSCRIPTION-HWID-SECRET", state_text)
        self.assertNotIn("auth-secret", state_text)
        self.assertNotIn("cover-secret", state_text)
        self.assertNotIn("warning-private-key", state_text)
        self.assertNotIn("log-secret", logs_text)

    def test_qimage_is_passed_directly_and_only_http_is_accepted(self) -> None:
        image = QImage(2, 2, QImage.Format.Format_RGB32)
        received = []

        def read_barcode(value, **_kwargs):
            received.append(value)
            return SimpleNamespace(text="https://sub.example/list")

        fake_module = SimpleNamespace(
            read_barcode=read_barcode,
            BarcodeFormat=SimpleNamespace(QRCode=object()),
        )
        with patch.dict(sys.modules, {"zxingcpp": fake_module}):
            self.assertEqual(decode_subscription_qr(image), "https://sub.example/list")
        self.assertIs(received[0], image)

        fake_module.read_barcode = lambda *_args, **_kwargs: SimpleNamespace(
            text="happ://add/https://sub.example/list"
        )
        with patch.dict(sys.modules, {"zxingcpp": fake_module}):
            self.assertEqual(
                decode_subscription_qr(image),
                "happ://add/https://sub.example/list",
            )

        fake_module.read_barcode = lambda *_args, **_kwargs: SimpleNamespace(text="vless://secret")
        with patch.dict(sys.modules, {"zxingcpp": fake_module}):
            with self.assertRaises(QrDecodeError):
                decode_subscription_qr(image)


if __name__ == "__main__":
    unittest.main()
