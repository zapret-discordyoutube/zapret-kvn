from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from xray_fluent.engines.xray.config_builder import build_xray_config
from xray_fluent.engines.xray.core_updater import _install_zip_archive
from xray_fluent.link_parser import parse_single
from xray_fluent.models import AppSettings, RoutingSettings


ROOT = Path(__file__).resolve().parents[1]
SINGBOX_TEMPLATES = sorted((ROOT / "data" / "templates" / "sing-box").glob("*.json"))
XRAY_TEMPLATES = sorted((ROOT / "data" / "templates" / "xray").glob("*.json"))

BLOCKED_CHECK_DOMAINS = [
    "mobileproxy.passport.yandex.net",
    "relay-api.eu.2gis.com",
    "api.ipify.org",
    "checkip.amazonaws.com",
    "ifconfig.me",
    "ip.mail.ru",
    "ipv4-internet.yandex.net",
    "ipv6-internet.yandex.net",
    "trace-flow.ru",
    "api.oneme.ru",
    "vk-analytics.ru",
    "apptracer.ru",
]


class NativeSingboxRoutingTemplateTests(unittest.TestCase):
    def test_all_templates_keep_ru_rule_sets_and_priority(self) -> None:
        self.assertTrue(SINGBOX_TEMPLATES)
        for path in SINGBOX_TEMPLATES:
            with self.subTest(template=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                route = payload["route"]
                rule_sets = {item["tag"]: item for item in route["rule_set"]}
                self.assertEqual(
                    set(rule_sets),
                    {
                        "geosite-ru-blocked",
                        "geoip-ru-blocked",
                        "geosite-category-ru",
                        "geoip-ru",
                    },
                )
                self.assertTrue(all(item["update_interval"] == "6h" for item in rule_sets.values()))
                self.assertTrue(all(item["download_detour"] == "direct" for item in rule_sets.values()))

                rules = route["rules"]
                self.assertEqual(rules[0], {"action": "sniff"})
                self.assertEqual(rules[1], {"protocol": "dns", "action": "hijack-dns"})
                self.assertEqual(rules[2]["domain_suffix"], BLOCKED_CHECK_DOMAINS)
                self.assertEqual(
                    (rules[2]["action"], rules[2]["outbound"]),
                    ("route", "block"),
                )

                blocked_index = next(
                    index
                    for index, rule in enumerate(rules)
                    if rule.get("rule_set") == ["geosite-ru-blocked", "geoip-ru-blocked"]
                )
                ru_direct_index = next(
                    index
                    for index, rule in enumerate(rules)
                    if rule.get("rule_set") == ["geosite-category-ru", "geoip-ru"]
                )
                self.assertLess(blocked_index, ru_direct_index)
                private_index = next(
                    (
                        index
                        for index, rule in enumerate(rules)
                        if rule.get("ip_is_private") is True
                    ),
                    None,
                )
                if private_index is not None:
                    self.assertLess(blocked_index, private_index)
                    self.assertLess(private_index, ru_direct_index)
                self.assertEqual(rules[blocked_index]["outbound"], "proxy")
                self.assertEqual(rules[ru_direct_index]["outbound"], "direct")


class NativeXrayRoutingTemplateTests(unittest.TestCase):
    def assert_protected_russian_routing(self, payload: dict) -> None:
        routing = payload["routing"]
        self.assertEqual(routing["domainStrategy"], "IPIfNonMatch")
        rules = routing["rules"]
        detection_index = next(
            index
            for index, rule in enumerate(rules)
            if rule.get("domain") == [f"domain:{domain}" for domain in BLOCKED_CHECK_DOMAINS]
        )
        blocked_domain_index = next(
            index for index, rule in enumerate(rules) if rule.get("domain") == ["geosite:ru-blocked"]
        )
        blocked_ip_index = next(
            index for index, rule in enumerate(rules) if rule.get("ip") == ["geoip:ru-blocked"]
        )
        direct_domain_index = next(
            index for index, rule in enumerate(rules) if rule.get("domain") == ["geosite:category-ru"]
        )
        direct_ip_index = next(
            index for index, rule in enumerate(rules) if rule.get("ip") == ["geoip:ru"]
        )
        self.assertEqual(rules[detection_index]["outboundTag"], "block")
        self.assertEqual(rules[blocked_domain_index]["outboundTag"], "proxy")
        self.assertEqual(rules[blocked_ip_index]["outboundTag"], "proxy")
        self.assertEqual(rules[direct_domain_index]["outboundTag"], "direct")
        self.assertEqual(rules[direct_ip_index]["outboundTag"], "direct")
        self.assertLess(detection_index, blocked_domain_index)
        self.assertLess(blocked_domain_index, direct_domain_index)
        self.assertLess(blocked_ip_index, direct_ip_index)

    def test_all_native_templates_have_the_same_protected_order(self) -> None:
        self.assertTrue(XRAY_TEMPLATES)
        for path in XRAY_TEMPLATES:
            with self.subTest(template=path.name):
                self.assert_protected_russian_routing(
                    json.loads(path.read_text(encoding="utf-8"))
                )

    def test_runtime_builder_keeps_the_same_default_policy(self) -> None:
        node = parse_single(
            "vless://11111111-1111-1111-1111-111111111111@vpn.example:443"
            "?type=tcp&security=tls&sni=vpn.example#vpn"
        )
        payload = build_xray_config(node, RoutingSettings(), AppSettings())
        self.assert_protected_russian_routing(payload)


class RoutingAssetOwnershipTests(unittest.TestCase):
    def test_core_bundle_manifest_records_only_the_final_overlay_owner(self) -> None:
        script = (ROOT / "scripts" / "build_core_bundle.ps1").read_text(encoding="utf-8")
        self.assertIn("$manifestFilesByName[$targetName] =", script)
        self.assertIn("files = @($manifestFilesByName.Values)", script)
        self.assertNotIn("$manifestFiles +=", script)

    def test_core_lock_overlays_pinned_runetfreedom_data_after_xray(self) -> None:
        lock = json.loads(
            (ROOT / "scripts" / "core-lock.windows-x64.json").read_text(encoding="utf-8")
        )
        sources = lock["sources"]
        ids = [source["id"] for source in sources]
        self.assertLess(ids.index("xray-core"), ids.index("runetfreedom-routing-data"))
        source = sources[ids.index("runetfreedom-routing-data")]
        self.assertEqual(source["version"], "97fafe95f258ee9e41a18e112c1fbf06db51c2c3")
        self.assertEqual(
            {mapping["target"] for mapping in source["files"]},
            {"geoip.dat", "geosite.dat"},
        )

    def test_core_only_update_preserves_application_owned_geo_data(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            target = root / "core" / "xray.exe"
            target.parent.mkdir()
            target.write_bytes(b"old-xray")
            (target.parent / "geoip.dat").write_bytes(b"runetfreedom-geoip")
            (target.parent / "geosite.dat").write_bytes(b"runetfreedom-geosite")
            archive = root / "Xray-windows-64.zip"
            with zipfile.ZipFile(archive, "w") as payload:
                payload.writestr("xray.exe", b"new-xray")
                payload.writestr("geoip.dat", b"official-geoip")
                payload.writestr("geosite.dat", b"official-geosite")
                payload.writestr("wintun.dll", b"new-wintun")

            _install_zip_archive(archive, target)

            self.assertEqual(target.read_bytes(), b"new-xray")
            self.assertEqual((target.parent / "wintun.dll").read_bytes(), b"new-wintun")
            self.assertEqual((target.parent / "geoip.dat").read_bytes(), b"runetfreedom-geoip")
            self.assertEqual(
                (target.parent / "geosite.dat").read_bytes(),
                b"runetfreedom-geosite",
            )


if __name__ == "__main__":
    unittest.main()
