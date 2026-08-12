from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
EXPECTATIONS_PATH = ROOT / "data" / "routing" / "vpnbot-route-expectations.json"


def _suffix_matches(domain: str, suffix: str) -> bool:
    return domain == suffix or domain.endswith(f".{suffix}")


def _classify_xray(payload: dict, domain: str) -> str:
    for rule in payload["routing"]["rules"]:
        for matcher in rule.get("domain", []):
            if matcher.startswith("domain:") and _suffix_matches(domain, matcher[7:]):
                return rule["outboundTag"]
        if not any(key in rule for key in ("domain", "ip", "process", "protocol", "port")):
            return rule["outboundTag"]
    raise AssertionError(f"Xray route not found for {domain}")


def _classify_singbox(payload: dict, domain: str) -> str:
    for rule in payload["route"]["rules"]:
        if any(_suffix_matches(domain, suffix) for suffix in rule.get("domain_suffix", [])):
            return rule["outbound"]
    return payload["route"]["final"]


class ZapretMoeProxyTemplateTests(unittest.TestCase):
    def test_all_native_templates_match_the_unified_vpnbot_route_table(self) -> None:
        expectations = json.loads(EXPECTATIONS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(1, expectations["schema_version"])
        self.assertEqual("vpnbot-network-policy-v2", expectations["policy_id"])
        self.assertRegex(expectations["source_policy_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            12,
            sum(case["inline_required"] for case in expectations["cases"]),
        )

        for engine, directory, classifier in (
            ("xray", ROOT / "data" / "templates" / "xray", _classify_xray),
            ("sing-box", ROOT / "data" / "templates" / "sing-box", _classify_singbox),
        ):
            for path in sorted(directory.glob("*.json")):
                payload = json.loads(path.read_text(encoding="utf-8"))
                is_vpn_default = path.name == "default.json"
                for case in expectations["cases"]:
                    if case["profile_modes"] == ["vpn-default"] and not is_vpn_default:
                        continue
                    with self.subTest(
                        engine=engine,
                        template=path.name,
                        policy_class=case["policy_class"],
                        domain=case["domain"],
                    ):
                        self.assertEqual(
                            case["expected_route"],
                            classifier(payload, case["domain"]),
                        )

    def test_critical_detection_set_is_the_first_domain_rule_everywhere(self) -> None:
        expectations = json.loads(EXPECTATIONS_PATH.read_text(encoding="utf-8"))
        critical = {
            case["domain"]
            for case in expectations["cases"]
            if case["inline_required"]
        }
        for path in sorted((ROOT / "data" / "templates" / "xray").glob("*.json")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            first = payload["routing"]["rules"][0]
            self.assertEqual(critical, {value[7:] for value in first["domain"]})
            self.assertEqual("block", first["outboundTag"])
        for path in sorted((ROOT / "data" / "templates" / "sing-box").glob("*.json")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            first_domain_rule = next(
                rule for rule in payload["route"]["rules"] if "domain_suffix" in rule
            )
            self.assertEqual(critical, set(first_domain_rule["domain_suffix"]))
            self.assertEqual("block", first_domain_rule["outbound"])

    def test_all_singbox_templates_route_zapret_moe_and_subdomains_to_proxy(self) -> None:
        template_dir = ROOT / "data" / "templates" / "sing-box"

        for path in sorted(template_dir.glob("*.json")):
            with self.subTest(template=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                rules = payload["route"]["rules"]
                proxy_index = next(
                    index
                    for index, rule in enumerate(rules)
                    if "zapret.moe" in rule.get("domain_suffix", [])
                )
                proxy_rule = rules[proxy_index]

                self.assertEqual(proxy_rule.get("action"), "route")
                self.assertEqual(proxy_rule.get("outbound"), "proxy")
                self.assertTrue(
                    all(
                        index > proxy_index
                        for index, rule in enumerate(rules)
                        if rule.get("outbound") == "direct" and "rule_set" in rule
                    ),
                    "zapret.moe proxy must precede broad direct rule sets",
                )

    def test_all_xray_templates_route_zapret_moe_and_subdomains_to_proxy(self) -> None:
        template_dir = ROOT / "data" / "templates" / "xray"

        for path in sorted(template_dir.glob("*.json")):
            with self.subTest(template=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                rules = payload["routing"]["rules"]
                proxy_index = next(
                    index
                    for index, rule in enumerate(rules)
                    if "domain:zapret.moe" in rule.get("domain", [])
                )
                proxy_rule = rules[proxy_index]

                self.assertEqual(proxy_rule.get("type"), "field")
                self.assertEqual(proxy_rule.get("network"), "tcp,udp")
                self.assertEqual(proxy_rule.get("outboundTag"), "proxy")
                self.assertTrue(
                    all(
                        index > proxy_index
                        for index, rule in enumerate(rules)
                        if rule.get("outboundTag") == "direct"
                        and any(
                            value in {"geosite:category-ru", "geoip:ru"}
                            for key in ("domain", "ip")
                            for value in rule.get(key, [])
                        )
                    ),
                    "zapret.moe proxy must precede broad Russian direct rules",
                )


if __name__ == "__main__":
    unittest.main()
