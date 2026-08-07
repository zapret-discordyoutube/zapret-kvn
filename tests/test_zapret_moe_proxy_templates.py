from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ZapretMoeProxyTemplateTests(unittest.TestCase):
    def test_all_singbox_templates_route_zapret_moe_and_subdomains_to_proxy(self) -> None:
        template_dir = ROOT / "data" / "templates" / "sing-box"

        for path in sorted(template_dir.glob("*.json")):
            with self.subTest(template=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                rules = payload["route"]["rules"]
                proxy_index = next(
                    index
                    for index, rule in enumerate(rules)
                    if rule.get("domain_suffix") == ["zapret.moe"]
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
                    if rule.get("domain") == ["domain:zapret.moe"]
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
