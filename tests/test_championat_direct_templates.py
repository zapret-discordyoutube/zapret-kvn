from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ChampionatDirectTemplateTests(unittest.TestCase):
    def test_all_singbox_templates_route_championat_direct_before_proxy_rules(self) -> None:
        template_dir = ROOT / "data" / "templates" / "sing-box"

        for path in sorted(template_dir.glob("*.json")):
            with self.subTest(template=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                rules = payload["route"]["rules"]
                direct_index = next(
                    index
                    for index, rule in enumerate(rules)
                    if "championat.com" in rule.get("domain_suffix", [])
                )
                direct_rule = rules[direct_index]

                self.assertEqual(direct_rule.get("action"), "route")
                self.assertEqual(direct_rule.get("outbound"), "direct")
                self.assertTrue(
                    all(
                        index > direct_index
                        for index, rule in enumerate(rules)
                        if rule.get("outbound") == "proxy"
                    ),
                    "Championat direct must precede every proxy rule",
                )

    def test_all_xray_templates_route_championat_direct_before_proxy_rules(self) -> None:
        template_dir = ROOT / "data" / "templates" / "xray"

        for path in sorted(template_dir.glob("*.json")):
            with self.subTest(template=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                rules = payload["routing"]["rules"]
                direct_index = next(
                    index
                    for index, rule in enumerate(rules)
                    if "domain:championat.com" in rule.get("domain", [])
                )
                direct_rule = rules[direct_index]

                self.assertEqual(direct_rule.get("type"), "field")
                self.assertEqual(direct_rule.get("network"), "tcp,udp")
                self.assertEqual(direct_rule.get("outboundTag"), "direct")
                self.assertTrue(
                    all(
                        index > direct_index
                        for index, rule in enumerate(rules)
                        if rule.get("outboundTag") == "proxy"
                    ),
                    "Championat direct must precede every proxy rule",
                )


if __name__ == "__main__":
    unittest.main()
