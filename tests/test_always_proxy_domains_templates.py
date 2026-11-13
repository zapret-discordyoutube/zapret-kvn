"""YouTube cache hosts must go through the VPN even when their address is Russian (owner decision 2026-11-13).

The broad Russia-direct rules match by address (geoip-ru / geoip:ru). A googlevideo cache inside a Russian operator network has
a Russian address, so without a name rule above them the video leaves the VPN and is blocked. Every shipped template carries the
same name list, as a native rule above the broad direct rules (no Python route injection), and the sing-box templates resolve
those names through the tunnel resolver.
"""

from __future__ import annotations

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "data" / "templates"

ALWAYS_PROXY = [
    "googlevideo.com",
    "youtube.com",
    "youtu.be",
    "ytimg.com",
    "ggpht.com",
    "youtube-nocookie.com",
    "youtubei.googleapis.com",
]
CACHE_HOST = "rr2---sn-8ph2xajvh-3a4l.googlevideo.com"


def _matches(domain: str, suffix: str) -> bool:
    return domain == suffix or domain.endswith(f".{suffix}")


def _singbox_rules(payload: dict) -> list[dict]:
    return payload["route"]["rules"]


def _xray_rules(payload: dict) -> list[dict]:
    return payload["routing"]["rules"]


def _is_broad_direct_singbox(rule: dict) -> bool:
    return rule.get("outbound") == "direct" and "rule_set" in rule


def _is_broad_direct_xray(rule: dict) -> bool:
    if rule.get("outboundTag") != "direct":
        return False
    return any(item in ("geoip:ru", "geosite:category-ru") for item in rule.get("ip", []) + rule.get("domain", []))


class AlwaysProxyDomainsTemplateTests(unittest.TestCase):
    def test_singbox_templates_route_the_list_to_proxy_above_the_russia_direct_sets(self) -> None:
        for path in sorted((TEMPLATES / "sing-box").glob("*.json")):
            with self.subTest(template=path.name):
                rules = _singbox_rules(json.loads(path.read_text(encoding="utf-8")))
                found = [i for i, rule in enumerate(rules) if rule.get("domain_suffix") == ALWAYS_PROXY]
                self.assertEqual(1, len(found), "exactly one always-proxy rule")
                rule = rules[found[0]]
                self.assertEqual("route", rule["action"])
                self.assertEqual("proxy", rule["outbound"])
                direct_sets = [i for i, r in enumerate(rules) if _is_broad_direct_singbox(r)]
                self.assertTrue(direct_sets, "the template keeps its Russia-direct rule set")
                self.assertTrue(all(found[0] < i for i in direct_sets), "above every broad direct rule set")
                self.assertTrue(
                    any(_matches(CACHE_HOST, s) for s in rule["domain_suffix"]),
                    "a Russian-address cache host is covered",
                )

    def test_singbox_templates_resolve_the_list_through_the_tunnel_resolver(self) -> None:
        for path in sorted((TEMPLATES / "sing-box").glob("*.json")):
            with self.subTest(template=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                dns_rules = payload["dns"]["rules"]
                matching = [r for r in dns_rules if r.get("domain_suffix") == ALWAYS_PROXY]
                self.assertEqual(1, len(matching))
                self.assertEqual("proxy-dns", matching[0]["server"])

    def test_xray_templates_route_the_list_to_proxy_above_the_russia_direct_rules(self) -> None:
        wanted = [f"domain:{name}" for name in ALWAYS_PROXY]
        for path in sorted((TEMPLATES / "xray").glob("*.json")):
            with self.subTest(template=path.name):
                rules = _xray_rules(json.loads(path.read_text(encoding="utf-8")))
                found = [i for i, rule in enumerate(rules) if rule.get("domain") == wanted]
                self.assertEqual(1, len(found), "exactly one always-proxy rule")
                self.assertEqual("proxy", rules[found[0]]["outboundTag"])
                self.assertEqual("field", rules[found[0]]["type"])
                direct = [i for i, r in enumerate(rules) if _is_broad_direct_xray(r)]
                self.assertTrue(direct, "the template keeps its Russia-direct rules")
                self.assertTrue(all(found[0] < i for i in direct), "above every broad direct rule")

    def test_the_detection_block_stays_first(self) -> None:
        for path in sorted((TEMPLATES / "xray").glob("*.json")):
            first = _xray_rules(json.loads(path.read_text(encoding="utf-8")))[0]
            self.assertEqual("block", first["outboundTag"], path.name)
        for path in sorted((TEMPLATES / "sing-box").glob("*.json")):
            rules = _singbox_rules(json.loads(path.read_text(encoding="utf-8")))
            first_domain_rule = next(rule for rule in rules if "domain_suffix" in rule)
            self.assertEqual("block", first_domain_rule["outbound"], path.name)


if __name__ == "__main__":
    unittest.main()
