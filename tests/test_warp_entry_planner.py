"""The WARP entry hop through the real Windows planner (owner decision 2026-11-25): each protocol owner enters through it."""
from __future__ import annotations

from pathlib import Path
import unittest

from xray_fluent.constants import HYSTERIA_PATH_DEFAULT
from xray_fluent.engines.singbox.runtime_planner import (
    _APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG,
    parse_singbox_document,
    plan_singbox_runtime,
)
from xray_fluent.engines.singbox.warp_entry import WARP_ENTRY_API_TAG, WARP_ENTRY_TAG, violations
from xray_fluent.importer.link_parser import parse_single

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "data" / "templates" / "sing-box" / "default.json"
PROFILE = r"C:\Users\me\AppData\Roaming\ZapretKVN\warp-entry-profile.json"
HY2 = "hy2://secret@example.com:443/?insecure=1&pinSHA256=" + "a" * 64 + "#hy"
VLESS = "vless://11111111-1111-1111-1111-111111111111@vless.example.com:443?security=tls&sni=vless.example.com&type=tcp#vl"
SS = "ss://YWVzLTEyOC1nY206cGFzcw@ss.example.com:8388#ss"


def plan(link: str, profile: str = PROFILE):
    document = parse_singbox_document(TEMPLATE_PATH, TEMPLATE_PATH.read_text(encoding="utf-8"))
    return plan_singbox_runtime(document, parse_single(link), warp_entry_profile=profile)


def rules(plan_) -> list[dict]:
    return plan_.singbox_config["route"]["rules"]


def hop(plan_) -> dict:
    return next(e for e in plan_.singbox_config["endpoints"] if e["tag"] == WARP_ENTRY_TAG)


class WarpEntryPlannerTests(unittest.TestCase):
    def test_off_by_default_leaves_no_hop_anywhere(self) -> None:
        for link in (HY2, VLESS, SS):
            with self.subTest(link[:4]):
                built = plan(link, profile="")
                self.assertNotIn(WARP_ENTRY_TAG, str(built.singbox_config))
                self.assertIsNone(built.warp_entry)

    def test_hysteria_sidecar_enters_through_the_hop_by_its_process_rule(self) -> None:
        built = plan(HY2)
        executable = str(HYSTERIA_PATH_DEFAULT.resolve())
        rule = next(r for r in rules(built) if r.get("process_path") == [executable])
        self.assertEqual(WARP_ENTRY_TAG, rule["outbound"])
        self.assertEqual("warp", hop(built)["type"])
        self.assertEqual({"cache_path": PROFILE, "detour": WARP_ENTRY_API_TAG}, hop(built)["profile"])
        self.assertTrue(any(o.get("tag") == WARP_ENTRY_API_TAG for o in built.singbox_config["outbounds"]))
        self.assertTrue(built.warp_entry.active)

    def test_xray_hybrid_enters_through_the_hop_by_its_protect_inbound_rule(self) -> None:
        built = plan(VLESS)
        rule = next(r for r in rules(built) if r.get("inbound") == [_APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG])
        self.assertEqual(WARP_ENTRY_TAG, rule["outbound"])
        self.assertEqual("warp", hop(built)["type"])

    def test_native_outbound_enters_through_a_detour(self) -> None:
        built = plan(SS)
        proxy = next(o for o in built.singbox_config["outbounds"] if o.get("tag") == "proxy")
        self.assertEqual(WARP_ENTRY_TAG, proxy["detour"])
        self.assertEqual(1, built.warp_entry.chained)

    def test_hop_is_an_entry_only_in_every_built_plan(self) -> None:
        for link, paths, inbounds in (
            (HY2, [str(HYSTERIA_PATH_DEFAULT.resolve())], []),
            (VLESS, [], [_APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG]),
            (SS, [], []),
        ):
            with self.subTest(link[:4]):
                built = plan(link)
                self.assertEqual([], violations(built.singbox_config, sidecar_process_paths=paths, sidecar_inbounds=inbounds))
                self.assertNotEqual(WARP_ENTRY_TAG, built.singbox_config["route"].get("final"))
                direct_rules = [r for r in rules(built) if r.get("outbound") == "direct"]
                self.assertFalse(any(WARP_ENTRY_TAG in str(r) for r in direct_rules))

    def test_only_remote_servers_dial_through_the_hop_in_every_built_plan(self) -> None:
        # Regression of 0.8.110: the loopback relays to the Hysteria/Xray helpers were chained through the hop too.
        for link in (HY2, VLESS, SS):
            with self.subTest(link[:4]):
                for outbound in plan(link).singbox_config["outbounds"]:
                    if outbound.get("detour") == WARP_ENTRY_TAG:
                        self.assertNotIn(outbound.get("server"), ("127.0.0.1", "::1", "localhost"), outbound.get("tag"))

    def test_registration_resolves_outside_the_tunnel_in_every_built_plan(self) -> None:
        # Regression of 0.8.110, seen on a real run: without a resolver the registration lookup went through the proxied
        # DNS that waits for the hop, and the hop never came up.
        for link in (HY2, VLESS, SS):
            with self.subTest(link[:4]):
                api = next(o for o in plan(link).singbox_config["outbounds"] if o.get("tag") == WARP_ENTRY_API_TAG)
                self.assertEqual("bootstrap-dns", api["domain_resolver"])


if __name__ == "__main__":
    unittest.main()
