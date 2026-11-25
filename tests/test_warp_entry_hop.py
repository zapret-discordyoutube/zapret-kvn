"""WARP as the entry hop (owner decision 2026-11-25): servers and sidecars enter through it, and it is never an exit."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xray_fluent.engines.singbox.warp_entry import (  # noqa: E402
    WARP_ENTRY_API_TAG,
    WARP_ENTRY_MTU,
    WARP_ENTRY_TAG,
    apply_entry_hop,
    violations,
)

HYSTERIA = r"C:\Program Files\ZapretKVN\core\hysteria.exe"
PROTECT = "__app_hybrid_protect_in"
PROFILE = r"C:\Users\me\AppData\Roaming\ZapretKVN\warp-entry-profile.json"


def config() -> dict:
    return {
        "outbounds": [
            {"type": "shadowsocks", "tag": "ss", "server": "ss.example.net", "server_port": 8388},
            {"type": "socks", "tag": "ip", "server": "203.0.113.7", "server_port": 1080},
            {"type": "http", "tag": "chained", "server": "h.example", "server_port": 80, "detour": "ss"},
            {"type": "selector", "tag": "proxy", "outbounds": ["ss", "ip"]},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "final": "proxy",
            "rules": [
                {"process_path": [HYSTERIA], "outbound": "direct"},
                {"inbound": [PROTECT], "outbound": "direct"},
                {"domain_suffix": ["ru"], "outbound": "direct"},
            ],
        },
    }


def apply(payload: dict, **kwargs):
    kwargs.setdefault("resolver", "dns-direct")
    kwargs.setdefault("sidecar_process_paths", [HYSTERIA])
    kwargs.setdefault("sidecar_inbounds", [PROTECT])
    return apply_entry_hop(payload, PROFILE, **kwargs)


def check(payload: dict) -> list[str]:
    return violations(payload, sidecar_process_paths=[HYSTERIA], sidecar_inbounds=[PROTECT])


def by_tag(items: list, tag: str) -> dict:
    return next(item for item in items if item.get("tag") == tag)


class WarpEntryHopTests(unittest.TestCase):
    def test_native_servers_detour_and_local_types_do_not(self) -> None:
        payload = config()
        result = apply(payload)
        outbounds = payload["outbounds"]
        self.assertEqual(2, result.chained)
        self.assertEqual(WARP_ENTRY_TAG, by_tag(outbounds, "ss")["detour"])
        self.assertEqual(WARP_ENTRY_TAG, by_tag(outbounds, "ip")["detour"])
        self.assertEqual("ss", by_tag(outbounds, "chained")["detour"], "not the first link of its chain")
        for tag in ("proxy", "direct"):
            self.assertNotIn("detour", by_tag(outbounds, tag))

    def test_server_names_resolve_outside_the_hop_and_literals_and_user_choices_stay(self) -> None:
        payload = config()
        by_tag(payload["outbounds"], "ss")["domain_resolver"] = "mine"
        payload["outbounds"].append({"type": "tuic", "tag": "t", "server": "t.example", "server_port": 443})
        apply(payload)
        self.assertEqual("mine", by_tag(payload["outbounds"], "ss")["domain_resolver"])
        self.assertEqual("dns-direct", by_tag(payload["outbounds"], "t")["domain_resolver"])
        self.assertNotIn("domain_resolver", by_tag(payload["outbounds"], "ip"))
        bare = config()
        apply(bare, resolver=None)
        self.assertNotIn("domain_resolver", by_tag(bare["outbounds"], "ss"))

    def test_sidecar_rules_lead_into_the_hop_and_user_rules_stay_direct(self) -> None:
        payload = config()
        result = apply(payload)
        rules = payload["route"]["rules"]
        self.assertEqual(2, result.rerouted)
        self.assertEqual(WARP_ENTRY_TAG, rules[0]["outbound"])
        self.assertEqual(WARP_ENTRY_TAG, rules[1]["outbound"])
        self.assertEqual("direct", rules[2]["outbound"], "direct traffic never enters WARP")
        self.assertEqual("proxy", payload["route"]["final"])

    def test_sidecar_path_match_ignores_case_as_windows_does(self) -> None:
        payload = config()
        payload["route"]["rules"][0]["process_path"] = [HYSTERIA.upper()]
        self.assertEqual(2, apply(payload).rerouted)

    def test_hop_endpoint_has_mtu_and_private_profile_path_and_dials_directly(self) -> None:
        payload = config()
        apply(payload)
        hop = by_tag(payload["endpoints"], WARP_ENTRY_TAG)
        self.assertEqual("warp", hop["type"])
        self.assertEqual(WARP_ENTRY_MTU, hop["mtu"])
        self.assertEqual({"cache_path": PROFILE, "detour": WARP_ENTRY_API_TAG}, hop["profile"])
        self.assertNotIn("detour", hop)
        # registration goes through its own direct outbound, not through the TUN and the hop it waits for
        api = by_tag(payload["outbounds"], WARP_ENTRY_API_TAG)
        self.assertEqual("direct", api["type"])
        self.assertEqual("dns-direct", api["domain_resolver"])

    def test_nothing_to_enter_means_no_hop_and_no_registration(self) -> None:
        payload = {"outbounds": [{"type": "direct", "tag": "direct"}], "route": {"rules": []}}
        result = apply(payload)
        self.assertFalse(result.active)
        self.assertNotIn("endpoints", payload)
        self.assertNotIn(WARP_ENTRY_API_TAG, str(payload))

    def test_a_runtime_copy_fed_back_in_keeps_one_hop(self) -> None:
        payload = config()
        apply(payload)
        again = apply(payload)
        self.assertEqual(2, again.chained)
        self.assertEqual(2, again.rerouted)
        self.assertEqual(1, sum(1 for e in payload["endpoints"] if e["tag"] == WARP_ENTRY_TAG))
        self.assertEqual(1, sum(1 for o in payload["outbounds"] if o["tag"] == WARP_ENTRY_API_TAG))

    def test_guard_accepts_the_built_config(self) -> None:
        payload = config()
        apply(payload)
        self.assertEqual([], check(payload))

    def test_guard_rejects_every_other_use_of_the_hop(self) -> None:
        for name, mutate in {
            "final": lambda p: p["route"].__setitem__("final", WARP_ENTRY_TAG),
            "user rule": lambda p: p["route"]["rules"].append({"domain_suffix": ["x.example"], "outbound": WARP_ENTRY_TAG}),
            "selector member": lambda p: by_tag(p["outbounds"], "proxy")["outbounds"].append(WARP_ENTRY_TAG),
            "foreign process": lambda p: p["route"]["rules"].append({"process_path": [r"C:\x\other.exe"], "outbound": WARP_ENTRY_TAG}),
            "sidecar rule with extra match": lambda p: p["route"]["rules"][0].update({"domain": ["a.example"]}),
            "detour outside servers": lambda p: p["route"].__setitem__("detour", WARP_ENTRY_TAG),
            "tag among outbounds": lambda p: p["outbounds"].append({"type": "direct", "tag": WARP_ENTRY_TAG}),
        }.items():
            with self.subTest(name):
                payload = config()
                apply(payload)
                mutate(payload)
                self.assertTrue(check(payload), name)

    def test_apply_is_pure_with_respect_to_the_caller_input_copy(self) -> None:
        original = config()
        snapshot = copy.deepcopy(original)
        apply(copy.deepcopy(original))
        self.assertEqual(snapshot, original)


if __name__ == "__main__":
    unittest.main()
