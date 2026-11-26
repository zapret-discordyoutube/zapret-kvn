"""WARP as the entry hop (owner decision 2026-11-25): servers and sidecars enter through it, and it is never an exit.

The configurations here are what the real planner builds for the real servers of the vpnbot test person (one Hysteria2
sidecar plan, one Xray hybrid plan), taken before the hop is applied; ``apply_entry_hop`` is then run on them.  The
detour of a native sing-box outbound (Shadowsocks, TUIC, ...) is not covered: the test person has no such server.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.real_subscription import nodes_of, requires_real_subscription  # noqa: E402
from tests.test_warp_entry_planner import PROFILE, plan  # noqa: E402
from xray_fluent.constants import HYSTERIA_PATH_DEFAULT  # noqa: E402
from xray_fluent.engines.singbox.runtime_planner import _APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG as PROTECT  # noqa: E402
from xray_fluent.engines.singbox.warp_entry import (  # noqa: E402
    WARP_ENTRY_API_TAG,
    WARP_ENTRY_MTU,
    WARP_ENTRY_TAG,
    apply_entry_hop,
    violations,
)

HYSTERIA = str(HYSTERIA_PATH_DEFAULT.resolve())


def config(scheme: str) -> dict:
    """The real plan of the first real server of this protocol, without the hop (the setting is off)."""
    return copy.deepcopy(plan(nodes_of(scheme)[0], profile="").singbox_config)


def apply(payload: dict, scheme: str, **kwargs):
    kwargs.setdefault("resolver", "bootstrap-dns")
    kwargs.setdefault("sidecar_process_paths", [HYSTERIA] if scheme == "hysteria2" else [])
    kwargs.setdefault("sidecar_inbounds", [PROTECT] if scheme == "vless" else [])
    return apply_entry_hop(payload, PROFILE, **kwargs)


def check(payload: dict, scheme: str) -> list[str]:
    return violations(
        payload,
        sidecar_process_paths=[HYSTERIA] if scheme == "hysteria2" else [],
        sidecar_inbounds=[PROTECT] if scheme == "vless" else [],
    )


def by_tag(items: list, tag: str) -> dict:
    return next(item for item in items if item.get("tag") == tag)


@requires_real_subscription
class WarpEntryHopTests(unittest.TestCase):
    SCHEMES = ("hysteria2", "vless")

    def test_the_real_plan_has_the_sidecar_rule_the_hop_leads_into(self) -> None:
        for scheme in self.SCHEMES:
            with self.subTest(scheme):
                payload = config(scheme)
                result = apply(payload, scheme)
                self.assertEqual(1, result.rerouted)
                rules = payload["route"]["rules"]
                lead = next(r for r in rules if r.get("outbound") == WARP_ENTRY_TAG)
                self.assertEqual("route", lead.get("action", "route"))
                self.assertEqual("proxy", payload["route"]["final"])

    def test_user_direct_rules_stay_direct(self) -> None:
        for scheme in self.SCHEMES:
            with self.subTest(scheme):
                sidecar = {"process_path": [HYSTERIA]} if scheme == "hysteria2" else {"inbound": [PROTECT]}

                def is_sidecar(rule: dict) -> bool:
                    return all(rule.get(key) == value for key, value in sidecar.items())

                before = [r for r in config(scheme)["route"]["rules"] if r.get("outbound") == "direct" and not is_sidecar(r)]
                payload = config(scheme)
                apply(payload, scheme)
                after = [r for r in payload["route"]["rules"] if r.get("outbound") == "direct"]
                self.assertTrue(before)
                self.assertEqual(before, after, "direct traffic never enters WARP")

    def test_sidecar_path_match_ignores_case_as_windows_does(self) -> None:
        payload = config("hysteria2")
        for rule in payload["route"]["rules"]:
            if rule.get("process_path") == [HYSTERIA]:
                rule["process_path"] = [HYSTERIA.upper()]
        self.assertEqual(1, apply(payload, "hysteria2").rerouted)

    def test_hop_endpoint_has_mtu_and_private_profile_path_and_dials_directly(self) -> None:
        for scheme in self.SCHEMES:
            with self.subTest(scheme):
                payload = config(scheme)
                apply(payload, scheme)
                hop = by_tag(payload["endpoints"], WARP_ENTRY_TAG)
                self.assertEqual("warp", hop["type"])
                self.assertEqual(WARP_ENTRY_MTU, hop["mtu"])
                self.assertEqual({"cache_path": PROFILE, "detour": WARP_ENTRY_API_TAG}, hop["profile"])
                self.assertNotIn("detour", hop)
                # registration goes through its own direct outbound, not through the TUN and the hop it waits for
                api = by_tag(payload["outbounds"], WARP_ENTRY_API_TAG)
                self.assertEqual("direct", api["type"])
                self.assertEqual("bootstrap-dns", api["domain_resolver"])

    def test_hop_endpoint_carries_client_side_noise_built_by_the_masking_module(self) -> None:
        # The same chain the app's WireGuard masking builds for the preset domain; only client-side Amnezia options.
        from xray_fluent.masking.wireguard import dns_chain, validate_chain

        payload = config("vless")
        apply(payload, "vless")
        noise = by_tag(payload["endpoints"], WARP_ENTRY_TAG)["amnezia"]
        self.assertEqual(dns_chain("yandex.ru"), noise["i1"])
        self.assertIsNone(validate_chain(noise["i1"])[1])
        self.assertEqual({"jc", "jmin", "jmax", "i1"}, set(noise))

    def test_nothing_to_enter_means_no_hop_and_no_registration(self) -> None:
        # The real plan of the real server, with the sidecar rule taken away: nothing leads into the hop.
        payload = config("vless")
        payload["route"]["rules"] = [r for r in payload["route"]["rules"] if r.get("inbound") != [PROTECT]]
        result = apply(payload, "vless")
        self.assertFalse(result.active)
        self.assertNotIn("endpoints", payload)
        self.assertNotIn(WARP_ENTRY_API_TAG, str(payload))

    def test_a_runtime_copy_fed_back_in_keeps_one_hop(self) -> None:
        for scheme in self.SCHEMES:
            with self.subTest(scheme):
                payload = config(scheme)
                first = apply(payload, scheme)
                again = apply(payload, scheme)
                self.assertEqual(first.rerouted, again.rerouted)
                self.assertEqual(1, sum(1 for e in payload["endpoints"] if e["tag"] == WARP_ENTRY_TAG))
                self.assertEqual(1, sum(1 for o in payload["outbounds"] if o["tag"] == WARP_ENTRY_API_TAG))

    def test_guard_accepts_the_built_config(self) -> None:
        for scheme in self.SCHEMES:
            with self.subTest(scheme):
                payload = config(scheme)
                apply(payload, scheme)
                self.assertEqual([], check(payload, scheme))

    def test_guard_rejects_every_other_use_of_the_hop(self) -> None:
        for scheme in self.SCHEMES:
            mutations = {
                "final": lambda p: p["route"].__setitem__("final", WARP_ENTRY_TAG),
                "user rule": lambda p: p["route"]["rules"].append({"domain_suffix": ["x.example"], "outbound": WARP_ENTRY_TAG}),
                "selector member": lambda p: p["outbounds"].append({"type": "selector", "tag": "pick", "outbounds": [WARP_ENTRY_TAG]}),
                "foreign process": lambda p: p["route"]["rules"].append({"process_path": [r"C:\x\other.exe"], "outbound": WARP_ENTRY_TAG}),
                "detour outside servers": lambda p: p["route"].__setitem__("detour", WARP_ENTRY_TAG),
                "tag among outbounds": lambda p: p["outbounds"].append({"type": "direct", "tag": WARP_ENTRY_TAG}),
            }
            for name, mutate in mutations.items():
                with self.subTest(f"{scheme}: {name}"):
                    payload = config(scheme)
                    apply(payload, scheme)
                    mutate(payload)
                    self.assertTrue(check(payload, scheme), name)

    def test_apply_is_pure_with_respect_to_the_caller_input_copy(self) -> None:
        original = config("vless")
        snapshot = copy.deepcopy(original)
        apply(copy.deepcopy(original), "vless")
        self.assertEqual(snapshot, original)


if __name__ == "__main__":
    unittest.main()
