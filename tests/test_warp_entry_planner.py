"""The WARP entry hop through the real Windows planner, on the real servers of the vpnbot test person.

Owner decisions 2026-11-25: each protocol owner enters through the hop; tests run on real data only.  Every VLESS and
Hysteria2 server of the test person goes through the real planner on the shipped sing-box template, and the same
invariants are asserted on each of them (the earlier synthetic version passed while the real plan chained the loopback
relays and left the pool servers outside the hop).  No native sing-box server (Shadowsocks, TUIC, ...) exists in the
test person's subscription, so the detour of a native outbound is not proven here (it is proven on the emulator).
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
import unittest

from tests.real_subscription import nodes_of, requires_real_subscription
from xray_fluent.constants import HYSTERIA_PATH_DEFAULT
from xray_fluent.engines.singbox.runtime_planner import (
    apply_warp_entry,
    _APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG,
    parse_singbox_document,
    plan_singbox_proxy_runtime,
    plan_singbox_runtime,
)
from xray_fluent.engines.singbox.warp_entry import WARP_ENTRY_API_TAG, WARP_ENTRY_MTU, WARP_ENTRY_TAG, violations

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "data" / "templates" / "sing-box" / "default.json"
PROFILE = r"C:\Users\me\AppData\Roaming\ZapretKVN\warp-entry-profile.json"


def plan(node, profile: str = PROFILE):
    document = parse_singbox_document(TEMPLATE_PATH, TEMPLATE_PATH.read_text(encoding="utf-8"))
    return plan_singbox_runtime(document, node, warp_entry_profile=profile)


def rules(plan_) -> list[dict]:
    return plan_.singbox_config["route"]["rules"]


def hop(plan_) -> dict:
    return next(e for e in plan_.singbox_config["endpoints"] if e["tag"] == WARP_ENTRY_TAG)


def is_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


@requires_real_subscription
class RealServersEnterThroughTheHopTests(unittest.TestCase):
    def test_the_test_person_has_the_protocols_these_tests_stand_on(self) -> None:
        self.assertGreaterEqual(len(nodes_of("vless")), 1)
        self.assertGreaterEqual(len(nodes_of("hysteria2")), 1)
        self.assertEqual(1, len(nodes_of("awg")))

    def test_off_by_default_leaves_no_hop_anywhere(self) -> None:
        for node in (*nodes_of("vless"), *nodes_of("hysteria2")):
            with self.subTest(node.scheme):
                built = plan(node, profile="")
                self.assertNotIn(WARP_ENTRY_TAG, str(built.singbox_config))
                self.assertIsNone(built.warp_entry)

    def test_hysteria_sidecar_enters_through_the_hop_by_its_process_rule(self) -> None:
        executable = str(HYSTERIA_PATH_DEFAULT.resolve())
        for node in nodes_of("hysteria2"):
            with self.subTest("hysteria2"):
                built = plan(node)
                rule = next(r for r in rules(built) if r.get("process_path") == [executable])
                self.assertEqual(WARP_ENTRY_TAG, rule["outbound"])
                self.assertEqual("warp", hop(built)["type"])
                self.assertEqual({"cache_path": PROFILE, "detour": WARP_ENTRY_API_TAG}, hop(built)["profile"])
                self.assertTrue(any(o.get("tag") == WARP_ENTRY_API_TAG for o in built.singbox_config["outbounds"]))
                self.assertTrue(built.warp_entry.active)

    def test_xray_hybrid_enters_through_the_hop_by_its_protect_inbound_rule(self) -> None:
        for node in nodes_of("vless"):
            with self.subTest("vless"):
                built = plan(node)
                rule = next(r for r in rules(built) if r.get("inbound") == [_APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG])
                self.assertEqual(WARP_ENTRY_TAG, rule["outbound"])
                self.assertEqual("warp", hop(built)["type"])

    def test_hop_is_an_entry_only_in_every_built_plan(self) -> None:
        for node in (*nodes_of("vless"), *nodes_of("hysteria2")):
            with self.subTest(node.scheme):
                built = plan(node)
                paths = [str(HYSTERIA_PATH_DEFAULT.resolve())] if node.scheme == "hysteria2" else []
                inbounds = [_APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG] if node.scheme == "vless" else []
                self.assertEqual([], violations(built.singbox_config, sidecar_process_paths=paths, sidecar_inbounds=inbounds))
                self.assertNotEqual(WARP_ENTRY_TAG, built.singbox_config["route"].get("final"))
                direct_rules = [r for r in rules(built) if r.get("outbound") == "direct"]
                self.assertFalse(any(WARP_ENTRY_TAG in str(r) for r in direct_rules))

    def test_only_remote_servers_dial_through_the_hop_in_every_built_plan(self) -> None:
        # Regression of 0.8.110: the loopback relays to the Hysteria/Xray helpers were chained through the hop too.
        for node in (*nodes_of("vless"), *nodes_of("hysteria2")):
            with self.subTest(node.scheme):
                for outbound in plan(node).singbox_config["outbounds"]:
                    if outbound.get("detour") == WARP_ENTRY_TAG:
                        self.assertNotIn(outbound.get("server"), ("127.0.0.1", "::1", "localhost"), outbound.get("tag"))

    def test_registration_resolves_outside_the_tunnel_in_every_built_plan(self) -> None:
        # Regression of 0.8.110, seen on a real run: without a resolver the registration lookup went through the proxied
        # DNS that waits for the hop, and the hop never came up.
        for node in (*nodes_of("vless"), *nodes_of("hysteria2")):
            with self.subTest(node.scheme):
                api = next(o for o in plan(node).singbox_config["outbounds"] if o.get("tag") == WARP_ENTRY_API_TAG)
                self.assertEqual("bootstrap-dns", api["domain_resolver"])

    def test_server_names_the_hop_dials_resolve_outside_the_tunnel(self) -> None:
        # Regression of 0.8.113, seen on the owner's machine: the hop's WireGuard endpoint resolves a domain destination
        # through the router's DNS rules, which end at the proxied DNS that waits for the very connection being opened.
        # Xray asks the hop to dial its server by name.  Hysteria resolves its own server in the app (bootstrap resolver)
        # and gives the helper an address, so no router DNS rule is involved there.
        named = [n for n in nodes_of("vless") if not is_literal(n.server)]
        self.assertTrue(named, "the test person has no VLESS server with a host name")
        for node in named:
            with self.subTest(node.scheme):
                built = plan(node)
                first = built.singbox_config["dns"]["rules"][0]
                # no assertEqual on the rule itself: a failure message would print the server name
                self.assertTrue({"domain": [node.server], "action": "route", "server": "bootstrap-dns"} == first)
                again = apply_warp_entry(built, PROFILE, tun=False)
                matching = [r for r in again.singbox_config["dns"]["rules"] if r.get("domain") == [node.server]]
                self.assertEqual(1, len(matching), "a second pass keeps one rule")

    def test_hysteria_server_names_need_no_router_dns_rule(self) -> None:
        for node in (n for n in nodes_of("hysteria2") if not is_literal(n.server)):
            with self.subTest(node.scheme):
                rules_ = plan(node).singbox_config["dns"]["rules"]
                self.assertFalse([r for r in rules_ if r.get("domain") == [node.server]])

    def test_a_literal_server_address_needs_no_dns_rule(self) -> None:
        literal = [n for n in (*nodes_of("vless"), *nodes_of("hysteria2")) if is_literal(n.server)]
        self.assertTrue(literal, "the test person has no server with an IP literal")
        for node in literal:
            with self.subTest(node.scheme):
                built = plan(node)
                self.assertFalse([r for r in built.singbox_config["dns"]["rules"] if r.get("domain") == [node.server]])

    def test_amnezia_server_enters_through_a_loopback_relay_in_both_modes(self) -> None:
        # The AWG helper binds its socket to the physical interface, so it talks to a loopback UDP inbound of sing-box
        # that carries the datagrams to the real server through the hop (owner request 2026-11-26).
        document = parse_singbox_document(TEMPLATE_PATH, TEMPLATE_PATH.read_text(encoding="utf-8"))
        node = nodes_of("awg")[0]
        for label, built in (
            ("tun", plan(node)),
            ("proxy", plan_singbox_proxy_runtime(document, node, warp_entry_profile=PROFILE)),
        ):
            with self.subTest(label):
                relay = next(i for i in built.singbox_config["inbounds"] if str(i.get("tag", "")).startswith("__app_warp_udp_amnezia"))
                self.assertEqual("udp", relay["network"])
                self.assertEqual("127.0.0.1", relay["listen"])
                rule = next(r for r in rules(built) if r.get("inbound") == [relay["tag"]])
                self.assertEqual(WARP_ENTRY_TAG, rule["outbound"])
                config = built.amnezia_sidecar.config
                peer = config["endpoint"]["peers"][0]
                self.assertEqual(("127.0.0.1", relay["listen_port"]), (peer["address"], peer["port"]))
                self.assertTrue(config["unbound"], "the helper must not bind to the physical interface")
                self.assertEqual("udp", relay["network"])
                self.assertTrue(relay["override_address"] and relay["override_port"])
                self.assertLessEqual(config["endpoint"]["mtu"], WARP_ENTRY_MTU - 80)
                self.assertFalse([a for a in config["endpoint"]["address"] if ":" in a], "IPv4 tunnel through the hop")
                self.assertEqual([], violations(built.singbox_config, sidecar_process_paths=[], sidecar_inbounds=[relay["tag"]]))
                again = apply_warp_entry(built, PROFILE, tun=label == "tun")
                self.assertEqual(1, sum(1 for i in again.singbox_config["inbounds"] if i.get("tag") == relay["tag"]), "a second pass keeps one relay")

    def test_hysteria_server_enters_through_a_loopback_relay_in_the_proxy_mode(self) -> None:
        document = parse_singbox_document(TEMPLATE_PATH, TEMPLATE_PATH.read_text(encoding="utf-8"))
        for node in nodes_of("hysteria2"):
            with self.subTest("hysteria2"):
                built = plan_singbox_proxy_runtime(document, node, warp_entry_profile=PROFILE)
                relay = next(i for i in built.singbox_config["inbounds"] if str(i.get("tag", "")).startswith("__app_warp_udp_hysteria"))
                server = built.hysteria_sidecar.config["server"]
                self.assertIn(f"127.0.0.1:{relay['listen_port']}", server)
                self.assertTrue(built.hysteria_sidecar.config["tls"]["sni"], "the real name stays in the TLS SNI")
                self.assertTrue(relay["override_address"] and relay["override_port"])
                rule = next(r for r in rules(built) if r.get("inbound") == [relay["tag"]])
                self.assertEqual(WARP_ENTRY_TAG, rule["outbound"])
                self.assertEqual([], violations(built.singbox_config, sidecar_process_paths=[], sidecar_inbounds=[relay["tag"]]))


@requires_real_subscription
class ExtraEdgesFromTheServiceTests(unittest.TestCase):
    """The edges the service sent (owner 2026-11-27) reach the hop endpoint of the real plan of every real server."""

    def test_the_edges_file_next_to_the_account_goes_into_the_hop_endpoint(self) -> None:
        import json
        import tempfile
        from pathlib import Path

        edges = [
            {"transport": "masque-http2", "address": "162.159.198.7", "sni": "www.cloudflare.com"},
            {"transport": "wireguard", "address": "188.114.97.5", "port": 2408},
        ]
        with tempfile.TemporaryDirectory() as directory:
            profile = str(Path(directory) / "warp-entry-profile.json")
            for node in (*nodes_of("vless"), *nodes_of("hysteria2")):
                with self.subTest(node.scheme):
                    self.assertNotIn("extra_edges", hop(plan(node, profile=profile)), "no file, no option")
            Path(profile + ".edges").write_text(json.dumps({"v": 1, "edges": edges}), encoding="utf-8")
            for node in (*nodes_of("vless"), *nodes_of("hysteria2")):
                with self.subTest(node.scheme):
                    self.assertEqual(edges, hop(plan(node, profile=profile))["extra_edges"])


if __name__ == "__main__":
    unittest.main()
