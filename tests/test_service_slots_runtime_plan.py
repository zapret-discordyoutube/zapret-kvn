"""How a ticked slot reaches its server at launch (docs/SERVICE_SLOTS.md, "Phase 3 plan")."""

from __future__ import annotations

import json
from pathlib import Path
import unittest

from xray_fluent.application.protocol_core import ProtocolCore
from xray_fluent.profiles.models import Node
from xray_fluent.slots import catalog
from xray_fluent.slots.config_writer import apply_slots
from xray_fluent.slots.runtime_plan import ensure_helper_direct_routes, plan_slots, slot_selector_ids, xray_helper_config

ROOT = Path(__file__).resolve().parents[1]
PROVIDER = "__app_nodes"

MAIN = Node(id="main", scheme="trojan", outbound={"protocol": "trojan"})
TROJAN = Node(id="tro", scheme="trojan", outbound={"protocol": "trojan"})
HY2 = Node(id="hy", scheme="hysteria2", link="hy2://x@h:443", outbound={"protocol": "hysteria2"})
VLESS = Node(id="vl", scheme="vless", outbound={"protocol": "vless", "settings": {}})
AWG = Node(id="awg", scheme="awg", outbound={"protocol": "awg"})


def runtime(slots=frozenset({catalog.YOUTUBE, catalog.AI, catalog.TELEGRAM})) -> dict:
    return apply_slots(json.loads((ROOT / "data/templates/sing-box/default.json").read_text(encoding="utf-8")), slots)


class Ports:
    def __init__(self):
        self.next = 40000

    def __call__(self) -> int:
        self.next += 1
        return self.next


def plan(config, assignments, provider_tags=None):
    return plan_slots(
        config,
        assignments,
        main_node_id=MAIN.id,
        provider_tags=provider_tags or {},
        provider_tag=PROVIDER,
        allocate_port=Ports(),
        credentials=lambda prefix: (f"{prefix}-user", f"{prefix}-pass"),
        build_native_outbound=lambda node, tag: {"type": "trojan", "tag": tag, "server": node.id},
    )


def outbound(config, tag):
    return next(o for o in config["outbounds"] if o.get("tag") == tag)


class SlotRuntimePlanTests(unittest.TestCase):
    def test_slot_ids_in_routing_order(self):
        self.assertEqual(["ai", "youtube", "telegram"], slot_selector_ids(runtime()))

    def test_no_server_or_the_main_server_follows_proxy(self):
        config = runtime({catalog.YOUTUBE})
        [only] = plan(config, {"youtube": MAIN})
        self.assertEqual("proxy", only.member_tag)
        self.assertIsNone(only.helper)
        # The relay is always a member: a later move to a Hysteria2 or VLESS server is hot.
        self.assertEqual({"type": "selector", "tag": "zapret-slot-youtube", "outbounds": ["proxy", "zapret-slot-relay-youtube"],
                          "default": "proxy", "interrupt_exist_connections": True}, outbound(config, "zapret-slot-youtube"))
        self.assertEqual("zapret-slot-relay-youtube", only.relay.tag)
        [none] = plan(runtime({catalog.YOUTUBE}), {})
        self.assertEqual("proxy", none.member_tag)

    def test_singbox_server_in_the_provider_is_a_provider_member(self):
        config = runtime({catalog.YOUTUBE})
        [only] = plan(config, {"youtube": TROJAN}, provider_tags={"tro": "__app_nodes/node_t", "main": "__app_nodes/node_m"})
        self.assertEqual("__app_nodes/node_t", only.member_tag)
        selector = outbound(config, "zapret-slot-youtube")
        self.assertEqual(["__app_nodes"], selector["providers"])
        self.assertEqual(["proxy", "zapret-slot-relay-youtube"], selector["outbounds"])
        self.assertEqual("proxy", selector["default"], "a provider member is pinned through the Clash API")

    def test_singbox_server_without_provider_gets_its_native_outbound(self):
        config = runtime({catalog.YOUTUBE})
        [only] = plan(config, {"youtube": TROJAN})
        self.assertEqual("zapret-slot-out-youtube", only.member_tag)
        self.assertEqual({"type": "trojan", "tag": "zapret-slot-out-youtube", "server": "tro"},
                         outbound(config, "zapret-slot-out-youtube"))
        selector = outbound(config, "zapret-slot-youtube")
        self.assertEqual(["proxy", "zapret-slot-relay-youtube", "zapret-slot-out-youtube"], selector["outbounds"])
        self.assertEqual("zapret-slot-out-youtube", selector["default"])
        self.assertNotIn("providers", selector)

    def test_hysteria_and_vless_get_a_relay_and_their_own_helper(self):
        config = runtime({catalog.YOUTUBE, catalog.TELEGRAM})
        plans = {p.slot_id: p for p in plan(config, {"youtube": HY2, "telegram": VLESS})}
        self.assertEqual(ProtocolCore.HYSTERIA, plans["youtube"].helper.core)
        self.assertEqual(ProtocolCore.XRAY, plans["telegram"].helper.core)
        relay = outbound(config, "zapret-slot-relay-youtube")
        self.assertEqual(("socks", "127.0.0.1", plans["youtube"].helper.relay_port, "slot-youtube-user"),
                         (relay["type"], relay["server"], relay["server_port"], relay["username"]))
        self.assertNotEqual(plans["youtube"].helper.relay_port, plans["telegram"].helper.relay_port)
        self.assertEqual("zapret-slot-relay-youtube", outbound(config, "zapret-slot-youtube")["default"])

    def test_awg_is_not_supported_yet_and_says_so(self):
        [only] = plan(runtime({catalog.AI}), {"ai": AWG})
        self.assertEqual("proxy", only.member_tag)
        self.assertIn("AWG", only.note)

    def test_replanning_replaces_and_does_not_duplicate(self):
        config = runtime({catalog.YOUTUBE})
        plan(config, {"youtube": HY2})
        plan(config, {"youtube": HY2})
        self.assertEqual(1, sum(o.get("tag") == "zapret-slot-relay-youtube" for o in config["outbounds"]))

    def test_xray_helper_config_routes_the_relay_to_the_one_server(self):
        config = runtime({catalog.TELEGRAM})
        [only] = plan(config, {"telegram": VLESS})
        xray = xray_helper_config(only.helper, {"protocol": "vless", "tag": "node_x", "settings": {}})
        self.assertEqual(only.helper.relay_port, xray["inbounds"][0]["port"])
        self.assertEqual("127.0.0.1", xray["inbounds"][0]["listen"])
        self.assertEqual("proxy", xray["outbounds"][0]["tag"])
        self.assertEqual([{"type": "field", "inboundTag": ["slot-relay-in"], "outboundTag": "proxy"}], xray["routing"]["rules"])

    def test_helper_executables_leave_the_tunnel_directly_once(self):
        config = runtime({catalog.YOUTUBE, catalog.TELEGRAM, catalog.AI})
        plans = plan(config, {"youtube": HY2, "telegram": VLESS, "ai": TROJAN})
        paths = lambda core, slot: f"C:/app/slots/{core.value}-slot-{slot}.exe"  # noqa: E731
        ensure_helper_direct_routes(config, plans, paths)
        ensure_helper_direct_routes(config, plans, paths)
        self.assertEqual({"process_path": ["C:/app/slots/hysteria-slot-youtube.exe", "C:/app/slots/xray-slot-telegram.exe"],
                          "action": "route", "outbound": "direct"}, config["route"]["rules"][0])
        self.assertEqual(1, sum("process_path" in r for r in config["route"]["rules"]))

    def test_no_helper_no_rule(self):
        config = runtime({catalog.YOUTUBE})
        before = json.dumps(config["route"])
        ensure_helper_direct_routes(config, plan(config, {"youtube": MAIN}), lambda core, slot: "h.exe")
        self.assertEqual(before, json.dumps(config["route"]))


if __name__ == "__main__":
    unittest.main()
