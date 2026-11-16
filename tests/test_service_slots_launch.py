"""Service slots through the real launch planner (docs/SERVICE_SLOTS.md, "Phase 3 plan")."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from xray_fluent.application.protocol_core import ProtocolCore
from xray_fluent.engines.singbox.runtime_planner import (
    attach_service_slots,
    parse_singbox_document,
    plan_singbox_runtime,
)
from xray_fluent.importer.link_parser import parse_single
from xray_fluent.slots import catalog
from xray_fluent.slots.config_writer import apply_slots

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "data/templates/sing-box/default.json"
LINUX_SINGBOX = ROOT.parent / "android/core-build/output/sing-box"

MAIN = parse_single("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@main.example:8388#main")
OTHER = parse_single("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@other.example:8388#other")
HY2 = parse_single("hy2://secret@hy.example:443/?sni=hy.example#hy")
VLESS = parse_single("vless://11111111-1111-1111-1111-111111111111@vl.example:443?type=tcp&security=tls&sni=vl.example#vl")
NODES = [MAIN, OTHER, HY2, VLESS]


def document(slots):
    text = json.dumps(apply_slots(json.loads(TEMPLATE.read_text(encoding="utf-8")), slots))
    return parse_singbox_document(TEMPLATE, text)


def outbound(config, tag):
    return next(o for o in config["outbounds"] if o.get("tag") == tag)


class SlotLaunchTests(unittest.TestCase):
    def plan(self, assignments, slots=frozenset({catalog.YOUTUBE, catalog.AI, catalog.TELEGRAM})):
        plan = plan_singbox_runtime(document(slots), MAIN, pool_nodes=NODES)
        return attach_service_slots(plan, assignments, main_node_id=MAIN.id)

    def test_each_kind_of_slot_server_on_a_native_main_server(self):
        plan = self.plan({"youtube": HY2, "ai": OTHER, "telegram": VLESS})
        self.assertEqual("native_singbox", plan.outcome)
        slots = {p.slot_id: p for p in plan.slot_plans}
        self.assertEqual(plan.selector_tags[OTHER.id], slots["ai"].member_tag, "a provider member: hot moves")
        self.assertEqual(ProtocolCore.HYSTERIA, slots["youtube"].helper.core)
        self.assertEqual(ProtocolCore.XRAY, slots["telegram"].helper.core)
        config = plan.singbox_config
        self.assertEqual(["__app_nodes"], outbound(config, "zapret-slot-ai")["providers"])
        self.assertEqual("socks", outbound(config, "zapret-slot-relay-youtube")["type"])
        direct = config["route"]["rules"][0]
        self.assertEqual("direct", direct["outbound"])
        self.assertTrue(any(path.endswith("hysteria-slot-youtube.exe") for path in direct["process_path"]))
        self.assertTrue(any(path.endswith("xray-slot-telegram.exe") for path in direct["process_path"]))
        ports = {p.helper.relay_port for p in plan.slot_plans if p.helper}
        self.assertEqual(2, len(ports))
        self.assertNotIn(plan.clash_api_port, ports)

    def test_no_slot_ticked_changes_nothing(self):
        plan = plan_singbox_runtime(document(set()), MAIN, pool_nodes=NODES)
        before = json.dumps(plan.singbox_config, sort_keys=True)
        attach_service_slots(plan, {}, main_node_id=MAIN.id)
        self.assertEqual(before, json.dumps(plan.singbox_config, sort_keys=True))
        self.assertEqual((), plan.slot_plans)

    def test_hysteria_main_server_has_no_provider_so_a_singbox_slot_server_gets_its_own_outbound(self):
        plan = attach_service_slots(plan_singbox_runtime(document({catalog.AI}), HY2, pool_nodes=NODES),
                                    {"ai": OTHER}, main_node_id=HY2.id)
        self.assertEqual("hysteria_sidecar", plan.outcome)
        [ai] = plan.slot_plans
        self.assertEqual("zapret-slot-out-ai", ai.member_tag)
        self.assertEqual("shadowsocks", outbound(plan.singbox_config, "zapret-slot-out-ai")["type"])

    @unittest.skipUnless(LINUX_SINGBOX.is_file(), "Linux sing-box of the pinned core not available")
    def test_launch_config_with_slots_passes_the_pinned_core_check(self):
        plan = self.plan({"youtube": HY2, "ai": OTHER, "telegram": VLESS})
        config = json.loads(json.dumps(plan.singbox_config))
        with tempfile.TemporaryDirectory() as directory:
            provider = Path(directory) / "nodes.json"
            provider.write_text(json.dumps(plan.provider_payload), encoding="utf-8")
            for item in config.get("providers", []):
                item["path"] = str(provider)
            config["route"]["rule_set"] = [
                {"type": "inline", "tag": rule_set["tag"], "rules": [{"domain_suffix": ["placeholder.invalid"]}]}
                for rule_set in config["route"]["rule_set"]
            ]
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            done = subprocess.run([str(LINUX_SINGBOX), "check", "-c", str(path)], capture_output=True, text=True, timeout=60)
            self.assertEqual(0, done.returncode, done.stderr[-2000:])


if __name__ == "__main__":
    unittest.main()
