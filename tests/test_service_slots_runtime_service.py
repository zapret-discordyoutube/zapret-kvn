"""Service-slot helpers next to sing-box: a slot never fails the main connection (docs/SERVICE_SLOTS.md)."""

from __future__ import annotations

from pathlib import Path
import unittest
from unittest.mock import patch

from PyQt6.QtCore import QCoreApplication

from tests.step_fakes import drive
from xray_fluent.application import slot_runtime_service as service_module
from xray_fluent.application.protocol_core import ProtocolCore
from xray_fluent.application.slot_runtime_service import SLOT_DESYNC_NOTE, SlotRuntimeService, helper_config
from xray_fluent.masking import presets
from xray_fluent.masking.model import OFF, Masking, MaskingSettings, MuxCool, XrayFragment, XrayShaping
from xray_fluent.profiles.models import Node
from xray_fluent.slots.runtime_plan import SlotHelper, SlotRuntimePlan

APP = QCoreApplication.instance() or QCoreApplication([])

HY2 = Node(id="hy", name="hy", scheme="hysteria2", link="hy2://secret@hy.example:443?sni=hy.example",
           outbound={"protocol": "hysteria2", "server": "hy.example", "server_port": 443})
VLESS = Node(id="vl", name="vl", scheme="vless", outbound={
    "protocol": "vless",
    "settings": {"vnext": [{"address": "vl.example", "port": 443, "users": [{"id": "00000000-0000-0000-0000-000000000000", "encryption": "none"}]}]},
    "streamSettings": {"network": "tcp", "security": "tls"},
})


class FakeManager:
    instances: list["FakeManager"] = []
    result = True

    def __init__(self, parent=None, **kwargs):
        self.kwargs = kwargs
        self.started_with = None
        self.stopped = False
        self.is_running = False
        FakeManager.instances.append(self)

    def start_steps(self, *args, **kwargs):
        self.started_with = (args, kwargs)
        self.is_running = FakeManager.result
        return FakeManager.result
        yield  # pragma: no cover

    def stop_steps(self, *args, **kwargs):
        self.stopped = True
        self.is_running = False
        return True
        yield  # pragma: no cover

    def deleteLater(self):
        pass


class SlotRuntimeServiceTests(unittest.TestCase):
    def setUp(self):
        FakeManager.instances = []
        FakeManager.result = True
        self.selected: list[tuple[str, str]] = []
        self.failed: list[tuple[str, str]] = []
        self.logs: list[str] = []
        self.service = SlotRuntimeService(
            None,
            log=self.logs.append,
            hysteria_source=lambda: Path("C:/app/core/hysteria.exe"),
            xray_source=lambda: Path("C:/app/core/xray.exe"),
            on_helper_failed=lambda slot, node: self.failed.append((slot, node)),
        )
        patches = [
            patch.object(service_module, "HysteriaManager", FakeManager),
            patch.object(service_module, "XrayManager", FakeManager),
            patch.object(service_module, "prepare_speed_test_xray", lambda source, target: target),
            patch.object(service_module, "select_outbound",
                         lambda port, selector, member: (self.selected.append((selector, member)) or True, "")),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def run_start(self, plans):
        self.service._generation += 1
        return drive(self.service._start_steps(plans, 19090, self.service._generation))

    def test_helper_started_from_its_own_copy_and_selector_pinned(self):
        helper = SlotHelper(ProtocolCore.HYSTERIA, HY2, 11821, "u", "p")
        plans = [SlotRuntimePlan("youtube", "zapret-slot-relay-youtube", helper, server_id="hy"),
                 SlotRuntimePlan("ai", "__app_nodes/node_x", server_id="x")]
        self.assertTrue(self.run_start(plans))
        [manager] = FakeManager.instances
        self.assertTrue(str(manager.kwargs["exe_path"]).endswith("hysteria-slot-youtube.exe"))
        self.assertTrue(str(manager.kwargs["config_file"]).endswith("hysteria-slot-youtube.json"))
        self.assertEqual(11821, manager.started_with[0][1])
        self.assertEqual([("zapret-slot-youtube", "zapret-slot-relay-youtube"), ("zapret-slot-ai", "__app_nodes/node_x")],
                         self.selected)
        self.assertEqual(["youtube"], self.service.running_slots)

    def test_a_helper_that_does_not_start_leaves_its_slot_on_the_main_server(self):
        FakeManager.result = False
        helper = SlotHelper(ProtocolCore.XRAY, VLESS, 11822, "u", "p")
        self.run_start([SlotRuntimePlan("telegram", "zapret-slot-relay-telegram", helper, server_id="vl")])
        self.assertEqual([("zapret-slot-telegram", "proxy")], self.selected)
        self.assertEqual([("telegram", "vl")], self.failed)
        self.assertTrue(any("follows the main server" in line for line in self.logs))

    def test_a_new_start_stops_the_old_helpers_first(self):
        helper = SlotHelper(ProtocolCore.HYSTERIA, HY2, 11821, "u", "p")
        self.run_start([SlotRuntimePlan("youtube", "zapret-slot-relay-youtube", helper)])
        first = FakeManager.instances[0]
        self.run_start([SlotRuntimePlan("youtube", "proxy")])
        self.assertTrue(first.stopped)
        self.assertEqual([], self.service.running_slots)

    def test_helper_configs_come_from_the_native_cores(self):
        hysteria = helper_config(SlotHelper(ProtocolCore.HYSTERIA, HY2, 11821, "u", "p"))
        self.assertEqual("127.0.0.1:11821", hysteria["socks5"]["listen"])
        xray = helper_config(SlotHelper(ProtocolCore.XRAY, VLESS, 11822, "u", "p"))
        self.assertEqual(11822, xray["inbounds"][0]["port"])
        self.assertEqual("vless", xray["outbounds"][0]["protocol"])

    def test_a_slot_xray_server_is_masked_like_the_main_one(self):
        settings = MaskingSettings(True, Masking(xray=XrayShaping(mux=MuxCool(), fragment=XrayFragment())))
        helper = SlotHelper(ProtocolCore.XRAY, VLESS, 11822, "u", "p")
        notes: list[str] = []
        server = helper_config(helper, settings, notes)["outbounds"][0]
        self.assertTrue(server["mux"]["enabled"])
        self.assertIn("finalmask", server["streamSettings"])
        self.assertNotIn("mux", VLESS.outbound)  # the stored node is untouched
        plain = helper_config(helper, MaskingSettings(True, settings.global_masking, {VLESS.id: OFF}))
        self.assertNotIn("mux", plain["outbounds"][0])
        self.assertNotIn("mux", helper_config(helper)["outbounds"][0])

    def test_a_slot_xray_never_sees_the_packet_trick_plan(self):
        helper = SlotHelper(ProtocolCore.XRAY, VLESS, 11822, "u", "p")
        notes: list[str] = []
        config = helper_config(helper, MaskingSettings(True, presets.DESYNC_DISORDER.masking), notes)
        self.assertNotIn("__kvn_desync", config["outbounds"][0])
        self.assertIn(SLOT_DESYNC_NOTE, notes)


if __name__ == "__main__":
    unittest.main()
