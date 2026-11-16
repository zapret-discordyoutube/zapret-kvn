"""YouTube slot rescue on Windows: a dead cluster moves the slot, not the main server (docs/SERVICE_SLOTS.md)."""

from __future__ import annotations

from pathlib import Path
import unittest
from unittest.mock import patch

from PyQt6.QtCore import QCoreApplication

from tests.step_fakes import drive
from tests.test_service_slots_runtime_service import FakeManager, HY2, VLESS
from xray_fluent.application import slot_runtime_service as service_module
from xray_fluent.application.slot_runtime_service import SlotRuntimeService
from xray_fluent.profiles.models import Node
from xray_fluent.slots.rescue import COOLDOWN_SEC, youtube_rescue
from xray_fluent.slots.runtime_plan import SlotRelay, SlotRuntimePlan

APP = QCoreApplication.instance() or QCoreApplication([])


def node(node_id, protocol="hysteria2", speed=None):
    return Node(id=node_id, name=node_id, scheme=protocol, outbound={"protocol": protocol}, is_alive=True, speed_mbps=speed)


class YoutubeRescueTests(unittest.TestCase):
    def decide(self, **overrides):
        args = dict(
            current_id="a",
            nodes=[node("main"), node("a"), node("b", speed=10), node("c", speed=50), node("tro", protocol="shadowsocks", speed=99)],
            main_node_id="main",
            other_slots={"ai": "c"},
            failed={},
            reachable=lambda n: n.scheme != "shadowsocks",
            now=1000.0,
            last_move_at=None,
        )
        args.update(overrides)
        return youtube_rescue(**args)

    def test_moves_to_the_best_free_reachable_server_never_the_dead_one(self):
        decision = self.decide()
        self.assertTrue(decision.move)
        # c is taken by the AI slot, shadowsocks is not reachable hot, a is where the video died.
        self.assertEqual("b", decision.node.id)

    def test_cooldown_holds_the_slot(self):
        held = self.decide(last_move_at=1000.0 - COOLDOWN_SEC + 1)
        self.assertFalse(held.move)
        self.assertIn("недавно", held.reason)
        self.assertTrue(self.decide(last_move_at=1000.0 - COOLDOWN_SEC).move)

    def test_servers_that_failed_for_the_slot_are_skipped(self):
        decision = self.decide(failed={"youtube": {"b"}})
        self.assertFalse(decision.move and decision.node is not None and decision.node.id == "b")

    def test_no_free_server_falls_back_to_the_main_server_once(self):
        decision = self.decide(nodes=[node("main"), node("a")])
        self.assertEqual((True, None), (decision.move, decision.node))
        already_main = self.decide(nodes=[node("main")], current_id=None)
        self.assertFalse(already_main.move)


class SlotHotMoveTests(unittest.TestCase):
    def setUp(self):
        FakeManager.instances = []
        FakeManager.result = True
        self.selected = []
        self.service = SlotRuntimeService(None, log=lambda line: None, hysteria_source=lambda: Path("h.exe"),
                                          xray_source=lambda: Path("x.exe"))
        for item in (
            patch.object(service_module, "HysteriaManager", FakeManager),
            patch.object(service_module, "XrayManager", FakeManager),
            patch.object(service_module, "prepare_speed_test_xray", lambda source, target: target),
            patch.object(service_module, "select_outbound", lambda port, sel, member: (self.selected.append((sel, member)) or True, "")),
        ):
            item.start()
            self.addCleanup(item.stop)
        relay = SlotRelay("zapret-slot-relay-youtube", 11821, "u", "p")
        self.service._plans = {"youtube": SlotRuntimePlan("youtube", "proxy", relay=relay)}
        self.service._provider_tags = {"tro": "__app_nodes/node_t"}
        self.service._main_node_id = "main"
        self.service._clash_api_port = 19090

    def move(self, target):
        self.service._generation += 1
        return drive(self.service._move_steps("youtube", target, self.service._generation))

    def test_move_to_a_hysteria_server_starts_its_helper_behind_the_same_relay(self):
        self.assertTrue(self.move(HY2))
        self.assertEqual(11821, FakeManager.instances[0].started_with[0][1])
        self.assertEqual([("zapret-slot-youtube", "zapret-slot-relay-youtube")], self.selected)
        self.assertEqual("hy", self.service.server_of("youtube"))

    def test_move_between_helper_servers_stops_the_old_helper(self):
        self.move(HY2)
        self.move(VLESS)
        self.assertTrue(FakeManager.instances[0].stopped)
        self.assertEqual("vl", self.service.server_of("youtube"))

    def test_move_to_a_provider_server_or_back_to_main(self):
        shadowsocks = node("tro", protocol="shadowsocks")
        self.assertTrue(self.service.can_move_hot(shadowsocks))
        self.assertFalse(self.service.can_move_hot(node("other", protocol="shadowsocks")))
        self.move(shadowsocks)
        self.assertEqual(("zapret-slot-youtube", "__app_nodes/node_t"), self.selected[-1])
        self.move(None)
        self.assertEqual(("zapret-slot-youtube", "proxy"), self.selected[-1])
        self.assertIsNone(self.service.server_of("youtube"))


if __name__ == "__main__":
    unittest.main()
