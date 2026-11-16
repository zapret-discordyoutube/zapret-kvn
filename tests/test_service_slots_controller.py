"""The controller side of service slots: tick/untick, pins, YouTube rescue (docs/SERVICE_SLOTS.md)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from xray_fluent.application import controller as controller_module
from xray_fluent.application.controller import AppController
from xray_fluent.profiles.models import AppSettings, Node

TEMPLATE = Path(__file__).resolve().parents[1] / "data/templates/sing-box/default.json"


class FakeSlots:
    def __init__(self, active=(), servers=None, main="main", hot=lambda node: True):
        self.active_slots = list(active)
        self._servers = dict(servers or {})
        self.main_node_id = main
        self.can_move_hot = hot
        self.moves: list[tuple[str, str | None]] = []

    def server_of(self, slot_id):
        return self._servers.get(slot_id)

    def servers_in_use(self):
        return dict(self._servers)

    def move(self, slot_id, node):
        self.moves.append((slot_id, node.id if node else None))
        return True


def fake_controller(**slots):
    nodes = [Node(id="main", name="Main", is_alive=True), Node(id="a", name="A", is_alive=True, speed_mbps=10),
             Node(id="b", name="B", is_alive=True, speed_mbps=50)]
    fake = SimpleNamespace(
        state=SimpleNamespace(nodes=nodes, settings=AppSettings()),
        slot_runtime=FakeSlots(**slots),
        _slot_failed={},
        connected=True,
        logs=[], statuses=[], saved=0, applied=[], transitions=[],
    )
    fake._log = fake.logs.append
    fake.status = SimpleNamespace(emit=lambda level, text: fake.statuses.append((level, text)))
    fake.save = lambda: setattr(fake, "saved", fake.saved + 1)
    fake.apply_singbox_config_text = lambda text: (fake.applied.append(text) or True, None, "Конфиг сохранён.")
    fake._request_transition = fake.transitions.append
    return fake


class ControllerSlotTests(unittest.TestCase):
    def setUp(self):
        text = TEMPLATE.read_text(encoding="utf-8")
        patcher = patch.object(controller_module, "load_active_config_text_operation", lambda _c, _e: (TEMPLATE, text))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_ticking_writes_the_slots_through_the_normal_config_apply(self):
        fake = fake_controller()
        ok, message = AppController.set_service_slots(fake, {"youtube"})
        self.assertTrue(ok)
        [written] = fake.applied
        self.assertIn("zapret-slot-youtube", {o["tag"] for o in json.loads(written)["outbounds"]})
        self.assertEqual((True, ""), AppController.set_service_slots(fake, set()), "nothing ticked = nothing to write")

    def test_view_reports_ticked_slots_and_where_they_are(self):
        fake = fake_controller(active=["youtube"], servers={"youtube": "b"})
        view = AppController.service_slots_view(fake)
        self.assertTrue(view["available"])
        self.assertEqual(set(), view["enabled"], "the template has no slot ticked")
        self.assertEqual("b", view["live"]["youtube"].id)

    def test_view_lists_only_servers_a_slot_can_use(self):
        fake = fake_controller()
        fake.state.nodes.append(Node(id="awg", name="AWG", scheme="awg", outbound={"protocol": "awg"}))
        ids = [n.id for n in AppController.service_slots_view(fake)["nodes"]]
        self.assertEqual(["main", "a", "b"], ids, "AmneziaWG has no slot helper yet: the card does not offer it")

    def test_pin_moves_a_running_slot_hot_and_auto_picks_the_best_free(self):
        fake = fake_controller(active=["youtube"], servers={"youtube": "a"})
        AppController.set_service_slot_pin(fake, "youtube", "a")
        self.assertEqual({"youtube": "a"}, fake.state.settings.service_slot_pins)
        self.assertEqual([], fake.slot_runtime.moves, "already on a: no helper restart")
        AppController.set_service_slot_pin(fake, "youtube", "")
        self.assertEqual([("youtube", "b")], fake.slot_runtime.moves)
        self.assertEqual(2, fake.saved)

    def test_pin_that_cannot_move_hot_reconnects(self):
        fake = fake_controller(active=["youtube"], servers={"youtube": "a"}, hot=lambda node: node.id != "b")
        AppController.set_service_slot_pin(fake, "youtube", "b")
        self.assertEqual([], fake.slot_runtime.moves)
        self.assertEqual(["service slot pin"], fake.transitions)

    def test_dead_cluster_moves_the_youtube_slot_not_the_main_server(self):
        fake = fake_controller(active=["youtube"], servers={"youtube": "a"})
        self.assertTrue(AppController._youtube_slot_rescue(fake, ["sn-abc"]))
        self.assertEqual([("youtube", "b")], fake.slot_runtime.moves)
        self.assertEqual({"a"}, fake._slot_failed["youtube"])
        self.assertIn("остальные программы не тронуты", fake.statuses[-1][1])
        # Cooldown: the next dead-cluster event right away does not move again.
        self.assertTrue(AppController._youtube_slot_rescue(fake, ["sn-abc"]))
        self.assertEqual(1, len(fake.slot_runtime.moves))

    def test_without_the_youtube_slot_the_main_smart_switch_handles_it(self):
        self.assertFalse(AppController._youtube_slot_rescue(fake_controller(), ["sn-abc"]))

    def test_rescue_respects_the_auto_switch_settings(self):
        fake = fake_controller(active=["youtube"], servers={"youtube": "a"})
        fake.state.settings.auto_switch_enabled = False
        self.assertTrue(AppController._youtube_slot_rescue(fake, ["sn-abc"]))
        self.assertEqual([], fake.slot_runtime.moves)


if __name__ == "__main__":
    unittest.main()
