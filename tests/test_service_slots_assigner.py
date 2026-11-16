"""Which server each ticked slot uses (docs/SERVICE_SLOTS.md, "Phase 3 plan")."""

from __future__ import annotations

import unittest

from xray_fluent.profiles.models import Node
from xray_fluent.slots.assigner import assign_slots


def node(node_id, *, alive=True, speed=None, ping=None, protocol="trojan"):
    return Node(id=node_id, scheme=protocol, outbound={"protocol": protocol}, is_alive=alive, speed_mbps=speed, ping_ms=ping)


class SlotAssignerTests(unittest.TestCase):
    def test_separate_servers_best_first_never_the_main_one(self):
        pool = [node("main", speed=90), node("slow", speed=5), node("fast", speed=50), node("mid", speed=20)]
        result = assign_slots(["ai", "youtube", "telegram"], pool, main_node_id="main", pins={})
        self.assertEqual(["fast", "mid", "slow"], [a.node.id for a in result])

    def test_a_pin_wins_and_is_not_given_to_another_slot(self):
        pool = [node("main"), node("a", speed=50), node("b", speed=10)]
        result = assign_slots(["ai", "youtube"], pool, main_node_id="main", pins={"youtube": "a"})
        self.assertEqual(("b", False), (result[0].node.id, result[0].pinned))
        self.assertEqual(("a", True), (result[1].node.id, result[1].pinned))

    def test_pin_may_be_the_main_server(self):
        [only] = assign_slots(["youtube"], [node("main"), node("a")], main_node_id="main", pins={"youtube": "main"})
        self.assertEqual(("main", True), (only.node.id, only.pinned))

    def test_failed_pin_falls_back_and_says_why(self):
        pool = [node("main"), node("a"), node("b")]
        [only] = assign_slots(["youtube"], pool, main_node_id="main", pins={"youtube": "a"}, failed={"youtube": {"a"}})
        self.assertEqual("b", only.node.id)
        self.assertIn("не отвечал", only.reason)
        [gone] = assign_slots(["youtube"], pool, main_node_id="main", pins={"youtube": "zzz"})
        self.assertIn("нет в списке", gone.reason)

    def test_dead_and_awg_servers_are_skipped_and_a_small_pool_follows_the_main_server(self):
        pool = [node("main"), node("dead", alive=False, speed=99), node("awg", protocol="awg", speed=99)]
        [only] = assign_slots(["youtube"], pool, main_node_id="main", pins={})
        self.assertIsNone(only.node)
        self.assertTrue(only.reason)

    def test_unmeasured_ranks_after_alive_and_ping_breaks_ties(self):
        pool = [node("main"), node("unknown", alive=None, speed=80), node("near", ping=30), node("far", ping=200)]
        [first, second, third] = assign_slots(["ai", "youtube", "telegram"], pool, main_node_id="main", pins={})
        self.assertEqual(["near", "far", "unknown"], [first.node.id, second.node.id, third.node.id])


if __name__ == "__main__":
    unittest.main()
