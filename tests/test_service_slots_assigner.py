"""Which server each ticked slot uses (docs/SERVICE_SLOTS.md, "Phase 3 plan")."""

from __future__ import annotations

import unittest

from xray_fluent.profiles.models import Node
from xray_fluent.slots.assigner import assign_slots, off_machines, slot_capable


def node(node_id, *, alive=True, speed=None, ping=None, protocol="trojan", server=""):
    return Node(id=node_id, scheme=protocol, outbound={"protocol": protocol}, is_alive=alive, speed_mbps=speed,
                ping_ms=ping, server=server)


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

    def test_a_pin_on_a_server_that_failed_its_check_falls_back_and_says_why(self):
        # Owner 2026-11-17: the program picks the best server when the user's pinned one is bad.
        pool = [node("main"), node("pinned", alive=False), node("good", speed=10)]
        [only] = assign_slots(["youtube"], pool, main_node_id="main", pins={"youtube": "pinned"})
        self.assertEqual(("good", False), (only.node.id, only.pinned))
        self.assertIn("не отвечал", only.reason)
        pool[1].is_alive = None  # not checked yet: the pin is trusted
        [back] = assign_slots(["youtube"], pool, main_node_id="main", pins={"youtube": "pinned"})
        self.assertEqual(("pinned", True), (back.node.id, back.pinned))

    def test_dead_and_awg_servers_are_skipped_and_a_small_pool_follows_the_main_server(self):
        pool = [node("main"), node("dead", alive=False, speed=99), node("awg", protocol="awg", speed=99)]
        [only] = assign_slots(["youtube"], pool, main_node_id="main", pins={})
        self.assertIsNone(only.node)
        self.assertTrue(only.reason)

    def test_an_awg_pin_falls_back_and_says_awg_is_not_supported(self):
        pool = [node("main"), node("awg", protocol="awg", speed=99), node("a")]
        [only] = assign_slots(["youtube"], pool, main_node_id="main", pins={"youtube": "awg"})
        self.assertEqual(("a", False), (only.node.id, only.pinned))
        self.assertIn("AmneziaWG", only.reason, "the server is in the list: do not say it is missing")
        self.assertFalse(slot_capable(pool[1]))
        self.assertTrue(slot_capable(pool[2]))

    def test_unmeasured_ranks_after_alive_and_ping_breaks_ties(self):
        pool = [node("main"), node("unknown", alive=None, speed=80), node("near", ping=30), node("far", ping=200)]
        [first, second, third] = assign_slots(["ai", "youtube", "telegram"], pool, main_node_id="main", pins={})
        self.assertEqual(["near", "far", "unknown"], [first.node.id, second.node.id, third.node.id])



class SlotMachineTests(unittest.TestCase):
    """One provider machine often comes as several entries (2026-11-16 e2e: five entries, one address)."""

    def test_sibling_entries_of_the_main_machine_are_not_a_slot_server(self):
        pool = [node("main", server="fi.example"), node("fi-2", speed=99, server="FI.example"),
                node("nl", speed=5, server="nl.example")]
        [only] = assign_slots(["youtube"], pool, main_node_id="main", pins={})
        self.assertEqual("nl", only.node.id)

    def test_two_slots_never_share_a_machine_and_a_crowded_pool_follows_the_main_server(self):
        pool = [node("main", server="m.example"), node("fi-1", speed=50, server="fi.example"),
                node("fi-2", speed=40, server="fi.example")]
        ai, youtube = assign_slots(["ai", "youtube"], pool, main_node_id="main", pins={})
        self.assertEqual("fi-1", ai.node.id)
        self.assertIsNone(youtube.node)

    def test_resolved_addresses_join_different_host_names(self):
        addresses = {"a.example": "203.0.113.7", "b.example": "203.0.113.7", "c.example": "198.51.100.1"}
        keys = lambda n: frozenset({n.server, addresses[n.server]})  # noqa: E731
        pool = [node("main", server="a.example"), node("b", speed=99, server="b.example"),
                node("c", speed=1, server="c.example")]
        [only] = assign_slots(["youtube"], pool, main_node_id="main", pins={}, host_keys=keys)
        self.assertEqual("c", only.node.id)

    def test_a_pin_on_a_sibling_entry_is_honoured(self):
        pool = [node("main", server="fi.example"), node("fi-2", server="fi.example"), node("nl", server="nl.example")]
        [only] = assign_slots(["youtube"], pool, main_node_id="main", pins={"youtube": "fi-2"})
        self.assertEqual(("fi-2", True), (only.node.id, only.pinned))

    def test_entries_without_a_server_are_separate_machines(self):
        pool = [node("main"), node("a", speed=2), node("b", speed=1)]
        self.assertEqual(["a", "b"], [a.node.id for a in assign_slots(["ai", "youtube"], pool, main_node_id="main", pins={})])

    def test_off_machines_drops_siblings_but_keeps_the_named_entries(self):
        nodes = [node("x", server="fi.example"), node("x2", server="fi.example"), node("y", server="nl.example")]
        self.assertEqual(["x", "y"], [n.id for n in off_machines(nodes, nodes, ["x"])])


if __name__ == "__main__":
    unittest.main()
