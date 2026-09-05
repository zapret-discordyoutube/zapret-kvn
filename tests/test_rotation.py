from __future__ import annotations

import random
import unittest

from xray_fluent.application.outbound_pool_service import build_xray_outbound_pool
from xray_fluent.application.rotation_service import (
    MAX_POOL_NODES,
    MIN_INTERVAL_SEC,
    build_rotation_plan,
    pick_next_node,
    rotation_interval_ms,
)
from xray_fluent.engines.xray.balancer_api import build_balancer_override_command
from xray_fluent.engines.xray.config_builder import build_xray_config
from xray_fluent.profiles.models import AppSettings, Node, RoutingSettings


def make_node(index: int, **kwargs) -> Node:
    node = Node(
        name=f"node-{index}",
        scheme="vless",
        server=f"10.0.0.{index}",
        port=443,
        link=f"vless://node-{index}",
        outbound={
            "protocol": "vless",
            "settings": {"vnext": [{"address": f"10.0.0.{index}", "port": 443}]},
        },
        sort_order=index,
    )
    for key, value in kwargs.items():
        setattr(node, key, value)
    return node


def rotation_settings(**kwargs) -> AppSettings:
    settings = AppSettings()
    settings.rotation_enabled = True
    for key, value in kwargs.items():
        setattr(settings, key, value)
    return settings


class RotationPlanTests(unittest.TestCase):
    def test_disabled_rotation_has_no_plan(self) -> None:
        nodes = [make_node(i) for i in range(3)]
        self.assertIsNone(build_rotation_plan(AppSettings(), nodes))

    def test_pool_needs_at_least_two_nodes(self) -> None:
        self.assertIsNone(build_rotation_plan(rotation_settings(), [make_node(1)]))
        self.assertIsNotNone(build_rotation_plan(rotation_settings(), [make_node(1), make_node(2)]))

    def test_plan_is_independent_of_active_node(self) -> None:
        nodes = [make_node(1), make_node(2), make_node(3)]
        settings = rotation_settings()
        plans = [build_rotation_plan(settings, nodes, node.id) for node in nodes]
        ids = [[item.id for item in plan.nodes] for plan in plans]  # type: ignore[union-attr]
        self.assertEqual(ids[0], ids[1])
        self.assertEqual(ids[1], ids[2])

    def test_pool_order_follows_sort_order(self) -> None:
        nodes = [make_node(3), make_node(1), make_node(2)]
        plan = build_rotation_plan(rotation_settings(), nodes, nodes[0].id)
        assert plan is not None
        self.assertEqual([node.sort_order for node in plan.nodes], [1, 2, 3])

    def test_active_node_survives_truncation(self) -> None:
        nodes = [make_node(i) for i in range(1, 11)]
        outsider = nodes[-1]
        plan = build_rotation_plan(rotation_settings(rotation_max_nodes=3), nodes, outsider.id)
        assert plan is not None
        self.assertEqual(len(plan.nodes), 3)
        self.assertTrue(plan.contains(outsider.id))

    def test_only_nodes_present_in_the_core_are_offered(self) -> None:
        # Ядро держит раскладку, полученную при старте. Нода, которой в нём нет,
        # переключением не активируется, поэтому в ротацию попадать не должна.
        nodes = [make_node(1), make_node(2), make_node(3)]
        available = {nodes[0].id, nodes[1].id}
        plan = build_rotation_plan(
            rotation_settings(), nodes, nodes[0].id, available_ids=available
        )
        assert plan is not None
        self.assertEqual({node.id for node in plan.nodes}, available)

    def test_empty_core_pool_disables_rotation(self) -> None:
        nodes = [make_node(1), make_node(2), make_node(3)]
        self.assertIsNone(
            build_rotation_plan(rotation_settings(), nodes, nodes[0].id, available_ids=set())
        )

    def test_group_pool_filter(self) -> None:
        nodes = [make_node(1, group="A"), make_node(2, group="B"), make_node(3, group="A")]
        plan = build_rotation_plan(
            rotation_settings(rotation_pool="group", rotation_pool_value="A"), nodes
        )
        assert plan is not None
        self.assertEqual({node.group for node in plan.nodes}, {"A"})
        self.assertEqual(len(plan.nodes), 2)

    def test_tag_pool_filter(self) -> None:
        nodes = [make_node(1, tags=["fast"]), make_node(2, tags=["slow"]), make_node(3, tags=["fast"])]
        plan = build_rotation_plan(
            rotation_settings(rotation_pool="tag", rotation_pool_value="fast"), nodes
        )
        assert plan is not None
        self.assertEqual(len(plan.nodes), 2)

    def test_subscription_pool_filter(self) -> None:
        nodes = [make_node(i, subscription_id="sub-1" if i < 3 else "sub-2") for i in range(1, 5)]
        plan = build_rotation_plan(
            rotation_settings(rotation_pool="subscription", rotation_pool_value="sub-1"), nodes
        )
        assert plan is not None
        self.assertEqual({node.subscription_id for node in plan.nodes}, {"sub-1"})

    def test_dead_nodes_excluded_when_requested(self) -> None:
        nodes = [make_node(1, is_alive=True), make_node(2, is_alive=False), make_node(3, is_alive=None)]
        plan = build_rotation_plan(rotation_settings(rotation_only_alive=True), nodes)
        assert plan is not None
        self.assertEqual(len(plan.nodes), 2)
        self.assertFalse(plan.contains(nodes[1].id))

        relaxed = build_rotation_plan(rotation_settings(rotation_only_alive=False), nodes)
        assert relaxed is not None
        self.assertEqual(len(relaxed.nodes), 3)

    def test_pool_is_truncated_and_reports_it(self) -> None:
        nodes = [make_node(i) for i in range(1, 12)]
        plan = build_rotation_plan(rotation_settings(rotation_max_nodes=5), nodes)
        assert plan is not None
        self.assertEqual(len(plan.nodes), 5)
        self.assertEqual(plan.candidates, 11)
        self.assertTrue(plan.truncated)

    def test_pool_size_is_capped(self) -> None:
        nodes = [make_node(i) for i in range(1, MAX_POOL_NODES + 20)]
        plan = build_rotation_plan(rotation_settings(rotation_max_nodes=10_000), nodes)
        assert plan is not None
        self.assertEqual(len(plan.nodes), MAX_POOL_NODES)
        self.assertTrue(plan.truncated)

    def test_pool_membership_tracks_the_node_list(self) -> None:
        nodes = [make_node(1), make_node(2), make_node(3)]
        settings = rotation_settings()
        full = build_rotation_plan(settings, nodes, nodes[0].id)
        shrunk = build_rotation_plan(settings, nodes[:2], nodes[0].id)
        assert full is not None and shrunk is not None
        self.assertNotEqual(full.node_ids(), shrunk.node_ids())


class PickNextNodeTests(unittest.TestCase):
    def test_sequential_walks_the_whole_pool(self) -> None:
        nodes = [make_node(i) for i in range(1, 4)]
        plan = build_rotation_plan(rotation_settings(), nodes, nodes[0].id)
        assert plan is not None
        visited = []
        current = plan.nodes[0].id
        for _ in range(len(plan.nodes)):
            nxt = pick_next_node(plan, current, "sequential")
            assert nxt is not None
            visited.append(nxt.id)
            current = nxt.id
        self.assertEqual(len(set(visited)), len(plan.nodes))
        self.assertEqual(current, plan.nodes[0].id)

    def test_random_never_repeats_current(self) -> None:
        nodes = [make_node(i) for i in range(1, 5)]
        plan = build_rotation_plan(rotation_settings(), nodes)
        assert plan is not None
        rng = random.Random(1234)
        current = plan.nodes[0].id
        for _ in range(50):
            nxt = pick_next_node(plan, current, "random", rng)
            assert nxt is not None
            self.assertNotEqual(nxt.id, current)
            current = nxt.id

    def test_single_node_pool_returns_that_node(self) -> None:
        nodes = [make_node(1), make_node(2)]
        plan = build_rotation_plan(rotation_settings(), nodes)
        assert plan is not None
        plan.nodes = plan.nodes[:1]
        self.assertEqual(pick_next_node(plan, plan.nodes[0].id, "random"), plan.nodes[0])


class RotationIntervalTests(unittest.TestCase):
    def test_interval_without_jitter_is_exact(self) -> None:
        settings = rotation_settings(rotation_interval_sec=300, rotation_jitter_pct=0)
        self.assertEqual(rotation_interval_ms(settings), 300_000)

    def test_interval_is_clamped_to_minimum(self) -> None:
        settings = rotation_settings(rotation_interval_sec=1, rotation_jitter_pct=0)
        self.assertEqual(rotation_interval_ms(settings), MIN_INTERVAL_SEC * 1000)

    def test_jitter_stays_within_bounds(self) -> None:
        settings = rotation_settings(rotation_interval_sec=600, rotation_jitter_pct=20)
        rng = random.Random(7)
        values = [rotation_interval_ms(settings, rng) for _ in range(200)]
        self.assertTrue(all(480_000 <= value <= 720_000 for value in values), min(values))
        self.assertGreater(len(set(values)), 1)


class BalancerCommandTests(unittest.TestCase):
    def test_override_command(self) -> None:
        command = build_balancer_override_command("C:/core/xray.exe", 19085, "bal", "proxy-3")
        self.assertEqual(
            command,
            ["C:/core/xray.exe", "api", "bo", "--server=127.0.0.1:19085", "-b", "bal", "proxy-3"],
        )

    def test_remove_command(self) -> None:
        command = build_balancer_override_command("xray", 1234, "bal", remove=True)
        self.assertEqual(command[-1], "-r")

    def test_invalid_arguments_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_balancer_override_command("", 19085, "bal", "proxy")
        with self.assertRaises(ValueError):
            build_balancer_override_command("xray", 0, "bal", "proxy")
        with self.assertRaises(ValueError):
            build_balancer_override_command("xray", 19085, "", "proxy")
        with self.assertRaises(ValueError):
            build_balancer_override_command("xray", 19085, "bal", "")


class ConfigBuilderPoolTests(unittest.TestCase):
    """Ротация не имеет отдельного транспорта: конфиг зависит только от пула."""

    def build(self, node, pool=None):
        return build_xray_config(node, RoutingSettings(), AppSettings(), outbound_pool=pool)

    def test_config_without_pool_is_single_node(self) -> None:
        config = self.build(make_node(1))
        self.assertNotIn("balancers", config["routing"])
        self.assertEqual(config["api"]["services"], ["StatsService"])
        self.assertEqual([out["tag"] for out in config["outbounds"]], ["proxy", "direct", "block", "api"])
        for rule in config["routing"]["rules"]:
            self.assertNotIn("balancerTag", rule)

    def test_rotation_settings_alone_do_not_change_the_config(self) -> None:
        node = make_node(1)
        plain = self.build(node)
        settings = rotation_settings()
        rotated = build_xray_config(node, RoutingSettings(), settings)
        self.assertEqual(plain, rotated)

    def test_pool_config_carries_every_node_and_a_balancer(self) -> None:
        nodes = [make_node(i) for i in range(1, 4)]
        pool = build_xray_outbound_pool(nodes)
        config = self.build(nodes[0], pool=pool)
        tags = [out["tag"] for out in config["outbounds"]]
        for node in nodes:
            self.assertIn(pool.tag_for(node.id), tags)
        self.assertTrue(config["routing"]["balancers"])
        self.assertIn("RoutingService", config["api"]["services"])

    def test_pool_tags_are_stable_across_pool_changes(self) -> None:
        # Тег выводится из id ноды, поэтому выпадение соседа его не сдвигает —
        # именно это делает переключение по тегу безопасным.
        nodes = [make_node(i) for i in range(1, 4)]
        full = build_xray_outbound_pool(nodes)
        without_middle = build_xray_outbound_pool([nodes[0], nodes[2]])
        self.assertEqual(full.tag_for(nodes[2].id), without_middle.tag_for(nodes[2].id))


if __name__ == "__main__":
    unittest.main()
