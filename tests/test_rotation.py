from __future__ import annotations

import random
import unittest

from xray_fluent.application.rotation_service import (
    BALANCER_TAG,
    MAX_POOL_NODES,
    MIN_INTERVAL_SEC,
    PRIMARY_OUTBOUND_TAG,
    build_rotation_plan,
    pick_next_node,
    rotation_interval_ms,
    rotation_pool_signature,
)
from xray_fluent.engines.xray.balancer_api import build_balancer_override_command
from xray_fluent.engines.xray.config_builder import build_xray_config
from xray_fluent.models import AppSettings, Node, RoutingSettings


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

    def test_tag_layout_does_not_depend_on_active_node(self) -> None:
        # Работающий xray хранит раскладку тегов с момента запуска. Если бы она
        # зависела от активной ноды, команда `bo proxy-N` после переключения
        # уводила бы трафик на другой сервер.
        nodes = [make_node(1), make_node(2), make_node(3)]
        settings = rotation_settings()
        layouts = [
            build_rotation_plan(settings, nodes, node.id).tags  # type: ignore[union-attr]
            for node in nodes
        ]
        self.assertEqual(layouts[0], layouts[1])
        self.assertEqual(layouts[1], layouts[2])
        self.assertEqual(
            sorted(layouts[0].values()),
            sorted([PRIMARY_OUTBOUND_TAG, f"{PRIMARY_OUTBOUND_TAG}-2", f"{PRIMARY_OUTBOUND_TAG}-3"]),
        )

    def test_pool_order_follows_sort_order(self) -> None:
        nodes = [make_node(3), make_node(1), make_node(2)]
        plan = build_rotation_plan(rotation_settings(), nodes, nodes[0].id)
        assert plan is not None
        self.assertEqual([node.sort_order for node in plan.nodes], [1, 2, 3])
        self.assertEqual(plan.tag_for(plan.nodes[0].id), PRIMARY_OUTBOUND_TAG)

    def test_active_node_survives_truncation(self) -> None:
        nodes = [make_node(i) for i in range(1, 11)]
        outsider = nodes[-1]
        plan = build_rotation_plan(rotation_settings(rotation_max_nodes=3), nodes, outsider.id)
        assert plan is not None
        self.assertEqual(len(plan.nodes), 3)
        self.assertTrue(plan.contains(outsider.id))

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
        self.assertNotIn(nodes[1].id, plan.tags)

        relaxed = build_rotation_plan(rotation_settings(rotation_only_alive=False), nodes)
        assert relaxed is not None
        self.assertEqual(len(relaxed.nodes), 3)

    def test_native_singbox_nodes_never_enter_pool(self) -> None:
        native = make_node(9)
        native.outbound = {"type": "hysteria2", "server": "10.0.0.9", "server_port": 443}
        nodes = [make_node(1), make_node(2), native]
        plan = build_rotation_plan(rotation_settings(), nodes)
        assert plan is not None
        self.assertNotIn(native.id, plan.tags)

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

    def test_signature_ignores_active_node_but_tracks_pool(self) -> None:
        nodes = [make_node(1), make_node(2), make_node(3)]
        settings = rotation_settings()
        first = rotation_pool_signature(build_rotation_plan(settings, nodes, nodes[0].id))
        second = rotation_pool_signature(build_rotation_plan(settings, nodes, nodes[1].id))
        self.assertEqual(first, second)

        changed = rotation_pool_signature(build_rotation_plan(settings, nodes[:2], nodes[0].id))
        self.assertNotEqual(first, changed)

    def test_signature_tracks_outbound_edits(self) -> None:
        nodes = [make_node(1), make_node(2)]
        settings = rotation_settings()
        before = rotation_pool_signature(build_rotation_plan(settings, nodes, nodes[0].id))
        nodes[1].outbound = dict(nodes[1].outbound, protocol="trojan")
        after = rotation_pool_signature(build_rotation_plan(settings, nodes, nodes[0].id))
        self.assertNotEqual(before, after)


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
        command = build_balancer_override_command("C:/core/xray.exe", 19085, BALANCER_TAG, "proxy-3")
        self.assertEqual(
            command,
            [
                "C:/core/xray.exe",
                "api",
                "bo",
                "--server=127.0.0.1:19085",
                "-b",
                BALANCER_TAG,
                "proxy-3",
            ],
        )

    def test_remove_command(self) -> None:
        command = build_balancer_override_command("xray", 1234, BALANCER_TAG, remove=True)
        self.assertEqual(command[-1], "-r")
        self.assertNotIn("proxy", command[-1])

    def test_invalid_arguments_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_balancer_override_command("", 19085, BALANCER_TAG, "proxy")
        with self.assertRaises(ValueError):
            build_balancer_override_command("xray", 0, BALANCER_TAG, "proxy")
        with self.assertRaises(ValueError):
            build_balancer_override_command("xray", 19085, "", "proxy")
        with self.assertRaises(ValueError):
            build_balancer_override_command("xray", 19085, BALANCER_TAG, "")


class ConfigBuilderRotationTests(unittest.TestCase):
    def build(self, rotation=None, node=None):
        node = node or make_node(1)
        return build_xray_config(node, RoutingSettings(), AppSettings(), rotation=rotation)

    def test_config_without_rotation_is_unchanged(self) -> None:
        config = self.build()
        self.assertNotIn("balancers", config["routing"])
        self.assertEqual(config["api"]["services"], ["StatsService"])
        self.assertEqual([out["tag"] for out in config["outbounds"]], ["proxy", "direct", "block", "api"])
        for rule in config["routing"]["rules"]:
            self.assertNotIn("balancerTag", rule)

    def test_rotation_emits_pool_outbounds_and_balancer(self) -> None:
        nodes = [make_node(i) for i in range(1, 4)]
        plan = build_rotation_plan(rotation_settings(), nodes, nodes[0].id)
        assert plan is not None
        config = self.build(rotation=plan, node=nodes[0])

        tags = [out["tag"] for out in config["outbounds"]]
        self.assertEqual(tags, ["proxy", "proxy-2", "proxy-3", "direct", "block", "api"])
        # Первым обязан идти прокси: пустой выбор балансировщика уходит в outbounds[0].
        self.assertEqual(tags[0], PRIMARY_OUTBOUND_TAG)

        balancers = config["routing"]["balancers"]
        self.assertEqual(len(balancers), 1)
        self.assertEqual(balancers[0]["tag"], BALANCER_TAG)
        self.assertNotIn("fallbackTag", balancers[0])
        self.assertNotIn("observatory", config)
        self.assertNotIn("burstObservatory", config)
        self.assertIn("RoutingService", config["api"]["services"])
        self.assertIn("StatsService", config["api"]["services"])

    def test_balancer_selector_covers_every_pool_tag(self) -> None:
        nodes = [make_node(i) for i in range(1, 5)]
        plan = build_rotation_plan(rotation_settings(), nodes, nodes[0].id)
        assert plan is not None
        config = self.build(rotation=plan, node=nodes[0])
        selector = config["routing"]["balancers"][0]["selector"]
        pool_tags = set(plan.tags.values())
        other_tags = {"direct", "block", "api"}
        for tag in pool_tags:
            self.assertTrue(any(tag.startswith(prefix) for prefix in selector), tag)
        for tag in other_tags:
            self.assertFalse(any(tag.startswith(prefix) for prefix in selector), tag)

    def test_proxy_rules_move_to_balancer(self) -> None:
        nodes = [make_node(i) for i in range(1, 3)]
        plan = build_rotation_plan(rotation_settings(), nodes, nodes[0].id)
        assert plan is not None
        routing = RoutingSettings()
        routing.proxy_domains = ["example.com"]
        routing.direct_domains = ["direct.example"]
        routing.block_domains = ["ads.example"]
        config = build_xray_config(nodes[0], routing, AppSettings(), rotation=plan)

        for rule in config["routing"]["rules"]:
            # outboundTag имеет приоритет над balancerTag — на прокси-правилах его быть не должно.
            self.assertNotEqual(rule.get("outboundTag"), PRIMARY_OUTBOUND_TAG)
            if rule.get("balancerTag"):
                self.assertEqual(rule["balancerTag"], BALANCER_TAG)
                self.assertNotIn("outboundTag", rule)

        tags = {rule.get("outboundTag") for rule in config["routing"]["rules"]}
        self.assertIn("direct", tags)
        self.assertIn("block", tags)
        balanced = [rule for rule in config["routing"]["rules"] if rule.get("balancerTag")]
        self.assertTrue(balanced)

    def test_pool_outbounds_carry_distinct_servers(self) -> None:
        nodes = [make_node(i) for i in range(1, 4)]
        plan = build_rotation_plan(rotation_settings(), nodes, nodes[0].id)
        assert plan is not None
        config = self.build(rotation=plan, node=nodes[0])
        addresses = [
            out["settings"]["vnext"][0]["address"]
            for out in config["outbounds"]
            if out["tag"].startswith(PRIMARY_OUTBOUND_TAG)
        ]
        self.assertEqual(len(set(addresses)), 3)


if __name__ == "__main__":
    unittest.main()
