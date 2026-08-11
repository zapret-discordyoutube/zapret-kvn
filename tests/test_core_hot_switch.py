from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from xray_fluent.application.node_service import set_selected_node
from xray_fluent.application.outbound_pool_service import (
    XRAY_BALANCER_TAG,
    XRAY_OUTBOUND_PREFIX,
    build_xray_outbound_pool,
)
from xray_fluent.engines.singbox.runtime_planner import (
    parse_singbox_document,
    plan_singbox_proxy_runtime,
)
from xray_fluent.engines.singbox.selector_api import build_selector_url, select_outbound
from xray_fluent.engines.xray.config_builder import build_xray_config
from xray_fluent.link_parser import parse_single
from xray_fluent.models import AppSettings, RoutingSettings

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SINGBOX_TEMPLATE = ROOT / "data" / "templates" / "sing-box" / "default.json"


def xray_nodes():
    return [
        parse_single(
            "vless://11111111-1111-1111-1111-111111111111@one.example:443"
            "?type=tcp&security=tls&sni=one.example#one"
        ),
        parse_single("trojan://secret@two.example:443?security=tls&sni=two.example#two"),
    ]


class XrayPoolTests(unittest.TestCase):
    def test_pool_tags_are_stable_and_not_display_name_based(self) -> None:
        nodes = xray_nodes()
        first = build_xray_outbound_pool(nodes)
        nodes[0].name = "renamed locally"
        second = build_xray_outbound_pool(reversed(nodes))
        self.assertEqual(first.tags, second.tags)
        self.assertTrue(all(tag.startswith(XRAY_OUTBOUND_PREFIX) for tag in first.tags.values()))

    def test_generated_config_keeps_routing_but_uses_core_balancer(self) -> None:
        nodes = xray_nodes()
        routing = RoutingSettings()
        routing.bypass_lan = False
        pool = build_xray_outbound_pool(nodes)
        config = build_xray_config(nodes[0], routing, AppSettings(), outbound_pool=pool)

        tags = [outbound["tag"] for outbound in config["outbounds"]]
        self.assertEqual(tags[:2], [pool.tag_for(node.id) for node in pool.nodes])
        self.assertEqual(config["routing"]["balancers"][0]["tag"], XRAY_BALANCER_TAG)
        self.assertTrue(
            any(rule.get("balancerTag") == XRAY_BALANCER_TAG for rule in config["routing"]["rules"])
        )
        self.assertEqual(
            config["api"]["services"],
            ["StatsService", "RoutingService", "HandlerService"],
        )


class SingboxPoolTests(unittest.TestCase):
    def test_native_nodes_are_exposed_through_provider_selector(self) -> None:
        nodes = [
            parse_single("hy2://secret@one.example:443/?insecure=1#one"),
            parse_single(
                "vless://11111111-1111-1111-1111-111111111111@two.example:443"
                "?type=tcp&security=tls&sni=two.example#two"
            ),
        ]
        document = parse_singbox_document(SINGBOX_TEMPLATE, SINGBOX_TEMPLATE.read_text(encoding="utf-8"))
        plan = plan_singbox_proxy_runtime(document, nodes[0], pool_nodes=nodes)

        selector = next(item for item in plan.singbox_config["outbounds"] if item.get("tag") == "proxy")
        self.assertEqual(selector["type"], "selector")
        self.assertEqual(selector["default"], "direct")
        self.assertTrue(selector["interrupt_exist_connections"])
        self.assertEqual(set(plan.selector_tags or {}), {node.id for node in nodes})
        self.assertEqual(len((plan.provider_payload or {})["outbounds"]), 2)
        self.assertEqual(plan.selected_outbound_tag, plan.selector_tags[nodes[0].id])

    def test_hybrid_sidecar_has_its_own_persistent_xray_pool(self) -> None:
        nodes = [
            parse_single(
                "vless://11111111-1111-1111-1111-111111111111@one.example:443"
                "?type=xhttp&security=tls&sni=one.example&path=%2Fapi#xhttp"
            ),
            parse_single("trojan://secret@two.example:443?security=tls&sni=two.example#trojan"),
        ]
        document = parse_singbox_document(SINGBOX_TEMPLATE, SINGBOX_TEMPLATE.read_text(encoding="utf-8"))
        plan = plan_singbox_proxy_runtime(document, nodes[0], pool_nodes=nodes)

        self.assertTrue(plan.is_hybrid)
        self.assertGreater(plan.xray_sidecar.api_port, 0)
        self.assertEqual(set(plan.selector_tags or {}), {node.id for node in nodes})
        sidecar = plan.xray_sidecar.config
        self.assertEqual(sidecar["routing"]["balancers"][0]["tag"], XRAY_BALANCER_TAG)
        self.assertIn("RoutingService", sidecar["api"]["services"])
        self.assertIn("HandlerService", sidecar["api"]["services"])


class SelectorApiTests(unittest.TestCase):
    def test_url_is_loopback_and_tag_is_escaped(self) -> None:
        self.assertEqual(build_selector_url(19090, "proxy group"), "http://127.0.0.1:19090/proxies/proxy%20group")

    @patch("xray_fluent.engines.singbox.selector_api.build_opener")
    def test_puts_exact_target_without_system_proxy(self, build_opener_mock: Mock) -> None:
        response = Mock(status=204)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = build_opener_mock.return_value
        opener.open.return_value = response

        ok, message = select_outbound(19090, "proxy", "provider/node")

        self.assertTrue(ok, message)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.method, "PUT")
        self.assertEqual(request.data, b'{"name": "provider/node"}')


class ManualSelectionTests(unittest.TestCase):
    def _controller(self, hot_result: bool):
        nodes = xray_nodes()
        controller = Mock()
        controller.state.selected_node_id = nodes[0].id
        controller.state.nodes = nodes
        controller.selected_node = nodes[1]
        controller.connected = True
        controller._desired_connected = True
        controller._try_hot_switch_selected_node.return_value = hot_result
        return controller, nodes

    def test_successful_core_switch_skips_transition_queue(self) -> None:
        controller, nodes = self._controller(True)
        set_selected_node(controller, nodes[1].id)
        controller._try_hot_switch_selected_node.assert_called_once_with()
        controller._request_transition.assert_not_called()

    def test_rejected_core_switch_falls_back_to_transition(self) -> None:
        controller, nodes = self._controller(False)
        set_selected_node(controller, nodes[1].id)
        controller._request_transition.assert_called_once_with("node switched")


if __name__ == "__main__":
    unittest.main()
