from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from xray_fluent.app_controller import AppController
from xray_fluent.application.node_service import set_selected_node
from xray_fluent.application.signature_service import transition_signature
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
        selector = next(
            item for item in plan.singbox_config["outbounds"] if item.get("tag") == "proxy"
        )
        self.assertEqual(selector["type"], "selector")
        self.assertEqual(tuple(selector["outbounds"]), plan.hybrid_relay_selector_tags)
        self.assertTrue(selector["interrupt_exist_connections"])

    def test_hybrid_signature_is_stable_before_and_after_session_capture(self) -> None:
        nodes = [
            parse_single(
                "vless://11111111-1111-1111-1111-111111111111@one.example:443"
                "?type=xhttp&security=tls&sni=one.example&path=%2Fapi#xhttp"
            ),
            parse_single("trojan://secret@two.example:443?security=tls&sni=two.example#trojan"),
        ]

        class Controller:
            def __init__(self):
                settings = AppSettings()
                settings.proxy_engine = "singbox"
                self.state = SimpleNamespace(
                    settings=settings,
                    routing=RoutingSettings(),
                    nodes=nodes,
                    selected_node_id=nodes[0].id,
                )
                self.selected_node = nodes[0]
                self._active_session = None

            @staticmethod
            def is_singbox_editor_mode(_settings=None):
                return True

            @staticmethod
            def is_singbox_tun_mode(_settings=None):
                return False

            @staticmethod
            def is_singbox_proxy_mode(_settings=None):
                return True

            @staticmethod
            def _inspect_active_singbox_config():
                return SINGBOX_TEMPLATE, "config-hash", True

            def xray_outbound_pool(self):
                return build_xray_outbound_pool(self.state.nodes)

        controller = Controller()
        before = transition_signature(controller)
        controller._active_session = SimpleNamespace(
            hybrid=True,
            outbound_pool_tags=controller.xray_outbound_pool().tags,
        )
        after = transition_signature(controller)

        self.assertEqual(before, after)


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


def run_hot_switch_generator(controller):
    """Deliberate async update (hot-switch-hardening, AC7/C1).

    ``_try_hot_switch_selected_node`` больше не выполняет control-plane I/O
    синхронно: проверки — в ``_hot_switch_precheck``, вызовы ядра — воркер-шаги
    генератора ``_hot_switch_selected_node_steps``. Семантические контракты
    (порядок xray→singbox, откат, коммит сессии только после подтверждения)
    проверяются прогоном генератора с замоканными control-plane шагами; сами
    шаги замоканы, поэтому генератор обязан завершиться без единого yield.
    """
    plan = AppController._hot_switch_precheck(controller)
    if plan is None:
        return False
    generator = AppController._hot_switch_selected_node_steps(controller, plan)
    try:
        step = next(generator)
    except StopIteration as stop:
        return stop.value
    raise AssertionError(f"unexpected async step from mocked hot switch: {step!r}")


class LiveConnectionCutoverTests(unittest.TestCase):
    def _controller(self, *, hybrid: bool, apply_results: list[bool] | None = None):
        nodes = xray_nodes()
        tags = {nodes[0].id: "old-tag", nodes[1].id: "new-tag"}
        session = SimpleNamespace(
            node_id=nodes[0].id,
            active_core="singbox" if hybrid else "xray",
            hybrid=hybrid,
            outbound_pool_tags=tags,
            hybrid_relay_selector_tags=("relay-a", "relay-b") if hybrid else (),
            hybrid_relay_selected_tag="relay-a" if hybrid else "",
        )
        controller = Mock()
        controller.selected_node = nodes[1]
        controller._active_session = session
        controller.connected = True
        controller.zapret.apply_cached_proxy_node.return_value = True

        apply_calls: list[unittest.mock._Call] = []
        results = list(apply_results) if apply_results is not None else None

        def apply_core_outbound_tag_steps(core: str, outbound_tag: str):
            apply_calls.append(unittest.mock.call(core, outbound_tag))
            return True if results is None else results.pop(0)
            yield  # unreachable — сохраняет генераторную форму продуктового метода

        controller._apply_core_outbound_tag_steps = apply_core_outbound_tag_steps
        controller._apply_core_calls = apply_calls
        controller._capture_hot_switched_session = Mock()
        return controller, nodes, tags, session

    def test_hybrid_switch_changes_xray_then_interrupts_old_singbox_generation(self) -> None:
        controller, nodes, tags, session = self._controller(hybrid=True)

        self.assertTrue(run_hot_switch_generator(controller))

        self.assertEqual(
            controller._apply_core_calls,
            [
                unittest.mock.call("xray", "new-tag"),
                unittest.mock.call("singbox", "relay-b"),
            ],
        )
        controller._capture_hot_switched_session.assert_called_once_with(
            nodes[1],
            session,
            tags,
            "new-tag",
            hybrid_relay_selected_tag="relay-b",
        )

    def test_hybrid_selector_failure_restores_previous_xray_outbound(self) -> None:
        controller, _nodes, _tags, _session = self._controller(
            hybrid=True,
            apply_results=[True, False, True],
        )

        self.assertFalse(run_hot_switch_generator(controller))

        self.assertEqual(
            controller._apply_core_calls,
            [
                unittest.mock.call("xray", "new-tag"),
                unittest.mock.call("singbox", "relay-b"),
                unittest.mock.call("xray", "old-tag"),
            ],
        )
        controller._capture_hot_switched_session.assert_not_called()

    def test_xray_only_does_not_report_cutover_without_connection_interrupt_api(self) -> None:
        controller, _nodes, _tags, _session = self._controller(hybrid=False)

        self.assertFalse(run_hot_switch_generator(controller))

        self.assertEqual(controller._apply_core_calls, [])
        controller._capture_hot_switched_session.assert_not_called()

    def test_udp_hot_switch_waits_for_zapret_pass_restart_readiness(self) -> None:
        controller, _nodes, _tags, _session = self._controller(hybrid=True)
        controller.zapret.proxy_protection_is_ready.return_value = False

        self.assertFalse(run_hot_switch_generator(controller))

        self.assertEqual(controller._apply_core_calls, [])
        controller._capture_hot_switched_session.assert_not_called()


class ProxyProtectionTransitionTests(unittest.TestCase):
    def test_transition_waits_for_cached_pass_restart_readiness(self) -> None:
        node = parse_single("hy2://secret@one.example:443/?insecure=1#one")
        controller = Mock()
        controller.selected_node = node
        controller.zapret.apply_cached_proxy_node.return_value = True
        controller.zapret.proxy_protection_is_ready.return_value = False
        controller.zapret.proxy_protection_generation = 7
        controller._proxy_protection_wait_generation = 0
        controller._proxy_protection_wait_token = 0

        def wait_for_protection(generation: int) -> None:
            controller._proxy_protection_wait_generation = generation
            controller._proxy_protection_wait_token = 7
            controller.transition_state_changed.emit(
                True,
                "Ожидание перезапуска UDP-защиты...",
            )

        controller._wait_for_proxy_protection = wait_for_protection

        self.assertTrue(AppController._prepare_proxy_protection(controller, 11))

        self.assertEqual(controller._proxy_protection_wait_generation, 11)
        self.assertEqual(controller._proxy_protection_wait_token, 7)
        controller.transition_state_changed.emit.assert_called_once_with(
            True,
            "Ожидание перезапуска UDP-защиты...",
        )

    def test_readiness_failure_keeps_existing_connection_and_fences_transition(self) -> None:
        controller = Mock()
        controller._proxy_protection_wait_generation = 11
        controller._proxy_protection_wait_token = 7
        controller._transition_generation = 11
        controller._transition_pending = True
        controller.connected = True
        controller._transition_signature.return_value = "blocked-signature"

        AppController._on_proxy_protection_failed(controller, 7, "timeout")

        self.assertFalse(controller._transition_pending)
        self.assertTrue(controller._desired_connected)
        self.assertEqual(controller._blocked_transition_signature, "blocked-signature")
        controller.status.emit.assert_called_once_with(
            "warning",
            "Не удалось подтвердить UDP-защиту; переход отменён",
        )
        controller.transition_state_changed.emit.assert_called_once_with(False, "")

    def test_dns_failure_with_running_zapret_keeps_existing_connection(self) -> None:
        node = parse_single("hy2://secret@one.example:443/?insecure=1#one")
        controller = Mock()
        controller.selected_node = node
        controller.zapret.running = True
        controller.zapret.proxy_protection_server.return_value = "one.example"
        controller._transition_generation = 11
        controller._proxy_protection_wait_generation = 11
        controller._proxy_protection_wait_token = 0
        controller._desired_connected = True
        controller.connected = True
        controller._transition_pending = True
        controller._transition_signature.return_value = "blocked-dns"

        AppController._on_proxy_protection_resolved(
            controller,
            11,
            "one.example",
            set(),
            OSError("temporary DNS failure"),
        )

        self.assertFalse(controller._transition_pending)
        self.assertTrue(controller._desired_connected)
        self.assertEqual(controller._blocked_transition_signature, "blocked-dns")
        controller.status.emit.assert_called_once_with(
            "warning",
            "Не удалось подготовить UDP-защиту: адрес сервера не определён",
        )
        controller._schedule_transition_drain.assert_not_called()


class HybridRuntimeStartupTests(unittest.TestCase):
    def test_start_pins_xray_target_and_known_relay_generation(self) -> None:
        sidecar = SimpleNamespace(
            protect_port=19084,
            protect_password="protect",
            relay_port=19080,
            api_port=19085,
            config={"sidecar": True},
        )
        plan = SimpleNamespace(
            provider_payload=None,
            xray_sidecar=sidecar,
            selected_outbound_tag="node-tag",
            clash_api_port=19090,
            singbox_config={"main": True},
            is_hybrid=True,
            hybrid_relay_selected_tag="relay-a",
        )
        controller = Mock()
        controller.state.settings.xray_path = "xray.exe"
        controller.state.settings.singbox_path = "sing-box.exe"
        controller.xray.start.return_value = True
        controller.xray.is_running = True
        controller.singbox.start.return_value = True
        controller._apply_core_outbound_tag.return_value = True

        self.assertTrue(AppController._start_singbox_runtime_plan(controller, plan))

        self.assertEqual(
            controller._apply_core_outbound_tag.call_args_list,
            [
                unittest.mock.call("xray", "node-tag"),
                unittest.mock.call("singbox", "relay-a"),
            ],
        )
        self.assertEqual(controller._xray_api_port, 19085)
        self.assertEqual(controller._singbox_clash_api_port, 19090)


if __name__ == "__main__":
    unittest.main()
