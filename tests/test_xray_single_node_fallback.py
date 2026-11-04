"""Аварийный режим Xray: управляющий порт молчит — ядро работает с пулом из одного сервера."""
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock

from tests.step_fakes import bridge_controller, drive
from xray_fluent.application.controller import AppController
from xray_fluent.application.outbound_pool_service import (
    XRAY_OUTBOUND_PREFIX,
    single_node_xray_config,
    xray_outbound_tag,
)

TAGS = [xray_outbound_tag(f"node-{index}") for index in range(4)]
SELECTED = TAGS[2]


def sidecar_config() -> dict:
    return {
        "inbounds": [{"tag": "__app_hybrid_relay_in", "port": 11808, "protocol": "socks"}],
        "outbounds": [{"tag": tag, "protocol": "vless"} for tag in TAGS]
        + [{"tag": "direct", "protocol": "freedom"}, {"tag": "proxy", "protocol": "vless"}],
        "routing": {"balancers": [{"tag": "__app_proxy_selector", "selector": [XRAY_OUTBOUND_PREFIX]}]},
        "api": {"tag": "__app_sidecar_api", "services": ["RoutingService"]},
    }


def make_plan(config: dict, selected: str = SELECTED) -> SimpleNamespace:
    sidecar = SimpleNamespace(
        config=config, relay_port=11809, context=None, protect_port=11810, protect_password="", api_port=19085,
        outbound_pool_tags={},
    )
    return SimpleNamespace(
        amnezia_sidecar=None, provider_payload=None, hysteria_sidecar=None, xray_sidecar=sidecar,
        used_selected_node=True, clash_api_port=0, is_hybrid=True, selected_outbound_tag=selected,
        hybrid_relay_selected_tag="proxy", singbox_config={},
    )


def make_controller(*, control_plane_ok: bool, single_node: bool = False) -> Mock:
    controller = bridge_controller(Mock())
    controller._transition_generation = 1
    controller._desired_connected = True
    controller._active_singbox_plan = None
    controller._xray_single_node_pool = single_node
    controller._rejected_xray_tags = lambda: []
    controller._xray_single_node_fallback_steps = lambda plan: AppController._xray_single_node_fallback_steps(controller, plan)
    controller.xray.start.return_value = True
    # Дальше по цепочке запуск sing-box: он нарочно падает, чтобы разбор останавливался после Xray.
    controller.singbox.start.return_value = False
    controller._apply_core_outbound_tag.side_effect = lambda core, *_a, **_k: True if core != "xray" else control_plane_ok
    return controller


class SingleNodeConfigTests(TestCase):
    def test_only_the_selected_pool_outbound_survives_and_other_outbounds_are_kept(self) -> None:
        original = sidecar_config()
        reduced = single_node_xray_config(original, SELECTED)
        tags = [item["tag"] for item in reduced["outbounds"]]
        self.assertEqual(tags, [SELECTED, "direct", "proxy"])
        self.assertEqual(reduced["routing"], original["routing"])  # балансировщик остаётся, в пуле один член
        self.assertEqual(len(original["outbounds"]), 6, "исходный конфиг не меняется")

    def test_unknown_selected_tag_or_bad_config_gives_none(self) -> None:
        self.assertIsNone(single_node_xray_config(sidecar_config(), xray_outbound_tag("missing")))
        self.assertIsNone(single_node_xray_config({"outbounds": "oops"}, SELECTED))
        self.assertIsNone(single_node_xray_config({}, SELECTED))


class StartupFallbackTests(TestCase):
    def run_start(self, controller: Mock, plan: SimpleNamespace) -> bool:
        return drive(AppController._start_singbox_runtime_plan_steps(controller, plan))

    def test_failed_control_plane_restarts_xray_with_a_single_node_pool(self) -> None:
        controller = make_controller(control_plane_ok=False)
        config = sidecar_config()
        plan = make_plan(deepcopy(config))
        self.run_start(controller, plan)
        self.assertEqual(controller.xray.start.call_count, 2, "первый запуск и перезапуск")
        first_config = controller.xray.start.call_args_list[0].args[1]
        second_config = controller.xray.start.call_args_list[1].args[1]
        self.assertEqual(len(first_config["outbounds"]), 6)
        self.assertEqual([item["tag"] for item in second_config["outbounds"]], [SELECTED, "direct", "proxy"])
        self.assertIs(controller._xray_single_node_pool, True)
        controller.xray.stop.assert_called()  # перед перезапуском
        xray_calls = [call for call in controller._apply_core_outbound_tag.call_args_list if call.args[0] == "xray"]
        self.assertEqual(len(xray_calls), 1, "управляющий порт спрошен один раз")

    def test_in_single_node_mode_the_control_plane_is_not_called_at_all(self) -> None:
        controller = make_controller(control_plane_ok=False, single_node=True)
        plan = make_plan(sidecar_config())
        self.run_start(controller, plan)
        self.assertEqual(controller.xray.start.call_count, 1)
        xray_calls = [call for call in controller._apply_core_outbound_tag.call_args_list if call.args[0] == "xray"]
        self.assertEqual(xray_calls, [])

    def test_a_healthy_control_plane_keeps_the_full_pool(self) -> None:
        controller = make_controller(control_plane_ok=True)
        plan = make_plan(sidecar_config())
        self.run_start(controller, plan)
        self.assertEqual(controller.xray.start.call_count, 1)
        self.assertIsNot(controller._xray_single_node_pool, True)

    def test_when_the_fallback_is_impossible_startup_fails_and_xray_is_stopped(self) -> None:
        controller = make_controller(control_plane_ok=False)
        plan = make_plan(sidecar_config(), selected=xray_outbound_tag("missing"))
        self.assertFalse(self.run_start(controller, plan))
        self.assertEqual(controller.xray.start.call_count, 1)
        controller.xray.stop.assert_called()
        self.assertIsNot(controller._xray_single_node_pool, True)

    def test_a_failed_restart_does_not_leave_the_mode_on(self) -> None:
        controller = make_controller(control_plane_ok=False)
        controller.xray.start.side_effect = [True, False]
        plan = make_plan(sidecar_config())
        self.assertFalse(self.run_start(controller, plan))
        self.assertIsNot(controller._xray_single_node_pool, True)


class ModeGuardsTests(TestCase):
    def test_pool_candidates_shrink_to_the_selected_node_in_the_mode(self) -> None:
        selected = SimpleNamespace(id="a")
        controller = SimpleNamespace(
            _xray_single_node_pool=True, state=SimpleNamespace(nodes=[selected, SimpleNamespace(id="b")]),
            _xray_pool_quarantine_reasons=lambda: {},
        )
        self.assertEqual(AppController._pool_candidate_nodes(controller, selected), [selected])
        controller._xray_single_node_pool = False
        self.assertEqual(len(AppController._pool_candidate_nodes(controller, selected)), 2)

    def test_hot_switch_goes_through_a_restart_in_the_mode(self) -> None:
        controller = SimpleNamespace(_xray_single_node_pool=True, _log=Mock())
        self.assertIsNone(AppController._hot_switch_precheck(controller))
        controller._log.assert_not_called()
