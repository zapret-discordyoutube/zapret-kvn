from __future__ import annotations

import unittest

from xray_fluent.app_controller import AppController
from xray_fluent.application.signature_service import (
    transition_signature,
    tun_layer_signature,
    xray_layer_signature,
)
from xray_fluent.application.transition_engine import TransitionContext, needs_transition
from xray_fluent.models import AppSettings, AppState, RoutingSettings
from xray_fluent.application.session_state import build_active_session_snapshot

from tests.test_rotation import make_node


class StubController:
    """Достаточная часть контроллера для расчёта сигнатур.

    Методы ротации и определения режима берутся у настоящего AppController, чтобы
    тест проверял рабочую логику, а не её копию.
    """

    is_rotation_supported = AppController.is_rotation_supported
    rotation_plan = AppController.rotation_plan
    is_tun2socks_mode = AppController.is_tun2socks_mode
    is_xray_tun_mode = AppController.is_xray_tun_mode
    is_singbox_tun_mode = AppController.is_singbox_tun_mode
    is_singbox_proxy_mode = AppController.is_singbox_proxy_mode
    is_singbox_editor_mode = AppController.is_singbox_editor_mode
    uses_xray_raw_config = AppController.uses_xray_raw_config

    def __init__(self, settings: AppSettings, nodes: list) -> None:
        self.state = AppState()
        self.state.settings = settings
        self.state.routing = RoutingSettings()
        self.state.nodes = nodes
        self.state.selected_node_id = nodes[0].id if nodes else None
        self._rotation_pool_logged = ""
        self.logs: list[str] = []

    def _log(self, line: str) -> None:
        self.logs.append(line)

    @property
    def selected_node(self):
        return next(
            (node for node in self.state.nodes if node.id == self.state.selected_node_id), None
        )


def tun_rotation_settings(**kwargs) -> AppSettings:
    settings = AppSettings()
    settings.tun_mode = True
    settings.tun_engine = "tun2socks"
    settings.rotation_enabled = True
    for key, value in kwargs.items():
        setattr(settings, key, value)
    return settings


class RotationSignatureTests(unittest.TestCase):
    def _controller(self, **kwargs) -> StubController:
        nodes = kwargs.pop("nodes", None) or [make_node(i) for i in range(1, 4)]
        return StubController(tun_rotation_settings(**kwargs), nodes)

    def test_switching_inside_pool_keeps_signatures(self) -> None:
        controller = self._controller()
        before = (
            transition_signature(controller),
            xray_layer_signature(controller),
            tun_layer_signature(controller),
        )
        controller.state.selected_node_id = controller.state.nodes[1].id
        after = (
            transition_signature(controller),
            xray_layer_signature(controller),
            tun_layer_signature(controller),
        )
        self.assertEqual(before, after)

    def test_switching_without_rotation_changes_signature(self) -> None:
        controller = self._controller()
        controller.state.settings.rotation_enabled = False
        before = transition_signature(controller)
        controller.state.selected_node_id = controller.state.nodes[1].id
        self.assertNotEqual(before, transition_signature(controller))

    def test_pool_change_changes_signature(self) -> None:
        controller = self._controller()
        before = transition_signature(controller)
        controller.state.nodes = controller.state.nodes[:2]
        self.assertNotEqual(before, transition_signature(controller))

    def test_disabling_rotation_changes_signature(self) -> None:
        controller = self._controller()
        before = transition_signature(controller)
        controller.state.settings.rotation_enabled = False
        self.assertNotEqual(before, transition_signature(controller))

    def test_tun_layer_covers_every_pool_server(self) -> None:
        controller = self._controller()
        signature = tun_layer_signature(controller)
        for node in controller.state.nodes:
            self.assertIn(node.server, signature)

    def test_rotation_inside_pool_needs_no_transition(self) -> None:
        controller = self._controller()
        node = controller.selected_node
        session = build_active_session_snapshot(
            node_id=node.id,
            node_server=node.server,
            active_core="tun2socks",
            tun_mode=True,
            tun_engine="tun2socks",
            proxy_enabled=False,
            proxy_bypass_lan=True,
            xray_path="",
            singbox_path="",
            socks_port=1390,
            http_port=1391,
            routing_signature="",
            transition_signature=transition_signature(controller),
            xray_layer_signature=xray_layer_signature(controller),
            tun_layer_signature=tun_layer_signature(controller),
            hybrid=False,
            api_port=19085,
            xray_inbound_tags=("socks-in",),
            sidecar_relay_port=0,
            protect_ss_port=0,
            protect_ss_password="",
            ping_host=node.server,
            ping_port=node.port,
        )

        controller.state.selected_node_id = controller.state.nodes[2].id
        context = TransitionContext(
            desired_connected=True,
            locked=False,
            has_selected_node=True,
            can_connect_without_selected_node=False,
            connected=True,
            blocked_transition_signature="",
            current_transition_signature=transition_signature(controller),
            active_session=session,
            can_apply_proxy_runtime_change=False,
            can_tun_hot_swap=False,
            can_proxy_hot_swap=False,
        )
        # Ядро уже содержит все серверы пула — перезапускать его не нужно.
        self.assertFalse(needs_transition(context))


class RotationScopeTests(unittest.TestCase):
    def test_rotation_is_off_outside_tun2socks(self) -> None:
        nodes = [make_node(i) for i in range(1, 4)]
        cases = {
            "sing-box TUN": {"tun_mode": True, "tun_engine": "singbox"},
            "xray native TUN": {"tun_mode": True, "tun_engine": "xray"},
            "sing-box proxy": {"tun_mode": False, "proxy_engine": "singbox"},
            "xray raw proxy": {"tun_mode": False, "proxy_engine": "xray"},
        }
        for label, overrides in cases.items():
            with self.subTest(mode=label):
                settings = AppSettings()
                settings.rotation_enabled = True
                for key, value in overrides.items():
                    setattr(settings, key, value)
                controller = StubController(settings, nodes)
                self.assertFalse(controller.is_rotation_supported())
                self.assertIsNone(controller.rotation_plan())

    def test_rotation_is_on_for_tun2socks(self) -> None:
        nodes = [make_node(i) for i in range(1, 4)]
        controller = StubController(tun_rotation_settings(), nodes)
        self.assertTrue(controller.is_rotation_supported())
        self.assertIsNotNone(controller.rotation_plan())

    def test_truncation_is_logged_once(self) -> None:
        nodes = [make_node(i) for i in range(1, 12)]
        controller = StubController(tun_rotation_settings(rotation_max_nodes=4), nodes)
        for _ in range(5):
            controller.rotation_plan()
        truncation_logs = [line for line in controller.logs if "усеч" in line]
        self.assertEqual(len(truncation_logs), 1)
        self.assertIn("11", truncation_logs[0])
        self.assertIn("4", truncation_logs[0])


if __name__ == "__main__":
    unittest.main()
