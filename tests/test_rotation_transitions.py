from __future__ import annotations

import random
import unittest

from xray_fluent.app_controller import AppController
from xray_fluent.application.outbound_pool_service import build_xray_outbound_pool
from xray_fluent.models import AppSettings, AppState, RoutingSettings

from tests.test_rotation import make_node


class StubSession:
    def __init__(self, tags: dict[str, str]) -> None:
        self.outbound_pool_tags = tags


class StubController:
    """Достаточная часть контроллера для проверки политики ротации.

    Методы ротации берутся у настоящего AppController, чтобы тест проверял рабочую
    логику, а не её копию. Переключение подменяется, чтобы не трогать процессы.
    """

    is_rotation_supported = AppController.is_rotation_supported
    _rotation_available_ids = AppController._rotation_available_ids
    rotation_plan = AppController.rotation_plan
    rotate_now = AppController.rotate_now

    def __init__(self, settings: AppSettings, nodes: list, *, connected: bool = True) -> None:
        self.state = AppState()
        self.state.settings = settings
        self.state.routing = RoutingSettings()
        self.state.nodes = nodes
        self.state.selected_node_id = nodes[0].id if nodes else None
        self.connected = connected
        self._rotation_pool_logged = ""
        self._rotation_rng = random.Random(42)
        self._active_session = StubSession(build_xray_outbound_pool(nodes).tags)
        self.logs: list[str] = []
        self.switched: list[str] = []
        self.status_messages: list[tuple[str, str]] = []

    def _log(self, line: str) -> None:
        self.logs.append(line)

    def set_selected_node(self, node_id: str) -> None:
        self.switched.append(node_id)
        self.state.selected_node_id = node_id

    @property
    def status(self):
        controller = self

        class _Signal:
            @staticmethod
            def emit(level: str, message: str) -> None:
                controller.status_messages.append((level, message))

        return _Signal()

    @property
    def selected_node(self):
        return next(
            (node for node in self.state.nodes if node.id == self.state.selected_node_id), None
        )


def rotation_settings(**kwargs) -> AppSettings:
    settings = AppSettings()
    settings.rotation_enabled = True
    for key, value in kwargs.items():
        setattr(settings, key, value)
    return settings


class RotateNowTests(unittest.TestCase):
    def _controller(self, **kwargs) -> StubController:
        nodes = kwargs.pop("nodes", None) or [make_node(i) for i in range(1, 4)]
        connected = kwargs.pop("connected", True)
        return StubController(rotation_settings(**kwargs), nodes, connected=connected)

    def test_rotation_uses_the_standard_switch_path(self) -> None:
        controller = self._controller()
        first = controller.state.selected_node_id
        self.assertTrue(controller.rotate_now())
        self.assertEqual(len(controller.switched), 1)
        self.assertNotEqual(controller.switched[0], first)
        self.assertEqual(controller.state.selected_node_id, controller.switched[0])

    def test_rotation_does_nothing_while_disconnected(self) -> None:
        controller = self._controller(connected=False)
        self.assertFalse(controller.rotate_now())
        self.assertEqual(controller.switched, [])

    def test_rotation_does_nothing_when_disabled(self) -> None:
        controller = self._controller()
        controller.state.settings.rotation_enabled = False
        self.assertFalse(controller.rotate_now())
        self.assertEqual(controller.switched, [])

    def test_rotation_never_leaves_the_core_pool(self) -> None:
        # Ядро запущено с двумя нодами, третью добавили уже после старта.
        nodes = [make_node(1), make_node(2)]
        controller = StubController(rotation_settings(), nodes)
        latecomer = make_node(3)
        controller.state.nodes = [*nodes, latecomer]

        for _ in range(20):
            controller.rotate_now()
        self.assertTrue(controller.switched)
        self.assertNotIn(latecomer.id, controller.switched)

    def test_plan_falls_back_to_the_node_list_without_a_session(self) -> None:
        # Без активной сессии состав ядра неизвестен, и ограничивать пул нечем;
        # переключение всё равно не состоится, пока нет подключения.
        controller = self._controller()
        controller._active_session = None
        plan = controller.rotation_plan()
        assert plan is not None
        self.assertEqual(len(plan.nodes), len(controller.state.nodes))

    def test_dead_node_is_skipped_without_breaking_switching(self) -> None:
        nodes = [make_node(1), make_node(2), make_node(3)]
        controller = StubController(rotation_settings(rotation_only_alive=True), nodes)
        nodes[1].is_alive = False
        for _ in range(20):
            controller.rotate_now()
        self.assertTrue(controller.switched)
        self.assertNotIn(nodes[1].id, controller.switched)

    def test_sequential_rotation_visits_every_node(self) -> None:
        nodes = [make_node(i) for i in range(1, 4)]
        controller = StubController(rotation_settings(rotation_mode="sequential"), nodes)
        for _ in range(3):
            controller.rotate_now()
        self.assertEqual(set(controller.switched), {node.id for node in nodes})

    def test_status_is_reported_to_the_user(self) -> None:
        controller = self._controller()
        controller.rotate_now()
        self.assertTrue(controller.status_messages)
        self.assertIn("Ротация", controller.status_messages[0][1])

    def test_truncation_is_logged_once(self) -> None:
        nodes = [make_node(i) for i in range(1, 12)]
        controller = StubController(rotation_settings(rotation_max_nodes=4), nodes)
        for _ in range(5):
            controller.rotation_plan()
        truncation_logs = [line for line in controller.logs if "усеч" in line]
        self.assertEqual(len(truncation_logs), 1)
        self.assertIn("11", truncation_logs[0])
        self.assertIn("4", truncation_logs[0])


class RotationSettingsTests(unittest.TestCase):
    def test_jitter_default_survives_a_round_trip(self) -> None:
        # Дефолт dataclass и дефолт from_dict должны совпадать, иначе первое же
        # сохранение состояния молча меняет поведение ротации.
        default = AppSettings()
        restored = AppSettings.from_dict({})
        self.assertEqual(restored.rotation_jitter_pct, default.rotation_jitter_pct)
        self.assertEqual(restored.rotation_interval_sec, default.rotation_interval_sec)
        self.assertEqual(restored.rotation_mode, default.rotation_mode)
        self.assertEqual(restored.rotation_enabled, default.rotation_enabled)

    def test_explicit_zero_jitter_is_preserved(self) -> None:
        restored = AppSettings.from_dict({"rotation_jitter_pct": 0})
        self.assertEqual(restored.rotation_jitter_pct, 0)

    def test_settings_round_trip(self) -> None:
        settings = rotation_settings(
            rotation_mode="sequential",
            rotation_interval_sec=120,
            rotation_jitter_pct=5,
            rotation_pool="group",
            rotation_pool_value="NL",
            rotation_only_alive=False,
            rotation_max_nodes=7,
        )
        restored = AppSettings.from_dict(settings.to_dict())
        for field in (
            "rotation_enabled",
            "rotation_mode",
            "rotation_interval_sec",
            "rotation_jitter_pct",
            "rotation_pool",
            "rotation_pool_value",
            "rotation_only_alive",
            "rotation_max_nodes",
        ):
            self.assertEqual(getattr(restored, field), getattr(settings, field), field)


if __name__ == "__main__":
    unittest.main()
