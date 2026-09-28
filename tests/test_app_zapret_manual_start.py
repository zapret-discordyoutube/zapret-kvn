"""Ручной запуск/остановка Zapret: «занято» снимается фактом, последний клик побеждает.

Keep the ``test_app_*`` prefix (QApplication before tests/test_engine_process_stop.py).
"""

from __future__ import annotations

import os
import threading
import time
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError("widget tests need a QApplication")
app = _existing or QApplication([])

from xray_fluent.application.controller import AppController
from xray_fluent.engines.zapret.endpoint import ResolvedEndpoint, ServerEndpoint

_ENDPOINT = ServerEndpoint("tcp", ("example.com",), ("443",))


def _pump_until(predicate, timeout_s: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return True
        time.sleep(0.005)
    app.processEvents()
    return predicate()


class ManualZapretStartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controller = AppController()
        cls.controller.schedule_save = lambda: None  # type: ignore[method-assign]

    def setUp(self) -> None:
        controller = self.controller
        zapret = controller.zapret
        self.release = threading.Event()
        self.release.set()
        self.resolved_calls = 0
        self.workers: list = []

        def resolve(endpoint):
            self.resolved_calls += 1
            self.release.wait(5)
            return ResolvedEndpoint(endpoint, ("203.0.113.1",))

        controller._active_config_uses_selected_node = lambda _node: True  # type: ignore[method-assign]
        controller.state.selected_node_id = None
        for target, value in (
            ("endpoint_for_node", lambda _node: _ENDPOINT),
            ("resolve_endpoint", resolve),
        ):
            patcher = patch(f"xray_fluent.application.server_bypass.{target}", value)
            patcher.start()
            self.addCleanup(patcher.stop)
        # Процесс «запустился»: менеджер сообщает об этом сигналом started.
        zapret.apply = Mock(side_effect=lambda _plan: zapret.started.emit())  # type: ignore[method-assign]
        zapret.stop = Mock()  # type: ignore[method-assign]
        self.busy: list[bool] = []
        controller.transition_state_changed.connect(self._on_busy)

    def tearDown(self) -> None:
        self.release.set()
        for worker in self.workers:
            try:
                worker.wait(5000)
            except RuntimeError:  # уже удалён deleteLater после finished
                pass
        app.processEvents()
        self.controller.transition_state_changed.disconnect(self._on_busy)
        self.controller.bypass._manual_busy = False
        self.controller._transition_active = False

    def _on_busy(self, busy: bool, _text: str) -> None:
        self.busy.append(busy)

    def _start(self, preset: str) -> None:
        self.controller.start_zapret(preset)
        self.workers.extend(w for w in self.controller.bypass.workers() if w not in self.workers)

    def _workers_done(self) -> bool:
        def done(worker) -> bool:
            try:
                return worker.isFinished()
            except RuntimeError:  # удалён deleteLater после finished
                return True

        return all(done(worker) for worker in self.workers)

    def test_successful_start_releases_busy(self) -> None:
        self._start("general")
        self.assertEqual(self.busy, [True])
        self.assertTrue(_pump_until(lambda: self.controller.zapret.apply.called))
        self.assertEqual(self.controller.zapret.apply.call_args.args[0].preset, "general")
        self.assertIsNotNone(self.controller.zapret.apply.call_args.args[0].rule)
        # Раньше последним оставалось «занято» — панель висела недоступной.
        self.assertEqual(self.busy[-1], False)
        self.assertFalse(self.controller.bypass.manual_start_pending)

    def test_stop_during_pending_start_wins(self) -> None:
        self.release.clear()  # DNS выбранного сервера ещё идёт
        self._start("general")
        self.assertTrue(_pump_until(lambda: self.resolved_calls == 1))
        self.controller.stop_zapret()
        self.controller.zapret.stop.assert_called_once_with()
        self.assertEqual(self.busy, [True, False])
        # DNS завершился уже после «стоп» — Zapret не должен подняться обратно.
        self.release.set()
        self.assertTrue(_pump_until(self._workers_done))
        _pump_until(lambda: False, timeout_s=0.1)
        self.controller.zapret.apply.assert_not_called()
        self.assertEqual(self.busy, [True, False])
        # Выход приложения ждёт живые воркеры — завершённый там не нужен.
        self.assertTrue(_pump_until(lambda: not self.controller.bypass.workers()))

    def test_second_start_retargets_to_latest_preset(self) -> None:
        self.release.clear()
        self._start("first")
        self._start("second")
        self.release.set()
        self.assertTrue(_pump_until(self._workers_done))
        self.assertTrue(_pump_until(lambda: self.controller.zapret.apply.called))
        _pump_until(lambda: False, timeout_s=0.1)
        self.controller.zapret.apply.assert_called_once()
        self.assertEqual(self.controller.zapret.apply.call_args.args[0].preset, "second")
        self.assertEqual(self.busy[-1], False)

    def test_connection_transition_keeps_its_busy(self) -> None:
        self.release.clear()
        self._start("general")
        self.controller._transition_active = True  # индикатор держит переход подключения
        self.controller.stop_zapret()
        self.assertEqual(self.busy, [True])
        self.assertFalse(self.controller.bypass.manual_start_pending)


if __name__ == "__main__":
    unittest.main()
