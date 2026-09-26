"""Обновление ядра Xray при активном подключении: остановка — через координатор."""

from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from xray_fluent.application.update_service import run_xray_core_update


class CoreUpdateStopTests(unittest.TestCase):
    def _controller(self) -> Mock:
        controller = Mock()
        controller._xray_update_worker = None
        controller.connected = True
        controller._run_coordinated_stop.return_value = True
        return controller

    def test_update_waits_for_coordinated_stop_before_replacing_core(self) -> None:
        controller = self._controller()
        with patch("xray_fluent.application.update_service.XrayCoreUpdateWorker") as worker_cls:
            run_xray_core_update(controller, True)

            # Никакого синхронного disconnect_current() в GUI-потоке.
            controller.disconnect_current.assert_not_called()
            controller._run_coordinated_stop.assert_called_once()
            worker_cls.assert_not_called()

            on_stopped = controller._run_coordinated_stop.call_args.args[1]
            on_stopped(True)

        worker_cls.assert_called_once()
        worker_cls.return_value.start.assert_called_once_with()
        self.assertTrue(controller._reconnect_after_xray_update)

    def test_failed_stop_cancels_update(self) -> None:
        controller = self._controller()
        with patch("xray_fluent.application.update_service.XrayCoreUpdateWorker") as worker_cls:
            run_xray_core_update(controller, True)
            controller._run_coordinated_stop.call_args.args[1](False)

        worker_cls.assert_not_called()
        self.assertFalse(controller._reconnect_after_xray_update)
        controller.status.emit.assert_called_once()
        self.assertEqual(controller.status.emit.call_args.args[0], "error")

    def test_update_during_transition_is_not_nested(self) -> None:
        controller = self._controller()
        controller._run_coordinated_stop.return_value = False
        with patch("xray_fluent.application.update_service.XrayCoreUpdateWorker") as worker_cls:
            run_xray_core_update(controller, True)

        worker_cls.assert_not_called()
        self.assertEqual(controller.status.emit.call_args.args[0], "warning")


if __name__ == "__main__":
    unittest.main()
