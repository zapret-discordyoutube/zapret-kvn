from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from PyQt6.QtCore import QCoreApplication, QObject, pyqtSignal

from xray_fluent.application.runtime_services import on_live_metrics, stop_metrics_worker

_APP = QCoreApplication.instance() or QCoreApplication([])


class _FakeMetricsWorker(QObject):
    finished = pyqtSignal()
    metrics = pyqtSignal(dict)

    def __init__(self) -> None:
        super().__init__()
        self.stop_calls = 0
        self.wait_calls: list[int | None] = []
        self.delete_later_calls = 0
        self.running = True

    def isRunning(self) -> bool:  # noqa: N802 - QThread API
        return self.running

    def stop(self) -> None:
        self.stop_calls += 1

    def wait(self, timeout: int | None = None) -> bool:
        self.wait_calls.append(timeout)
        self.running = False
        return True

    def deleteLater(self) -> None:  # noqa: N802 - QObject API
        self.delete_later_calls += 1


def _make_controller(worker: _FakeMetricsWorker | None) -> SimpleNamespace:
    return SimpleNamespace(
        _metrics_worker=worker,
        _on_live_metrics=lambda payload: None,
    )


class StopMetricsWorkerTests(unittest.TestCase):
    def test_hot_swap_path_does_not_block_on_wait(self) -> None:
        worker = _FakeMetricsWorker()
        controller = _make_controller(worker)

        stop_metrics_worker(controller)

        self.assertIsNone(controller._metrics_worker)
        self.assertEqual(worker.stop_calls, 1)
        self.assertEqual(worker.wait_calls, [])
        self.assertEqual(controller._retiring_metrics_workers, [worker])

    def test_retiring_worker_is_released_on_finished(self) -> None:
        worker = _FakeMetricsWorker()
        controller = _make_controller(worker)
        stop_metrics_worker(controller)

        worker.running = False
        worker.finished.emit()

        self.assertEqual(controller._retiring_metrics_workers, [])
        self.assertEqual(worker.delete_later_calls, 1)

    def test_finished_emitted_twice_releases_once(self) -> None:
        worker = _FakeMetricsWorker()
        controller = _make_controller(worker)
        stop_metrics_worker(controller)

        worker.running = False
        worker.finished.emit()
        worker.finished.emit()

        self.assertEqual(controller._retiring_metrics_workers, [])
        self.assertEqual(worker.delete_later_calls, 1)

    def test_shutdown_path_still_waits(self) -> None:
        worker = _FakeMetricsWorker()
        controller = _make_controller(worker)

        stop_metrics_worker(controller, wait=True)

        self.assertIsNone(controller._metrics_worker)
        self.assertEqual(worker.stop_calls, 1)
        self.assertEqual(worker.wait_calls, [1200])
        self.assertEqual(getattr(controller, "_retiring_metrics_workers", []), [])

    def test_idle_worker_is_dropped_without_retiring(self) -> None:
        worker = _FakeMetricsWorker()
        worker.running = False
        controller = _make_controller(worker)

        stop_metrics_worker(controller)

        self.assertIsNone(controller._metrics_worker)
        self.assertEqual(worker.stop_calls, 0)
        self.assertEqual(getattr(controller, "_retiring_metrics_workers", []), [])

    def test_missing_worker_is_noop(self) -> None:
        controller = _make_controller(None)
        stop_metrics_worker(controller)
        self.assertIsNone(controller._metrics_worker)


class LiveMetricsValidityTests(unittest.TestCase):
    def test_invalid_sample_is_forwarded_as_invalid_not_zero_speed(self) -> None:
        payloads: list[dict] = []
        worker = SimpleNamespace(pings_active_node=lambda: False)
        controller = SimpleNamespace(
            _metrics_worker=worker,
            live_metrics_updated=SimpleNamespace(emit=payloads.append),
            _check_auto_switch=Mock(),
        )

        on_live_metrics(
            controller,
            {
                "down_bps": None,
                "up_bps": None,
                "traffic_valid": False,
                "latency_ms": None,
            },
        )

        controller._check_auto_switch.assert_called_once_with(
            0.0,
            None,
            traffic_valid=False,
        )
        self.assertIsNone(payloads[0]["down_bps"])


if __name__ == "__main__":
    unittest.main()
