"""Время жизни QThread-воркеров (xray_fluent/application/worker_keeper.py).

Главный сценарий — вылет «QThread: Destroyed while thread is still running»:
слот сигнала, испущенного внутри ``run()``, обнулял последнюю ссылку на
поток. С корзиной ``keep_until_finished`` поток живёт до своего ``finished``.
"""

from __future__ import annotations

import gc
import threading
import time
import unittest

from PyQt6.QtCore import QCoreApplication, QEventLoop, QObject, QThread, QTimer, pyqtSignal

from xray_fluent.application.worker_keeper import keep_until_finished, start_kept, wait_all

_APP = QCoreApplication.instance() or QCoreApplication([])


def _spin_until(predicate, timeout_ms: int = 3000) -> bool:
    deadline = time.monotonic() + timeout_ms / 1000.0
    while time.monotonic() < deadline:
        if predicate():
            return True
        loop = QEventLoop()
        QTimer.singleShot(5, loop.quit)
        loop.exec()
    return predicate()


class _Worker(QThread):
    completed = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()
        # Событие, а не sleep: слот с gc.collect() в большом процессе идёт
        # дольше любой паузы, и поток успевал завершиться до проверки.
        self.release = threading.Event()

    def run(self) -> None:
        self.completed.emit()
        # Поток ещё внутри run(), когда GUI-поток обрабатывает completed.
        self.release.wait(5)


class _Owner(QObject):
    def __init__(self) -> None:
        super().__init__()
        self.worker: _Worker | None = None
        self.bucket: list = []
        self.completed = 0

    def on_completed(self) -> None:
        self.completed += 1
        self.worker = None  # так делали on_ping_complete / on_speed_complete
        gc.collect()


class WorkerKeeperTests(unittest.TestCase):
    def test_dropping_current_handle_in_completed_slot_is_safe(self) -> None:
        owner = _Owner()
        for _ in range(5):
            worker = _Worker()
            owner.worker = worker
            worker.completed.connect(owner.on_completed)
            start_kept(owner.bucket, worker)
            release = worker.release
            del worker
            self.assertTrue(_spin_until(lambda: owner.worker is None))
            self.assertEqual(len(owner.bucket), 1, "поток ещё работает — корзина его держит")
            release.set()
            self.assertTrue(_spin_until(lambda: not owner.bucket))
        self.assertEqual(owner.completed, 5)

    def test_released_once_on_finished(self) -> None:
        class _Fake(QObject):
            finished = pyqtSignal()

            def __init__(self) -> None:
                super().__init__()
                self.deleted = 0

            def deleteLater(self) -> None:  # noqa: N802 - QObject API
                self.deleted += 1

        bucket: list = []
        fake = _Fake()
        keep_until_finished(bucket, fake)
        keep_until_finished(bucket, fake)
        self.assertEqual(bucket, [fake])
        fake.finished.emit()
        fake.finished.emit()
        self.assertEqual(bucket, [])
        self.assertEqual(fake.deleted, 1)

    def test_wait_all_waits_running_workers(self) -> None:
        bucket: list = []
        worker = start_kept(bucket, _Worker())
        worker.release.set()
        wait_all(bucket, 2000)
        self.assertFalse(worker.isRunning())
        self.assertTrue(_spin_until(lambda: not bucket))


if __name__ == "__main__":
    unittest.main()
