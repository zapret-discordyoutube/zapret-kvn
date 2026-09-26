"""Снимок журнала ошибок уходит в GUI не чаще раза в секунду.

Keep the ``test_app_*`` prefix (QApplication must exist before
tests/test_engine_process_stop.py creates a bare QCoreApplication).
"""

from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QEventLoop, QObject, QTimer, pyqtSignal
from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError("widget tests need a QApplication")
app = _existing or QApplication([])

from xray_fluent.application.controller import AppController
from xray_fluent.diagnostics.runtime_errors import RuntimeErrorJournal, core_failure


def _spin(ms: int) -> None:
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


class _Host(QObject):
    runtime_errors_changed = pyqtSignal(object)
    _schedule_runtime_errors_emit = AppController._schedule_runtime_errors_emit

    def __init__(self) -> None:
        super().__init__()
        self.runtime_errors = RuntimeErrorJournal()


class RuntimeErrorsThrottleTests(unittest.TestCase):
    def test_burst_of_errors_emits_one_snapshot(self) -> None:
        host = _Host()
        snapshots = []
        host.runtime_errors_changed.connect(snapshots.append)
        for i in range(200):
            host.runtime_errors.record(core_failure("xray", "runtime", f"[Warning] failed to dial port {i}"))
            host._schedule_runtime_errors_emit()
        self.assertEqual(snapshots, [])  # не на каждую строку
        _spin(1200)
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0][0].occurrences, 200)


if __name__ == "__main__":
    unittest.main()
