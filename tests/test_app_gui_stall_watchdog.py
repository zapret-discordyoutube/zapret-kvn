"""GUI-stall watchdog: ловит блокировку GUI-потока и снимает её стек.

Keep the ``test_app_*`` prefix: widget test modules must sort before
``tests/test_engine_process_stop.py`` which creates a bare QCoreApplication
at import time (see tests/test_app_nodes_page_view.py).
"""

from __future__ import annotations

import os
import time
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QEventLoop, QTimer
from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError("widget tests need a QApplication")
app = _existing or QApplication([])

from xray_fluent.diagnostics.gui_stall_watchdog import GuiStallWatchdog


def _spin(ms: int) -> None:
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def _blocking_culprit(seconds: float) -> None:
    time.sleep(seconds)


class GuiStallWatchdogTests(unittest.TestCase):
    def setUp(self) -> None:
        # Хвосты прошлых тестов (deleteLater) не должны попасть в замер.
        app.sendPostedEvents(None, 0)
        _spin(50)
        self.watchdog = GuiStallWatchdog(threshold_ms=50)
        self.watchdog.start()
        _spin(40)
        self.watchdog.reset()

    def tearDown(self) -> None:
        self.watchdog.stop()

    def test_idle_loop_has_no_stalls(self) -> None:
        _spin(300)
        self.assertEqual(self.watchdog.records, [])

    def test_blocking_call_is_measured_with_stack(self) -> None:
        QTimer.singleShot(0, lambda: _blocking_culprit(0.2))
        _spin(150)
        _spin(150)
        self.assertEqual(len(self.watchdog.records), 1)
        record = self.watchdog.records[0]
        self.assertGreaterEqual(record.duration_ms, 180)
        self.assertIn("_blocking_culprit", record.stack)
        self.assertGreaterEqual(self.watchdog.max_stall_ms, 180)


if __name__ == "__main__":
    unittest.main()
