"""A stopped connection must not leave ``naive.exe`` alive, and a cleanup that cannot help must not spin the GUI thread.

Owner report 2026-11-27 (0.8.135, video plus a 5000-line diagnostic holding nothing but this): after leaving a NaiveProxy
server the window stopped answering clicks. ``_has_residual_processes`` counted naive, ``_connection_managers`` did not, so
the ``cleanup`` action found nothing to stop, the runner saw a process still alive and queued another cleanup at 0 ms:
1,667 empty cleanups in five minutes on the GUI thread.

Real AppController, the real NaiveManager and a real child process in its QProcess (a long sleep stands in for naive.exe:
the app only watches the process, the protocol is not under test here). Keep the ``test_app_*`` prefix (QApplication).
"""

from __future__ import annotations

import os
import sys
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QEventLoop, QTimer
from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
app = _existing if isinstance(_existing, QApplication) else (_existing or QApplication([]))

CLEANUP_LINE = "[transition] stopping partial connection processes"


def _spin(ms: int) -> None:
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def _spin_until(condition, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if condition():
            return True
        _spin(20)
    return condition()


class ResidualNaiveCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        from xray_fluent.application import runtime_services
        from xray_fluent.application.controller import AppController
        from xray_fluent.profiles.models import AppState
        from tests.test_app_transition_gui_stalls import _FakeWinProxy

        self.patchers = [patch.object(runtime_services, "start_metrics_worker", lambda controller: None)]
        for patcher in self.patchers:
            patcher.start()
        controller = AppController()
        controller.schedule_save = lambda: None  # type: ignore[method-assign]
        controller.save = lambda: None  # type: ignore[method-assign]
        controller._start_metrics_worker = lambda: None  # type: ignore[method-assign]
        controller.proxy = _FakeWinProxy()
        controller.state = AppState()
        controller.state.settings.enable_system_proxy = False
        self.controller = controller
        self.logs: list[str] = []
        controller.log_line.connect(self.logs.append)
        self.naive = controller.naive
        self.naive._process.setProgram(sys.executable)
        self.naive._process.setArguments(["-c", "import time; time.sleep(120)"])
        self.naive._process.start()
        self.assertTrue(self.naive._process.waitForStarted(10000))

    def tearDown(self) -> None:
        self.naive._process.kill()
        self.naive._process.waitForFinished(5000)
        for patcher in reversed(self.patchers):
            patcher.stop()

    def _idle(self) -> bool:
        c = self.controller
        return not c._transition_active and not c._transition_pending and not c._transition_timer.isActive()

    def _cleanup_count(self) -> int:
        return sum(1 for line in self.logs if CLEANUP_LINE in line)

    def test_the_stop_list_holds_every_helper_the_residual_check_counts(self) -> None:
        from xray_fluent.application.runtime_services import _connection_managers

        managers = _connection_managers(self.controller)
        for name in ("singbox", "xray", "hysteria", "amnezia", "naive"):
            self.assertIn(getattr(self.controller, name), managers, name)

    def test_a_running_naive_without_a_session_is_stopped_by_one_cleanup(self) -> None:
        c = self.controller
        self.assertTrue(c._has_residual_processes())
        c._desired_connected = False
        c._cleanup_pending = True
        c._kick_transition(0)
        self.assertTrue(_spin_until(lambda: not self.naive.process_alive and self._idle(), 15), "\n".join(self.logs[-20:]))
        _spin(500)
        self.assertFalse(c._has_residual_processes())
        self.assertLessEqual(self._cleanup_count(), 1, "cleanup repeated after it had finished the job")

    def test_a_process_that_cannot_be_stopped_is_cleaned_up_once_not_forever(self) -> None:
        c = self.controller

        def stops_nothing(*_args, **_kwargs):
            return True
            yield  # pragma: no cover - makes this a generator like the real step

        c._desired_connected = False
        with patch.object(type(c), "_stop_active_connection_processes_steps", lambda self_, **kw: stops_nothing()):
            c._cleanup_pending = True
            c._kick_transition(0)
            _spin(2000)
        self.assertTrue(self.naive.process_alive)
        self.assertLessEqual(self._cleanup_count(), 2, f"{self._cleanup_count()} cleanups in 2 s: the GUI thread is being spun")
        self.assertTrue(any("cleanup left processes alive" in line for line in self.logs))


if __name__ == "__main__":
    unittest.main()
