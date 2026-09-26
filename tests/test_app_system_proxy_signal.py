"""После операции очереди системного прокси UI получает свежий снимок реестра.

Keep the ``test_app_*`` prefix (QApplication before tests/test_engine_process_stop.py).
"""

from __future__ import annotations

import os
import time
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError("widget tests need a QApplication")
app = _existing or QApplication([])

from xray_fluent.application.async_steps import run_steps_blocking
from xray_fluent.application.controller import AppController
from xray_fluent.platform.windows.proxy_manager import SystemProxyState


class _FakeProxy:
    def __init__(self) -> None:
        self.enabled = True

    def disable(self, *_args, **_kwargs) -> None:
        time.sleep(0.05)  # WinAPI не мгновенный
        self.enabled = False

    def query_state(self) -> SystemProxyState:
        return SystemProxyState(supported=True, enabled=self.enabled, is_ours=self.enabled)


class SystemProxySignalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controller = AppController()
        cls.controller.schedule_save = lambda: None  # type: ignore[method-assign]

    def setUp(self) -> None:
        self.proxy = _FakeProxy()
        self.controller.proxy = self.proxy
        self.states: list[SystemProxyState] = []
        self.controller.system_proxy_state_changed.connect(self.states.append)

    def tearDown(self) -> None:
        self.controller.system_proxy_state_changed.disconnect(self.states.append)

    def test_background_operation_reports_fresh_state(self) -> None:
        self.controller._proxy_nowait("disable")
        deadline = time.monotonic() + 3
        while not self.states and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.01)
        self.assertTrue(self.states, "снимок не пришёл после фоновой операции")
        self.assertFalse(self.states[-1].enabled)

    def test_transition_step_reports_fresh_state(self) -> None:
        run_steps_blocking(self.controller._proxy_steps("disable"))
        self.assertTrue(self.states)
        self.assertFalse(self.states[-1].enabled)


if __name__ == "__main__":
    unittest.main()
