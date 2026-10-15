"""Окно появляется на экране уже нарисованным: при запуске и при возврате из трея.

Keep the ``test_app_*`` prefix (QApplication before tests/test_engine_process_stop.py).
"""

from __future__ import annotations

import os
import re
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtGui import QPaintEvent
from PyQt6.QtWidgets import QApplication, QWidget

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError("widget tests need a QApplication")
app = _existing or QApplication([])

from xray_fluent.ui import window_reveal
from xray_fluent.ui.window_reveal import (
    FrameReveal,
    cloak_until_painted,
    is_system_show_event,
    set_window_cloaked,
)

MAIN_WINDOW = Path(__file__).resolve().parent.parent / "xray_fluent" / "ui" / "main_window.py"


class FrameRevealTests(unittest.TestCase):
    def setUp(self) -> None:
        self.calls: list[bool] = []
        self.order: list[str] = []
        self.accept = True
        self.window = QWidget()
        self.addCleanup(self.window.deleteLater)

    def _cloak(self, hwnd: int, cloaked: bool) -> bool:
        self.assertTrue(hwnd)
        self.calls.append(cloaked)
        self.order.append("cloak" if cloaked else "uncloak")
        return self.accept

    def _composed(self) -> None:
        self.order.append("composed")

    def _reveal(self, **kwargs) -> FrameReveal:
        return FrameReveal(self.window, cloak=self._cloak, wait_composed=self._composed, **kwargs)

    def _paint(self) -> None:
        app.sendEvent(self.window, QPaintEvent(self.window.rect()))

    def test_window_stays_hidden_until_painted(self) -> None:
        reveal = self._reveal()

        self.assertTrue(reveal.start())
        # Событие отрисовки приходит раньше самой отрисовки: открывать окно
        # прямо в нём рано, на экран попал бы тот же пустой кадр.
        self._paint()
        self.assertEqual(self.calls, [True])
        self.assertTrue(reveal.is_cloaked())

        app.processEvents()
        self.assertEqual(self.calls, [True, False])
        self.assertFalse(reveal.is_cloaked())

    def test_shade_lifts_only_after_windows_composed_the_frame(self) -> None:
        # Иначе окно ещё ~20 мс показывалось белым уже без шторки.
        reveal = self._reveal()
        reveal.start()
        self._paint()
        app.processEvents()

        self.assertEqual(self.order, ["cloak", "composed", "uncloak"])

    def test_window_is_hidden_again_on_next_show(self) -> None:
        # Возврат из трея: окно снова прячется до своей отрисовки.
        reveal = self._reveal()
        reveal.start()
        self._paint()
        app.processEvents()

        self.assertTrue(reveal.start())
        self._paint()
        app.processEvents()

        self.assertEqual(self.calls, [True, False, True, False])

    def test_one_reveal_serves_every_show_of_a_window(self) -> None:
        self.window._frame_reveal = self._reveal()

        first = cloak_until_painted(self.window)
        self._paint()
        app.processEvents()
        second = cloak_until_painted(self.window)

        self.assertIs(first, second)
        self.assertEqual(self.calls, [True, False, True])

    def test_window_is_revealed_when_paint_never_comes(self) -> None:
        # Белое окно лучше невидимой программы.
        reveal = self._reveal(wait_max_ms=0)
        reveal.start()

        app.processEvents()

        self.assertEqual(self.calls, [True, False])

    def test_refused_cloak_leaves_window_alone(self) -> None:
        self.accept = False
        reveal = self._reveal()

        self.assertFalse(reveal.start())
        self._paint()
        app.processEvents()

        self.assertEqual(self.calls, [True])
        self.assertFalse(reveal.is_cloaked())

    def test_other_systems_do_nothing(self) -> None:
        if sys.platform == "win32":
            self.skipTest("проверка для систем без DWM")
        self.assertFalse(set_window_cloaked(1, True))

    def test_deadline_is_bounded(self) -> None:
        self.assertLessEqual(window_reveal.FRAME_WAIT_MAX_MS, 2_000)

    def test_window_restored_by_windows_is_not_ours(self) -> None:
        self.assertTrue(is_system_show_event(SimpleNamespace(spontaneous=lambda: True)))
        self.assertFalse(is_system_show_event(SimpleNamespace(spontaneous=lambda: False)))


class MainWindowWiringTests(unittest.TestCase):
    def test_every_own_show_hides_window_until_painted(self) -> None:
        source = MAIN_WINDOW.read_text(encoding="utf-8")
        show_event = re.search(r"    def showEvent\(self, event\):\n(?P<body>(?:        .*\n|\n)+)", source)
        self.assertIsNotNone(show_event)
        body = show_event.group("body")
        self.assertIn("if not is_system_show_event(event):", body)
        self.assertIn("cloak_until_painted(self)", body)
        # Не только первый показ: вызов стоит до проверки первого показа.
        self.assertLess(body.index("cloak_until_painted(self)"), body.index("_first_show_logged"))


if __name__ == "__main__":
    unittest.main()
