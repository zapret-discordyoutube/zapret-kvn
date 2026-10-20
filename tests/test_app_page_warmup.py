"""Страницы окна строятся заранее, пока окно скрыто и человек отошёл (xray_fluent.ui.page_warmup).

Keep the ``test_app_*`` prefix (QApplication before tests/test_engine_process_stop.py).
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QWidget

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError("widget tests need a QApplication")
app = _existing or QApplication([])

from xray_fluent.ui import page_warmup
from xray_fluent.ui.page_warmup import HiddenPageWarmup

MAIN_WINDOW = Path(__file__).resolve().parent.parent / "xray_fluent" / "ui" / "main_window.py"


class _Page:
    def __init__(self, name: str, log: list[str], *, fail: bool = False) -> None:
        self._page = None
        self._name = name
        self._log = log
        self._fail = fail

    def objectName(self) -> str:
        return self._name

    def ensure_page(self):
        if self._fail:
            raise RuntimeError("страница не собралась")
        self._page = object()
        self._log.append(self._name)


class _World:
    def __init__(self) -> None:
        self.now = 1000.0
        self.idle: int | None = 5 * 60_000
        self.built: list[str] = []
        self.pages = [_Page("nodes", self.built), _Page("settings", self.built)]
        self.window = QWidget()

    def make(self, **kwargs) -> HiddenPageWarmup:
        warmup = HiddenPageWarmup(
            self.window,
            lambda: self.pages,
            idle_ms=lambda: self.idle,
            clock=lambda: self.now,
            **kwargs,
        )
        warmup._timer.stop()  # такт вызываем сами
        return warmup


class HiddenPageWarmupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = _World()
        self.addCleanup(self.world.window.deleteLater)

    def _after_start(self, seconds: float) -> None:
        self.world.now += seconds

    def test_nothing_is_built_during_the_first_two_minutes(self) -> None:
        warmup = self.world.make()
        self._after_start(page_warmup.AFTER_S - 1)

        warmup._on_timer()

        self.assertEqual(self.world.built, [])

    def test_hidden_window_and_an_absent_person_get_one_page_per_tick(self) -> None:
        warmup = self.world.make()
        self._after_start(page_warmup.AFTER_S + 1)

        warmup._on_timer()
        self.assertEqual(self.world.built, ["nodes"])

        warmup._on_timer()
        self.assertEqual(self.world.built, ["nodes", "settings"])

        warmup._on_timer()
        self.assertTrue(warmup.finished)

    def test_a_visible_window_is_left_alone(self) -> None:
        warmup = self.world.make()
        self.world.window.show()
        app.processEvents()
        self._after_start(page_warmup.AFTER_S + 1)

        warmup._on_timer()

        self.assertEqual(self.world.built, [])
        self.assertFalse(warmup.finished)

    def test_a_working_person_or_unknown_idle_time_stops_the_build(self) -> None:
        warmup = self.world.make()
        self._after_start(page_warmup.AFTER_S + 1)
        self.world.idle = page_warmup.IDLE_MS - 1

        warmup._on_timer()
        self.world.idle = None
        warmup._on_timer()

        self.assertEqual(self.world.built, [])

    def test_a_page_that_fails_to_build_does_not_stop_the_others(self) -> None:
        self.world.pages = [_Page("bad", self.world.built, fail=True), _Page("good", self.world.built)]
        warmup = self.world.make()
        self._after_start(page_warmup.AFTER_S + 1)

        warmup._on_timer()  # первая падает, ошибка не выходит наружу
        self.world.pages[0]._fail = False
        warmup._on_timer()

        self.assertIn("bad", self.world.built)

    def test_already_built_pages_are_skipped(self) -> None:
        self.world.pages[0]._page = object()
        warmup = self.world.make()
        self._after_start(page_warmup.AFTER_S + 1)

        warmup._on_timer()

        self.assertEqual(self.world.built, ["settings"])

    def test_idle_time_is_unknown_outside_windows(self) -> None:
        from unittest.mock import patch

        with patch.object(page_warmup.sys, "platform", "linux"):
            self.assertIsNone(page_warmup.user_idle_ms())

    def test_main_window_starts_the_warmup_after_creating_the_pages(self) -> None:
        source = MAIN_WINDOW.read_text(encoding="utf-8")
        self.assertIn("HiddenPageWarmup(", source)
        self.assertLess(source.index('self.about_page = DeferredPage'), source.index("HiddenPageWarmup("))


if __name__ == "__main__":
    unittest.main()
