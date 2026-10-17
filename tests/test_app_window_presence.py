"""Присутствие окна: память подтягивается при возврате из долгого фона (xray_fluent.ui.window_presence).

Жалоба пользователя 2026-10-17: окно долго в фоне, потом открываешь из панели
задач — «ничего не работает»: Windows отобрала память программы, и окно тянуло
её с диска по странице. Проверяется порядок действий, а не скорость диска.

Keep the ``test_app_*`` prefix (QApplication before tests/test_engine_process_stop.py).
"""

from __future__ import annotations

import inspect
import os
import re
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QWidget

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError("widget tests need a QApplication")
app = _existing or QApplication([])

from xray_fluent.platform.windows import working_set
from xray_fluent.platform.windows.working_set import PrefetchResult, WorkingSetSnapshot
from xray_fluent.ui import window_presence
from xray_fluent.ui.window_presence import WindowPresence, is_native_restore_command

MAIN_WINDOW = Path(__file__).resolve().parent.parent / "xray_fluent" / "ui" / "main_window.py"
SNAPSHOT = WorkingSetSnapshot(ranges=((0x1000, 0x2000), (0x8000, 0x1000)), total_bytes=0x3000, taken_ms=1.0)


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _make(window):
    calls: list[str] = []
    clock = _Clock()
    presence = WindowPresence(
        window,
        settle_ms=60_000,
        report_ms=60_000,
        min_away_for_prefetch_s=20.0,
        take_snapshot=lambda: calls.append("snapshot") or SNAPSHOT,
        prefetch=lambda snap: calls.append("prefetch") or PrefetchResult(len(snap.ranges), snap.total_bytes, 1.0, True),
        start_worker=lambda fn: fn(),
        clock=clock,
    )
    return presence, calls, clock


class WindowPresenceTests(unittest.TestCase):
    def _window(self, *, shown: bool = True) -> QWidget:
        window = QWidget()
        self.addCleanup(window.deleteLater)
        if shown:
            window.show()
            app.processEvents()
        return window

    def test_hidden_window_starts_away(self) -> None:
        presence, _calls, _clock = _make(self._window(shown=False))

        self.assertTrue(presence.away)

    def test_pages_are_remembered_once_the_window_stayed_away(self) -> None:
        window = self._window()
        presence, calls, _clock = _make(window)
        window.hide()
        self.assertTrue(presence._settle_timer.isActive())

        presence._settle_timer.stop()  # так таймер выглядит после срабатывания
        presence._on_settle_timeout()

        self.assertEqual(calls, ["snapshot"])

    def test_showing_the_window_cancels_a_pending_snapshot(self) -> None:
        window = self._window()
        presence, calls, _clock = _make(window)
        window.hide()

        window.show()
        app.processEvents()

        self.assertFalse(presence._settle_timer.isActive())
        presence._on_settle_timeout()
        self.assertEqual(calls, [])

    def test_return_intent_comes_before_qt_shows_a_minimized_window(self) -> None:
        window = self._window()
        presence, calls, clock = _make(window)
        window.setWindowState(Qt.WindowState.WindowMinimized)
        app.processEvents()
        presence._on_settle_timeout()
        clock.now += 600
        calls.clear()

        presence.return_intent()
        self.assertEqual(calls, ["prefetch"])

        # Позднее событие Qt уже ничего не повторяет.
        window.setWindowState(Qt.WindowState.WindowNoState)
        app.processEvents()
        self.assertEqual(calls, ["prefetch"])

    def test_short_absence_does_not_prefetch(self) -> None:
        window = self._window()
        presence, calls, clock = _make(window)
        window.hide()
        presence._on_settle_timeout()
        calls.clear()
        clock.now += 3

        presence.return_intent()

        self.assertEqual(calls, [])

    def test_return_before_the_snapshot_is_ready_does_not_fail(self) -> None:
        window = self._window()
        presence, calls, clock = _make(window)
        window.hide()
        clock.now += 600

        presence.return_intent()

        self.assertEqual(calls, [])

    def test_return_report_goes_to_the_log(self) -> None:
        window = self._window()
        presence, _calls, clock = _make(window)
        window.hide()
        presence._on_settle_timeout()
        clock.now += 600
        presence.return_intent()

        with patch.object(window_presence.LOG, "info") as info:
            presence._report_return()

        text = info.call_args.args[0] % info.call_args.args[1:]
        self.assertIn("window returned from background (600 s)", text)
        self.assertIn("prefetched", text)


class NativeRestoreTests(unittest.TestCase):
    def test_restore_command_is_recognised_and_other_commands_are_not(self) -> None:
        def message(command: int):
            return SimpleNamespace(message=window_presence.WM_SYSCOMMAND, wParam=command)

        with (
            patch.object(window_presence.sys, "platform", "win32"),
            patch("ctypes.wintypes.MSG") as msg_type,
        ):
            msg_type.from_address.side_effect = lambda address: message(address)
            self.assertTrue(is_native_restore_command(window_presence.SC_RESTORE))
            self.assertTrue(is_native_restore_command(window_presence.SC_RESTORE | 0x2))
            self.assertFalse(is_native_restore_command(0xF020))  # SC_MINIMIZE

    def test_other_systems_never_see_a_restore_command(self) -> None:
        with patch.object(window_presence.sys, "platform", "linux"):
            self.assertFalse(is_native_restore_command(1))

    def test_main_window_tells_presence_before_qt_handles_the_command(self) -> None:
        source = MAIN_WINDOW.read_text(encoding="utf-8")
        match = re.search(r"def nativeEvent\(.*?\n(?=    def )", source, re.S)
        self.assertIsNotNone(match)
        body = match.group(0)
        self.assertLess(body.index("is_native_restore_command"), body.index("super().nativeEvent"))
        self.assertIn("_window_presence.return_intent()", body)


class TrayToggleTests(unittest.TestCase):
    def _toggle_source(self) -> str:
        source = MAIN_WINDOW.read_text(encoding="utf-8")
        return re.search(r"def _toggle_window_visible\(.*?\n(?=    def )", source, re.S).group(0)

    def test_minimized_window_is_brought_back_not_hidden(self) -> None:
        # У свёрнутого окна isVisible() тоже True: клик по значку в трее прятал его.
        body = self._toggle_source()
        self.assertIn("self.isVisible() and not self.isMinimized()", body)
        self.assertIn("showNormal()", body)

    def test_tray_show_tells_presence_first(self) -> None:
        body = self._toggle_source()
        self.assertLess(body.index("return_intent()"), body.index("self.show()"))


class WorkingSetTests(unittest.TestCase):
    def test_neighbouring_pages_become_one_range(self) -> None:
        page = working_set.PAGE_SIZE
        merged = working_set._merge_pages([0x10000, 0x10000 + page, 0x10000 + 2 * page, 0x40000])

        self.assertEqual(merged, [(0x10000, 3 * page), (0x40000, page)])

    def test_other_systems_do_nothing(self) -> None:
        with patch.object(working_set.sys, "platform", "linux"):
            self.assertIsNone(working_set.snapshot_working_set())
            self.assertIsNone(working_set.prefetch_working_set(SNAPSHOT))

    def test_the_program_never_empties_its_own_working_set(self) -> None:
        for module in (working_set, window_presence):
            source = inspect.getsource(module)
            self.assertNotIn("EmptyWorkingSet(", source)
            self.assertNotIn("SetProcessWorkingSetSize", source)


if __name__ == "__main__":
    unittest.main()
