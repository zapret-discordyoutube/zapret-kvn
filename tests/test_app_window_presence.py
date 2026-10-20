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
from xray_fluent.platform.windows.working_set import PrefetchResult, WorkingSetHold, WorkingSetSnapshot
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
            # «Минус единицы» в SetProcessWorkingSetSizeEx — это выгрузка памяти.
            self.assertNotIn("(-1", source)
            self.assertNotIn("c_size_t(-1)", source)
        # Работает с минимумом рабочего набора только модуль working_set, не само окно.
        self.assertNotIn("SetProcessWorkingSetSize", inspect.getsource(window_presence))
        self.assertNotIn("import psutil", inspect.getsource(window_presence))

    def test_weak_pc_with_under_a_gigabyte_free_is_still_protected(self) -> None:
        mb = 1 << 20
        self.assertIsNotNone(working_set.hold_size_for(80 * mb, 700 * mb))
        size = 80 * mb + working_set.HOLD_MARGIN_BYTES
        self.assertIsNone(working_set.hold_size_for(80 * mb, size + working_set.HOLD_SPARE_BYTES - 1))
        self.assertIsNone(working_set.hold_size_for(None, None))
        self.assertIsNone(working_set.hold_size_for(working_set.HOLD_MIN_BYTES - 1, None))

    def test_hold_and_counters_do_nothing_outside_windows(self) -> None:
        with patch.object(working_set.sys, "platform", "linux"):
            self.assertIsNone(working_set.hold_working_set(100 << 20))
            self.assertFalse(working_set.release_working_set_hold())
            self.assertIsNone(working_set.current_working_set_bytes())
            self.assertIsNone(working_set.available_physical_bytes())
            self.assertIsNone(working_set.process_page_faults())


class EarlyAwayIntentTests(unittest.TestCase):
    """Windows сжимает набор свёрнутого окна сразу: защита ставится до этого, а не после."""

    def _window(self) -> QWidget:
        window = QWidget()
        self.addCleanup(window.deleteLater)
        window.show()
        app.processEvents()
        return window

    def _make(self, window, *, snapshots=None):
        events: list[str] = []
        queue = list(snapshots or [SNAPSHOT])
        presence = WindowPresence(
            window,
            settle_ms=60_000,
            report_ms=60_000,
            min_away_for_prefetch_s=20.0,
            take_snapshot=lambda: events.append("snapshot") or (queue.pop(0) if len(queue) > 1 else queue[0]),
            prefetch=lambda snap: events.append("prefetch") or PrefetchResult(len(snap.ranges), snap.total_bytes, 1.0, True),
            hold=lambda: events.append("hold") or WorkingSetHold(bytes=80 << 20, ok=True, error=0),
            release_hold=lambda: events.append("release"),
            start_worker=lambda fn: fn(),
            clock=_Clock(),
        )
        events.clear()
        return presence, events

    def test_intent_holds_and_remembers_pages_before_the_window_leaves(self) -> None:
        window = self._window()
        presence, events = self._make(window)

        presence.away_intent()

        self.assertEqual(events, ["hold", "snapshot"])
        # Состояние «в фоне» сам сигнал не ставит: сворачивание могло не состояться.
        self.assertFalse(presence.away)

    def test_the_late_qt_event_does_not_repeat_the_snapshot_but_keeps_the_hold(self) -> None:
        window = self._window()
        presence, events = self._make(window)
        presence.away_intent()
        events.clear()

        window.hide()
        app.processEvents()

        self.assertTrue(presence.away)
        self.assertEqual(events, ["hold"])

    def test_window_that_stayed_on_screen_gets_its_protection_removed(self) -> None:
        window = self._window()
        presence, events = self._make(window)
        presence.away_intent()
        events.clear()

        presence._on_intent_timeout()

        self.assertEqual(events, ["release"])

    def test_window_that_left_is_not_released_by_the_intent_timer(self) -> None:
        window = self._window()
        presence, events = self._make(window)
        presence.away_intent()
        window.hide()
        app.processEvents()
        events.clear()

        presence._on_intent_timeout()

        self.assertEqual(events, [])

    def test_return_releases_the_hold_even_after_a_short_absence(self) -> None:
        window = self._window()
        presence, events = self._make(window)
        window.hide()
        app.processEvents()
        events.clear()

        presence.return_intent()

        self.assertEqual(events, ["release"])

    def test_poorer_snapshot_taken_after_the_trim_does_not_replace_the_full_one(self) -> None:
        full = WorkingSetSnapshot(ranges=((0x1000, 0x9000),), total_bytes=0x9000, taken_ms=1.0)
        trimmed = WorkingSetSnapshot(ranges=((0x1000, 0x1000),), total_bytes=0x1000, taken_ms=1.0)
        window = self._window()
        presence, _events = self._make(window, snapshots=[full, trimmed])

        presence.away_intent()
        window.hide()
        app.processEvents()
        presence._on_settle_timeout()

        self.assertIs(presence._snapshot, full)

    def test_hold_size_follows_the_hot_size_not_the_trimmed_one(self) -> None:
        window = self._window()
        presence = WindowPresence(window, start_worker=lambda fn: fn())
        presence._hot_bytes = 150 << 20

        with (
            patch.object(window_presence, "current_working_set_bytes", return_value=10 << 20),
            patch.object(window_presence, "available_physical_bytes", return_value=4096 << 20),
            patch.object(window_presence, "hold_working_set") as hold,
        ):
            presence._hold_hot_set()

        self.assertGreaterEqual(hold.call_args.args[0], 150 << 20)

    def test_minimize_command_is_recognised_and_main_window_tells_presence_first(self) -> None:
        def message(command: int):
            return SimpleNamespace(message=window_presence.WM_SYSCOMMAND, wParam=command)

        with (
            patch.object(window_presence.sys, "platform", "win32"),
            patch("ctypes.wintypes.MSG") as msg_type,
        ):
            msg_type.from_address.side_effect = lambda address: message(address)
            self.assertTrue(window_presence.is_native_minimize_command(window_presence.SC_MINIMIZE))
            self.assertFalse(window_presence.is_native_minimize_command(window_presence.SC_RESTORE))

        source = MAIN_WINDOW.read_text(encoding="utf-8")
        body = re.search(r"def nativeEvent\(.*?\n(?=    def )", source, re.S).group(0)
        self.assertIn("is_native_minimize_command", body)
        self.assertIn("_window_presence.away_intent()", body)
        for name in ("_toggle_window_visible", "closeEvent"):
            method = re.search(rf"def {name}\(.*?(?=\n    def |\Z)", source, re.S).group(0)
            self.assertLess(method.index("away_intent()"), method.index("self.hide()"), name)


class AwayHoldRefreshTests(unittest.TestCase):
    """Запуск в трей: хватка берётся рано, потом память растёт — хватка растёт вместе с ней."""

    def _make(self, window):
        sizes: list[int] = []

        def hold():
            size = (len(sizes) + 1) * 100 << 20
            sizes.append(size)
            return WorkingSetHold(bytes=size, ok=True, error=0)

        window.show()
        app.processEvents()
        presence = WindowPresence(
            window,
            settle_ms=60_000,
            report_ms=60_000,
            min_away_for_prefetch_s=20.0,
            take_snapshot=lambda: SNAPSHOT,
            prefetch=lambda snap: PrefetchResult(len(snap.ranges), snap.total_bytes, 1.0, True),
            hold=hold,
            release_hold=lambda: None,
            start_worker=lambda fn: fn(),
            clock=_Clock(),
        )
        sizes.clear()
        window.hide()
        app.processEvents()
        return presence, sizes

    def _window(self) -> QWidget:
        window = QWidget()
        self.addCleanup(window.deleteLater)
        return window

    def test_hold_is_raised_when_the_program_grew_while_hidden(self) -> None:
        presence, sizes = self._make(self._window())
        self.assertEqual(sizes, [100 << 20])

        with patch.object(window_presence, "current_working_set_bytes", return_value=150 << 20):
            presence._refresh_hold_if_grown()

        self.assertEqual(sizes, [100 << 20, 200 << 20])

    def test_hold_is_not_touched_when_nothing_grew(self) -> None:
        presence, sizes = self._make(self._window())

        with patch.object(window_presence, "current_working_set_bytes", return_value=105 << 20):
            presence._refresh_hold_if_grown()

        self.assertEqual(sizes, [100 << 20])

    def test_refresh_runs_only_while_the_window_is_away(self) -> None:
        window = self._window()
        presence, sizes = self._make(window)
        self.assertTrue(presence._away_refresh_timer.isActive())

        window.show()
        app.processEvents()
        self.assertFalse(presence._away_refresh_timer.isActive())

        sizes.clear()
        with patch.object(window_presence, "current_working_set_bytes", return_value=900 << 20):
            presence._on_away_refresh()
        self.assertEqual(sizes, [])


class DashboardVisibilityTests(unittest.TestCase):
    """Скрытое окно не обновляет дашборд: изменения раскладки копились бы до показа."""

    def _window(self, *, on_dashboard=True, visible=True, minimized=False):
        from xray_fluent.ui.main_window import MainWindow

        dashboard = object()
        window = SimpleNamespace(
            dashboard_page=dashboard,
            stackedWidget=SimpleNamespace(currentWidget=lambda: dashboard if on_dashboard else object()),
            isVisible=lambda: visible,
            isMinimized=lambda: minimized,
        )
        window._is_dashboard_active = lambda: MainWindow._is_dashboard_active(window)
        return MainWindow, window

    def test_dashboard_is_active_only_when_the_window_is_on_screen(self) -> None:
        cls, window = self._window()
        self.assertTrue(cls._is_dashboard_active(window))
        for kwargs in ({"visible": False}, {"minimized": True}, {"on_dashboard": False}):
            _cls, window = self._window(**kwargs)
            self.assertFalse(cls._is_dashboard_active(window), kwargs)

    def test_metrics_wait_while_hidden_and_arrive_after_the_window_returns(self) -> None:
        from unittest.mock import Mock

        cls, window = self._window(visible=False)
        window._deferred_dashboard_metrics = None
        window._deferred_process_stats = None
        window._has_deferred_process_stats = False
        window.dashboard_page = Mock()
        window.stackedWidget = SimpleNamespace(currentWidget=lambda: window.dashboard_page)
        window._is_dashboard_active = lambda: cls._is_dashboard_active(window)

        cls._on_live_metrics_updated(window, {"down_bps": 5.0, "up_bps": 2.0, "latency_ms": 40, "process_stats": [1]})
        window.dashboard_page.set_live_metrics.assert_not_called()

        window.isVisible = lambda: True
        cls._flush_deferred_dashboard_metrics(window)

        window.dashboard_page.set_live_metrics.assert_called_once_with(5.0, 2.0, 40)
        window.dashboard_page.set_process_stats.assert_called_once_with([1])
        self.assertIsNone(window._deferred_dashboard_metrics)


if __name__ == "__main__":
    unittest.main()
