"""Field crashes of the main window (field check #5, 2026-11-25), tested without building the window."""
from __future__ import annotations

import unittest
from types import MethodType
from unittest.mock import Mock, patch

from xray_fluent.platform.windows.win32_errors import is_win32_error
from xray_fluent.ui import main_window
from xray_fluent.ui.main_window import MainWindow


def _pywintypes_error() -> BaseException:
    # Same identity as the real class (checked on win10: module pywintypes, name error, not an OSError).
    kind = type("error", (Exception,), {"__module__": "pywintypes"})
    return kind(5, "GetCursorPos", "Access is denied.")


class _Shell:
    """A window whose initialize() has not finished: no pages yet."""

    def __init__(self) -> None:
        self._quitting = False
        self._window_built = False
        self._build_waits = 0
        self._when_built = MethodType(MainWindow._when_built, self)


class StartupResultBeforeWindowTest(unittest.TestCase):
    def test_failure_before_the_pages_exist_is_shown_after_them(self) -> None:
        # 0.8.108: «failed» reached main.failed → _startup_failed while dashboard_page did not exist yet.
        shell = _Shell()
        retries = []
        with patch.object(main_window.QTimer, "singleShot", side_effect=lambda ms, fn: retries.append(fn)):
            MainWindow._startup_failed(shell, "Не удалось загрузить данные приложения")
        self.assertEqual(len(retries), 1)

        shell._window_built = True
        shell.dashboard_page = Mock()
        shell._show_status = Mock()
        shell._startup_failed = MethodType(MainWindow._startup_failed, shell)
        retries[0]()
        shell.dashboard_page.set_runtime_status.assert_called_once_with("error", "Не удалось загрузить данные приложения")
        shell._show_status.assert_called_once_with("error", "Не удалось загрузить данные приложения")

    def test_old_code_shape_raises_the_field_attribute_error(self) -> None:
        shell = _Shell()
        shell._window_built = True  # what the old code assumed
        with self.assertRaises(AttributeError):
            MainWindow._startup_failed(shell, "x")

    def test_waiting_for_a_window_that_never_appears_stops(self) -> None:
        shell = _Shell()
        retries = []
        with patch.object(main_window.QTimer, "singleShot", side_effect=lambda ms, fn: retries.append(fn)):
            for _ in range(250):
                MainWindow._startup_failed(shell, "x")
        self.assertEqual(len(retries), 200)

    def test_loaded_state_before_the_pages_exist_waits_too(self) -> None:
        shell = _Shell()
        shell._geometry_persistence_ready = False
        shell._ask_startup_password = MethodType(MainWindow._ask_startup_password, shell)
        retries = []
        with patch.object(main_window.QTimer, "singleShot", side_effect=lambda ms, fn: retries.append(fn)):
            MainWindow.complete_initialization(shell, object(), object())
            MainWindow._ask_startup_password(shell)
        self.assertEqual(len(retries), 2)


class NativeEventWin32ErrorTest(unittest.TestCase):
    def test_recognises_only_pywintypes_error(self) -> None:
        self.assertTrue(is_win32_error(_pywintypes_error()))
        self.assertFalse(is_win32_error(OSError(5, "denied")))
        self.assertFalse(is_win32_error(type("error", (Exception,), {"__module__": "zlib"})()))

    def _window(self) -> MainWindow:
        window = MainWindow.__new__(MainWindow)
        window._window_presence = Mock()
        return window

    def test_refused_cursor_call_falls_back_to_qt(self) -> None:
        # 0.8.107/0.8.108: crash:error at qframelesswindow nativeEvent:126 (win32api.GetCursorPos) ← main_window.nativeEvent.
        parent = MainWindow.__mro__[1]
        with patch.object(parent, "nativeEvent", side_effect=_pywintypes_error()):
            self.assertEqual(MainWindow.nativeEvent(self._window(), b"windows_generic_MSG", 0), (False, 0))

    def test_other_errors_still_reach_the_crash_hook(self) -> None:
        parent = MainWindow.__mro__[1]
        with patch.object(parent, "nativeEvent", side_effect=ValueError("ours")):
            with self.assertRaises(ValueError):
                MainWindow.nativeEvent(self._window(), b"windows_generic_MSG", 0)


if __name__ == "__main__":
    unittest.main()
