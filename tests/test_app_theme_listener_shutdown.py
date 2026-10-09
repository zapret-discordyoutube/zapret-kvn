"""Слушатель системной темы обязан завершаться до разрушения окон.

Иначе окно остаётся с работающим дочерним QThread и процесс падает на выходе:
``QThread: Destroyed while thread is still running`` (0xc0000409 в Qt6Core.dll).

Keep the ``test_app_*`` prefix: widget test modules must sort before
``tests/test_engine_process_stop.py`` which creates a bare QCoreApplication
at import time (see tests/test_app_nodes_page_view.py).
"""

from __future__ import annotations

import os
import sys
import threading
import unittest
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6 import sip
from PyQt6.QtCore import QThread
from PyQt6.QtWidgets import QApplication, QWidget

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError("widget tests need a QApplication")
app = _existing or QApplication([])

from xray_fluent.platform.windows.theme_watch import ThemeRegistryWatch
from xray_fluent.ui import theme


def _running_threads(window: QWidget) -> list[QThread]:
    return [thread for thread in window.findChildren(QThread) if thread.isRunning()]


class StoppableListenerTests(unittest.TestCase):
    def setUp(self) -> None:
        # Проверяется остановка потока, а не смена темы: настоящий слушатель
        # перекрасил бы виджеты соседних тестов из фонового потока.
        patcher = mock.patch.object(
            theme.StoppableSystemThemeListener, "_onThemeChanged", lambda self, name: None
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(theme.stop_system_theme_listener)

    def test_real_listener_stops_on_request(self) -> None:
        listener = theme.sync_system_theme_listener("system")
        self.assertIsInstance(listener, theme.StoppableSystemThemeListener)
        self.assertTrue(listener.isRunning())

        self.assertTrue(theme.stop_system_theme_listener())

        self.assertFalse(listener.isRunning())
        self.assertIsNone(theme.system_theme_listener())

    def test_leaving_system_mode_stops_the_real_thread(self) -> None:
        listener = theme.sync_system_theme_listener("system")
        self.assertIsNone(theme.sync_system_theme_listener("dark"))
        self.assertFalse(listener.isRunning())

    def test_stop_without_listener_is_a_no_op(self) -> None:
        self.assertTrue(theme.stop_system_theme_listener())

    def test_window_has_no_running_thread_once_the_listener_is_stopped(self) -> None:
        window = QWidget()
        self.addCleanup(sip.delete, window)
        theme.sync_system_theme_listener("system", window)
        # Ровно это условие заставляет dispose_windows оставить окно до
        # выхода из интерпретатора, где его разрушение — уже qFatal.
        self.assertEqual(len(_running_threads(window)), 1)

        self.assertTrue(theme.stop_system_theme_listener())

        self.assertEqual(_running_threads(window), [])

    def test_unstoppable_listener_is_reported(self) -> None:
        class Stuck:
            def __init__(self, parent=None):
                pass

            def start(self) -> None:
                pass

            def stop(self) -> bool:
                return False

            def deleteLater(self) -> None:
                pass

        theme.sync_system_theme_listener("system", None, Stuck)
        self.assertFalse(theme.stop_system_theme_listener())


class MainWindowShutdownWiringTests(unittest.TestCase):
    def test_background_shutdown_stops_the_listener_first(self) -> None:
        import inspect

        from xray_fluent.ui.main_window import MainWindow

        source = inspect.getsource(MainWindow.finish_background_shutdown)
        self.assertIn("stop_system_theme_listener()", source)


@unittest.skipUnless(sys.platform == "win32", "registry notifications exist only on Windows")
class ThemeRegistryWatchTests(unittest.TestCase):
    def test_run_returns_after_stop(self) -> None:
        watch = ThemeRegistryWatch()
        thread = threading.Thread(target=watch.run, args=(lambda _theme: None,), daemon=True)
        thread.start()
        thread.join(0.3)
        self.assertTrue(thread.is_alive(), "the watch must block while nothing changes")

        watch.stop()
        thread.join(5)

        self.assertFalse(thread.is_alive())
        watch.close()

    def test_stop_before_run_returns_immediately(self) -> None:
        watch = ThemeRegistryWatch()
        watch.stop()
        thread = threading.Thread(target=watch.run, args=(lambda _theme: None,), daemon=True)
        thread.start()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        watch.close()


if __name__ == "__main__":
    unittest.main()
