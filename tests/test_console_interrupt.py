"""Ctrl+C в консоли собранного приложения не должен срывать запуск."""

from __future__ import annotations

import signal
import unittest
from unittest.mock import patch

import main


class ConsoleInterruptTests(unittest.TestCase):
    def setUp(self) -> None:
        previous = signal.getsignal(signal.SIGINT)
        self.addCleanup(signal.signal, signal.SIGINT, previous)
        signal.signal(signal.SIGINT, signal.default_int_handler)

    def test_frozen_app_ignores_ctrl_c(self) -> None:
        with patch.object(main.sys, "frozen", True, create=True):
            main._ignore_console_interrupt()
        self.assertIs(signal.getsignal(signal.SIGINT), signal.SIG_IGN)

    def test_source_run_keeps_ctrl_c(self) -> None:
        with patch.object(main.sys, "frozen", False, create=True):
            main._ignore_console_interrupt()
        self.assertIs(signal.getsignal(signal.SIGINT), signal.default_int_handler)

    def test_startup_ignores_ctrl_c_before_anything_else(self) -> None:
        import inspect

        body = inspect.getsource(main.main)
        self.assertLess(body.index("_ignore_console_interrupt()"), body.index("_update_plan_argument()"))


class ExitTimeErrorTests(unittest.TestCase):
    """startup.log 2026-11-19: an error while the old version closed for an update showed «не удалось запустить»
    although the new version started fine. After the event loop it is logged only."""

    def test_error_after_the_event_loop_is_logged_without_the_startup_box(self) -> None:
        self.addCleanup(setattr, main, "_event_loop_exited", False)
        main._event_loop_exited = True
        with patch.object(main, "_show_fatal_message_box") as box, patch.object(main._bootstrap_logger, "exception") as log:
            main._log_unhandled_exception(RuntimeError, RuntimeError("deleted"), None)
        box.assert_not_called()
        self.assertIn("after the event loop exited", log.call_args.args[0])

    def test_error_while_running_still_shows_the_box(self) -> None:
        with patch.object(main, "_show_fatal_message_box") as box, patch.object(main._bootstrap_logger, "exception"):
            main._log_unhandled_exception(RuntimeError, RuntimeError("boom"), None)
        box.assert_called_once()


if __name__ == "__main__":
    unittest.main()
