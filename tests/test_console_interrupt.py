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


if __name__ == "__main__":
    unittest.main()
