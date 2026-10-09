"""Журнал сообщений Qt должен сохранять фатальное сообщение до гибели процесса."""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace

from PyQt6.QtCore import QtMsgType, qWarning

from xray_fluent.diagnostics import qt_message_log
from xray_fluent.diagnostics.qt_message_log import (
    MAX_DISTINCT_MESSAGES,
    MAX_LOG_BYTES,
    QT_MESSAGE_LOG_NAME,
    QtMessageLog,
)

ROOT = Path(__file__).resolve().parents[1]

_FATAL_SCRIPT = """
import sys
from pathlib import Path

from PyQt6.QtCore import qFatal

from xray_fluent.diagnostics import qt_message_log


def culprit_function():
    qFatal("QThread: Destroyed while thread is still running")


qt_message_log.install(Path(sys.argv[1]))
culprit_function()
"""


def _context(**fields):
    return SimpleNamespace(**{"category": "default", "file": None, "line": 0, "function": None, **fields})


class QtFatalSurvivesAbortTests(unittest.TestCase):
    def test_fatal_message_and_python_stack_reach_disk_before_abort(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, "-c", textwrap.dedent(_FATAL_SCRIPT), tmp],
                cwd=ROOT,
                capture_output=True,
                timeout=60,
            )
            # qFatal обязан убить процесс: иначе тест ничего не доказывает.
            self.assertNotEqual(result.returncode, 0)
            text = (Path(tmp) / QT_MESSAGE_LOG_NAME).read_text(encoding="utf-8")
        self.assertIn("FATAL", text)
        self.assertIn("QThread: Destroyed while thread is still running", text)
        self.assertIn("culprit_function", text)


class QtMessageLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / QT_MESSAGE_LOG_NAME
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        self.console = io.StringIO()
        self.log = QtMessageLog(fd, self.path, console=self.console)
        self.addCleanup(self.log.close)

    def _text(self) -> str:
        return self.path.read_text(encoding="utf-8")

    def test_repeated_warning_is_written_once(self) -> None:
        for _ in range(5):
            self.log(QtMsgType.QtWarningMsg, _context(), "QFont::setPointSize: Point size <= 0")
        self.assertEqual(self._text().count("Point size"), 1)

    def test_distinct_warnings_are_bounded(self) -> None:
        for index in range(MAX_DISTINCT_MESSAGES + 50):
            self.log(QtMsgType.QtWarningMsg, _context(), f"warning {index}")
        self.assertEqual(len(self._text().splitlines()), MAX_DISTINCT_MESSAGES)

    def test_fatal_is_written_even_after_the_warning_limit(self) -> None:
        for index in range(MAX_DISTINCT_MESSAGES + 1):
            self.log(QtMsgType.QtWarningMsg, _context(), f"warning {index}")
        self.log(QtMsgType.QtFatalMsg, _context(), "ASSERT failure")
        self.assertIn("FATAL", self._text())
        self.assertIn("ASSERT failure", self._text())

    def test_debug_goes_to_console_only(self) -> None:
        self.log(QtMsgType.QtDebugMsg, _context(), "just noise")
        self.assertEqual(self._text(), "")
        self.assertIn("just noise", self.console.getvalue())

    def test_context_is_recorded(self) -> None:
        self.log(
            QtMsgType.QtCriticalMsg,
            _context(category="qt.core.qobject", file="qobject.cpp", line=42, function="QObject::startTimer"),
            "Timers cannot be started from another thread",
        )
        text = self._text()
        self.assertIn("category=qt.core.qobject", text)
        self.assertIn("at=qobject.cpp:42", text)
        self.assertIn("in=QObject::startTimer", text)

    def test_broken_context_does_not_raise(self) -> None:
        class Broken:
            def __getattr__(self, name):
                raise RuntimeError("no context")

        self.log(QtMsgType.QtWarningMsg, Broken(), "still alive")


class QtMessageLogInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(qt_message_log.uninstall)
        self.log_dir = Path(self._tmp.name) / "logs"

    def test_installed_handler_receives_real_qt_warning(self) -> None:
        log = qt_message_log.install(self.log_dir)
        self.assertIsNotNone(log)
        log._console = None
        qWarning("real warning from Qt")
        self.assertIn("real warning from Qt", log.path.read_text(encoding="utf-8"))

    def test_oversized_log_is_rotated_on_install(self) -> None:
        self.log_dir.mkdir(parents=True)
        path = self.log_dir / QT_MESSAGE_LOG_NAME
        path.write_bytes(b"x" * (MAX_LOG_BYTES + 1))
        qt_message_log.install(self.log_dir)
        self.assertEqual(path.stat().st_size, 0)
        self.assertEqual(path.with_name(path.name + ".1").stat().st_size, MAX_LOG_BYTES + 1)

    def test_unwritable_directory_does_not_break_startup(self) -> None:
        blocker = Path(self._tmp.name) / "file"
        blocker.write_text("not a directory", encoding="utf-8")
        self.assertIsNone(qt_message_log.install(blocker / "logs"))


if __name__ == "__main__":
    unittest.main()
