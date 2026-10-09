"""Журнал сообщений Qt: фатальное сообщение сохраняется до гибели процесса.

``qFatal()`` в Qt 6 для MSVC завершается ``__fastfail`` (исключение
0xc0000409, параметр 7). Он обходит все обработчики исключений, поэтому
``faulthandler`` из ``main.py`` ничего не записывает, а сам текст сообщения Qt
пишет в stderr уровня C — мимо ``sys.stderr``, который ведёт в startup.log.
От падения оставалась только запись в журнале Windows со смещением внутри
Qt6Core.dll, по которому причину не найти.

Обработчик пишет в ``data/logs/qt-messages.log`` напрямую через дескриптор:
без буферов Python, чтобы строка пережила завершение процесса. Для
фатального сообщения следом идут стеки всех потоков Python и ``fsync``.
"""

from __future__ import annotations

import faulthandler
import logging
import os
import sys
import threading
import time
from pathlib import Path

from PyQt6.QtCore import QtMsgType, qInstallMessageHandler

QT_MESSAGE_LOG_NAME = "qt-messages.log"
MAX_LOG_BYTES = 512 * 1024
# Предупреждения Qt бывают однотипными и частыми (шрифты, таймеры): каждое
# разное пишется один раз, а всего их не больше этого числа за запуск.
MAX_DISTINCT_MESSAGES = 200

_LEVELS = {
    QtMsgType.QtDebugMsg: "DEBUG",
    QtMsgType.QtInfoMsg: "INFO",
    QtMsgType.QtWarningMsg: "WARNING",
    QtMsgType.QtCriticalMsg: "CRITICAL",
    QtMsgType.QtFatalMsg: "FATAL",
}
_RECORDED = {QtMsgType.QtWarningMsg, QtMsgType.QtCriticalMsg, QtMsgType.QtFatalMsg}


class QtMessageLog:
    """Обработчик сообщений Qt.

    Всё нужное хранится в атрибутах экземпляра: фатальное сообщение может
    прийти при финализации интерпретатора, когда глобальные имена модулей уже
    недоступны.
    """

    def __init__(self, fd: int, path: Path, console=None, logger: logging.Logger | None = None) -> None:
        self.path = path
        self._fd = fd
        self._console = console
        self._logger = logger
        self._seen: set[tuple[str, str]] = set()
        self._lock = threading.Lock()
        self._levels = dict(_LEVELS)
        self._recorded = set(_RECORDED)
        self._fatal = QtMsgType.QtFatalMsg
        self._write = os.write
        self._fsync = os.fsync
        self._strftime = time.strftime
        self._native_id = threading.get_native_id
        self._dump_traceback = faulthandler.dump_traceback

    def __call__(self, msg_type, context, message) -> None:
        # Исключение из обработчика скрыло бы само сообщение.
        try:
            self._handle(msg_type, context, message)
        except BaseException:
            pass

    def _handle(self, msg_type, context, message) -> None:
        level = self._levels.get(msg_type, "UNKNOWN")
        text = str(message)
        self._echo(level, text)
        if msg_type not in self._recorded:
            return
        fatal = msg_type == self._fatal
        if not fatal and not self._first_occurrence(level, text):
            return
        self._write(self._fd, self._format(level, context, text).encode("utf-8", "replace"))
        if not fatal:
            return
        self._write(self._fd, "Стеки потоков Python в момент сообщения:\n".encode("utf-8"))
        try:
            self._dump_traceback(self._fd, all_threads=True)
        except BaseException:
            pass
        self._write(self._fd, b"\n")
        self._fsync(self._fd)
        if self._logger is not None:
            self._logger.critical("Qt fatal: %s (стеки потоков: %s)", text, self.path)

    def _first_occurrence(self, level: str, text: str) -> bool:
        key = (level, text)
        with self._lock:
            if key in self._seen or len(self._seen) >= MAX_DISTINCT_MESSAGES:
                return False
            self._seen.add(key)
            return True

    def _format(self, level: str, context, text: str) -> str:
        parts = [self._strftime("%Y-%m-%d %H:%M:%S"), level, f"thread={self._native_id()}"]
        category = getattr(context, "category", None)
        if category and category != "default":
            parts.append(f"category={category}")
        file = getattr(context, "file", None)
        if file:
            parts.append(f"at={file}:{getattr(context, 'line', 0)}")
        function = getattr(context, "function", None)
        if function:
            parts.append(f"in={function}")
        return "  ".join(parts) + "  " + text + "\n"

    def _echo(self, level: str, text: str) -> None:
        # Свой обработчик отключает вывод Qt по умолчанию; консоль при запуске
        # из исходников и в тестах должна показывать то же, что раньше.
        if self._console is None:
            return
        try:
            self._console.write(f"Qt {level}: {text}\n")
            self._console.flush()
        except Exception:
            pass

    def close(self) -> None:
        try:
            os.close(self._fd)
        except OSError:
            pass


_installed: QtMessageLog | None = None


def _rotate(path: Path) -> None:
    try:
        if path.stat().st_size > MAX_LOG_BYTES:
            os.replace(path, path.with_name(path.name + ".1"))
    except OSError:
        pass


def install(log_dir: Path, logger: logging.Logger | None = None) -> QtMessageLog | None:
    """Поставить обработчик; ``None`` — журнал открыть не удалось."""

    global _installed
    if _installed is not None:
        return _installed
    path = Path(log_dir) / QT_MESSAGE_LOG_NAME
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        _rotate(path)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    except OSError:
        if logger is not None:
            logger.exception("Failed to open Qt message log")
        return None
    _installed = QtMessageLog(fd, path, console=getattr(sys, "__stderr__", None), logger=logger)
    qInstallMessageHandler(_installed)
    return _installed


def uninstall() -> None:
    global _installed
    if _installed is None:
        return
    qInstallMessageHandler(None)
    _installed.close()
    _installed = None
