"""Сообщения, появившиеся до создания окна и ждущие показа пользователю.

Синхронизация шаблонов идёт в bootstrap, когда интерфейса ещё нет. То, что
пользователю нужно узнать о её итогах, складывается сюда и показывается
главным окном один раз после запуска.
"""

from __future__ import annotations

import threading

_lock = threading.Lock()
_pending: list[tuple[str, str]] = []


def add(level: str, message: str) -> None:
    with _lock:
        if (level, message) not in _pending:
            _pending.append((level, message))


def drain() -> list[tuple[str, str]]:
    with _lock:
        notices = list(_pending)
        _pending.clear()
    return notices
