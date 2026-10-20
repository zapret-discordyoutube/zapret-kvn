"""Страницы строятся заранее, пока окно скрыто в трее и человек за компьютером ничего не делает.

Страницы окна (``DeferredPage``) строятся только при первом открытии. После запуска в
трей это значит: первое открытие окна строит всё, что человек нажмёт, прямо под щелчком,
в потоке окна, а код, который ни разу не выполнялся, никакое удержание памяти не
сохранит (в журнале Zapret 2 GUI 21.1.7.183 первый показ после трея — 5,6 с замирания).

Прогрев идёт тихо: не раньше чем через ``AFTER_S`` после запуска, только когда окно
скрыто или свёрнуто и человек не трогал мышь и клавиатуру ``IDLE_MS``, по одной странице
с паузой ``GAP_MS``. Окно на экране прогрев не трогает: страницы тогда строит сам человек
своими щелчками. Цена — память нескольких страниц, пока программа сидит в трее
(решение пользователя 2026-10-20 для Zapret 2 GUI, здесь так же).
"""

from __future__ import annotations

import ctypes
import logging
import sys
import time
from collections.abc import Callable, Sequence
from ctypes import wintypes

from PyQt6.QtCore import QObject, QTimer

LOG = logging.getLogger("xray_fluent.page_warmup")

# Не раньше чем через столько после запуска.
AFTER_S = 120.0
# Сколько человек должен не трогать мышь и клавиатуру.
IDLE_MS = 60_000
# Пауза между страницами.
GAP_MS = 3_000
# Как часто проверять, не пора ли.
POLL_MS = 5_000


class _LastInputInfo(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]


def user_idle_ms() -> int | None:
    """Сколько миллисекунд человек не трогал мышь и клавиатуру; не Windows или сбой — None."""
    if sys.platform != "win32":
        return None
    try:
        info = _LastInputInfo()
        info.cbSize = ctypes.sizeof(info)
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetTickCount.restype = wintypes.DWORD
        if not user32.GetLastInputInfo(ctypes.byref(info)):
            return None
        return int((kernel32.GetTickCount() - info.dwTime) & 0xFFFFFFFF)
    except Exception:
        return None


class HiddenPageWarmup(QObject):
    """Строит отложенные страницы по одной, пока окно скрыто и человек отошёл."""

    def __init__(
        self,
        window,
        pages: Callable[[], Sequence[object]],
        *,
        idle_ms: Callable[[], int | None] = user_idle_ms,
        clock: Callable[[], float] = time.monotonic,
        after_s: float = AFTER_S,
        required_idle_ms: int = IDLE_MS,
        gap_ms: int = GAP_MS,
        poll_ms: int = POLL_MS,
    ) -> None:
        super().__init__(window)
        self._window = window
        self._pages = pages
        self._idle_ms = idle_ms
        self._clock = clock
        self._started_at = clock()
        self._after_s = float(after_s)
        self._required_idle_ms = int(required_idle_ms)
        self._gap_ms = int(gap_ms)
        self._poll_ms = int(poll_ms)
        self._finished = False
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._on_timer)
        self._timer.start(self._poll_ms)

    @property
    def finished(self) -> bool:
        return self._finished

    def _window_on_screen(self) -> bool:
        window = self._window
        try:
            return bool(window.isVisible()) and not bool(window.isMinimized())
        except Exception:
            return True

    def _pending(self) -> list[object]:
        return [page for page in self._pages() if getattr(page, "_page", object()) is None]

    def _may_build_now(self) -> bool:
        if self._clock() - self._started_at < self._after_s:
            return False
        if self._window_on_screen():
            return False
        try:
            idle = self._idle_ms()
        except Exception:
            idle = None
        return idle is not None and int(idle) >= self._required_idle_ms

    def _on_timer(self) -> None:
        pending = self._pending()
        if not pending:
            self._finished = True
            return
        delay = self._poll_ms
        if self._may_build_now():
            started = time.perf_counter()
            try:
                pending[0].ensure_page()
            except Exception as exc:  # noqa: BLE001 — прогрев не должен ронять окно
                LOG.info("page warmup failed for %r: %s", pending[0], exc)
            else:
                LOG.info("page warmup: built %s in %.0f ms", getattr(pending[0], "objectName", lambda: "?")(), (time.perf_counter() - started) * 1000)
            delay = max(self._gap_ms, self._poll_ms)
        self._timer.start(delay)


__all__ = ["AFTER_S", "GAP_MS", "HiddenPageWarmup", "IDLE_MS", "POLL_MS", "user_idle_ms"]
