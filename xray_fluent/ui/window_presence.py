"""Присутствие окна: смотрит ли сейчас человек на программу и что делать при возврате из фона.

Окно из панели задач разворачивает Windows, и программа узнавала об этом, когда
Qt уже начал рисовать. На слабом ПК после долгого фона это давало «ничего не
работает» на десятки секунд: Windows за время фона отобрала память программы, и
окно подтягивало её с диска по 4 КБ за обращение (замер на win10: после выгрузки
возврат стоит ~11 000 таких обращений).

Уход в фон (свёрнуто или скрыто в трей): через AWAY_SETTLE_MS, если окно всё ещё
в фоне, запоминается, какие страницы памяти программе нужны (снимок рабочего
набора).

Возврат (самый ранний из сигналов: команда Windows «развернуть» ``SC_RESTORE``,
показ из трея, событие показа Qt): если окно было в фоне заметно долго, в
отдельном потоке запрашивается подтягивание запомненных страниц большими
пачками (PrefetchVirtualMemory) — до того, как главный поток начнёт ходить по
ним по одной. Через RETURN_REPORT_MS в журнал пишется итог возврата.

Принудительной выгрузки памяти здесь нет и быть не должно: она как раз и
заставляет окно открываться медленно.
"""

from __future__ import annotations

import logging
import sys
import threading
import time
from collections.abc import Callable

from PyQt6.QtCore import QEvent, QObject, QTimer

from ..platform.windows.working_set import (
    PrefetchResult,
    WorkingSetSnapshot,
    prefetch_working_set,
    snapshot_working_set,
)

LOG = logging.getLogger("xray_fluent.window_presence")

WM_SYSCOMMAND = 0x0112
SC_RESTORE = 0xF120
_SC_COMMAND_MASK = 0xFFF0

# Сколько окно должно пробыть в фоне, прежде чем запомнить страницы: короткое
# сворачивание и разворот ничего не стоят.
AWAY_SETTLE_MS = 5 * 1000
# Короче этого срока Windows страницы не отбирает, подтягивать нечего.
MIN_AWAY_FOR_PREFETCH_S = 20.0
# Через сколько после возврата писать итог в журнал.
RETURN_REPORT_MS = 3 * 1000

_WATCHED_EVENTS = (QEvent.Type.Hide, QEvent.Type.Show, QEvent.Type.WindowStateChange)


def is_native_restore_command(message) -> bool:
    """Команда Windows «развернуть» (клик по окну в панели задач, Alt+Tab).

    Приходит раньше, чем Qt покажет и нарисует окно. Сообщение не «съедается».
    """
    if sys.platform != "win32":
        return False
    try:
        from ctypes import wintypes

        address = int(message)
        if address <= 0:
            return False
        msg = wintypes.MSG.from_address(address)
        return int(msg.message) == WM_SYSCOMMAND and (int(msg.wParam) & _SC_COMMAND_MASK) == SC_RESTORE
    except Exception:
        return False


def _page_faults() -> int | None:
    try:
        import psutil

        return int(psutil.Process().memory_info().num_page_faults)
    except Exception:
        return None


def _run_in_thread(target: Callable[[], None]) -> None:
    threading.Thread(target=target, name="window-presence", daemon=True).start()


class WindowPresence(QObject):
    """Следит за окном и подтягивает память при возврате из долгого фона."""

    def __init__(
        self,
        window,
        *,
        settle_ms: int = AWAY_SETTLE_MS,
        report_ms: int = RETURN_REPORT_MS,
        min_away_for_prefetch_s: float = MIN_AWAY_FOR_PREFETCH_S,
        take_snapshot: Callable[[], WorkingSetSnapshot | None] = snapshot_working_set,
        prefetch: Callable[[WorkingSetSnapshot | None], PrefetchResult | None] = prefetch_working_set,
        start_worker: Callable[[Callable[[], None]], object] = _run_in_thread,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(window)
        self._window = window
        self._report_ms = int(report_ms)
        self._min_away_for_prefetch_s = float(min_away_for_prefetch_s)
        self._take_snapshot = take_snapshot
        self._prefetch = prefetch
        self._start_worker = start_worker
        self._clock = clock

        self._away = True
        self._away_since: float | None = None
        self._snapshot: WorkingSetSnapshot | None = None
        self._snapshot_lock = threading.Lock()
        self._last_prefetch: PrefetchResult | None = None
        self._return_faults: int | None = None
        self._return_away_s = 0.0

        self._settle_timer = QTimer(self)
        self._settle_timer.setSingleShot(True)
        self._settle_timer.setInterval(int(settle_ms))
        self._settle_timer.timeout.connect(self._on_settle_timeout)

        self._report_timer = QTimer(self)
        self._report_timer.setSingleShot(True)
        self._report_timer.setInterval(self._report_ms)
        self._report_timer.timeout.connect(self._report_return)

        window.installEventFilter(self)
        self._sync(initial=True)

    @property
    def away(self) -> bool:
        return self._away

    def _window_on_screen(self) -> bool:
        window = self._window
        return bool(window.isVisible()) and not bool(window.isMinimized())

    def _sync(self, *, initial: bool = False) -> None:
        on_screen = self._window_on_screen()
        if on_screen and self._away:
            self._enter_shown()
        elif not on_screen and (not self._away or initial):
            self._enter_away()

    def eventFilter(self, obj, event):  # noqa: N802 (Qt API)
        if obj is self._window and event.type() in _WATCHED_EVENTS:
            self._sync()
        return False

    def return_intent(self) -> None:
        """Окно сейчас вернут (команда Windows «развернуть», показ из трея).

        Повторные вызовы и позднее событие показа ничего не повторяют.
        """
        if self._away:
            self._enter_shown()

    def _enter_away(self) -> None:
        self._away = True
        self._away_since = self._clock()
        self._report_timer.stop()
        self._settle_timer.start()

    def _on_settle_timeout(self) -> None:
        if self._away:
            self._start_worker(self._store_snapshot)

    def _store_snapshot(self) -> None:
        try:
            snapshot = self._take_snapshot()
        except Exception:
            snapshot = None
        with self._snapshot_lock:
            self._snapshot = snapshot

    def _enter_shown(self) -> None:
        self._away = False
        self._settle_timer.stop()
        since, self._away_since = self._away_since, None
        away_s = 0.0 if since is None else max(0.0, self._clock() - since)
        with self._snapshot_lock:
            snapshot = self._snapshot
        self._last_prefetch = None
        if away_s < self._min_away_for_prefetch_s:
            return
        if snapshot is not None:
            self._start_worker(lambda: self._run_prefetch(snapshot))
        self._return_away_s = away_s
        self._return_faults = _page_faults()
        self._report_timer.start()

    def _run_prefetch(self, snapshot: WorkingSetSnapshot) -> None:
        try:
            self._last_prefetch = self._prefetch(snapshot)
        except Exception:
            self._last_prefetch = None

    def _report_return(self) -> None:
        faults_now = _page_faults()
        faults = "?" if faults_now is None or self._return_faults is None else str(faults_now - self._return_faults)
        prefetch = self._last_prefetch
        if prefetch is None:
            pulled = "pages not prefetched"
        else:
            pulled = f"prefetched {prefetch.total_bytes / (1024 * 1024):.0f} MB in {prefetch.elapsed_ms:.0f} ms"
        LOG.info(
            "window returned from background (%.0f s): %s; page faults in %.0f s after return: %s",
            self._return_away_s,
            pulled,
            self._report_ms / 1000,
            faults,
        )


__all__ = [
    "AWAY_SETTLE_MS",
    "MIN_AWAY_FOR_PREFETCH_S",
    "RETURN_REPORT_MS",
    "WindowPresence",
    "is_native_restore_command",
]
