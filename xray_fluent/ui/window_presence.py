"""Присутствие окна: смотрит ли сейчас человек на программу и что делать при уходе и возврате.

Окно из панели задач разворачивает Windows, и программа узнавала об этом, когда
Qt уже начал рисовать. На слабом ПК после долгого фона это давало «ничего не
работает» на десятки секунд: Windows за время фона отобрала память программы, и
окно подтягивало её с диска по 4 КБ за обращение (замер на win10: после выгрузки
возврат стоит ~11 000 таких обращений).

Уход в фон (свёрнуто или скрыто в трей). Самый ранний сигнал — ``away_intent``
(команда Windows «свернуть», сворачивание в трей): Windows ещё не успела сжать
рабочий набор свёрнутого окна, поэтому именно сейчас видно, какие страницы
программе нужны. Раньше снимок брался через 5 с после ухода, когда набор уже
был сжат, и подтягивать было нечего.
- запоминается, сколько памяти программа держала на виду (самое большое
  значение за время показа), и снимок нужных страниц;
- рабочий набор объявляется «жёстким минимумом» (``hold_working_set``) по этому
  размеру: Windows не отбирает эти страницы, пока окно скрыто, и возврат идёт из
  памяти, а не с диска;
- через AWAY_SETTLE_MS, если окно всё ещё в фоне, снимок берётся ещё раз, но
  более скудный (уже сжатый) снимок не затирает полный, взятый на виду;
- если «свернуть» пришло не командой (Win+D и т. п.), сигналом служит событие
  Qt, а снимок и размер берутся из того, что запомнено через SAMPLE_AFTER_SHOW_MS
  после показа окна.

Возврат (самый ранний из сигналов: команда Windows «развернуть» ``SC_RESTORE``,
показ из трея, событие показа Qt): хватка снимается, а если окно было в фоне
заметно долго, в отдельном потоке запрашивается подтягивание запомненных
страниц большими пачками (PrefetchVirtualMemory) — до того, как главный поток
начнёт ходить по ним по одной. Через RETURN_REPORT_MS в журнал пишется итог.

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
    WorkingSetHold,
    WorkingSetSnapshot,
    available_physical_bytes,
    current_working_set_bytes,
    hold_size_for,
    hold_working_set,
    prefetch_working_set,
    process_page_faults,
    release_working_set_hold,
    snapshot_working_set,
)

LOG = logging.getLogger("xray_fluent.window_presence")

WM_SYSCOMMAND = 0x0112
SC_MINIMIZE = 0xF020
SC_RESTORE = 0xF120
_SC_COMMAND_MASK = 0xFFF0

# Сколько окно должно пробыть в фоне, прежде чем запомнить страницы: короткое
# сворачивание и разворот ничего не стоят.
AWAY_SETTLE_MS = 5 * 1000
# Короче этого срока Windows страницы не отбирает, подтягивать нечего.
MIN_AWAY_FOR_PREFETCH_S = 20.0
# Через сколько после возврата писать итог в журнал.
RETURN_REPORT_MS = 3 * 1000
# Через сколько после показа окна запомнить, сколько памяти и каких страниц ему
# нужно (окно уже отрисовано и «прогрелось»), — на случай ухода без команды «свернуть».
SAMPLE_AFTER_SHOW_MS = 4 * 1000
# Сколько ждать, что окно, собравшееся уйти, действительно ушло.
INTENT_CONFIRM_MS = 2 * 1000

_WATCHED_EVENTS = (QEvent.Type.Hide, QEvent.Type.Show, QEvent.Type.WindowStateChange)


def _system_command(message) -> int | None:
    """Команда WM_SYSCOMMAND из сообщения Windows (без младших 4 бит) или None."""
    if sys.platform != "win32":
        return None
    try:
        from ctypes import wintypes

        address = int(message)
        if address <= 0:
            return None
        msg = wintypes.MSG.from_address(address)
        if int(msg.message) != WM_SYSCOMMAND:
            return None
        return int(msg.wParam) & _SC_COMMAND_MASK
    except Exception:
        return None


def is_native_restore_command(message) -> bool:
    """Команда Windows «развернуть» (клик по окну в панели задач, Alt+Tab).

    Приходит раньше, чем Qt покажет и нарисует окно. Сообщение не «съедается».
    """
    return _system_command(message) == SC_RESTORE


def is_native_minimize_command(message) -> bool:
    """Команда Windows «свернуть»: приходит до того, как Windows сожмёт рабочий набор окна."""
    return _system_command(message) == SC_MINIMIZE


# Читается напрямую через WinAPI: раньше здесь подгружался psutil, и его первый
# импорт читал диск ровно на пути возврата из фона.
_page_faults = process_page_faults


def _run_in_thread(target: Callable[[], None]) -> None:
    threading.Thread(target=target, name="window-presence", daemon=True).start()


class WindowPresence(QObject):
    """Следит за окном: защищает память при уходе в фон и подтягивает её при возврате."""

    def __init__(
        self,
        window,
        *,
        settle_ms: int = AWAY_SETTLE_MS,
        report_ms: int = RETURN_REPORT_MS,
        sample_ms: int = SAMPLE_AFTER_SHOW_MS,
        min_away_for_prefetch_s: float = MIN_AWAY_FOR_PREFETCH_S,
        take_snapshot: Callable[[], WorkingSetSnapshot | None] = snapshot_working_set,
        prefetch: Callable[[WorkingSetSnapshot | None], PrefetchResult | None] = prefetch_working_set,
        hold: Callable[[], WorkingSetHold | None] | None = None,
        release_hold: Callable[[], object] = release_working_set_hold,
        start_worker: Callable[[Callable[[], None]], object] = _run_in_thread,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(window)
        self._window = window
        self._report_ms = int(report_ms)
        self._min_away_for_prefetch_s = float(min_away_for_prefetch_s)
        self._take_snapshot = take_snapshot
        self._prefetch = prefetch
        # Без своей подмены удерживаем по размеру, запомненному на виду.
        self._hold = hold if hold is not None else self._hold_hot_set
        self._release_hold = release_hold
        self._start_worker = start_worker
        self._clock = clock
        self._hot_bytes = 0

        self._away = True
        self._away_since: float | None = None
        self._snapshot: WorkingSetSnapshot | None = None
        self._snapshot_lock = threading.Lock()
        self._last_prefetch: PrefetchResult | None = None
        # Хватку включает и снимает рабочий поток; замок держит их по порядку, а
        # проверка «окно всё ещё в фоне» внутри замка не даёт хватке пережить возврат.
        self._hold_lock = threading.Lock()
        self._held: WorkingSetHold | None = None
        self._return_faults: int | None = None
        self._return_away_s = 0.0
        self._return_hold: WorkingSetHold | None = None

        self._settle_timer = QTimer(self)
        self._settle_timer.setSingleShot(True)
        self._settle_timer.setInterval(int(settle_ms))
        self._settle_timer.timeout.connect(self._on_settle_timeout)

        self._sample_timer = QTimer(self)
        self._sample_timer.setSingleShot(True)
        self._sample_timer.setInterval(int(sample_ms))
        self._sample_timer.timeout.connect(self._on_sample_timeout)

        self._intent_timer = QTimer(self)
        self._intent_timer.setSingleShot(True)
        self._intent_timer.setInterval(INTENT_CONFIRM_MS)
        self._intent_timer.timeout.connect(self._on_intent_timeout)

        self._report_timer = QTimer(self)
        self._report_timer.setSingleShot(True)
        self._report_timer.setInterval(self._report_ms)
        self._report_timer.timeout.connect(self._report_return)

        window.installEventFilter(self)
        self._sync(initial=True)
        if not self._away:
            self._sample_timer.start()

    # ---- состояние -----------------------------------------------------

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

    def away_intent(self) -> None:
        """Окно сейчас уйдёт в фон (команда Windows «свернуть», сворачивание в трей).

        Windows сжимает рабочий набор свёрнутого окна сразу, поэтому защита
        ставится здесь, пока память на месте: запоминается, сколько программа
        держала на виду, тут же (в потоке окна, это один быстрый вызов, а фоновый
        поток мог бы не успеть) ставится удержание, а снимок страниц берётся в
        фоне — удержание уже не даст набору сжаться. Состояние «в фоне» сам этот
        сигнал не ставит: сворачивание могло не состояться. Его по-прежнему
        переключают события Qt; если окно так и не ушло, защита снимается через
        INTENT_CONFIRM_MS.
        """
        if self._away:
            return
        self._remember_hot_bytes()
        with self._hold_lock:
            try:
                self._held = self._hold()
            except Exception:
                self._held = None
        self._start_worker(lambda: self._store_snapshot(from_view=True))
        self._intent_timer.start()

    def _on_intent_timeout(self) -> None:
        """Окно, которое собралось уйти, осталось на экране: защита больше не нужна."""
        if not self._away:
            self._held = None
            self._start_worker(self._release_if_shown)

    def _remember_hot_bytes(self) -> None:
        try:
            current = current_working_set_bytes() or 0
        except Exception:
            current = 0
        self._hot_bytes = max(self._hot_bytes, int(current))

    def _hold_hot_set(self) -> WorkingSetHold | None:
        """Удержать столько, сколько программа держала на виду (в разумных пределах)."""
        try:
            current = current_working_set_bytes() or 0
        except Exception:
            current = 0
        size = hold_size_for(max(int(current), self._hot_bytes), available_physical_bytes())
        return None if size is None else hold_working_set(size)

    def _on_sample_timeout(self) -> None:
        if self._away:
            return
        self._remember_hot_bytes()
        self._start_worker(lambda: self._store_snapshot(from_view=True))

    # ---- границы --------------------------------------------------------

    def _enter_away(self) -> None:
        self._away = True
        self._away_since = self._clock()
        self._report_timer.stop()
        self._sample_timer.stop()
        self._intent_timer.stop()
        self._settle_timer.start()
        self._start_worker(self._hold_if_away)

    def _on_settle_timeout(self) -> None:
        if self._away:
            self._start_worker(self._hold_if_away)
            self._start_worker(self._store_snapshot)

    def _hold_if_away(self) -> None:
        with self._hold_lock:
            if not self._away:
                return
            try:
                self._held = self._hold()
            except Exception:
                self._held = None

    def _release_if_shown(self) -> None:
        with self._hold_lock:
            if self._away:
                return
            try:
                self._release_hold()
            except Exception:
                pass

    def _store_snapshot(self, from_view: bool = False) -> None:
        """Запоминает страницы, нужные программе.

        Снимок, взятый на виду, полный. Взятый уже в фоне (Windows успела сжать
        набор) беднее: он заменяет запомненное, только если не меньше его.
        """
        try:
            snapshot = self._take_snapshot()
        except Exception:
            snapshot = None
        if snapshot is None:
            return
        with self._snapshot_lock:
            current = self._snapshot
            if from_view or current is None or snapshot.total_bytes >= current.total_bytes:
                self._snapshot = snapshot

    def _enter_shown(self) -> None:
        self._away = False
        self._settle_timer.stop()
        self._sample_timer.start()
        since, self._away_since = self._away_since, None
        away_s = 0.0 if since is None else max(0.0, self._clock() - since)
        with self._snapshot_lock:
            snapshot = self._snapshot
        self._last_prefetch = None
        held, self._held = self._held, None
        self._return_hold = held
        self._start_worker(self._release_if_shown)
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
        hold = self._return_hold
        if hold is None:
            kept = "memory not held"
        elif hold.ok:
            kept = f"held {hold.bytes / (1024 * 1024):.0f} MB"
        else:
            kept = f"hold failed (code {hold.error})"
        LOG.info(
            "window returned from background (%.0f s): %s; %s; page faults in %.0f s after return: %s",
            self._return_away_s,
            kept,
            pulled,
            self._report_ms / 1000,
            faults,
        )


__all__ = [
    "AWAY_SETTLE_MS",
    "INTENT_CONFIRM_MS",
    "MIN_AWAY_FOR_PREFETCH_S",
    "RETURN_REPORT_MS",
    "SAMPLE_AFTER_SHOW_MS",
    "WindowPresence",
    "is_native_minimize_command",
    "is_native_restore_command",
]
