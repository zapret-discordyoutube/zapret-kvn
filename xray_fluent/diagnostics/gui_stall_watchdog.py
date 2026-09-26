"""Измеритель зависаний GUI-потока.

GUI-поток каждые ``heartbeat_ms`` отмечает «пульс» через ``QTimer``. Фоновый
поток следит за пульсом: как только тот запаздывает больше чем на
``threshold_ms``, он начинает снимать стек GUI-потока (``sys._current_frames``)
каждые ~``threshold_ms / 2``. В отчёт идёт самый частый стек — место, где
поток провёл большую часть зависания. Длительность считает сам GUI-поток по
разрыву между пульсами, когда снова оживает.

В приложении включается переменной окружения ``ZAPRETKVN_STALL_WATCHDOG``
(``1`` или порог в миллисекундах) и пишет в ``data/logs/gui-stalls.log``.
В тестах используется напрямую: ``max_stall_ms`` и ``records`` — критерий
приёмки «переход не блокирует интерфейс».
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
import traceback
from collections import Counter
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from pathlib import Path

from PyQt6.QtCore import QObject, Qt, QTimer

ENV_VAR = "ZAPRETKVN_STALL_WATCHDOG"
DEFAULT_THRESHOLD_MS = 50
_LOGGER_NAME = "xray_fluent.gui_stalls"


@dataclass(frozen=True)
class StallRecord:
    duration_ms: float
    stack: str


class GuiStallWatchdog(QObject):
    def __init__(
        self,
        threshold_ms: float = DEFAULT_THRESHOLD_MS,
        heartbeat_ms: int = 10,
        logger: logging.Logger | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.threshold_ms = float(threshold_ms)
        self.records: list[StallRecord] = []
        self._logger = logger
        self._lock = threading.Lock()
        self._last_beat = time.perf_counter()
        self._samples: list[str] = []
        self._gui_thread_id = threading.get_ident()
        self._stop_event = threading.Event()
        self._watcher: threading.Thread | None = None
        self._timer = QTimer(self)
        self._timer.setTimerType(Qt.TimerType.PreciseTimer)
        self._timer.setInterval(heartbeat_ms)
        self._timer.timeout.connect(self._beat)

    @property
    def max_stall_ms(self) -> float:
        return max((record.duration_ms for record in self.records), default=0.0)

    def start(self) -> None:
        self._gui_thread_id = threading.get_ident()
        self.reset()
        self._stop_event.clear()
        self._timer.start()
        self._watcher = threading.Thread(target=self._watch, name="gui-stall-watchdog", daemon=True)
        self._watcher.start()

    def stop(self) -> None:
        self._timer.stop()
        self._stop_event.set()
        if self._watcher is not None:
            self._watcher.join(timeout=1.0)
            self._watcher = None

    def reset(self) -> None:
        with self._lock:
            self.records.clear()
            self._samples = []
            self._last_beat = time.perf_counter()

    def _beat(self) -> None:
        now = time.perf_counter()
        with self._lock:
            gap_ms = (now - self._last_beat) * 1000.0
            self._last_beat = now
            samples = self._samples
            self._samples = []
        if gap_ms <= self.threshold_ms:
            return
        stack = Counter(samples).most_common(1)[0][0] if samples else ""
        record = StallRecord(duration_ms=gap_ms, stack=stack)
        self.records.append(record)
        if self._logger is not None:
            self._logger.warning("GUI stall %.0f ms\n%s", gap_ms, stack or "  (стек не снят)")

    def _watch(self) -> None:
        poll = min(self.threshold_ms / 4000.0, 0.01)
        sample_every = self.threshold_ms / 2000.0
        next_sample = 0.0
        while not self._stop_event.wait(poll):
            now = time.perf_counter()
            with self._lock:
                late_ms = (now - self._last_beat) * 1000.0
            if late_ms <= self.threshold_ms or now < next_sample:
                continue
            next_sample = now + sample_every
            frame = sys._current_frames().get(self._gui_thread_id)
            stack = "".join(traceback.format_stack(frame)) if frame is not None else ""
            with self._lock:
                self._samples.append(stack)


def install_from_environment(log_dir: Path, parent: QObject | None = None) -> GuiStallWatchdog | None:
    """Включить watchdog, если задана ``ZAPRETKVN_STALL_WATCHDOG``."""
    raw = os.environ.get(ENV_VAR, "").strip()
    if not raw or raw == "0":
        return None
    try:
        threshold = float(raw) if raw not in {"1", "true", "yes"} else DEFAULT_THRESHOLD_MS
    except ValueError:
        threshold = DEFAULT_THRESHOLD_MS
    logger = logging.getLogger(_LOGGER_NAME)
    if not logger.handlers:
        log_dir.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            log_dir / "gui-stalls.log", maxBytes=2 * 1024 * 1024, backupCount=1, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(asctime)s  %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        logger.addHandler(handler)
        logger.setLevel(logging.WARNING)
        logger.propagate = False
    watchdog = GuiStallWatchdog(threshold_ms=max(threshold, 20.0), logger=logger, parent=parent)
    watchdog.start()
    return watchdog
