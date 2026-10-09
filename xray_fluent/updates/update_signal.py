"""Связка слушателя сервера с окном программы.

Слушатель (``release_watch.ReleaseWatcher``) живёт в фоновом потоке и про Qt
не знает. Здесь его разрешения превращаются в сигнал Qt, а окно получает
простые ответы: ведёт ли сервер очередь, разрешена ли версия, занят ли
человек и что сказать серверу после обновления.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from ..constants import APP_VERSION
from .release_watch import (
    ACTIVITY_FULLSCREEN,
    ACTIVITY_TRAY,
    ACTIVITY_WINDOW,
    ReleaseWatcher,
    fullscreen_app_active,
    screen_state,
)

# Как часто окно сообщает слушателю, видно ли оно и включено ли подключение.
# Слушатель читает это из своего потока и Qt не трогает.
PRESENCE_REFRESH_MS = 15 * 1000


class UpdateSignal(QObject):
    """Разрешения сервера на обновление — для окна программы."""

    # Сервер разрешил обновиться до этой версии.
    granted = pyqtSignal(str)
    # Версия вышла, но очередь на скачивание до программы ещё не дошла.
    queued = pyqtSignal(str)

    def __init__(
        self,
        *,
        is_enabled: Callable[[], bool],
        window_shown: Callable[[], bool],
        connected: Callable[[], bool],
        parent: QObject | None = None,
        watcher_factory: Callable[..., ReleaseWatcher] = ReleaseWatcher,
    ) -> None:
        super().__init__(parent)
        self._window_shown = window_shown
        self._connected = connected
        self._lock = threading.Lock()
        self._presence: dict[str, bool] = {}
        self._granted_at: dict[str, float] = {}
        self._report: dict[str, str] = {}
        self._watcher = watcher_factory(
            current_version=APP_VERSION,
            on_release=self._on_release,
            on_queued=lambda version: self.queued.emit(str(version)),
            is_enabled=is_enabled,
            activity=self._activity,
            pending_report=self._pending_report,
            report_delivered=self._report_delivered,
        )
        self._timer = QTimer(self)
        self._timer.setInterval(PRESENCE_REFRESH_MS)
        self._timer.timeout.connect(self.refresh_presence)

    def start(self) -> None:
        self.refresh_presence()
        self._timer.start()
        self._watcher.start()

    def stop(self) -> None:
        self._timer.stop()
        self._watcher.stop()

    # --- для окна (поток интерфейса) ---

    def refresh_presence(self) -> None:
        """Запоминает, видно ли окно и включено ли подключение."""
        try:
            presence = {"window": bool(self._window_shown()), "connected": bool(self._connected())}
        except Exception:
            return
        with self._lock:
            self._presence = presence

    def queue_reachable(self) -> bool:
        """Сервер ведёт очередь: ставить версию можно только с его разрешения."""
        return self._watcher.reachable is True

    def is_granted(self, version: str) -> bool:
        with self._lock:
            return str(version) in self._granted_at

    def granted_at(self, version: str) -> float:
        with self._lock:
            return float(self._granted_at.get(str(version), 0.0))

    @staticmethod
    def busy_reason() -> str:
        """Почему обновляться сейчас не время; пусто — можно."""
        return "на экране игра или видео на весь экран" if fullscreen_app_active() else ""

    def set_report(self, report: dict | None) -> None:
        """Что сказать серверу об исходе прошлого обновления (один раз)."""
        with self._lock:
            self._report = {str(key): str(value) for key, value in (report or {}).items()}

    # --- для слушателя (его поток) ---

    def _on_release(self, version: str) -> None:
        with self._lock:
            self._granted_at.setdefault(str(version), time.time())
        self.granted.emit(str(version))

    def _activity(self) -> dict:
        with self._lock:
            presence = dict(self._presence)
        if not presence:
            return {}
        if fullscreen_app_active():
            act = ACTIVITY_FULLSCREEN
        else:
            act = ACTIVITY_WINDOW if presence["window"] else ACTIVITY_TRAY
        # scr — сырой ответ Windows о занятости экрана, только общим счётом.
        return {"act": act, "run": "1" if presence["connected"] else "0", "scr": screen_state()}

    def _pending_report(self) -> dict:
        with self._lock:
            return dict(self._report)

    def _report_delivered(self, _report: dict) -> None:
        with self._lock:
            self._report = {}
