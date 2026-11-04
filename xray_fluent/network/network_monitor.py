from __future__ import annotations

import socket
from typing import Callable

from PyQt6.QtCore import QObject, QTimer, QThread, pyqtSignal

from .physical_route import is_physical_fingerprint


class _FingerprintWorker(QThread):
    result = pyqtSignal(str)

    def __init__(self, provider: Callable[[], str], parent=None):
        super().__init__(parent)
        self._provider = provider

    def run(self):
        try:
            value = self._provider()
        except Exception:
            # Сбой чтения не «сеть пропала»: пустой ответ монитор пропускает.
            value = ""
        self.result.emit(value)


class NetworkMonitor(QObject):
    network_changed = pyqtSignal(str, str)

    def __init__(self, interval_ms: int = 5000, parent=None, provider: Callable[[], str] | None = None):
        super().__init__(parent)
        # Отпечаток считает владелец: в TUN-сессии он видит физическую сеть, иначе путь в интернет.
        self._provider = provider or NetworkMonitor._fingerprint
        self._timer = QTimer(self)
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self._check)
        self._last_fingerprint = ""
        self._worker = None

    def start(self):
        self._timer.start()
        self._check()

    def stop(self):
        self._timer.stop()
        if self._worker is not None:
            self._worker.wait()

    def _check(self):
        if self._worker is not None and self._worker.isRunning():
            return
        self._worker = _FingerprintWorker(self._provider, self)
        self._worker.result.connect(self._apply_fingerprint)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.finished.connect(self._finished)
        self._worker.start()

    def _finished(self):
        self._worker = None

    def _apply_fingerprint(self, current):
        if not self._timer.isActive() or not current:
            return
        previous, self._last_fingerprint = self._last_fingerprint, current
        if previous and current != previous:
            if is_physical_fingerprint(previous) != is_physical_fingerprint(current):
                # Сессия перешла между обычным и TUN-отпечатком: формат другой, сеть та же.
                return
            self.network_changed.emit(previous, current)

    @staticmethod
    def _fingerprint():
        try:
            # UDP connect only selects a local route; no payload and no DNS lookup.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))
                return sock.getsockname()[0]
        except OSError:
            return "0.0.0.0"
