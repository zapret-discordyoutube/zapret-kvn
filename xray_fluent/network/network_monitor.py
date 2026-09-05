from __future__ import annotations

import socket
from PyQt6.QtCore import QObject, QTimer, QThread, pyqtSignal


class _FingerprintWorker(QThread):
    result = pyqtSignal(str)

    def run(self):
        self.result.emit(NetworkMonitor._fingerprint())


class NetworkMonitor(QObject):
    network_changed = pyqtSignal(str, str)

    def __init__(self, interval_ms: int = 5000, parent=None):
        super().__init__(parent)
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
        self._worker = _FingerprintWorker(self)
        self._worker.result.connect(self._apply_fingerprint)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.finished.connect(self._finished)
        self._worker.start()

    def _finished(self):
        self._worker = None

    def _apply_fingerprint(self, current):
        if not self._timer.isActive():
            return
        previous, self._last_fingerprint = self._last_fingerprint, current
        if previous and current != previous:
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
