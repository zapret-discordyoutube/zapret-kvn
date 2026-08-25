from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
import socket
import time
from typing import Any

from PyQt6.QtCore import QObject, QProcess, pyqtSignal

from ...constants import HYSTERIA_CONFIG_FILE, HYSTERIA_PATH_DEFAULT, PROXY_HOST, RUNTIME_DIR
from ...subprocess_utils import (
    decode_output,
    kill_processes_by_path,
    sleep_with_events,
    wait_for_qprocess_finished,
    wait_for_qprocess_started,
)


class HysteriaManager(QObject):
    """Run the unmodified official Hysteria client as a local SOCKS sidecar."""

    started = pyqtSignal()
    stopped = pyqtSignal(int)
    log_received = pyqtSignal(str)
    error = pyqtSignal(str)
    state_changed = pyqtSignal(bool)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._process = QProcess(self)
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._process.readyReadStandardOutput.connect(self._on_ready_read)
        self._process.started.connect(self._on_started)
        self._process.errorOccurred.connect(self._on_error)
        self._process.finished.connect(self._on_finished)
        self._running = False
        self._starting = False
        self._stop_requested = False
        self._last_output_lines: deque[str] = deque(maxlen=20)

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self, config: dict[str, Any], relay_port: int) -> bool:
        exe = HYSTERIA_PATH_DEFAULT.resolve()
        if not exe.is_file():
            self.error.emit(
                f"hysteria.exe не найден: {exe}. Переустановите или обновите Zapret KVN."
            )
            return False
        if relay_port <= 0:
            self.error.emit("Некорректный локальный порт Hysteria sidecar")
            return False

        if self._process.state() != QProcess.ProcessState.NotRunning:
            if not self.stop(expected=True):
                self.error.emit("Не удалось остановить предыдущий процесс Hysteria")
                return False
        elif self._running:
            self._running = False
            self.state_changed.emit(False)

        self._kill_orphaned(exe)
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        temporary = HYSTERIA_CONFIG_FILE.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(config, ensure_ascii=True, indent=2), encoding="utf-8")
        temporary.replace(HYSTERIA_CONFIG_FILE)

        self._starting = True
        self._stop_requested = False
        self._last_output_lines.clear()
        self._process.setWorkingDirectory(str(exe.parent))
        self._process.setProgram(str(exe))
        self._process.setArguments(
            [
                "--config",
                str(HYSTERIA_CONFIG_FILE),
                "--disable-update-check",
                "--log-level",
                "warn",
                "client",
            ]
        )
        self._process.start()
        if not wait_for_qprocess_started(self._process, 4000):
            self._starting = False
            self._cleanup_config()
            self.error.emit(f"Не удалось запустить Hysteria: {self._process.errorString()}")
            return False

        if not self._wait_until_relay_ready(relay_port):
            details = self._last_output_lines[-1] if self._last_output_lines else "локальный SOCKS не открылся"
            self.stop(expected=True)
            self._starting = False
            self.error.emit(f"Hysteria sidecar не запустился: {details}")
            return False

        # Hysteria has parsed the config by the time its SOCKS listener is
        # ready. Do not leave the URI/passwords on disk for the whole session.
        self._cleanup_config()
        self._starting = False
        self._mark_running()
        return True

    def stop(self, expected: bool = True) -> bool:
        self._cleanup_config()
        if self._process.state() == QProcess.ProcessState.NotRunning:
            self._stop_requested = False
            self._starting = False
            if self._running:
                self._running = False
                self.state_changed.emit(False)
            return True

        self._stop_requested = expected
        self._process.kill()
        if not wait_for_qprocess_finished(self._process, 2000):
            self._stop_requested = False
            self.error.emit("Не удалось вовремя остановить процесс Hysteria")
            return False
        self._starting = False
        return True

    def _wait_until_relay_ready(self, relay_port: int, timeout: float = 10.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._process.state() == QProcess.ProcessState.NotRunning:
                return False
            try:
                with socket.create_connection((PROXY_HOST, relay_port), timeout=0.15):
                    return True
            except OSError:
                sleep_with_events(0.05)
        return False

    @staticmethod
    def _kill_orphaned(exe: Path) -> None:
        if os.name != "nt":
            return
        try:
            if kill_processes_by_path(exe.name, exe, timeout=5):
                sleep_with_events(0.5)
        except Exception:
            pass

    @staticmethod
    def _cleanup_config() -> None:
        try:
            HYSTERIA_CONFIG_FILE.unlink(missing_ok=True)
            HYSTERIA_CONFIG_FILE.with_suffix(".json.tmp").unlink(missing_ok=True)
        except OSError:
            pass

    @staticmethod
    def redact_log_line(line: str) -> str:
        lowered = line.lower()
        if "hy2://" in lowered or "hysteria2://" in lowered:
            return "[hysteria] строка с конфиденциальной URI скрыта"
        return line

    def _on_ready_read(self) -> None:
        chunk = self._process.readAllStandardOutput()
        raw = getattr(chunk, "data")()
        text = decode_output(bytes(raw)) if isinstance(raw, (bytes, bytearray)) else str(raw)
        for line in text.splitlines():
            clean = self.redact_log_line(line.rstrip())
            if clean:
                self._last_output_lines.append(clean)
                self.log_received.emit(clean)

    def _on_started(self) -> None:
        # Readiness is established by the SOCKS probe in start(); do not expose
        # the process as a healthy sidecar merely because CreateProcess worked.
        self.started.emit()

    def _mark_running(self) -> None:
        if self._running:
            return
        self._running = True
        self.state_changed.emit(True)

    def _on_error(self, process_error: QProcess.ProcessError) -> None:
        if self._stop_requested and process_error == QProcess.ProcessError.Crashed:
            return
        self.error.emit(
            f"Ошибка процесса Hysteria: {process_error.name} ({self._process.errorString()})"
        )

    def _on_finished(self, exit_code: int, _status: QProcess.ExitStatus) -> None:
        was_running = self._running
        expected = self._stop_requested
        self._cleanup_config()
        self._running = False
        self._starting = False
        self._stop_requested = False
        if was_running:
            self.state_changed.emit(False)
        if not expected and not self._starting:
            details = self._last_output_lines[-1] if self._last_output_lines else "без диагностического сообщения"
            self.error.emit(f"Hysteria неожиданно завершилась (код {exit_code}): {details}")
        self.stopped.emit(exit_code)
