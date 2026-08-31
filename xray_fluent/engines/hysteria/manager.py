from __future__ import annotations

from collections import deque
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import time
from typing import Any

from PyQt6.QtCore import QObject, QProcess, QTimer, pyqtSignal

from ...constants import HYSTERIA_CONFIG_FILE, HYSTERIA_PATH_DEFAULT, PROXY_HOST, RUNTIME_DIR
from ...runtime_logging import RuntimeNodeIdentity, redact_runtime_log
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
        self._last_output_lines: deque[str] = deque(maxlen=100)
        self._context: RuntimeNodeIdentity | None = None
        self._attempt = 0
        self._failure_reported = False
        self._stdout_buffer = ""
        self._secret_values: tuple[str, ...] = ()
        self._compatibility_generation = 0
        self._compatibility_config: dict[str, Any] | None = None
        self._compatibility_relay_port = 0
        self._compatibility_context: RuntimeNodeIdentity | None = None
        self._chrome_fallback_pending = False
        self._chrome_fallback_used = False
        self._chrome_fallback_in_progress = False
        self._suppress_state_change = False
        # A crash can leave a short-lived config behind. It is never reusable:
        # every start writes a fresh one, so remove stale secrets immediately.
        self._cleanup_config()

    @property
    def is_running(self) -> bool:
        return self._running

    def start(
        self,
        config: dict[str, Any],
        relay_port: int,
        *,
        context: RuntimeNodeIdentity | None = None,
        _compatibility_retry: bool = False,
    ) -> bool:
        if not _compatibility_retry:
            self._compatibility_generation += 1
            self._chrome_fallback_pending = False
            self._chrome_fallback_used = False
            self._chrome_fallback_in_progress = False
        self._compatibility_config = deepcopy(config)
        self._compatibility_relay_port = relay_port
        self._compatibility_context = context
        exe = HYSTERIA_PATH_DEFAULT.resolve()
        if not exe.is_file():
            self._begin_attempt(context, config)
            self._emit_error(
                f"hysteria.exe не найден: {exe}. Переустановите или обновите Zapret KVN.",
                stage="validate",
            )
            self._clear_compatibility_state()
            return False
        if relay_port <= 0:
            self._begin_attempt(context, config)
            self._emit_error("Некорректный локальный порт Hysteria sidecar", stage="validate")
            self._clear_compatibility_state()
            return False

        # Keep the old identity active until its process is fully stopped. This
        # prevents a late finished/error signal from being attributed to the
        # connection that is only about to start.
        if self._process.state() != QProcess.ProcessState.NotRunning:
            self._failure_reported = False
            if not self.stop(expected=True, _preserve_compatibility=True):
                self._emit_error(
                    "Не удалось остановить предыдущий процесс Hysteria",
                    stage="stop_previous",
                )
                self._clear_compatibility_state()
                return False
        elif self._running:
            self._running = False
            self.state_changed.emit(False)

        self._begin_attempt(context, config)
        self._kill_orphaned(exe)
        self._cleanup_config()
        temporary = HYSTERIA_CONFIG_FILE.with_suffix(".json.tmp")
        try:
            RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
            temporary.write_text(json.dumps(config, ensure_ascii=True, indent=2), encoding="utf-8")
            temporary.chmod(0o600)
            temporary.replace(HYSTERIA_CONFIG_FILE)
        except OSError as exc:
            self._cleanup_config()
            self._emit_error(f"Не удалось записать временный конфиг: {exc}", stage="write_config")
            self._clear_compatibility_state()
            return False

        self._starting = True
        self._stop_requested = False
        self._last_output_lines.clear()
        self._emit_log(
            f"launch relay={PROXY_HOST}:{relay_port} remote_handshake=deferred(lazy)",
            stage="spawn",
        )
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
            self._emit_error(
                f"Не удалось запустить Hysteria: {self._process.errorString()}",
                stage="spawn",
            )
            self._clear_compatibility_state()
            return False

        if not self._wait_until_relay_ready(relay_port):
            details = self._last_output_lines[-1] if self._last_output_lines else "локальный SOCKS не открылся"
            self.stop(expected=True)
            self._starting = False
            self._emit_error(f"Hysteria sidecar не запустился: {details}", stage="wait_ready")
            return False

        # Hysteria has parsed the config by the time its SOCKS listener is
        # ready. Do not leave the URI/passwords on disk for the whole session.
        self._cleanup_config()
        self._starting = False
        self._mark_running()
        return True

    def _begin_attempt(
        self,
        context: RuntimeNodeIdentity | None,
        config: dict[str, Any],
    ) -> None:
        self._attempt += 1
        self._context = context
        self._failure_reported = False
        self._stdout_buffer = ""
        self._secret_values = self._collect_secret_values(config)

    def stop(self, expected: bool = True, *, _preserve_compatibility: bool = False) -> bool:
        if not _preserve_compatibility:
            self._clear_compatibility_state()
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
            self._emit_error("Не удалось вовремя остановить процесс Hysteria", stage="stop")
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
        return redact_runtime_log(line)

    @staticmethod
    def _collect_secret_values(config: dict[str, Any]) -> tuple[str, ...]:
        secret_keys = {
            "auth",
            "password",
            "username",
            "obfs-password",
            "obfs_password",
            "pinsha256",
            "pin_sha256",
            "ech",
            "clientkey",
            "client_key",
        }
        values: list[str] = []

        def visit(value: Any, key: str = "") -> None:
            if isinstance(value, dict):
                for item_key, item in value.items():
                    visit(item, str(item_key).lower())
            elif isinstance(value, (list, tuple)):
                for item in value:
                    visit(item, key)
            elif key in secret_keys:
                text = str(value or "")
                if len(text) >= 4:
                    values.append(text)

        visit(config)
        return tuple(dict.fromkeys(values))

    def _format_message(self, message: str, *, stage: str) -> str:
        clean = redact_runtime_log(message, secrets=self._secret_values)
        fields = f"attempt={self._attempt} stage={stage}"
        if self._context is not None:
            fields += f" {self._context.fields()}"
        return f"[hysteria][{fields}] {clean}".strip()

    def _emit_log(self, message: str, *, stage: str) -> None:
        formatted = self._format_message(message, stage=stage)
        if not formatted:
            return
        self._last_output_lines.append(formatted)
        self.log_received.emit(formatted)

    def _emit_error(self, message: str, *, stage: str) -> None:
        if self._failure_reported:
            return
        self._failure_reported = True
        self.error.emit(self._format_message(message, stage=stage))

    def _on_ready_read(self) -> None:
        chunk = self._process.readAllStandardOutput()
        raw = getattr(chunk, "data")()
        text = decode_output(bytes(raw)) if isinstance(raw, (bytes, bytearray)) else str(raw)
        self._stdout_buffer += text
        lines = self._stdout_buffer.splitlines(keepends=True)
        self._stdout_buffer = ""
        for item in lines:
            if not item.endswith(("\n", "\r")):
                self._stdout_buffer = item
                continue
            self._emit_process_line(item.rstrip("\r\n"))

    def _emit_process_line(self, line: str) -> None:
        clean = redact_runtime_log(line, secrets=self._secret_values)
        lowered = clean.lower()
        stage = (
            "remote_handshake"
            if any(
                marker in lowered
                for marker in (
                    "crypto_error",
                    "no recent network activity",
                    "handshake",
                    "failed to initialize client",
                    "tls:",
                    "certificate",
                    "x509",
                    "authentication failed",
                    "server rejected",
                )
            )
            else "runtime"
        )
        if clean:
            self._emit_log(clean, stage=stage)
        if self._is_chrome_parrot_compatibility_error(clean):
            if not self._chrome_fallback_used and not self._chrome_fallback_pending:
                self._schedule_chrome_parrot_fallback()
            elif (
                self._chrome_fallback_used
                and not self._chrome_fallback_pending
                and not self._chrome_fallback_in_progress
            ):
                self._emit_error(
                    "Удалённое TLS-рукопожатие Hysteria2 завершилось tls: internal error "
                    "после одноразовой проверки совместимости сертификата.",
                    stage="remote_handshake",
                )

    @staticmethod
    def _is_chrome_parrot_compatibility_error(line: str) -> bool:
        lowered = str(line or "").lower()
        return (
            "crypto_error 0x150" in lowered
            and "(remote)" in lowered
            and "tls: internal error" in lowered
        )

    def _schedule_chrome_parrot_fallback(self) -> None:
        if self._compatibility_config is None or self._compatibility_relay_port <= 0:
            return
        self._chrome_fallback_pending = True
        self._chrome_fallback_used = True
        generation = self._compatibility_generation
        self._emit_log(
            "remote TLS internal_error; scheduling one compatibility retry "
            "without Chrome QUIC parroting",
            stage="compatibility_retry",
        )
        QTimer.singleShot(0, lambda: self._run_chrome_parrot_fallback(generation))

    def _run_chrome_parrot_fallback(self, generation: int) -> None:
        if generation != self._compatibility_generation:
            return
        self._chrome_fallback_pending = False
        if (
            self._compatibility_config is None
            or self._compatibility_relay_port <= 0
            or self._stop_requested
        ):
            return

        config = deepcopy(self._compatibility_config)
        quic = config.get("quic")
        if not isinstance(quic, dict):
            quic = {}
            config["quic"] = quic
        quic["disableChromeParrot"] = True
        relay_port = self._compatibility_relay_port
        context = self._compatibility_context
        self._chrome_fallback_in_progress = True
        self._suppress_state_change = True
        try:
            started = self.start(
                config,
                relay_port,
                context=context,
                _compatibility_retry=True,
            )
        finally:
            self._suppress_state_change = False
            self._chrome_fallback_in_progress = False
        if not started:
            if not self._running:
                self.state_changed.emit(False)
            self._emit_error(
                "Не удалось повторно запустить Hysteria2 в режиме совместимости сертификата.",
                stage="compatibility_retry",
            )
            self._clear_compatibility_state()

    def _clear_compatibility_state(self) -> None:
        self._compatibility_generation += 1
        self._compatibility_config = None
        self._compatibility_relay_port = 0
        self._compatibility_context = None
        self._chrome_fallback_pending = False
        self._chrome_fallback_used = False
        self._chrome_fallback_in_progress = False

    def _flush_stdout_buffer(self) -> None:
        self._on_ready_read()
        if self._stdout_buffer:
            tail = self._stdout_buffer
            self._stdout_buffer = ""
            self._emit_process_line(tail)

    def _on_started(self) -> None:
        # Readiness is established by the SOCKS probe in start(); do not expose
        # the process as a healthy sidecar merely because CreateProcess worked.
        self._emit_log("process started; waiting for local SOCKS relay", stage="process_started")
        self.started.emit()

    def _mark_running(self) -> None:
        if self._running:
            return
        self._running = True
        self._emit_log(
            "local SOCKS relay ready; remote handshake not checked yet because lazy=true",
            stage="relay_ready",
        )
        if not self._suppress_state_change:
            self.state_changed.emit(True)

    def _on_error(self, process_error: QProcess.ProcessError) -> None:
        if self._stop_requested and process_error == QProcess.ProcessError.Crashed:
            return
        self._emit_error(
            f"Ошибка процесса Hysteria: {process_error.name} ({self._process.errorString()})",
            stage="spawn" if self._starting else "process_error",
        )

    def _on_finished(self, exit_code: int, _status: QProcess.ExitStatus) -> None:
        was_running = self._running
        was_starting = self._starting
        expected = self._stop_requested
        self._flush_stdout_buffer()
        self._cleanup_config()
        self._running = False
        self._starting = False
        self._stop_requested = False
        compatibility_pending = self._chrome_fallback_pending
        if was_running and not self._suppress_state_change and not compatibility_pending:
            self.state_changed.emit(False)
        if not expected and not compatibility_pending:
            details = self._last_output_lines[-1] if self._last_output_lines else "без диагностического сообщения"
            self._emit_error(
                f"Hysteria неожиданно завершилась (код {exit_code}): {details}",
                stage="startup_exit" if was_starting else "unexpected_exit",
            )
            self._clear_compatibility_state()
        elif not expected:
            self._emit_log(
                f"process exited with code {exit_code}; continuing scheduled compatibility retry",
                stage="compatibility_retry",
            )
        self.stopped.emit(exit_code)
