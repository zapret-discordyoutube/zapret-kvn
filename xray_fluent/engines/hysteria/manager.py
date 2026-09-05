from __future__ import annotations

from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import ssl
import time
from typing import Any

from PyQt6.QtCore import QObject, QProcess, QTimer, pyqtSignal

from ...constants import HYSTERIA_CONFIG_FILE, HYSTERIA_PATH_DEFAULT, PROXY_HOST, RUNTIME_DIR
from ...diagnostics import capture_runtime_config
from ...application.hysteria_runtime_contract import (
    SECURITY_FAILURES,
    HysteriaFailureCode,
    classify_hysteria_failure,
)
from ...runtime_logging import RuntimeNodeIdentity, redact_runtime_log
from ...subprocess_utils import (
    decode_output,
    kill_processes_by_path,
    sleep_with_events,
    wait_for_qprocess_finished,
    wait_for_qprocess_started,
)


_FUNCTIONAL_HTTPS_ENDPOINTS: tuple[tuple[str, str, str], ...] = (
    ("cloudflare-dns.com", "cloudflare-dns.com", "/"),
    ("dns.google", "dns.google", "/"),
    ("dns.quad9.net", "dns.quad9.net", "/"),
)


class HysteriaManager(QObject):
    """Run the unmodified official Hysteria client as a local SOCKS sidecar."""

    started = pyqtSignal()
    stopped = pyqtSignal(int)
    log_received = pyqtSignal(str)
    error = pyqtSignal(str)
    failure = pyqtSignal(str, str, int)
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
        self._process_generation = 0
        self._config_path = HYSTERIA_CONFIG_FILE
        self._last_failure_code: HysteriaFailureCode | None = None
        self.diagnostic_config: dict[str, Any] | None = None
        self._compatibility_allow_parallel = False
        self._compatibility_verify_remote = True
        self._attempt_started_at = 0.0
        # A crash can leave a short-lived config behind. It is never reusable:
        # every start writes a fresh one, so remove stale secrets immediately.
        self._cleanup_config()
        self._cleanup_stale_generation_configs()

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def process_generation(self) -> int:
        return self._process_generation

    @property
    def last_failure_code(self) -> HysteriaFailureCode | None:
        return self._last_failure_code

    def start(
        self,
        config: dict[str, Any],
        relay_port: int,
        *,
        context: RuntimeNodeIdentity | None = None,
        process_generation: int = 0,
        allow_parallel: bool = False,
        verify_remote: bool = True,
        _compatibility_retry: bool = False,
    ) -> bool:
        if not _compatibility_retry:
            self._compatibility_generation += 1
            self._chrome_fallback_pending = False
            self._chrome_fallback_used = False
            self._chrome_fallback_in_progress = False
            self._process_generation = max(0, int(process_generation))
            self._config_path = (
                HYSTERIA_CONFIG_FILE.with_name(
                    f"{HYSTERIA_CONFIG_FILE.stem}-{self._process_generation}.json"
                )
                if allow_parallel and self._process_generation > 0
                else HYSTERIA_CONFIG_FILE
            )
            self._compatibility_allow_parallel = bool(allow_parallel)
            self._compatibility_verify_remote = bool(verify_remote)
            self._last_failure_code = None
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
        if not allow_parallel:
            self._kill_orphaned(exe)
        self._cleanup_config()
        temporary = self._config_path.with_suffix(".json.tmp")
        try:
            RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
            temporary.write_text(json.dumps(config, ensure_ascii=True, indent=2), encoding="utf-8")
            temporary.chmod(0o600)
            temporary.replace(self._config_path)
            self.diagnostic_config = capture_runtime_config(exe, config)
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
                str(self._config_path),
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

        self._emit_log(
            f"local relay ready in {int((time.monotonic() - self._attempt_started_at) * 1000)} ms",
            stage="relay_ready",
        )

        socks = config.get("socks5")
        socks = socks if isinstance(socks, dict) else {}
        if verify_remote and not self._wait_until_remote_ready(
            relay_port,
            username=str(socks.get("username") or ""),
            password=str(socks.get("password") or ""),
        ):
            details = self._last_output_lines[-1] if self._last_output_lines else "HTTPS probe через relay не завершился"
            self.stop(expected=True)
            self._starting = False
            self._emit_error(
                f"Hysteria relay локально открыт, но удалённый handshake не готов: {details}",
                stage="remote_handshake",
                code=self._last_failure_code
                or classify_hysteria_failure(details)
                or HysteriaFailureCode.TARGET_NETWORK_TIMEOUT,
            )
            return False
        if verify_remote:
            self._emit_log(
                "functional readiness completed in "
                f"{int((time.monotonic() - self._attempt_started_at) * 1000)} ms",
                stage="functional_ready",
            )

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
        self._attempt_started_at = time.monotonic()
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

    def _wait_until_remote_ready(
        self,
        relay_port: int,
        *,
        username: str,
        password: str,
        timeout: float = 15.0,
    ) -> bool:
        """Prove HTTPS egress without making one external provider authoritative."""

        deadline = time.monotonic() + timeout
        failures: dict[str, str] = {}
        while time.monotonic() < deadline:
            if (
                self._process.state() == QProcess.ProcessState.NotRunning
                or self._last_failure_code in SECURITY_FAILURES
            ):
                return False
            probe_timeout = min(4.0, max(0.2, deadline - time.monotonic()))
            executor = ThreadPoolExecutor(
                max_workers=len(_FUNCTIONAL_HTTPS_ENDPOINTS),
                thread_name_prefix="hysteria-ready",
            )
            futures: dict[Future[None], tuple[str, str, str]] = {
                executor.submit(
                    self._probe_remote_endpoint,
                    relay_port,
                    username=username,
                    password=password,
                    endpoint=endpoint,
                    timeout=probe_timeout,
                ): endpoint
                for endpoint in _FUNCTIONAL_HTTPS_ENDPOINTS
            }
            succeeded: tuple[str, str, str] | None = None
            while futures and time.monotonic() < deadline:
                if (
                    self._process.state() == QProcess.ProcessState.NotRunning
                    or self._last_failure_code in SECURITY_FAILURES
                ):
                    executor.shutdown(wait=False, cancel_futures=True)
                    return False
                completed = [future for future in futures if future.done()]
                for future in completed:
                    endpoint = futures.pop(future)
                    error = future.exception()
                    if error is None:
                        succeeded = endpoint
                        break
                    failures[endpoint[1]] = f"{type(error).__name__}: {error}"
                if succeeded is not None:
                    break
                sleep_with_events(0.05)
            executor.shutdown(wait=False, cancel_futures=True)
            if self._last_failure_code in SECURITY_FAILURES:
                return False
            if succeeded is not None:
                self._emit_log(
                    f"functional HTTPS probe succeeded via {succeeded[1]}",
                    stage="functional_ready",
                )
                return True
            sleep_with_events(0.1)
        if failures:
            summary = "; ".join(
                f"{host}={detail}" for host, detail in sorted(failures.items())
            )
            self._emit_log(f"functional HTTPS probes failed: {summary}", stage="functional_ready")
        return False

    def _probe_remote_endpoint(
        self,
        relay_port: int,
        *,
        username: str,
        password: str,
        endpoint: tuple[str, str, str],
        timeout: float,
    ) -> None:
        connect_host, server_name, path = endpoint
        raw = self._open_socks_connection(
            relay_port,
            username=username,
            password=password,
            timeout=timeout,
            target_host=connect_host,
        )
        context = ssl.create_default_context()
        try:
            with context.wrap_socket(raw, server_hostname=server_name) as secure:
                secure.settimeout(timeout)
                request = (
                    f"HEAD {path} HTTP/1.1\r\n"
                    f"Host: {server_name}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
                secure.sendall(request)
                if not secure.recv(16).startswith(b"HTTP/"):
                    raise OSError("HTTPS endpoint returned no HTTP response")
        except BaseException:
            raw.close()
            raise

    @staticmethod
    def _open_socks_connection(
        relay_port: int,
        *,
        username: str,
        password: str,
        timeout: float,
        target_host: str = "cloudflare-dns.com",
    ) -> socket.socket:
        sock = socket.create_connection((PROXY_HOST, relay_port), timeout=timeout)
        try:
            sock.settimeout(timeout)
            methods = b"\x02" if username or password else b"\x00"
            sock.sendall(b"\x05\x01" + methods)
            response = HysteriaManager._recv_exact(sock, 2)
            if response != b"\x05" + methods:
                raise OSError("SOCKS authentication method rejected")
            if methods == b"\x02":
                encoded_user = username.encode("utf-8")
                encoded_password = password.encode("utf-8")
                if len(encoded_user) > 255 or len(encoded_password) > 255:
                    raise OSError("SOCKS credentials are too long")
                sock.sendall(
                    b"\x01"
                    + bytes((len(encoded_user),))
                    + encoded_user
                    + bytes((len(encoded_password),))
                    + encoded_password
                )
                if HysteriaManager._recv_exact(sock, 2) != b"\x01\x00":
                    raise OSError("SOCKS authentication rejected")
            encoded_target = target_host.encode("idna")
            if not encoded_target or len(encoded_target) > 255:
                raise OSError("SOCKS target host is invalid")
            sock.sendall(
                b"\x05\x01\x00\x03"
                + bytes((len(encoded_target),))
                + encoded_target
                + b"\x01\xbb"
            )
            header = HysteriaManager._recv_exact(sock, 4)
            if len(header) != 4 or header[0] != 5 or header[1] != 0:
                raise OSError("SOCKS CONNECT rejected")
            address_length = {1: 4, 4: 16}.get(header[3])
            if header[3] == 3:
                address_length = HysteriaManager._recv_exact(sock, 1)[0]
            if address_length is None:
                raise OSError("SOCKS returned an invalid address type")
            HysteriaManager._recv_exact(sock, address_length + 2)
            return sock
        except Exception:
            sock.close()
            raise

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            chunk = sock.recv(size - len(chunks))
            if not chunk:
                raise OSError("SOCKS connection closed")
            chunks.extend(chunk)
        return bytes(chunks)

    @staticmethod
    def _kill_orphaned(exe: Path) -> None:
        if os.name != "nt":
            return
        try:
            if kill_processes_by_path(exe.name, exe, timeout=5):
                sleep_with_events(0.5)
        except Exception:
            pass

    def _cleanup_config(self) -> None:
        try:
            self._config_path.unlink(missing_ok=True)
            self._config_path.with_suffix(".json.tmp").unlink(missing_ok=True)
        except OSError:
            pass

    @staticmethod
    def _cleanup_stale_generation_configs() -> None:
        try:
            for path in HYSTERIA_CONFIG_FILE.parent.glob(
                f"{HYSTERIA_CONFIG_FILE.stem}-*.json*"
            ):
                if path.is_file():
                    path.unlink(missing_ok=True)
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

    def _emit_error(
        self,
        message: str,
        *,
        stage: str,
        code: HysteriaFailureCode | None = None,
    ) -> None:
        resolved = code or classify_hysteria_failure(message)
        if resolved is None:
            resolved = {
                "validate": HysteriaFailureCode.LOCAL_CONFIG_INVALID,
                "write_config": HysteriaFailureCode.LOCAL_CONFIG_INVALID,
                "spawn": HysteriaFailureCode.LOCAL_PROCESS_START_FAILED,
                "startup_exit": HysteriaFailureCode.LOCAL_PROCESS_EXITED,
                "unexpected_exit": HysteriaFailureCode.LOCAL_PROCESS_EXITED,
                "wait_ready": HysteriaFailureCode.LOCAL_RELAY_NOT_READY,
                "stop": HysteriaFailureCode.LOCAL_PROCESS_EXITED,
            }.get(stage, HysteriaFailureCode.CORE_UNCLASSIFIED)
        if self._failure_reported and not (
            resolved in SECURITY_FAILURES and self._last_failure_code not in SECURITY_FAILURES
        ):
            return
        # A transient timeout can be logged by one parallel probe before
        # another reports a definitive TLS/auth rejection. Preserve both raw
        # log entries, but security must take precedence for recovery policy.
        self._failure_reported = True
        self._last_failure_code = resolved
        formatted = self._format_message(message, stage=stage)
        # The typed cause is published before generic process/state callbacks,
        # so exit code 62097 cannot replace the original failure episode.
        self.failure.emit(resolved.value, formatted, self._process_generation)
        self.error.emit(formatted)

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
                    "pinned",
                    "x509",
                    "authentication failed",
                    "server rejected",
                    "connection refused",
                    "actively refused",
                    "forcibly closed",
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
                self._emit_error(clean, stage="remote_handshake")
        else:
            failure = classify_hysteria_failure(clean)
            if failure is not None:
                self._emit_error(clean, stage=stage, code=failure)

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
                process_generation=self._process_generation,
                allow_parallel=self._compatibility_allow_parallel,
                verify_remote=self._compatibility_verify_remote,
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
            "local SOCKS relay and functional HTTPS handshake are ready",
            stage="functional_ready",
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
        if not expected and not compatibility_pending:
            details = self._last_output_lines[-1] if self._last_output_lines else "без диагностического сообщения"
            self._emit_error(
                f"Hysteria неожиданно завершилась (код {exit_code}): {details}",
                stage="startup_exit" if was_starting else "unexpected_exit",
                code=self._last_failure_code or classify_hysteria_failure(details, process_exited=True),
            )
            self._clear_compatibility_state()
        elif not expected:
            self._emit_log(
                f"process exited with code {exit_code}; continuing scheduled compatibility retry",
                stage="compatibility_retry",
            )
        if was_running and not self._suppress_state_change and not compatibility_pending:
            self.state_changed.emit(False)
        self.stopped.emit(exit_code)
