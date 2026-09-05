from __future__ import annotations

import csv
import json
import os
import subprocess
import time
from collections import deque
from pathlib import Path
from typing import Any

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

from PyQt6.QtCore import QObject, QProcess, pyqtSignal

from ...application.async_steps import (
    TransitionSteps,
    run_in_worker,
    run_steps_blocking,
    sleep_ms,
    wait_process_finished,
    wait_process_started,
)
from ...application.port_allocator import is_tcp_port_bindable
from ...constants import PROXY_HOST, RUNTIME_DIR, XRAY_CONFIG_FILE, XRAY_PATH_DEFAULT
from ...diagnostics import capture_runtime_config
from ...path_utils import resolve_configured_path
from ...proxy_readiness import probe_listener_role
from ...subprocess_utils import (
    decode_output,
    kill_processes_by_path,
    result_output_text,
    run_text,
    run_text_pumped,
)


class XrayManager(QObject):
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
        self._stop_requested = False
        self._starting = False
        self._startup_failure_reported = False
        self._runtime_error_reported = False
        self._last_output_lines: deque[str] = deque(maxlen=20)
        self._last_exit_code: int | None = None
        self._last_exit_status = QProcess.ExitStatus.NormalExit
        self._last_exit_expected = False
        self._exe_path: Path | None = None
        self.diagnostic_config: dict[str, Any] | None = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def last_exit_expected(self) -> bool:
        return self._last_exit_expected

    def start(self, xray_path: str, config: dict[str, Any]) -> bool:
        # Холодный совместимый путь (connect/reconnect, sing-box sidecar, тесты):
        # выполняет те же шаги синхронно. Горячие переходы (hot-swap) используют
        # start_steps() через TransitionRunner (AC22).
        return bool(run_steps_blocking(self.start_steps(xray_path, config)))

    def start_steps(self, xray_path: str, config: dict[str, Any]) -> TransitionSteps:
        if not xray_path or not xray_path.strip():
            self.error.emit("Путь к Xray не настроен (укажите его в Настройки -> Пути к ядрам)")
            return False
        exe = resolve_configured_path(
            xray_path,
            default_path=XRAY_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        if exe is None:
            self.error.emit("Путь к Xray не настроен (укажите его в Настройки -> Пути к ядрам)")
            return False
        if not exe.is_file():
            self.error.emit(f"xray.exe не найден: {exe}")
            return False
        self._exe_path = exe

        if self._process.state() != QProcess.ProcessState.NotRunning:
            if not (yield from self.stop_steps(expected=True)):
                self.error.emit("Не удалось остановить предыдущий процесс Xray")
                return False
        elif self._running:
            self._running = False
            self.state_changed.emit(False)

        start_began = time.monotonic()
        required_ports = self._extract_required_ports(config)
        ports_began = time.monotonic()
        port_error = yield from self._ensure_ports_available_steps(required_ports)
        ports_elapsed = time.monotonic() - ports_began
        if port_error:
            self.error.emit(port_error)
            return False

        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        XRAY_CONFIG_FILE.write_text(json.dumps(config, ensure_ascii=True, indent=2), encoding="utf-8")
        self.diagnostic_config = capture_runtime_config(exe, config)

        self._starting = True
        self._startup_failure_reported = False
        self._runtime_error_reported = False
        self._last_output_lines.clear()
        self._process.setWorkingDirectory(str(exe.parent))
        self._process.setProgram(str(exe))
        self._process.setArguments(["run", "-c", str(XRAY_CONFIG_FILE)])
        spawn_began = time.monotonic()
        self._process.start()

        started = yield wait_process_started(self._process, 2000)
        if not started:
            self._starting = False
            self._report_startup_failure(f"Не удалось запустить Xray: {self._process.errorString()}")
            return False
        spawn_elapsed = time.monotonic() - spawn_began

        ready_began = time.monotonic()
        ready = yield from self._wait_until_ready_steps(
            required_ports,
            credentials=self._extract_socks_credentials(config),
        )
        if not ready:
            self._starting = False
            return False
        ready_elapsed = time.monotonic() - ready_began

        self._starting = False
        self._mark_running()
        self.log_received.emit(
            "[xray-perf] start: "
            f"ensure_ports={ports_elapsed:.2f}s spawn={spawn_elapsed:.2f}s "
            f"wait_ready={ready_elapsed:.2f}s total={time.monotonic() - start_began:.2f}s"
        )
        return True

    def stop(self, expected: bool = True) -> bool:
        # Холодный совместимый путь (disconnect, shutdown, sing-box flows):
        # синхронный драйвер тех же шагов. Горячие переходы используют
        # stop_steps() через TransitionRunner (AC22).
        return bool(run_steps_blocking(self.stop_steps(expected=expected)))

    def stop_steps(self, expected: bool = True) -> TransitionSteps:
        if self._process.state() == QProcess.ProcessState.NotRunning:
            self._stop_requested = False
            if self._running:
                self._running = False
                self.state_changed.emit(False)
            return True

        stop_began = time.monotonic()
        self._stop_requested = expected
        # На Windows terminate() шлёт WM_CLOSE, консольный xray его игнорирует, а
        # процесс stateless (конфиг переписывается на каждый старт) — убиваем сразу,
        # не сжигая 3с таймаута terminate на каждом переключении.
        self._process.kill()
        if (yield wait_process_finished(self._process, 2000)):
            self._log_stop_perf(stop_began)
            return True

        exe = self._exe_path
        if os.name == "nt" and exe is not None:
            try:
                killed = yield run_in_worker(
                    lambda name=exe.name, path=exe: kill_processes_by_path(
                        name, path, timeout=5, pump=False
                    )
                )
            except Exception:
                killed = False
            if killed:
                yield sleep_ms(500)
                if (yield wait_process_finished(self._process, 1000)):
                    self._log_stop_perf(stop_began)
                    return True

        if self._process.state() == QProcess.ProcessState.NotRunning:
            self._log_stop_perf(stop_began)
            return True

        self._stop_requested = False
        self.error.emit("Не удалось вовремя остановить процесс Xray")
        return False

    def _log_stop_perf(self, stop_began: float) -> None:
        self.log_received.emit(f"[xray-perf] stop: total={time.monotonic() - stop_began:.2f}s")

    def _on_ready_read(self) -> None:
        chunk = self._process.readAllStandardOutput()
        raw = getattr(chunk, "data")()
        if isinstance(raw, (bytes, bytearray)):
            text = decode_output(bytes(raw))
        else:
            text = str(raw)
        for line in text.splitlines():
            clean = line.rstrip()
            if clean:
                self._last_output_lines.append(clean)
                self.log_received.emit(clean)

    def _on_started(self) -> None:
        self._stop_requested = False

    def _mark_running(self) -> None:
        if self._running:
            return
        self._running = True
        self.started.emit()
        self.state_changed.emit(True)

    def _on_error(self, process_error: QProcess.ProcessError) -> None:
        if self._stop_requested and process_error == QProcess.ProcessError.Crashed:
            return
        message = f"Ошибка процесса Xray: {process_error.name} ({self._process.errorString()})"
        if self._starting:
            self._report_startup_failure(message)
            return
        if self._runtime_error_reported:
            return
        self._runtime_error_reported = True
        self.error.emit(message)

    def _on_finished(self, exit_code: int, _exit_status: int = 0) -> None:
        exit_status = QProcess.ExitStatus(_exit_status)
        expected = self._stop_requested
        self._last_exit_expected = expected
        self._last_exit_code = exit_code
        self._last_exit_status = exit_status
        self._stop_requested = False
        self._running = False
        if self._starting and not expected:
            self._report_startup_failure(self._unexpected_exit_message(exit_code, exit_status, startup=True))
        elif not expected and not self._runtime_error_reported:
            self._runtime_error_reported = True
            self.error.emit(self._unexpected_exit_message(exit_code, exit_status, startup=False))
        self.stopped.emit(exit_code)
        self.state_changed.emit(False)

    def _extract_required_ports(self, config: dict[str, Any]) -> dict[int, str]:
        port_roles: dict[int, str] = {}
        for inbound in config.get("inbounds", []):
            if not isinstance(inbound, dict):
                continue
            port = inbound.get("port")
            if not isinstance(port, int) or port <= 0:
                continue
            protocol = str(inbound.get("protocol") or "").strip().lower()
            tag = str(inbound.get("tag") or "").strip().lower()
            if protocol == "http":
                role = "HTTP"
            elif protocol == "socks":
                role = "SOCKS"
            elif tag == "api":
                role = "API"
            else:
                role = tag or protocol or "local"
            port_roles[port] = role
        return port_roles

    @staticmethod
    def _extract_socks_credentials(config: dict[str, Any]) -> dict[int, dict[str, str]]:
        credentials: dict[int, dict[str, str]] = {}
        for inbound in config.get("inbounds", []):
            if not isinstance(inbound, dict):
                continue
            if str(inbound.get("protocol") or "").strip().lower() != "socks":
                continue
            port = inbound.get("port")
            if not isinstance(port, int) or port <= 0:
                continue
            settings = inbound.get("settings")
            if not isinstance(settings, dict) or settings.get("auth") != "password":
                continue
            accounts = settings.get("accounts")
            if not isinstance(accounts, list) or not accounts:
                continue
            first = accounts[0]
            if not isinstance(first, dict):
                continue
            username = str(first.get("user") or "")
            password = str(first.get("pass") or "")
            if username:
                credentials[port] = {"username": username, "password": password}
        return credentials

    def _ensure_ports_available(self, port_roles: dict[int, str]) -> str | None:
        return run_steps_blocking(self._ensure_ports_available_steps(port_roles))

    def _ensure_ports_available_steps(self, port_roles: dict[int, str]) -> TransitionSteps:
        for port, role in port_roles.items():
            # Быстрый путь: bind-проба вместо netstat (~мс против сотен мс на порт).
            if is_tcp_port_bindable(PROXY_HOST, port):
                continue
            # Порт занят — netstat/tasklist в worker-пуле, только как диагностика конфликта.
            owner = yield run_in_worker(
                lambda probe_port=port: self._find_listening_port_owner(probe_port)
            )
            pid, name = owner if owner is not None else (0, "")
            if pid > 0 and (name or "").strip().lower() == "xray.exe":
                killed = yield run_in_worker(lambda stale_pid=pid: self._kill_pid(stale_pid))
                if killed:
                    yield sleep_ms(500)
                    if is_tcp_port_bindable(PROXY_HOST, port):
                        self.log_received.emit(f"[xray] terminated stale xray.exe PID {pid} on port {port}")
                        continue
            return self._port_conflict_message(port, role, pid, name)
        return None

    def _find_listening_port_owner(self, port: int) -> tuple[int, str] | None:
        # Выполняется в worker-пуле (run_in_worker) — без прокачки Qt-событий.
        try:
            result = run_text(
                ["netstat", "-ano", "-p", "tcp"],
                timeout=5,
                check=False,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception:
            return None
        text = result_output_text(result)
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            state = parts[-2].upper()
            if state != "LISTENING":
                continue
            parsed_port = self._parse_port(parts[1])
            if parsed_port != port:
                continue
            try:
                pid = int(parts[-1])
            except ValueError:
                pid = 0
            return pid, self._lookup_process_name(pid)
        return None

    @staticmethod
    def _parse_port(endpoint: str) -> int | None:
        text = endpoint.strip()
        if text.startswith("[") and "]:" in text:
            _, port_text = text.rsplit("]:", 1)
        elif ":" in text:
            _, port_text = text.rsplit(":", 1)
        else:
            return None
        try:
            return int(port_text)
        except ValueError:
            return None

    @staticmethod
    def _lookup_process_name(pid: int) -> str:
        if pid <= 0:
            return ""
        try:
            result = run_text(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                timeout=5,
                check=False,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception:
            return ""
        rows = list(csv.reader(result_output_text(result).splitlines()))
        if not rows or not rows[0]:
            return ""
        name = rows[0][0].strip()
        if name.upper().startswith("INFO:"):
            return ""
        return name

    @staticmethod
    def _kill_pid(pid: int) -> bool:
        if pid <= 0:
            return False
        try:
            result = run_text(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                timeout=5,
                check=False,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception:
            return False
        return result.returncode == 0

    @staticmethod
    def _port_conflict_message(port: int, role: str, pid: int, name: str) -> str:
        prefix = f"{role} порт {port}" if role else f"Порт {port}"
        owner = "другим процессом"
        if name and pid > 0:
            owner = f"процессом {name} (PID {pid})"
        elif pid > 0:
            owner = f"PID {pid}"
        hint = ""
        if role == "HTTP":
            hint = " Измените HTTP порт в настройках или закройте конфликтующее приложение."
        elif role == "SOCKS":
            hint = " Измените SOCKS порт в настройках или закройте конфликтующее приложение."
        elif role == "API":
            hint = " Перезапустите приложение или завершите зависший Xray, который держит API порт."
        return f"{prefix} уже занят {owner}.{hint}"

    def _wait_until_ready(
        self,
        port_roles: dict[int, str],
        timeout_sec: float = 5.0,
        credentials: dict[int, dict[str, str]] | None = None,
    ) -> bool:
        return bool(
            run_steps_blocking(
                self._wait_until_ready_steps(port_roles, timeout_sec, credentials=credentials)
            )
        )

    def _wait_until_ready_steps(
        self,
        port_roles: dict[int, str],
        timeout_sec: float = 5.0,
        credentials: dict[int, dict[str, str]] | None = None,
    ) -> TransitionSteps:
        if not port_roles:
            return True
        ports = tuple(port_roles)
        port_credentials = credentials or {}
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            if self._process.state() == QProcess.ProcessState.NotRunning:
                self._report_startup_failure(self._unexpected_exit_message(self._last_exit_code, self._last_exit_status, startup=True))
                return False
            # Пробные connect'ы (до 0.2с на порт) уходят в worker-пул.
            ready = yield run_in_worker(
                lambda probe=ports, roles=port_roles, creds=port_credentials: all(
                    probe_listener_role(port, roles[port], **(creds.get(port) or {}))
                    for port in probe
                )
            )
            if ready:
                return True
            yield sleep_ms(100)
        pending = yield run_in_worker(
            lambda probe=ports, roles=port_roles, creds=port_credentials: [
                port
                for port in probe
                if not probe_listener_role(port, roles[port], **(creds.get(port) or {}))
            ]
        )
        not_ready = [
            f"{port_roles[port]} {port}" if port_roles[port] else str(port) for port in pending
        ]
        # Диагностику ядра нужно снять до stop(): штатная остановка стирает
        # контекст последних строк как «ожидаемый» выход.
        last_output = next(
            (line for line in reversed(self._last_output_lines) if line.strip()), ""
        )
        yield from self.stop_steps(expected=True)
        details = ", ".join(not_ready) if not_ready else "нужные порты"
        message = f"Xray запустился, но не открыл нужные порты: {details}"
        if last_output:
            message = f"{message}. Последний вывод ядра: {last_output}"
        self._report_startup_failure(message)
        return False

    def _unexpected_exit_message(
        self,
        exit_code: int | None,
        exit_status: QProcess.ExitStatus,
        *,
        startup: bool,
    ) -> str:
        stage = "во время запуска" if startup else "неожиданно"
        diagnostic = self._diagnose_output_failure(stage)
        if diagnostic:
            return diagnostic
        detail = self._best_output_detail()
        if detail:
            return f"Xray завершился {stage}: {detail}"
        if exit_code is None:
            return f"Xray завершился {stage}."
        status_name = "CrashExit" if exit_status == QProcess.ExitStatus.CrashExit else "NormalExit"
        return f"Xray завершился {stage} с кодом {exit_code} ({status_name})."

    def _report_startup_failure(self, message: str) -> None:
        if self._startup_failure_reported:
            return
        self._startup_failure_reported = True
        self.error.emit(message)

    def _best_output_detail(self) -> str:
        if not self._last_output_lines:
            return ""
        preferred_markers = ("panic:", "[xray-error]", "error", "failed", "invalid", "not found")
        for line in reversed(self._last_output_lines):
            clean = line.strip()
            lower = clean.lower()
            if any(marker in lower for marker in preferred_markers):
                return clean
        for line in reversed(self._last_output_lines):
            clean = line.strip()
            lower = clean.lower()
            if not clean:
                continue
            if clean.startswith("github.com/") or lower.startswith("goroutine ") or lower.startswith("[signal"):
                continue
            return clean
        return self._last_output_lines[-1].strip()

    def _diagnose_output_failure(self, stage: str) -> str | None:
        if not self._last_output_lines:
            return None
        joined = "\n".join(self._last_output_lines).lower()
        if "fakednspostprocessingstage" not in joined and "fakedns" not in joined:
            return None
        if "panic:" not in joined and "nil pointer dereference" not in joined:
            return None
        return (
            f"Xray завершился {stage}: текущий Xray core упал на секции FakeDNS в конфиге. "
            "Отключите FakeDNS в Xray JSON, сбросьте конфиг на шаблон по умолчанию или обновите Xray core."
        )


def get_xray_version(xray_path: str) -> str | None:
    exe = resolve_configured_path(
        xray_path,
        default_path=XRAY_PATH_DEFAULT,
        use_default_if_empty=True,
        migrate_default_location=True,
    )
    if exe is None:
        return None
    if not exe.exists():
        return None
    try:
        result = run_text_pumped(
            [str(exe), "version"],
            timeout=3,
            check=False,
            creationflags=_CREATE_NO_WINDOW,
        )
    except Exception:
        return None

    lines = result_output_text(result).splitlines()
    if not lines:
        return None
    return lines[0].strip()
