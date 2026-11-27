"""Lifecycle of the stock naive client (``core/naive.exe``) as a loopback SOCKS5 helper behind the sing-box front.

The helper reads ``{"listen": "socks://user:pass@127.0.0.1:port", "proxy": "https://id:secret@host:port"}``; sing-box
dials the loopback port with the random credentials, the same seam as the Hysteria2 and Xray helpers. The config file
holds the key's secret, so it exists only while the process starts (naive reads it at launch) and is deleted as soon as
the process is up or fails, never kept on disk for the whole session.
"""

from __future__ import annotations

from collections import deque
import ipaddress
import json
import os
import threading
from pathlib import Path
import time

from PyQt6.QtCore import QObject, QProcess, QTimer, pyqtSignal

from ...application.async_steps import (
    TransitionSteps,
    run_in_worker,
    run_steps_blocking,
    sleep_ms,
    wait_process_finished,
    wait_process_started,
)
from ...constants import NAIVE_PATH_DEFAULT, RUNTIME_DIR
from ...diagnostics.export import capture_runtime_config
from ...diagnostics.runtime_logging import RuntimeNodeIdentity, redact_runtime_log
from ...network import server_family
from ...network.bootstrap_dns import resolve_bootstrap
from ..sidecar import wait_for_loopback_relay_steps
from ..socks_probe import HTTPS_ENDPOINTS, probe_https

#: The first tunnel check retries instead of treating the first refusal as the answer (a node needs a moment after a key
#: is issued; the bot's canary keys were ready in 6-20 s). 25 s, not more: a wrong or expired key must not hold a connect
#: for over a minute with no word (owner report 2026-11-27, "thinking for a very long time").
READY_TIMEOUT_SECONDS = 25.0
PROBE_TIMEOUT_SECONDS = 3.0
#: Hard wall time of one probe step (see `_tunnel_ready_steps`).
PROBE_WALL_SECONDS = 4.0
RECENT_LINES = 40


class NaiveManager(QObject):
    log_received = pyqtSignal(str)
    error = pyqtSignal(str)
    warning = pyqtSignal(str)
    failure = pyqtSignal(object)
    stopped = pyqtSignal(int)
    state_changed = pyqtSignal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._process = QProcess(self)
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._process.readyReadStandardOutput.connect(self._read)
        self._process.finished.connect(self._finished)
        self._process.errorOccurred.connect(self._process_error)
        self._running = False
        self._expected = False
        self._failed = False
        self._buffer = b""
        self._secrets: tuple[str, ...] = ()
        self._context: RuntimeNodeIdentity | None = None
        self._config_path: Path | None = None
        self._recent: deque[str] = deque(maxlen=RECENT_LINES)
        self.diagnostic_config = None
        self.last_failure: tuple[str, str] | None = None
        #: «IPv6 к серверу первым» (controller): then naive resolves the name itself and races the families.
        self.server_ipv6_first = False

    # ── state ────────────────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        return self._running and not self._failed and self._process.state() != QProcess.ProcessState.NotRunning

    @property
    def process_alive(self) -> bool:
        """A spawned process exists, even if readiness was never confirmed."""
        return self._process.state() != QProcess.ProcessState.NotRunning

    @property
    def recent_output_lines(self) -> tuple[str, ...]:
        return tuple(self._recent)

    def _clean(self, raw: str) -> str:
        return redact_runtime_log(raw, secrets=self._secrets)

    def _report(self, stage: str, raw: str) -> None:
        from ...diagnostics.runtime_errors import core_failure

        clean = self._clean(raw)
        identity = self._context.fields() if self._context else ""
        message = f"[naive][stage={stage} {identity}] {clean}"
        if self.last_failure is None:
            # The first report of an attempt is its cause; later ones are fallout.
            self.last_failure = (stage, clean)
        self.log_received.emit(message)
        self.error.emit(message)
        self.failure.emit(core_failure("naive", stage, clean, target_id=self._context.ref if self._context else ""))

    # ── start ────────────────────────────────────────────────────────────

    def start(self, config: dict, relay_port: int, *, relay_username: str, relay_password: str, context=None,
              secrets: tuple[str, ...] = (), server_host: str = "", should_continue=None) -> bool:
        # Synchronous driver of the same steps: shutdown and tests only.
        return bool(run_steps_blocking(self.start_steps(
            config, relay_port, relay_username=relay_username, relay_password=relay_password, context=context,
            secrets=secrets, server_host=server_host, should_continue=should_continue)))

    def start_steps(self, config: dict, relay_port: int, *, relay_username: str, relay_password: str, context=None,
                    secrets: tuple[str, ...] = (), server_host: str = "", should_continue=None) -> TransitionSteps:
        if not (yield from self.stop_steps()):
            return False
        self._expected = self._failed = False
        self.last_failure = None
        self._buffer = b""
        self._recent.clear()
        self._context = context
        self._secrets = tuple(s for s in (*secrets, relay_username, relay_password) if s)
        cancelled = lambda: should_continue is not None and not should_continue()  # noqa: E731
        try:
            exe = NAIVE_PATH_DEFAULT
            if not exe.is_file():
                raise OSError("naive.exe is missing from the installed core bundle")
            config = yield from self._pin_trusted_address_steps(config, server_host)
            if cancelled():
                return False
            self.diagnostic_config = capture_runtime_config(exe, config)
            self._config_path = self._write_config(config)
            self._process.setProgram(str(exe))
            self._process.setArguments([str(self._config_path)])
            self._process.setWorkingDirectory(str(exe.parent))
            self._process.start()
            if not (yield wait_process_started(self._process, 5000)):
                raise OSError(self._process.errorString())
            if not (yield from wait_for_loopback_relay_steps(
                relay_port,
                should_continue=lambda: not self._failed and not cancelled()
                and self._process.state() != QProcess.ProcessState.NotRunning,
            )):
                if cancelled():
                    yield from self.stop_steps()
                    return False
                raise OSError("naive did not open its local SOCKS port")
            # naive has read its config by now; the secret no longer needs to sit on disk.
            self._cleanup_config()
            if not (yield from self._tunnel_ready_steps(relay_port, relay_username, relay_password, cancelled)):
                yield from self.stop_steps()
                return False
        except (OSError, ValueError) as exc:
            if not self._failed:
                self._report("startup", str(exc))
            yield from self.stop_steps()
            return False
        finally:
            self._cleanup_config()
        self._running = True
        self.state_changed.emit(True)
        return True

    def _pin_trusted_address_steps(self, config: dict, host: str) -> TransitionSteps:
        """The server's address from the app's trusted DoH, handed to naive as ``host-resolver-rules``.

        Like the Hysteria2 helper, naive would otherwise ask the system resolver, and a network that forges those answers
        leaves a live server with «no such host» or a wrong address. The TLS name stays the host name (Chromium's
        ``MAP name ip`` keeps SNI and the certificate check). No trusted answer, an IPv6-first setting or an IPv6-only
        server leaves the name for naive to resolve and race itself.
        """

        host = str(host or "").strip().lower()
        if not host or self.server_ipv6_first:
            return config
        try:
            ipaddress.ip_address(host)
            return config
        except ValueError:
            pass
        try:
            resolution = yield run_in_worker(lambda: resolve_bootstrap(host))
        except (OSError, UnicodeError):
            return config
        if resolution.source == "system" or not resolution.addresses:
            return config
        ordered = server_family.order_addresses(host, resolution.addresses, ipv6_first=False, memory=server_family.MEMORY)
        address = next((item for item in ordered if ":" not in item), "")
        if not address:
            return config
        self.log_received.emit(f"[naive][stage=resolve] server address from trusted DNS ({resolution.source}), IPv4")
        return {**config, "host-resolver-rules": f"MAP {host} {address}"}

    def _write_config(self, config: dict) -> Path:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        path = RUNTIME_DIR / f"naive_config_{os.getpid()}_{time.monotonic_ns()}.json"
        payload = dict(config)
        payload.setdefault("log", "")  # empty path = console: the manager reads the errors from the pipe
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        return path

    def _cleanup_config(self) -> None:
        path, self._config_path = self._config_path, None
        if path is not None:
            try:
                path.unlink()
            except OSError:
                pass

    def _tunnel_ready_steps(self, port: int, username: str, password: str, cancelled) -> TransitionSteps:
        """One HTTPS request through naive to the key's server proves the key is accepted and the path works."""

        deadline = time.monotonic() + READY_TIMEOUT_SECONDS
        errors: dict[str, str] = {}

        def attempt(endpoint) -> str | None:
            """One probe, never longer than PROBE_WALL_SECONDS: a newer click can only be served between two steps, so a
            step that ran for half a minute (three endpoints, several socket waits each) held the whole app on
            «Подключение…» (measured on win10, 2026-11-27: a click on a VLESS server waited 29 s behind a dead key)."""
            box: list[str | None] = []

            def run() -> None:
                try:
                    probe_https(port, username=username, password=password, endpoint=endpoint,
                                timeout=PROBE_TIMEOUT_SECONDS)
                    box.append(None)
                except (OSError, ValueError) as exc:
                    box.append(f"{type(exc).__name__}: {exc}")

            thread = threading.Thread(target=run, name="naive-probe", daemon=True)
            thread.start()
            thread.join(PROBE_WALL_SECONDS)
            return box[0] if box else f"no answer in {PROBE_WALL_SECONDS:.0f} s"

        turn = 0
        while time.monotonic() < deadline:
            if self._failed or cancelled() or self._process.state() == QProcess.ProcessState.NotRunning:
                return False
            endpoint = HTTPS_ENDPOINTS[turn % len(HTTPS_ENDPOINTS)]
            turn += 1
            outcome = yield run_in_worker(lambda endpoint=endpoint: attempt(endpoint))
            if outcome is None:
                return True
            errors[endpoint[0]] = str(outcome)
            yield sleep_ms(1000)
        last_error = "; ".join(f"{host}: {text}" for host, text in errors.items())
        if not self._failed and not cancelled():
            tail = " | ".join(self._recent)
            self._report("tunnel_readiness", f"No request got through the NaiveProxy server: {last_error}. {tail}")
        return False

    # ── output and exit ──────────────────────────────────────────────────

    def _read(self) -> None:
        self._buffer += bytes(self._process.readAllStandardOutput())
        if len(self._buffer) > 1024 * 1024:
            self._buffer = self._buffer[-65536:]
        while b"\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\n", 1)
            text = self._clean(line.decode("utf-8", errors="replace"))
            if not text:
                continue
            self._recent.append(text)
            self.log_received.emit(f"[naive] {text}")

    def _process_error(self, _error) -> None:
        if not self._expected:
            self._failed = True
            self._report("process", self._process.errorString())

    def _finished(self, exit_code, _status) -> None:
        self._read()
        was_running = self._running
        self._running = False
        self._cleanup_config()
        if not self._expected and not self._failed:
            self._failed = True
            self._report("process", f"naive process exited with code {exit_code}")
        if was_running:
            self.state_changed.emit(False)
        self.stopped.emit(exit_code)

    # ── stop ─────────────────────────────────────────────────────────────

    def stop(self, expected: bool = True) -> bool:
        return bool(run_steps_blocking(self.stop_steps(expected=expected)))

    def request_stop(self, expected: bool = True) -> None:
        """Close admission now without waiting (signal handlers): kill after the same 1.5 s grace."""
        self._expected = expected
        if self._process.state() == QProcess.ProcessState.NotRunning:
            self._running = False
            return
        self._process.terminate()
        QTimer.singleShot(1500, self._kill_if_running)

    def _kill_if_running(self) -> None:
        if self._process.state() != QProcess.ProcessState.NotRunning:
            self._process.kill()

    def stop_steps(self, expected: bool = True) -> TransitionSteps:
        self._expected = expected
        if self._process.state() != QProcess.ProcessState.NotRunning:
            # naive is a console program without a stdin protocol: a console process on Windows ignores terminate()
            # for a hidden window, so kill after a short grace.
            self._process.terminate()
            if not (yield wait_process_finished(self._process, 800)):
                self._process.kill()
                if not (yield wait_process_finished(self._process, 1500)):
                    return False
        self._cleanup_config()
        self._running = False
        return True
