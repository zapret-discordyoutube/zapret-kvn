from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import ipaddress
import json
import os
import time

from PyQt6.QtCore import QObject, QProcess, pyqtSignal

from ...constants import AMNEZIA_PATH_DEFAULT
from ...diagnostics.export import capture_runtime_config
from ...diagnostics.runtime_logging import RuntimeNodeIdentity, redact_runtime_log
from ...platform.windows.subprocess_utils import sleep_with_events, wait_for_qprocess_finished, wait_for_qprocess_started
from ...platform.windows import win_netinfo
from ..socks_probe import HTTPS_ENDPOINTS, probe_https
from ..health_check import BackgroundHealthCheck
from ..sidecar import wait_for_loopback_relay


PROBES = HTTPS_ENDPOINTS


def _first_peer_ipv4(config: dict) -> str | None:
    """The AWG server's IPv4 literal, if the config already carries one.

    Used to ask the OS which interface reaches the server (GetBestInterfaceEx),
    which returns the physical uplink even while a tunnel holds the default
    route. Peer addresses are resolved to IPs before the core sees them.
    """
    try:
        for peer in ((config or {}).get("endpoint") or {}).get("peers") or []:
            address = str((peer or {}).get("address") or "").strip()
            if address:
                ipaddress.IPv4Address(address)  # raises on hostname / IPv6
                return address
    except (ValueError, TypeError):
        return None
    return None


def physical_network(dest_ipv4: str | None = None, *, attempts: int = 5, retry_delay: float = 0.3) -> dict:
    """Resolve the physical uplink the AWG UDP socket must bind to.

    The owned Go core binds via ``IP_UNICAST_IF`` and hard-requires a valid,
    non-zero interface index (there is no default-bind fallback), so this must
    return a real physical interface. Resolution asks the OS which interface
    reaches ``dest_ipv4`` (``GetBestInterfaceEx``) — the authoritative
    default-route decision — instead of spawning PowerShell (~500 ms, and its
    ``HardwareInterface`` filter wrongly excluded Hyper-V / WSL / Docker
    ``vEthernet`` uplinks). The uplink can be briefly unavailable during a
    network transition, so a transient miss is retried instead of aborting.
    """
    if os.name != "nt":
        return {"interface_index": 0, "bootstrap_dns": []}
    target = dest_ipv4 or win_netinfo._DEFAULT_PROBE_DESTINATION
    last_error: Exception | None = None
    for attempt in range(max(1, attempts)):
        try:
            resolved = win_netinfo.resolve_physical_uplink(target)
        except win_netinfo.WinNetInfoError as exc:
            last_error, resolved = exc, None
        if resolved is not None:
            index, bootstrap_dns = resolved
            return {"interface_index": index, "bootstrap_dns": bootstrap_dns}
        if attempt + 1 < max(1, attempts):
            sleep_with_events(retry_delay)
    detail = f" ({last_error})" if last_error is not None else ""
    raise OSError("Physical interface for Amnezia UDP transport not found" + detail)


class AmneziaManager(QObject):
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
        self._relay_ready = False
        self._buffer = b""
        self._identity: dict = {}
        self._context: RuntimeNodeIdentity | None = None
        self.stats: dict = {}
        self.diagnostic_config = None
        self._is_current = None
        self._health = BackgroundHealthCheck(self)
        self._pending_front_config = None

    @property
    def is_running(self) -> bool:
        return self._running and not self._failed and self._process.state() != QProcess.ProcessState.NotRunning

    def _report(self, stage: str, raw: str) -> None:
        from ...diagnostics.runtime_errors import core_failure
        clean = redact_runtime_log(raw)
        identity = self._context.fields() if self._context else ""
        message = f"[amnezia][stage={stage} {identity}] {clean}"
        self.log_received.emit(message)
        self.error.emit(message)
        self.failure.emit(core_failure("amnezia", stage, clean, **self._identity))

    def start(self, config: dict, relay_port: int, *, context=None, session_generation=0, target_generation=0, is_current=None) -> bool:
        if not self.stop():
            return False
        self._expected = self._failed = self._relay_ready = False
        self._is_current = is_current
        self._buffer = b""
        self.stats = {}
        self._context = context
        self._identity = dict(session_generation=session_generation, target_generation=target_generation,
                              target_id=context.ref if context else "")
        payload = deepcopy(config)
        try:
            payload.update(physical_network(_first_peer_ipv4(payload)))
            if self._cancelled():
                return False
            payload.update(session_generation=session_generation, target_generation=target_generation,
                           target_ref=self._identity["target_id"])
            if not AMNEZIA_PATH_DEFAULT.is_file():
                raise OSError("zapret-amnezia.exe is missing from the installed core bundle")
            self.diagnostic_config = capture_runtime_config(AMNEZIA_PATH_DEFAULT, payload)
            self._process.setProgram(str(AMNEZIA_PATH_DEFAULT))
            self._process.setArguments([])
            self._process.start()
            if not wait_for_qprocess_started(self._process, 5000):
                raise OSError(self._process.errorString())
            encoded = json.dumps(payload, separators=(",", ":")).encode() + b"\n"
            if len(encoded) > 1024 * 1024 or self._process.write(encoded) != len(encoded):
                raise OSError("Failed to send bounded configuration to Amnezia stdin")
            deadline = time.monotonic() + 10
            while not self._relay_ready and time.monotonic() < deadline and not self._failed and not self._cancelled():
                if self._process.state() == QProcess.ProcessState.NotRunning:
                    break
                sleep_with_events(0.025)
            if self._cancelled():
                self.stop()
                return False
            if not self._relay_ready or self._failed:
                raise OSError("Amnezia local relay did not become ready")
            # Shared sidecar seam: confirm the loopback SOCKS listener actually
            # accepts a connection before firing the handshake probe, matching
            # the Hysteria contract. relay_ready already fired, so this is an
            # immediate confirmation that tolerates a brief bind delay.
            if not wait_for_loopback_relay(
                relay_port,
                should_continue=lambda: not self._failed and not self._cancelled()
                and self._process.state() != QProcess.ProcessState.NotRunning,
            ):
                if self._cancelled():
                    self.stop()
                    return False
                raise OSError("Amnezia local relay is not accepting loopback connections")
            if not self._ready(relay_port, payload):
                self.stop()
                return False
        except (OSError, ValueError, KeyError) as exc:
            if not self._failed:
                self._report("startup", str(exc))
            self.stop()
            return False
        self._running = True
        self.state_changed.emit(True)
        return True

    def verify_front_dns(self, config: dict) -> bool:
        # The authenticated tunnel is already running. Domain checks follow
        # the original IP probe wave, without delaying admission or doubling
        # the number of simultaneous probe sockets.
        if not self.is_running or self._cancelled():
            return False
        if self._health.active and self.stats.get("https_check") == "pending":
            self._pending_front_config = deepcopy(config)
            self.stats["front_dns_check"] = "queued"
            return True
        self._start_front_health(config)
        return True

    def _start_front_health(self, config):
        self._health.cancel()
        port = int(config["listen"].rsplit(":", 1)[1])
        executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="amnezia-health")
        futures = {executor.submit(probe_https, port, username=config["username"], password=config["password"],
                   endpoint=(name, name, path), timeout=20): name for _, name, path in PROBES}
        self.stats["front_dns_check"] = "pending"
        self._health.adopt(executor, futures, {},
            current=lambda: self.is_running and not self._cancelled(), complete=self._front_health_complete)
        return True

    def _front_health_complete(self, winner, failures):
        self.stats["front_dns_check"] = "passed" if winner else "warning"
        if winner:
            self.log_received.emit(f"[amnezia][stage=health_check] DNS/HTTPS check succeeded via {winner}")
            return
        detail = "; ".join(f"{host}: {message}" for host, message in sorted(failures.items()))
        self.log_received.emit("[amnezia][stage=health_check] WARNING: connection retained; " + redact_runtime_log(detail))
        self.warning.emit("AWG/WireGuard подключён, но проверка DNS/HTTPS по доменам не прошла. "
                          "Соединение сохранено; доступность сайтов по доменам пока не подтверждена. Подробности — в логах.")

    def _cancelled(self) -> bool:
        return self._expected or (self._is_current is not None and not self._is_current())

    def _monitor_transport_health(self, executor, futures):
        self.stats["remote_authenticated"] = True
        self.stats["https_check"] = "pending"
        self._health.adopt(executor, futures, {},
            current=lambda: self.is_running and not self._cancelled(),
            complete=self._transport_health_complete)

    def _transport_health_complete(self, winner, failures):
        self.stats["https_check"] = "passed" if winner else "warning"
        if winner:
            self.log_received.emit(f"[amnezia][stage=health_check] HTTPS check succeeded via {winner}")
        else:
            detail = "; ".join(f"{host}: {message}" for host, message in sorted(failures.items()))
            self.log_received.emit("[amnezia][stage=health_check] authenticated tunnel retained; " + redact_runtime_log(detail))
            # The AWG Noise handshake is already confirmed (peers reported a
            # handshake time), so the tunnel works. The public DoH probe
            # endpoints are commonly blocked on censored exits, so their
            # failure is not a user-facing problem — do not raise a warning.
        config, self._pending_front_config = self._pending_front_config, None
        if config is not None and self.is_running and not self._cancelled():
            self._start_front_health(config)

    def _ready(self, port: int, config: dict) -> bool:
        if self._failed or self._cancelled() or self._process.state() == QProcess.ProcessState.NotRunning:
            return False
        deadline = time.monotonic() + 20
        executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="amnezia-ready")
        transferred = False
        try:
            # One bounded wave triggers the lazy handshake and subsequently
            # becomes background diagnostics. Its destinations are not a gate
            # for a successful Noise handshake reported by the owned core.
            futures = {executor.submit(probe_https, port, username=config["username"], password=config["password"],
                                       endpoint=e, timeout=4): e[1] for e in PROBES}
            while time.monotonic() < deadline and not self._failed and not self._cancelled():
                if self._process.state() == QProcess.ProcessState.NotRunning:
                    return False
                if any(p.get("last_handshake_time_sec", 0) for p in self.stats.get("peers", [])):
                    self._monitor_transport_health(executor, futures)
                    transferred = True
                    return True
                sleep_with_events(0.025)
            if not self._failed and not self._cancelled():
                failures = []
                for future, host in futures.items():
                    if future.done() and not future.cancelled():
                        error = future.exception()
                        if error is not None:
                            failures.append(f"{host}: {type(error).__name__}: {error}")
                self._report("handshake_readiness", "No authenticated handshake observed; " + "; ".join(failures))
            return False
        finally:
            if not transferred:
                executor.shutdown(wait=False, cancel_futures=True)

    def _read(self) -> None:
        self._buffer += bytes(self._process.readAllStandardOutput())
        if len(self._buffer) > 2 * 1024 * 1024:
            self._failed = True
            self._report("observer", "Amnezia output exceeded the bounded control channel")
            self.stop()
            return
        while b"\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\n", 1)
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("control event must be an object")
                # Decoder/process failures can precede reading config identity.
                # This exception is confined to the owned pre-readiness pipe.
                pre_config_failure = (
                    not self._relay_ready and event.get("stage") == "process" and
                    event.get("session_generation") == 0 and
                    event.get("target_generation") == 0 and event.get("target_ref") == ""
                )
                if not pre_config_failure and (event.get("session_generation") != self._identity["session_generation"] or
                    event.get("target_generation") != self._identity["target_generation"] or
                    event.get("target_ref") != self._identity["target_id"]):
                    continue
                stage, raw = event["stage"], event.get("raw", "")
                if stage == "stats":
                    self.stats = {**{key: self.stats[key] for key in ("remote_authenticated", "https_check", "front_dns_check") if key in self.stats}, **event}
                elif stage == "relay_ready":
                    self._relay_ready = True
                elif stage in {"core_error", "configure", "netstack", "start", "relay", "process", "bootstrap_dns", "observer"}:
                    self._failed = True
                    self._report(stage, raw)
                elif stage in {"destination_dns", "relay_connection", "udp"}:
                    self._report(stage, raw)
                elif stage == "core" and "Handshake did not complete" in raw:
                    if "giving up" in raw:
                        self._failed = True
                        self._report("handshake_failed", raw)
                    else:
                        self._report("handshake_retry", raw)
                else:
                    self.log_received.emit(f"[amnezia][stage={stage}] {redact_runtime_log(raw)}")
            except (ValueError, KeyError, TypeError):
                self._failed = True
                self._report("observer", "Invalid Amnezia control event: " + redact_runtime_log(line.decode("utf-8", errors="replace")))

    def _process_error(self, _error) -> None:
        if not self._expected:
            self._failed = True
            self._report("process", self._process.errorString())

    def _finished(self, exit_code, _status) -> None:
        self._cancel_health()
        self._read()
        was_running = self._running
        self._running = False
        if not self._expected and not self._failed:
            self._failed = True
            self._report("process", f"Amnezia process exited with code {exit_code}")
        if was_running:
            self.state_changed.emit(False)
        self.stopped.emit(exit_code)

    def stop(self, expected: bool = True) -> bool:
        self._cancel_health()
        self._expected = expected
        if self._process.state() != QProcess.ProcessState.NotRunning:
            self._process.closeWriteChannel()
            if not wait_for_qprocess_finished(self._process, 1500):
                self._process.kill()
                if not wait_for_qprocess_finished(self._process, 1500):
                    return False
        self._running = False
        return True

    def _cancel_health(self):
        self._health.cancel()
        self._pending_front_config = None
        for key in ("https_check", "front_dns_check"):
            if self.stats.get(key) in {"pending", "queued"}:
                self.stats[key] = "cancelled"
