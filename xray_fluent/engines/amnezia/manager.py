from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
import os
import time

from PyQt6.QtCore import QObject, QProcess, pyqtSignal

from ...constants import AMNEZIA_PATH_DEFAULT
from ...diagnostics.export import capture_runtime_config
from ...diagnostics.runtime_logging import RuntimeNodeIdentity, redact_runtime_log
from ...platform.windows.subprocess_utils import CREATE_NO_WINDOW, result_output_text, run_text_pumped, sleep_with_events, wait_for_qprocess_finished, wait_for_qprocess_started
from ..socks_probe import probe_https


PROBES = (("1.1.1.1", "cloudflare-dns.com", "/"),
          ("8.8.8.8", "dns.google", "/"),
          ("9.9.9.9", "dns.quad9.net", "/"))


def physical_network() -> dict:
    if os.name != "nt":
        return {"interface_index": 0, "bootstrap_dns": []}
    # Resolve before installing the new TUN; exclude tunnel/software adapters.
    script = ("$r = Get-NetRoute | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } "
              "| Sort-Object RouteMetric,InterfaceMetric; "
              "foreach ($i in $r) { $a = Get-NetAdapter -InterfaceIndex $i.InterfaceIndex -ErrorAction SilentlyContinue; "
              "if ($a.Status -eq 'Up' -and $a.HardwareInterface) { "
              "$dns = @(Get-DnsClientServerAddress -InterfaceIndex $i.InterfaceIndex | ForEach-Object { $_.ServerAddresses }); "
              "@{ interface_index = [int]$i.InterfaceIndex; bootstrap_dns = $dns } | ConvertTo-Json -Compress; exit 0 } }; exit 1")
    result = run_text_pumped(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                             timeout=6, creationflags=CREATE_NO_WINDOW)
    if result.returncode:
        raise OSError("Physical interface for Amnezia UDP transport not found")
    network = json.loads(result_output_text(result).strip())
    if not isinstance(network, dict) or not isinstance(network.get("interface_index"), int) or network["interface_index"] <= 0:
        raise OSError("Invalid physical interface index")
    if not isinstance(network.get("bootstrap_dns"), list):
        raise OSError("Invalid physical DNS server list")
    return network


class AmneziaManager(QObject):
    log_received = pyqtSignal(str)
    error = pyqtSignal(str)
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

    def start(self, config: dict, relay_port: int, *, context=None, session_generation=0, target_generation=0) -> bool:
        if not self.stop():
            return False
        self._expected = self._failed = self._relay_ready = False
        self._buffer = b""
        self.stats = {}
        self._context = context
        self._identity = dict(session_generation=session_generation, target_generation=target_generation,
                              target_id=context.ref if context else "")
        payload = deepcopy(config)
        try:
            payload.update(physical_network())
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
            while not self._relay_ready and time.monotonic() < deadline and not self._failed:
                if self._process.state() == QProcess.ProcessState.NotRunning:
                    break
                sleep_with_events(0.025)
            if not self._relay_ready or self._failed:
                raise OSError("Amnezia local relay did not become ready")
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
        return self._ready(int(config["listen"].rsplit(":", 1)[1]), config, via_dns=True)

    def _ready(self, port: int, config: dict, *, via_dns: bool = False) -> bool:
        deadline = time.monotonic() + 20
        failures: dict[str, str] = {}
        executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="amnezia-ready")
        try:
            while time.monotonic() < deadline and not self._failed:
                endpoints = tuple((name, name, path) if via_dns else (ip, name, path) for ip, name, path in PROBES)
                futures = {executor.submit(probe_https, port, username=config["username"], password=config["password"],
                                            endpoint=e, timeout=4): e[1] for e in endpoints}
                success = False
                while futures and time.monotonic() < deadline and not self._failed:
                    if self._process.state() == QProcess.ProcessState.NotRunning:
                        return False
                    for future in list(futures):
                        if future.done():
                            host = futures.pop(future)
                            error = future.exception()
                            if error is None:
                                success = True
                            else:
                                failures[host] = f"{type(error).__name__}: {error}"
                    # Do not accumulate unbounded probe waves; each wave drains.
                    if success and any(p.get("last_handshake_time_sec", 0) for p in self.stats.get("peers", [])):
                        return True
                    sleep_with_events(0.025)
                for future in futures:
                    future.cancel()
            if not self._failed:
                handshake = any(p.get("last_handshake_time_sec", 0) for p in self.stats.get("peers", []))
                self._report("https_readiness" if handshake else "handshake_readiness",
                             ("HTTPS probes failed: " if handshake else "No authenticated handshake observed; ") +
                             "; ".join(f"{host}: {message}" for host, message in sorted(failures.items())))
            return False
        finally:
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
                    self.stats = event
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
        self._expected = expected
        if self._process.state() != QProcess.ProcessState.NotRunning:
            self._process.closeWriteChannel()
            if not wait_for_qprocess_finished(self._process, 1500):
                self._process.kill()
                if not wait_for_qprocess_finished(self._process, 1500):
                    return False
        self._running = False
        return True
