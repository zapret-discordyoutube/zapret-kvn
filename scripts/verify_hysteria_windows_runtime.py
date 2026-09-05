from __future__ import annotations

"""Windows-only runtime gate for the official Hysteria/sing-box PE path.

The gate deliberately accepts private Hysteria URIs through stdin and never
prints or persists them.  It is intended for a disposable Windows checkout,
not as an end-user launcher.
"""

from copy import deepcopy
from concurrent.futures import Future, ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
from typing import Any
from urllib.parse import urlsplit

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from PyQt6.QtCore import QCoreApplication

from xray_fluent.engines.hysteria.runtime_contract import classify_hysteria_uri
from xray_fluent.constants import (
    HYSTERIA_CONFIG_FILE,
    HYSTERIA_PATH_DEFAULT,
    PROXY_HOST,
    RUNTIME_DIR,
    SINGBOX_CONFIG_FILE,
    SINGBOX_PATH_DEFAULT,
)
from xray_fluent.engines.hysteria.manager import HysteriaManager
from xray_fluent.engines.singbox.runtime_planner import (
    SingboxRuntimePlan,
    parse_singbox_document,
    plan_singbox_proxy_runtime,
    plan_singbox_runtime,
)
from xray_fluent.engines.singbox.manager import SingBoxManager
from xray_fluent.importer.link_parser import parse_single


_HTTPS_ENDPOINTS: tuple[tuple[str, str], ...] = (
    ("cloudflare-dns.com", "/"),
    ("dns.google", "/"),
    ("dns.quad9.net", "/"),
)
_TEMPLATE = _ROOT / "data" / "templates" / "sing-box" / "default.json"


class GateFailure(RuntimeError):
    pass


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((PROXY_HOST, 0))
        return int(listener.getsockname()[1])


def _recv_headers(client: socket.socket, *, limit: int = 65536) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while size < limit:
        chunk = client.recv(min(4096, limit - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        joined = b"".join(chunks)
        if b"\r\n\r\n" in joined:
            return joined
    return b"".join(chunks)


def _probe_https_through_http_proxy(
    port: int,
    endpoint: tuple[str, str],
    *,
    timeout: float,
) -> None:
    host, path = endpoint
    raw = socket.create_connection((PROXY_HOST, int(port)), timeout=timeout)
    try:
        raw.settimeout(timeout)
        raw.sendall(
            f"CONNECT {host}:443 HTTP/1.1\r\n"
            f"Host: {host}:443\r\n"
            "Proxy-Connection: keep-alive\r\n\r\n".encode("ascii")
        )
        response = _recv_headers(raw)
        status = response.split(b"\r\n", 1)[0]
        if b" 200 " not in status:
            raise GateFailure("HTTP proxy CONNECT did not return 200")
        context = ssl.create_default_context()
        with context.wrap_socket(raw, server_hostname=host) as secure:
            raw = None
            secure.settimeout(timeout)
            secure.sendall(
                f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode(
                    "ascii"
                )
            )
            if not secure.recv(16).startswith(b"HTTP/"):
                raise GateFailure("HTTPS identity probe through HTTP proxy failed")
    finally:
        if raw is not None:
            raw.close()


def _probe_https_through_system_route(
    endpoint: tuple[str, str],
    *,
    timeout: float,
) -> None:
    host, path = endpoint
    raw: socket.socket | None = None
    try:
        raw = socket.create_connection((host, 443), timeout=timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw, server_hostname=host) as secure:
            raw = None
            secure.settimeout(timeout)
            secure.sendall(
                f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode(
                    "ascii"
                )
            )
            if not secure.recv(16).startswith(b"HTTP/"):
                raise GateFailure("HTTPS identity probe through Windows TUN failed")
    finally:
        if raw is not None:
            raw.close()


def _bounded_https_race(probe, *, timeout: float) -> None:
    executor = ThreadPoolExecutor(
        max_workers=len(_HTTPS_ENDPOINTS),
        thread_name_prefix="hysteria-gate-ready",
    )
    futures: dict[Future[None], tuple[str, str]] = {
        executor.submit(probe, endpoint, timeout=timeout): endpoint
        for endpoint in _HTTPS_ENDPOINTS
    }
    failures: dict[str, str] = {}
    deadline = time.monotonic() + timeout
    try:
        while futures and time.monotonic() < deadline:
            completed = [future for future in futures if future.done()]
            for future in completed:
                endpoint = futures.pop(future)
                error = future.exception()
                if error is None:
                    return
                failures[endpoint[0]] = type(error).__name__
            time.sleep(0.02)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    details = ", ".join(f"{host}={error}" for host, error in sorted(failures.items()))
    raise GateFailure(f"all HTTPS identity probes failed ({details or 'deadline'})")


def _https_through_http_proxy(port: int, *, timeout: float = 8.0) -> None:
    _bounded_https_race(
        lambda endpoint, *, timeout: _probe_https_through_http_proxy(
            port,
            endpoint,
            timeout=timeout,
        ),
        timeout=timeout,
    )


def _https_through_system_route(*, timeout: float = 8.0, attempts: int = 3) -> None:
    time.sleep(1.0)
    for _attempt in range(max(1, attempts)):
        try:
            _bounded_https_race(_probe_https_through_system_route, timeout=timeout)
            return
        except GateFailure:
            pass
        time.sleep(0.5)
    raise GateFailure("HTTPS identity probes through Windows TUN all failed")


def _require_hysteria_plan(plan: SingboxRuntimePlan) -> None:
    if not plan.is_hysteria_sidecar or plan.hysteria_sidecar is None:
        raise GateFailure("runtime planner did not select the official Hysteria sidecar")


def _start_sidecar(
    plan: SingboxRuntimePlan,
    *,
    generation: int,
    allow_parallel: bool,
    metrics: dict[str, int],
    verify_remote: bool = True,
) -> HysteriaManager:
    _require_hysteria_plan(plan)
    sidecar = plan.hysteria_sidecar
    assert sidecar is not None
    manager = HysteriaManager()
    manager.log_received.connect(
        lambda line: metrics.__setitem__(
            "hysteria_log_bytes",
            metrics["hysteria_log_bytes"] + len(line.encode("utf-8", errors="replace")),
        )
    )
    started_at = time.perf_counter()
    if not manager.start(
        sidecar.config,
        sidecar.relay_port,
        context=sidecar.context,
        process_generation=generation,
        allow_parallel=allow_parallel,
        verify_remote=verify_remote,
    ):
        code = manager.last_failure_code.value if manager.last_failure_code is not None else "unknown"
        raise GateFailure(f"Hysteria sidecar did not become ready ({code})")
    metrics["hysteria_starts"] += 1
    metrics["hysteria_readiness_total_ms"] += int((time.perf_counter() - started_at) * 1000)
    _sample_process_metrics(manager._process.processId(), "hysteria", metrics)
    return manager


def _start_front(plan: SingboxRuntimePlan, metrics: dict[str, int]) -> SingBoxManager:
    manager = SingBoxManager()
    manager.log_received.connect(
        lambda line: metrics.__setitem__(
            "singbox_log_bytes",
            metrics["singbox_log_bytes"] + len(line.encode("utf-8", errors="replace")),
        )
    )
    started_at = time.perf_counter()
    if not manager.start(str(SINGBOX_PATH_DEFAULT), plan.singbox_config):
        raise GateFailure("sing-box front did not become ready")
    metrics["singbox_starts"] += 1
    metrics["singbox_readiness_total_ms"] += int((time.perf_counter() - started_at) * 1000)
    _sample_process_metrics(manager._process.processId(), "singbox", metrics)
    return manager


def _sample_process_metrics(process_id: int, kind: str, metrics: dict[str, int]) -> None:
    if os.name != "nt" or process_id <= 0:
        return
    script = (
        f"$p=Get-Process -Id {int(process_id)} -ErrorAction SilentlyContinue; "
        "if($p){[Console]::Write($p.CPU.ToString([Globalization.CultureInfo]::InvariantCulture)); "
        "[Console]::Write('|'); [Console]::Write($p.WorkingSet64)}"
    )
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    cpu_text, separator, rss_text = completed.stdout.strip().partition("|")
    if not separator:
        return
    try:
        cpu_millis = int(float(cpu_text) * 1000)
        rss_bytes = int(rss_text)
    except ValueError:
        return
    metrics[f"{kind}_sampled_cpu_ms"] += cpu_millis
    metrics[f"{kind}_peak_rss_bytes"] = max(metrics[f"{kind}_peak_rss_bytes"], rss_bytes)


def _unreachable_replacement_config(plan: SingboxRuntimePlan, relay_port: int) -> dict[str, Any]:
    sidecar = plan.hysteria_sidecar
    assert sidecar is not None
    config = deepcopy(sidecar.config)
    parsed = urlsplit(str(config.get("server") or ""))
    userinfo = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
    config["server"] = parsed._replace(netloc=f"{userinfo}127.0.0.1:1").geturl()
    socks = config.get("socks5")
    if not isinstance(socks, dict):
        raise GateFailure("replacement config has no SOCKS contract")
    socks["listen"] = f"{PROXY_HOST}:{relay_port}"
    return config


def _exact_image_path_count(executable: Path) -> int:
    if os.name != "nt":
        return 0
    expected = str(executable.resolve()).replace("'", "''")
    script = (
        f"$p='{expected}'; "
        "$n=@(Get-CimInstance Win32_Process -Filter \"Name='" + executable.name.replace("'", "''") + "'\" "
        "| Where-Object { $_.ExecutablePath -and [string]::Equals($_.ExecutablePath,$p,[System.StringComparison]::OrdinalIgnoreCase) }).Count; "
        "[Console]::Out.Write($n)"
    )
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    try:
        return int(completed.stdout.strip())
    except ValueError:
        return -1


def _load_private_cases() -> list[tuple[str, str]]:
    try:
        payload = json.load(sys.stdin)
    except (OSError, json.JSONDecodeError) as exc:
        raise GateFailure("stdin does not contain the private JSON gate payload") from exc
    if not isinstance(payload, list) or len(payload) < 2:
        raise GateFailure("at least two Hysteria profiles are required")
    cases: list[tuple[str, str]] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise GateFailure(f"profile {index + 1} is not an object")
        identity = str(item.get("id") or f"profile-{index + 1}")
        uri = str(item.get("uri") or "")
        capability = classify_hysteria_uri(uri, platform="windows")
        if not capability.valid:
            raise GateFailure(f"{identity}: incompatible URI ({capability.failure_code.value})")
        cases.append((identity, uri))
    return cases


def _remove_runtime_artifacts() -> None:
    for path in (HYSTERIA_CONFIG_FILE, SINGBOX_CONFIG_FILE):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
    for path in RUNTIME_DIR.glob(f"{HYSTERIA_CONFIG_FILE.stem}-*.json"):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def main() -> int:
    if os.name != "nt":
        raise GateFailure("this gate must run on Windows")
    app = QCoreApplication.instance() or QCoreApplication([])
    cases = _load_private_cases()
    template_text = _TEMPLATE.read_text(encoding="utf-8")
    document = parse_singbox_document(_TEMPLATE, template_text)
    nodes = [(identity, parse_single(uri)) for identity, uri in cases]

    metrics = {
        "hysteria_starts": 0,
        "singbox_starts": 0,
        "hysteria_readiness_total_ms": 0,
        "singbox_readiness_total_ms": 0,
        "switch_commit_ms": 0,
        "failed_replacement_ms": 0,
        "hysteria_log_bytes": 0,
        "singbox_log_bytes": 0,
        "hysteria_sampled_cpu_ms": 0,
        "singbox_sampled_cpu_ms": 0,
        "hysteria_peak_rss_bytes": 0,
        "singbox_peak_rss_bytes": 0,
    }
    gate_started_at = time.perf_counter()
    fronts: list[SingBoxManager] = []
    sidecars: list[HysteriaManager] = []
    checks: list[str] = []
    try:
        first_id, first_node = nodes[0]
        first = plan_singbox_proxy_runtime(
            document,
            first_node,
            preferred_relay_port=_free_port(),
        )
        first_sidecar = _start_sidecar(
            first,
            generation=1,
            allow_parallel=False,
            metrics=metrics,
        )
        sidecars.append(first_sidecar)
        first_front = _start_front(first, metrics)
        fronts.append(first_front)
        _https_through_http_proxy(first.http_port)
        checks.append(f"proxy:{first_id}")

        second_id, second_node = nodes[1]
        replacement = plan_singbox_proxy_runtime(
            document,
            second_node,
            allowed_proxy_ports={first.socks_port, first.http_port},
            preferred_relay_port=_free_port(),
        )
        switch_started_at = time.perf_counter()
        replacement_sidecar = _start_sidecar(
            replacement,
            generation=2,
            allow_parallel=True,
            metrics=metrics,
        )
        sidecars.append(replacement_sidecar)
        _https_through_http_proxy(first.http_port)
        checks.append("old-front-live-during-prepare")

        if not first_front.stop(expected=True):
            raise GateFailure("old sing-box front did not stop for commit")
        fronts.remove(first_front)
        replacement_front = _start_front(replacement, metrics)
        fronts.append(replacement_front)
        _https_through_http_proxy(replacement.http_port)
        if not first_sidecar.stop(expected=True):
            raise GateFailure("old Hysteria sidecar did not stop after commit")
        sidecars.remove(first_sidecar)
        metrics["switch_commit_ms"] = int((time.perf_counter() - switch_started_at) * 1000)
        checks.append(f"switch:{first_id}->{second_id}")

        failed_replacement = HysteriaManager()
        failed_port = _free_port()
        failed_config = _unreachable_replacement_config(replacement, failed_port)
        failed_started_at = time.perf_counter()
        if failed_replacement.start(
            failed_config,
            failed_port,
            process_generation=3,
            allow_parallel=True,
            verify_remote=True,
        ):
            failed_replacement.stop(expected=True)
            raise GateFailure("intentionally unreachable replacement unexpectedly became ready")
        metrics["hysteria_starts"] += 1
        metrics["failed_replacement_ms"] = int((time.perf_counter() - failed_started_at) * 1000)
        _https_through_http_proxy(replacement.http_port)
        checks.append("failed-replacement-preserved-old-front")

        if not replacement_front.stop(expected=True):
            raise GateFailure("proxy front did not stop before TUN gate")
        fronts.remove(replacement_front)
        if not replacement_sidecar.stop(expected=True):
            raise GateFailure("proxy sidecar did not stop before TUN gate")
        sidecars.remove(replacement_sidecar)

        for generation, (identity, node) in enumerate(nodes[2:], start=4):
            profile_plan = plan_singbox_proxy_runtime(
                document,
                node,
                preferred_relay_port=_free_port(),
            )
            profile_sidecar = _start_sidecar(
                profile_plan,
                generation=generation,
                allow_parallel=False,
                metrics=metrics,
            )
            sidecars.append(profile_sidecar)
            profile_front = _start_front(profile_plan, metrics)
            fronts.append(profile_front)
            _https_through_http_proxy(profile_plan.http_port)
            checks.append(f"proxy:{identity}")
            if not profile_front.stop(expected=True):
                raise GateFailure(f"{identity}: proxy front did not stop")
            fronts.remove(profile_front)
            if not profile_sidecar.stop(expected=True):
                raise GateFailure(f"{identity}: Hysteria sidecar did not stop")
            sidecars.remove(profile_sidecar)

        tun = plan_singbox_runtime(
            document,
            first_node,
            preferred_relay_port=_free_port(),
        )
        tun_sidecar = _start_sidecar(
            tun,
            generation=len(nodes) + 2,
            allow_parallel=False,
            metrics=metrics,
        )
        sidecars.append(tun_sidecar)
        tun_front = _start_front(tun, metrics)
        fronts.append(tun_front)
        _https_through_system_route()
        checks.append(f"tun:{first_id}")
    finally:
        for front in reversed(fronts):
            front.stop(expected=True)
        for sidecar in reversed(sidecars):
            sidecar.stop(expected=True)
        app.processEvents()
        _remove_runtime_artifacts()

    orphan_counts = {
        "hysteria": _exact_image_path_count(HYSTERIA_PATH_DEFAULT),
        "sing-box": _exact_image_path_count(SINGBOX_PATH_DEFAULT),
    }
    if any(count != 0 for count in orphan_counts.values()):
        raise GateFailure(f"exact-path orphan processes remain: {orphan_counts}")
    stale_configs = list(RUNTIME_DIR.glob(f"{HYSTERIA_CONFIG_FILE.stem}*.json"))
    if stale_configs:
        raise GateFailure("temporary Hysteria configs remain after cleanup")

    metrics["gate_total_ms"] = int((time.perf_counter() - gate_started_at) * 1000)
    print(
        json.dumps(
            {
                "status": "ok",
                "checks": checks,
                "orphans": orphan_counts,
                "metrics": metrics,
            }
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateFailure as exc:
        print(json.dumps({"status": "failed", "reason": str(exc)}), file=sys.stderr)
        raise SystemExit(1)
