from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from typing import Any
from urllib.request import Request

from ..network.http_utils import urlopen

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

from PyQt6.QtCore import QThread, pyqtSignal

from ..constants import DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT, XRAY_PATH_DEFAULT
from ..profiles.path_utils import resolve_configured_path
from ..network import probe_gate
from ..platform.windows.process_traffic_collector import collect_process_stats, ProcessTrafficSnapshot
from ..platform.windows.subprocess_utils import decode_output, run_text
from ..platform.windows.win_proc_monitor import get_proxy_connections, ProxyProcessInfo
from .proxy_demand import clash_proxy_demand, local_proxy_demand


# Активный сервер на проводе не трогаем (требование незаметности, шлюз
# проверок).  Раньше здесь было пустое TCP-соединение раз в 10–60 с всю
# сессию — ровный маяк к VPN-серверу.  Теперь:
# * задержка — RTT уже открытых соединений ядра, его меряет сам стек Windows
#   (``platform/windows/tcp_rtt.py``), на провод не уходит ничего;
# * «канал мёртв» — только по сигналу: запросы уходят, ответа нет
#   ``LINK_SUSPECT_SEC`` подряд; тогда один HTTPS-запрос через локальный
#   прокси ядра (внутри туннеля) подтверждает или снимает подозрение.
RTT_READ_INTERVAL_SEC = 2.0
# Соединений ядра с сервером сейчас нет (простой) — показываем последнее
# известное значение не дольше этого.
RTT_KEEP_SEC = 300.0
PING_TRAFFIC_BPS = 2048.0
PING_UNANSWERED_UP_BPS = 512.0
LINK_IDLE_DOWN_BPS = 1024.0
LINK_SUSPECT_SEC = 10.0
LINK_CONFIRM_TIMEOUT_SEC = 6.0
LINK_CONFIRM_COOLDOWN_SEC = 30.0
LINK_CONFIRM_URL = "https://www.gstatic.com/generate_204"


def _read_connection_rtt(addresses: tuple[str, ...], port: int) -> int | None:
    try:
        from ..platform.windows.tcp_rtt import connection_rtt_ms
    except (ImportError, OSError, AttributeError):
        return None
    return connection_rtt_ms(addresses, port)


def _server_addresses(host: str) -> tuple[str, ...]:
    """Адреса сервера без сети: литерал или запомненный доверенный ответ."""

    import ipaddress

    from ..network.bootstrap_dns import cached_addresses

    host = str(host or "").strip().strip("[]")
    if not host:
        return ()
    try:
        return (str(ipaddress.ip_address(host)),)
    except ValueError:
        return tuple(cached_addresses(host))


def confirm_link_via_proxy(http_port: int, timeout: float = LINK_CONFIRM_TIMEOUT_SEC) -> bool | None:
    """Один запрос через локальный HTTP-прокси ядра: True — жив, False — нет ответа.

    None — до самого прокси не достучались (ядро перезапускается): это не
    вердикт о сервере.
    """

    import urllib.error
    from urllib.request import ProxyHandler

    from ..network.http_utils import build_opener
    from ..network.speed_test_worker import SPEED_TEST_USER_AGENT

    proxy = f"http://127.0.0.1:{int(http_port)}"
    opener = build_opener(ProxyHandler({"http": proxy, "https": proxy}))
    request = Request(LINK_CONFIRM_URL, headers={"User-Agent": SPEED_TEST_USER_AGENT})
    try:
        with opener.open(request, timeout=timeout) as response:
            response.read(16)
        return True
    except urllib.error.HTTPError:
        return True  # ответ пришёл — канал жив
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ConnectionRefusedError):
            return None
        return False
    except OSError:
        return False


class LiveMetricsWorker(QThread):
    metrics = pyqtSignal(object)

    def __init__(
        self,
        xray_path: str,
        api_port: int,
        ping_host: str = "",
        ping_port: int = 0,
        interval_ms: int = 1000,
        ping_interval_sec: float = 3.0,
        mode: str = "xray",
        clash_api_port: int = 19090,
        socks_port: int = DEFAULT_SOCKS_PORT,
        http_port: int = DEFAULT_HTTP_PORT,
        xray_inbound_tags: list[str] | None = None,
        transport_kind: str = "tcp",
        rtt_reader=_read_connection_rtt,
        link_confirmer=None,
    ):
        super().__init__()
        self._xray_path = xray_path
        self._api_port = api_port
        self._ping_host = ping_host
        self._ping_port = ping_port
        self._interval_ms = max(250, interval_ms)
        self._ping_interval_sec = max(1.0, ping_interval_sec)
        self._stopped = False
        self._last_ping_ms: int | None = None
        self._last_ping_ts = 0.0
        self._rtt_reader = rtt_reader
        self._link_confirmer = link_confirmer or (lambda: confirm_link_via_proxy(self._http_port))
        self._ping_addresses: tuple[str, ...] | None = None
        self._rtt_at = 0.0
        # Вердикт о канале: None — неизвестно, True — жив, False — подтверждено мёртв.
        self._link_verdict: bool | None = None
        self._unanswered_since = 0.0
        self._confirming = False
        self._confirmed_at = 0.0
        self._mode = mode
        self._clash_api_port = clash_api_port
        self._socks_port = socks_port
        self._http_port = http_port
        self._transport_kind = str(transport_kind or "tcp").strip().lower() or "tcp"
        normalized_inbound_tags: list[str] = []
        for tag in xray_inbound_tags or []:
            clean = str(tag).strip()
            if clean and clean not in normalized_inbound_tags:
                normalized_inbound_tags.append(clean)
        self._xray_inbound_tags = tuple(normalized_inbound_tags)
        # Спрос на туннель для «умной проверки» авто-переключения: считается
        # здесь, в потоке воркера, из уже полученных данных о соединениях.
        self._demand_prev_bytes: dict[str, tuple[int, int]] = {}
        self._demand_prev_ts: float | None = None
        self._proxy_demand: dict[str, float | int] | None = None

    def stop(self) -> None:
        self._stopped = True

    def pings_active_node(self) -> bool:
        """True when the worker watches the active node's TCP link (passively).

        UDP/QUIC protocols such as Hysteria 2 and TUIC must not use a TCP
        connect as their health verdict: the port can have different TCP and
        UDP behaviour, while neither one alone proves the tunnel works.
        """
        return (
            self._transport_kind != "udp"
            and bool(self._ping_host)
            and self._ping_port > 0
        )

    def set_ping_target(self, host: str, port: int, transport_kind: str | None = None) -> None:
        """Re-point the link watch after a hot-switch (the worker survives it).

        Plain attribute writes are GIL-atomic. Clearing the timestamp makes
        the loop read the new target's RTT on its next tick; the old verdict
        belongs to the old server and is dropped.
        """
        self._ping_host = host
        self._ping_port = int(port)
        if transport_kind is not None:
            self._transport_kind = str(transport_kind or "tcp").strip().lower() or "tcp"
        self._last_ping_ms = None
        self._last_ping_ts = 0.0
        self._ping_addresses = None
        self._rtt_at = 0.0
        self._link_verdict = None
        self._unanswered_since = 0.0

    def _watch_link(self, now: float, down_bps: float | None, up_bps: float | None) -> None:
        """Задержка — из RTT ядра, вердикт о канале — только по сигналу."""

        if now - self._last_ping_ts >= RTT_READ_INTERVAL_SEC or self._last_ping_ts <= 0.0:
            if self._ping_addresses is None:
                self._ping_addresses = _server_addresses(self._ping_host)
            try:
                rtt = self._rtt_reader(self._ping_addresses, self._ping_port)
            except Exception:
                rtt = None
            if rtt is not None:
                self._last_ping_ms = rtt
                self._rtt_at = now
            elif now - self._rtt_at > RTT_KEEP_SEC:
                self._last_ping_ms = None
            self._last_ping_ts = now
        down = down_bps or 0.0
        up = up_bps or 0.0
        if down >= PING_TRAFFIC_BPS:
            self._link_verdict = True  # ответы идут — канал доказанно жив
        if not (up >= PING_UNANSWERED_UP_BPS and down < LINK_IDLE_DOWN_BPS):
            self._unanswered_since = 0.0
            return
        if self._unanswered_since <= 0.0:
            self._unanswered_since = now
            return
        if (
            now - self._unanswered_since < LINK_SUSPECT_SEC
            or self._confirming
            or (self._confirmed_at and now - self._confirmed_at < LINK_CONFIRM_COOLDOWN_SEC)
        ):
            return
        self._confirming = True
        self._confirmed_at = now
        host = self._ping_host
        probe_gate.GATE.record(probe_gate.CURRENT, host)

        def confirm() -> None:
            try:
                verdict = self._link_confirmer()
            except Exception:
                verdict = None
            if self._ping_host == host:
                self._link_verdict = verdict
            self._confirming = False

        threading.Thread(target=confirm, name="link-confirm", daemon=True).start()

    def run(self) -> None:
        prev_uplink: int | None = None
        prev_downlink: int | None = None
        prev_ts: float | None = None
        iteration_count = 0

        # Proxy mode: per-process traffic via TCP connection estats
        proxy_prev_bytes: dict[str, tuple[int, int]] = {}  # {exe: (in, out)} for speed & drop detection
        proxy_closed_bytes: dict[str, tuple[int, int]] = {}  # {exe: (in, out)} accumulated from closed conns

        while not self._stopped:
            now = time.perf_counter()
            uplink_total, downlink_total = self._query_inbound_totals()

            traffic_valid = uplink_total is not None and downlink_total is not None
            down_bps: float | None = None
            up_bps: float | None = None
            if (
                traffic_valid
                and prev_uplink is not None
                and prev_downlink is not None
                and prev_ts is not None
            ):
                dt = max(0.001, now - prev_ts)
                up_bps = max(0.0, (uplink_total - prev_uplink) / dt)
                down_bps = max(0.0, (downlink_total - prev_downlink) / dt)

            if traffic_valid and down_bps is None:
                # The first valid counter sample establishes a baseline but is
                # not yet a measured speed.  It is still a valid observation;
                # the next sample can calculate the delta.
                down_bps = 0.0
                up_bps = 0.0

            if uplink_total is not None and downlink_total is not None:
                prev_uplink = uplink_total
                prev_downlink = downlink_total
                prev_ts = now

            if self.pings_active_node():
                self._watch_link(now, down_bps, up_bps)

            process_stats = None
            if self._mode != "singbox":
                # sing-box обновляет спрос каждую итерацию (в _query_clash_api_totals),
                # xray — только на итерациях со сбором процессов; иначе «нет данных».
                self._proxy_demand = None
            if iteration_count % 2 == 0:
                if self._mode == "singbox":
                    process_stats = collect_process_stats(self._clash_api_port)
                elif self._mode == "xray":
                    process_stats = self._collect_proxy_process_stats(
                        proxy_prev_bytes, proxy_closed_bytes,
                    )

            self.metrics.emit(
                {
                    "down_bps": down_bps,
                    "up_bps": up_bps,
                    "traffic_valid": traffic_valid,
                    "latency_ms": self._last_ping_ms,
                    "probe_kind": "tcp_rtt" if self.pings_active_node() else "none",
                    "probe_valid": (
                        self._last_ping_ms is not None
                        if self.pings_active_node()
                        else None
                    ),
                    "link_alive": self._link_verdict if self.pings_active_node() else None,
                    "process_stats": process_stats,
                    "proxy_demand": self._proxy_demand,
                }
            )

            iteration_count += 1
            slept = 0
            while slept < self._interval_ms and not self._stopped:
                self.msleep(100)
                slept += 100

    def _collect_proxy_process_stats(
        self,
        prev_bytes: dict[str, tuple[int, int]],
        closed_bytes: dict[str, tuple[int, int]],
    ) -> list[ProcessTrafficSnapshot] | None:
        """Build per-process stats in proxy mode.

        Uses GetPerTcpConnectionEStats for actual per-connection byte counts.
        Tracks closed connections: when active bytes drop, the lost bytes
        are accumulated in closed_bytes so "Всего" grows monotonically.
        """
        try:
            proxy_procs = get_proxy_connections(self._socks_port, self._http_port)
        except Exception:
            return None
        self._proxy_demand = local_proxy_demand(
            proxy_procs or (), self._demand_prev_bytes, self._demand_elapsed(),
        )
        if not proxy_procs:
            return None

        result: list[ProcessTrafficSnapshot] = []
        for p in proxy_procs:
            prev_in, prev_out = prev_bytes.get(p.exe, (0, 0))
            cl_in, cl_out = closed_bytes.get(p.exe, (0, 0))

            # Detect closed connections: active bytes dropped (but not to zero — that indicates API glitch)
            if p.bytes_in < prev_in and p.bytes_in > 0:
                cl_in += prev_in - p.bytes_in
            if p.bytes_out < prev_out and p.bytes_out > 0:
                cl_out += prev_out - p.bytes_out
            closed_bytes[p.exe] = (cl_in, cl_out)

            # Total = accumulated from closed conns + current active conns
            total_in = cl_in + p.bytes_in
            total_out = cl_out + p.bytes_out

            # Speed from active connection deltas
            down_speed = max(0.0, (p.bytes_in - prev_in) / 2.0) if prev_in > 0 and p.bytes_in >= prev_in else 0.0
            up_speed = max(0.0, (p.bytes_out - prev_out) / 2.0) if prev_out > 0 and p.bytes_out >= prev_out else 0.0
            prev_bytes[p.exe] = (p.bytes_in, p.bytes_out)

            result.append(ProcessTrafficSnapshot(
                exe=p.exe,
                upload=total_out,
                download=total_in,
                connections=p.connections,
                route="proxy",
                proxy_bytes=total_in + total_out,
                down_speed=down_speed,
                up_speed=up_speed,
            ))

        result.sort(key=lambda s: s.upload + s.download, reverse=True)
        return result

    def _query_inbound_totals(self) -> tuple[int | None, int | None]:
        if self._mode == "singbox":
            return self._query_clash_api_totals()
        return self._query_xray_stats()

    def _query_clash_api_totals(self) -> tuple[int | None, int | None]:
        try:
            req = Request(f"http://127.0.0.1:{self._clash_api_port}/connections")
            with urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read())
            upload = int(data.get("uploadTotal") or 0)
            download = int(data.get("downloadTotal") or 0)
        except Exception:
            self._proxy_demand = None
            return None, None
        try:
            self._proxy_demand = clash_proxy_demand(
                data.get("connections") or (),
                self._demand_prev_bytes,
                self._demand_elapsed(),
            )
        except Exception:
            self._proxy_demand = None
        return upload, download

    def _demand_elapsed(self) -> float:
        now = time.perf_counter()
        prev = self._demand_prev_ts
        self._demand_prev_ts = now
        return max(0.001, now - prev) if prev is not None else float(self._interval_ms) / 1000.0

    def _query_xray_stats(self) -> tuple[int | None, int | None]:
        if self._api_port <= 0:
            return None, None
        exe = resolve_configured_path(
            self._xray_path,
            default_path=XRAY_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        if exe is None:
            return None, None
        if not exe.exists():
            return None, None

        try:
            result = run_text(
                [str(exe), "api", "statsquery", f"--server=127.0.0.1:{self._api_port}"],
                timeout=2,
                check=False,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception:
            return None, None

        if result.returncode != 0:
            return None, None

        try:
            payload = json.loads(decode_output(result.stdout) or "{}")
        except json.JSONDecodeError:
            return None, None

        uplink = 0
        downlink = 0
        inbound_uplink_stats = {f"inbound>>>{tag}>>>traffic>>>uplink" for tag in self._xray_inbound_tags}
        inbound_downlink_stats = {f"inbound>>>{tag}>>>traffic>>>downlink" for tag in self._xray_inbound_tags}

        for stat in payload.get("stat", []):
            if not isinstance(stat, dict):
                continue
            name = str(stat.get("name") or "")
            value_raw = stat.get("value")
            try:
                value = int(value_raw or 0)
            except (TypeError, ValueError):
                value = 0

            if name in inbound_uplink_stats:
                uplink += value
            elif name in inbound_downlink_stats:
                downlink += value

        return uplink, downlink
