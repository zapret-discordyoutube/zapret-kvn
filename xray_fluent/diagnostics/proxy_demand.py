"""Спрос на туннель: есть ли приложения, которые прямо сейчас качают через прокси.

«Умная проверка» авто-переключения (``application/smart_switch_service.py``)
подозревает сервер в медленности, только когда туннелем реально пользуются:
низкая скорость без спроса — это простой, а не деградация.  Здесь — чистые
функции без I/O; вызываются из потока ``LiveMetricsWorker`` на данных,
которые воркер уже получил (Clash API ``/connections`` у sing-box или
TCP-соединения к локальному прокси у xray).

Результат — словарь ``{"active": int, "growing": int, "down_bps": float}``:
число проксируемых соединений, число соединений, у которых выросли счётчики
байт с прошлого опроса, и суммарная скорость загрузки по проксируемым
соединениям.
"""

from __future__ import annotations

import ntpath
import os
import sys
from typing import Any, Iterable

# Процессы самого приложения и ядер: их загрузки (контрольный замер скорости,
# обновление подписок, проверка обновлений) не являются спросом пользователя.
_CORE_PROCESSES = frozenset({"xray.exe", "sing-box.exe", "tun2socks.exe", "hysteria.exe"})


def own_process_names() -> frozenset[str]:
    names = {"zapretkvn.exe"}
    exe = os.path.basename(sys.executable or "").strip().lower()
    if exe:
        names.add(exe)
    return frozenset(names | _CORE_PROCESSES)


def _is_proxied_chain(chains: Any) -> bool:
    """Та же классификация, что у колонки «маршрут» (process_traffic_collector)."""

    if not isinstance(chains, list):
        return False
    return any("proxy" in str(item).lower() for item in chains)


def clash_proxy_demand(
    connections: Iterable[Any],
    prev_bytes: dict[str, tuple[int, int]],
    elapsed_sec: float,
    excluded_processes: frozenset[str] | None = None,
) -> dict[str, float | int]:
    """Спрос по списку соединений Clash API sing-box.

    ``prev_bytes`` — состояние предыдущего опроса ``{id: (upload, download)}``;
    функция обновляет его на месте (закрытые соединения выбрасываются).
    Новое соединение с ненулевыми счётчиками считается растущим: оно появилось
    и передало данные после прошлого опроса.
    """

    excluded = own_process_names() if excluded_processes is None else excluded_processes
    active = 0
    growing = 0
    down_delta = 0
    seen: set[str] = set()
    for conn in connections or ():
        if not isinstance(conn, dict):
            continue
        if not _is_proxied_chain(conn.get("chains")):
            continue
        meta = conn.get("metadata") if isinstance(conn.get("metadata"), dict) else {}
        # ntpath понимает и «\\», и «/»: путь процесса приходит в Windows-формате.
        exe = ntpath.basename(str(meta.get("processPath") or "")).lower()
        if exe and exe in excluded:
            continue
        conn_id = str(conn.get("id") or "")
        try:
            up = int(conn.get("upload") or 0)
            down = int(conn.get("download") or 0)
        except (TypeError, ValueError):
            continue
        active += 1
        if not conn_id:
            continue
        seen.add(conn_id)
        prev = prev_bytes.get(conn_id)
        if prev is None:
            if up + down > 0:
                growing += 1
                down_delta += down
        else:
            if up > prev[0] or down > prev[1]:
                growing += 1
            down_delta += max(0, down - prev[1])
        prev_bytes[conn_id] = (up, down)
    for stale in set(prev_bytes) - seen:
        prev_bytes.pop(stale, None)
    return {
        "active": active,
        "growing": growing,
        "down_bps": down_delta / max(0.001, float(elapsed_sec)),
    }


def local_proxy_demand(
    processes: Iterable[Any],
    prev_bytes: dict[str, tuple[int, int]],
    elapsed_sec: float,
    excluded_processes: frozenset[str] | None = None,
) -> dict[str, float | int]:
    """Спрос по TCP-соединениям к локальному прокси (режим xray).

    ``processes`` — элементы с полями ``exe``, ``bytes_in``, ``bytes_out``,
    ``connections`` (``win_proc_monitor.ProxyProcessInfo``).  Всё, что пришло
    на inbound прокси, считается проксируемым: разделить прямой и
    проксируемый трафик внутри xray здесь нельзя.
    """

    excluded = own_process_names() if excluded_processes is None else excluded_processes
    active = 0
    growing = 0
    down_delta = 0
    seen: set[str] = set()
    for proc in processes or ():
        exe = str(getattr(proc, "exe", "") or "").lower()
        if exe and exe in excluded:
            continue
        try:
            bytes_in = int(getattr(proc, "bytes_in", 0) or 0)
            bytes_out = int(getattr(proc, "bytes_out", 0) or 0)
            conns = int(getattr(proc, "connections", 0) or 0)
        except (TypeError, ValueError):
            continue
        active += max(0, conns)
        seen.add(exe)
        prev = prev_bytes.get(exe)
        if prev is not None and (bytes_in > prev[0] or bytes_out > prev[1]):
            growing += 1
            down_delta += max(0, bytes_in - prev[0])
        prev_bytes[exe] = (bytes_in, bytes_out)
    for stale in set(prev_bytes) - seen:
        prev_bytes.pop(stale, None)
    return {
        "active": active,
        "growing": growing,
        "down_bps": down_delta / max(0.001, float(elapsed_sec)),
    }
