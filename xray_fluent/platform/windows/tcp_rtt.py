"""Задержка до сервера без единого пакета: RTT уже открытого соединения ядра.

Ядро и так держит TCP-соединения с текущим сервером, а стек Windows сам
меряет их время ответа (SmoothedRtt). Его можно прочитать через
GetPerTcpConnectionEStats (статистика Path): на провод при этом ничего не
уходит — в отличие от пустого TCP-соединения раз в 10–60 с, которое на линии
выглядит ровным маяком к VPN-серверу.

Только IPv4 (таблица соединений IPv4); для IPv6 и при любой ошибке — None.
Включение сбора требует прав администратора (приложение их имеет).
"""

from __future__ import annotations

import ctypes
import ipaddress
import socket
import struct
from typing import Iterable

from .win_proc_monitor import (
    _AF_INET,
    _MIB_TCP_STATE_ESTAB,
    _MIB_TCPROW_OWNER_PID,
    _MIB_TCPTABLE_OWNER_PID,
    _TCP_ESTATS_DATA_RW_v0,
    _TCP_TABLE_OWNER_PID_CONN,
    _conn_key,
    _iphlpapi,
    _make_tcprow,
    _ntohs,
)

# TCP_ESTATS_TYPE.TcpConnectionEstatsPath
_TCP_ESTATS_PATH = 3

_PATH_FIELDS = (
    "FastRetran Timeouts SubsequentTimeouts CurTimeoutCount AbruptTimeouts PktsRetrans "
    "BytesRetrans DupAcksIn SacksRcvd SackBlocksRcvd CongSignals PreCongSumCwnd "
    "PreCongSumRtt PostCongSumRtt PostCongCountRtt EcnSignals EceRcvd SendStall "
    "QuenchRcvd RetranThresh SndDupAckEpisodes SumBytesReordered NonRecovDa "
    "NonRecovDaEpisodes AckAfterFr DsackDups SampleRtt SmoothedRtt RttVar MaxRtt "
    "MinRtt SumRtt CountRtt CurRto MaxRto MinRto CurMss MaxMss MinMss SpuriousRtoDetections"
).split()


class _TCP_ESTATS_PATH_ROD_v0(ctypes.Structure):
    """40 полей ULONG, 160 байт (проверено на Windows 10: значения совпадают с ping)."""

    _fields_ = [(name, ctypes.c_ulong) for name in _PATH_FIELDS]


_path_enabled: set[tuple[int, int, int, int]] = set()


def _ipv4_dword(address: str) -> int | None:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if parsed.version != 4:
        return None
    return struct.unpack("<I", socket.inet_aton(str(parsed)))[0]


def _rows() -> list[_MIB_TCPROW_OWNER_PID]:
    size = ctypes.c_ulong(0)
    _iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, _AF_INET, _TCP_TABLE_OWNER_PID_CONN, 0)
    if not size.value:
        return []
    buffer = (ctypes.c_byte * size.value)()
    if _iphlpapi.GetExtendedTcpTable(buffer, ctypes.byref(size), False, _AF_INET, _TCP_TABLE_OWNER_PID_CONN, 0):
        return []
    table = ctypes.cast(buffer, ctypes.POINTER(_MIB_TCPTABLE_OWNER_PID)).contents
    count = table.dwNumEntries
    if not count:
        return []
    array = ctypes.cast(ctypes.byref(table.table), ctypes.POINTER(_MIB_TCPROW_OWNER_PID * count)).contents
    return [array[index] for index in range(count)]


def _row_rtt_ms(row: _MIB_TCPROW_OWNER_PID) -> int | None:
    key = _conn_key(row)
    tcp_row = _make_tcprow(row)
    if key not in _path_enabled:
        enable = _TCP_ESTATS_DATA_RW_v0(EnableCollection=1)
        if _iphlpapi.SetPerTcpConnectionEStats(
            ctypes.byref(tcp_row), _TCP_ESTATS_PATH, ctypes.byref(enable), 0, ctypes.sizeof(enable), 0,
        ):
            return None
        _path_enabled.add(key)
    rod = _TCP_ESTATS_PATH_ROD_v0()
    if _iphlpapi.GetPerTcpConnectionEStats(
        ctypes.byref(tcp_row), _TCP_ESTATS_PATH,
        None, 0, 0,
        None, 0, 0,
        ctypes.byref(rod), 0, ctypes.sizeof(rod),
    ):
        return None
    if not rod.CountRtt:
        return None
    # Пока замеров мало, сглаженное значение ещё стартовое — берём последний.
    value = rod.SmoothedRtt if rod.CountRtt >= 3 else rod.SampleRtt
    return int(value) if value > 0 else None


def connection_rtt_ms(addresses: Iterable[str], port: int) -> int | None:
    """Наименьший RTT среди открытых соединений к ``addresses:port``; None — нет данных."""

    wanted = {value for value in (_ipv4_dword(address) for address in addresses) if value is not None}
    if not wanted or not 0 < int(port) < 65536:
        return None
    best: int | None = None
    try:
        rows = _rows()
        for row in rows:
            if row.dwState != _MIB_TCP_STATE_ESTAB or row.dwRemoteAddr not in wanted:
                continue
            if _ntohs(row.dwRemotePort & 0xFFFF) != int(port):
                continue
            rtt = _row_rtt_ms(row)
            if rtt is not None and (best is None or rtt < best):
                best = rtt
    except (OSError, ValueError):
        return None
    if len(_path_enabled) > 4096:
        live = {_conn_key(row) for row in rows}
        _path_enabled.intersection_update(live)
    return best
