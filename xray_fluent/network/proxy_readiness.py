from __future__ import annotations

import os
import socket
import struct

#: Шаг опроса, пока порт ещё не открыт: проверка таблицы почти бесплатна.
LISTENER_POLL_MS = 25
#: GetExtendedTcpTable: TCP_TABLE_OWNER_PID_LISTENER (для IPv6 «basic» не бывает).
_TCP_TABLE_OWNER_PID_LISTENER = 3
#: Смещение dwLocalPort в MIB_TCPROW_OWNER_PID / MIB_TCP6ROW_OWNER_PID и размер строки.
_TCP_TABLE_LAYOUT = {2: (8, 24), 23: (20, 56)}  # AF_INET, AF_INET6
_ERROR_INSUFFICIENT_BUFFER = 122


def _listening_ports_of_family(family: int) -> set[int]:
    import ctypes

    iphlpapi = ctypes.WinDLL("iphlpapi")
    size = ctypes.c_ulong(0)
    iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, family, _TCP_TABLE_OWNER_PID_LISTENER, 0)
    for _attempt in range(3):
        buffer = ctypes.create_string_buffer(size.value + 4096)
        size = ctypes.c_ulong(len(buffer))
        result = iphlpapi.GetExtendedTcpTable(
            buffer, ctypes.byref(size), False, family, _TCP_TABLE_OWNER_PID_LISTENER, 0
        )
        if result == 0:
            break
        if result != _ERROR_INSUFFICIENT_BUFFER:
            raise OSError(result, "GetExtendedTcpTable failed")
    else:
        raise OSError(_ERROR_INSUFFICIENT_BUFFER, "GetExtendedTcpTable keeps growing")
    return listening_ports_from_table(buffer.raw, family)


def listening_ports_from_table(raw: bytes, family: int) -> set[int]:
    """Локальные порты из MIB_TCP(6)TABLE_OWNER_PID (порт — в сетевом порядке)."""

    port_offset, row_size = _TCP_TABLE_LAYOUT[family]
    (count,) = struct.unpack_from("<I", raw, 0)
    ports: set[int] = set()
    for index in range(count):
        (value,) = struct.unpack_from("<I", raw, 4 + index * row_size + port_offset)
        ports.add(((value & 0xFF) << 8) | ((value >> 8) & 0xFF))
    return ports


def ports_listening(ports) -> bool | None:
    """Слушаются ли все ``ports`` (таблица TCP Windows, без подключения).

    ``None`` — ответа нет (не Windows или WinAPI отказал): тогда решает
    обычная проба подключением.  На Windows подключение к ещё не открытому
    локальному порту не отбивается сразу — система повторяет SYN, и ранняя
    проба готовности всегда выжидала весь свой таймаут; таблица отвечает
    за миллисекунду.
    """

    if os.name != "nt":
        return None
    try:
        listening = _listening_ports_of_family(2) | _listening_ports_of_family(23)
    except Exception:
        return None
    return all(int(port) in listening for port in ports)


def probe_tcp_listener(port: int, *, timeout: float = 0.25) -> bool:
    """Return whether a loopback TCP listener accepts connections."""

    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def _recv_exact(client: socket.socket, count: int) -> bytes:
    payload = b""
    while len(payload) < count:
        chunk = client.recv(count - len(payload))
        if not chunk:
            return payload
        payload += chunk
    return payload


def probe_socks5_listener(
    port: int,
    *,
    timeout: float = 0.35,
    username: str = "",
    password: str = "",
) -> bool:
    """Verify that the configured SOCKS authentication succeeds on loopback."""

    user_bytes = username.encode("utf-8") if username else b""
    pass_bytes = password.encode("utf-8") if password else b""
    has_credentials = bool(user_bytes) and len(user_bytes) <= 255 and len(pass_bytes) <= 255
    if username and not has_credentials:
        return False
    methods = b"\x02" if has_credentials else b"\x00"
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout) as client:
            client.settimeout(timeout)
            client.sendall(b"\x05" + bytes((len(methods),)) + methods)
            reply = _recv_exact(client, 2)
            if len(reply) != 2 or reply[0] != 0x05:
                return False
            chosen = reply[1]
            if chosen == 0xFF:
                return False
            if chosen not in methods:
                return False
            if chosen == 0x02:
                client.sendall(
                    b"\x01"
                    + bytes((len(user_bytes),))
                    + user_bytes
                    + bytes((len(pass_bytes),))
                    + pass_bytes
                )
                return _recv_exact(client, 2) == b"\x01\x00"
            return True
    except OSError:
        return False


def probe_http_proxy_listener(port: int, *, timeout: float = 0.35) -> bool:
    """Make the local HTTP proxy parser produce an HTTP response.

    ``OPTIONS *`` is handled or rejected by the inbound itself and therefore
    does not require a working remote server.  Any HTTP status proves that the
    configured port is an HTTP listener instead of merely an unrelated TCP
    service.
    """

    request = (
        b"OPTIONS * HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout) as client:
            client.settimeout(timeout)
            client.sendall(request)
            return client.recv(16).startswith(b"HTTP/")
    except OSError:
        return False


def probe_listener_role(
    port: int,
    role: str,
    *,
    username: str = "",
    password: str = "",
) -> bool:
    """Probe one runtime listener according to its declared protocol role."""

    normalized = str(role or "").strip().upper()
    if normalized in {"SOCKS", "MIXED"}:
        if username:
            return probe_socks5_listener(port, username=username, password=password)
        return probe_socks5_listener(port)
    if normalized == "HTTP":
        return probe_http_proxy_listener(port)
    return probe_tcp_listener(port)
