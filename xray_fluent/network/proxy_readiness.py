from __future__ import annotations

import socket


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
