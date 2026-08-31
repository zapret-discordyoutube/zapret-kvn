from __future__ import annotations

import socket


def probe_tcp_listener(port: int, *, timeout: float = 0.25) -> bool:
    """Return whether a loopback TCP listener accepts connections."""

    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def probe_socks5_listener(port: int, *, timeout: float = 0.35) -> bool:
    """Complete the unauthenticated SOCKS5 method negotiation on loopback."""

    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout) as client:
            client.settimeout(timeout)
            client.sendall(b"\x05\x01\x00")
            return client.recv(2) == b"\x05\x00"
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


def probe_listener_role(port: int, role: str) -> bool:
    """Probe one runtime listener according to its declared protocol role."""

    normalized = str(role or "").strip().upper()
    if normalized in {"SOCKS", "MIXED"}:
        return probe_socks5_listener(port)
    if normalized == "HTTP":
        return probe_http_proxy_listener(port)
    return probe_tcp_listener(port)
