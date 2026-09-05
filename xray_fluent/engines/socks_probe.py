"""Small authenticated SOCKS/HTTPS probe shared by protocol transports."""
from __future__ import annotations

import ipaddress
import socket
import ssl


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("SOCKS connection closed")
        data.extend(chunk)
    return bytes(data)


def open_socks_connection(relay_port: int, *, username: str, password: str,
                          timeout: float, target_host: str, target_port: int = 443) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", relay_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        method = b"\x02" if username or password else b"\x00"
        sock.sendall(b"\x05\x01" + method)
        if recv_exact(sock, 2) != b"\x05" + method:
            raise OSError("SOCKS authentication method rejected")
        if method == b"\x02":
            user, secret = username.encode(), password.encode()
            if not 0 < len(user) <= 255 or not 0 < len(secret) <= 255:
                raise ValueError("Invalid SOCKS credential length")
            sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(secret)]) + secret)
            if recv_exact(sock, 2) != b"\x01\x00":
                raise OSError("SOCKS authentication rejected")
        try:
            ip = ipaddress.ip_address(target_host)
        except ValueError:
            host = target_host.encode("idna")
            if not 0 < len(host) <= 255:
                raise ValueError("Invalid SOCKS destination")
            address = b"\x03" + bytes([len(host)]) + host
        else:
            address = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
        sock.sendall(b"\x05\x01\x00" + address + target_port.to_bytes(2, "big"))
        header = recv_exact(sock, 4)
        if header[:3] != b"\x05\x00\x00":
            raise OSError(f"SOCKS CONNECT rejected (reply={header[1]})")
        length = {1: 4, 4: 16}.get(header[3])
        if header[3] == 3:
            length = recv_exact(sock, 1)[0]
        if length is None:
            raise OSError("Invalid SOCKS response address")
        recv_exact(sock, length + 2)
        return sock
    except BaseException:
        sock.close()
        raise


def probe_https(relay_port: int, *, username: str, password: str,
                endpoint: tuple[str, str, str], timeout: float) -> None:
    address, name, path = endpoint
    raw = open_socks_connection(relay_port, username=username, password=password,
                                timeout=timeout, target_host=address)
    try:
        with ssl.create_default_context().wrap_socket(raw, server_hostname=name) as tls:
            tls.sendall(f"HEAD {path} HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode("ascii"))
            if not recv_exact(tls, 5).startswith(b"HTTP/"):
                raise OSError("HTTPS endpoint returned no HTTP response")
    finally:
        raw.close()
