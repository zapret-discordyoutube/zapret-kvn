"""Применение замера задержки к серверу; TCP-замер остался для зондов, где нужен голый connect.

Сам замер сервера — через ядро, ``latency_probe``; очередь — ``ping_service``.
"""

from __future__ import annotations

import socket
import time

from ..engines.singbox.config_builder import is_singbox_endpoint_node
from ..profiles.models import Node


def tcp_observation(host: str, port: int, timeout: float = 2.0) -> tuple[int | None, tuple[str, ...]]:
    if not host or not port:
        return None, ()
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as connection:
            elapsed = int((time.perf_counter() - start) * 1000.0)
            try:
                peer = (str(connection.getpeername()[0]),)
            except OSError:
                peer = ()
            return elapsed, peer
    except OSError:
        return None, ()


def tcp_ping(host: str, port: int, timeout: float = 2.0) -> int | None:
    return tcp_observation(host, port, timeout)[0]


def ping_node(node: Node, timeout: float = 2.0) -> int | None:
    """TCP-пинг ноды; endpoint-ноды (UDP-only, напр. WireGuard/AWG) не пингуются."""
    if is_singbox_endpoint_node(node):
        return None
    return tcp_ping(node.server, node.port, timeout)


def apply_ping_measurement(node: Node, ping_ms: int | None, *, measured: bool = True) -> None:
    """Применяет результат замера задержки к ноде.

    ``measured=False`` — проверить было нечем (ядра нет, адрес не узнать без
    открытого DNS): прежний вывод о сервере остаётся, «мёртвым» он не становится.
    """
    if not measured:
        return
    if is_singbox_endpoint_node(node):
        # Endpoint-ноды (WireGuard/AWG) замер не проверяет: не «мёртвые».
        node.ping_ms = None
        return
    node.ping_ms = ping_ms
    if ping_ms is not None or node.is_alive is None:
        node.is_alive = ping_ms is not None
