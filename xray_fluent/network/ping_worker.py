from __future__ import annotations

import socket
from copy import deepcopy
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait

from PyQt6.QtCore import QThread, pyqtSignal

from ..engines.singbox.config_builder import is_singbox_endpoint_node
from ..profiles.models import Node
from ..profiles.geoip import endpoint_hosts


_MAX_PING_WORKERS = 16


def _tcp_observation(host: str, port: int, timeout: float = 2.0) -> tuple[int | None, tuple[str, ...]]:
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
    return _tcp_observation(host, port, timeout)[0]


def _observe_node(node, timeout):
    if is_singbox_endpoint_node(node):
        return None, ()
    return _tcp_observation(node.server, node.port, timeout)


def ping_node(node: Node, timeout: float = 2.0) -> int | None:
    """TCP-пинг ноды; endpoint-ноды (UDP-only, напр. WireGuard/AWG) не пингуются."""
    if is_singbox_endpoint_node(node):
        return None
    return tcp_ping(node.server, node.port, timeout)


def apply_ping_measurement(node: Node, ping_ms: int | None) -> None:
    """Применяет результат TCP-пинга к ноде.

    Endpoint-ноды (UDP-only) не измеряются по TCP: ping_ms остаётся None,
    is_alive не сбрасывается в False.
    """
    if is_singbox_endpoint_node(node):
        node.ping_ms = None
        return
    node.ping_ms = ping_ms
    if ping_ms is not None or node.is_alive is None:
        node.is_alive = ping_ms is not None


class PingWorker(QThread):
    peer_observed = pyqtSignal(str, object, object)
    result = pyqtSignal(str, object)
    progress = pyqtSignal(int, int)  # current, total
    completed = pyqtSignal()

    def __init__(self, nodes: list[Node], timeout: float = 2.0):
        super().__init__()
        self._nodes = deepcopy(nodes)
        self._timeout = timeout
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        total = len(self._nodes)
        if total == 0:
            self.completed.emit()
            return

        max_workers = min(_MAX_PING_WORKERS, total)
        executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ping")
        pending: dict[Future, tuple[str, tuple[str, ...]]] = {}
        iterator = iter(self._nodes)
        completed = 0

        try:
            for _ in range(max_workers):
                node = next(iterator, None)
                if node is None:
                    break
                future = executor.submit(_observe_node, node, self._timeout)
                pending[future] = (node.id, endpoint_hosts(node))

            while pending and not self._cancelled:
                done, _ = wait(tuple(pending), timeout=0.1, return_when=FIRST_COMPLETED)
                if not done:
                    continue

                for future in done:
                    node_id, fingerprint = pending.pop(future)
                    try:
                        ms, addresses = future.result()
                    except Exception:
                        ms, addresses = None, ()

                    completed += 1
                    if addresses:
                        self.peer_observed.emit(node_id, fingerprint, addresses)
                    self.result.emit(node_id, ms)
                    self.progress.emit(completed, total)

                    if self._cancelled:
                        break

                    next_node = next(iterator, None)
                    if next_node is not None:
                        next_future = executor.submit(_observe_node, next_node, self._timeout)
                        pending[next_future] = (next_node.id, endpoint_hosts(next_node))

            if self._cancelled:
                for future in pending:
                    future.cancel()
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        self.completed.emit()
