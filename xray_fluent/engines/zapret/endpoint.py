"""Where the selected VPN server lives on the wire: kind, transport, hosts, ports.

Zapret applies its per-server rule by exact IP + transport + port, so this
module answers two questions for a node: which of the three server kinds it is
(each has its own strategy) and which addresses the rule must match.  Resolving
the hosts is blocking DNS — callers run :func:`resolve_endpoint` in a worker.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Iterable, Literal

from ...diagnostics.runtime_logging import register_server_aliases
from ...network.bootstrap_dns import resolve_bootstrap

ServerKind = Literal["tcp", "quic", "wireguard"]
Transport = Literal["tcp", "udp"]

KIND_TITLES: dict[str, str] = {
    "tcp": "TCP-серверы",
    "quic": "QUIC-серверы",
    "wireguard": "WireGuard",
}
KIND_PROTOCOLS: dict[str, str] = {
    "tcp": "VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP",
    "quic": "Hysteria, Hysteria2, TUIC, VLESS по QUIC/KCP",
    "wireguard": "WireGuard и AmneziaWG",
}
KIND_TRANSPORT: dict[str, Transport] = {"tcp": "tcp", "quic": "udp", "wireguard": "udp"}

_TCP_PROTOCOLS = frozenset({
    "vless", "vmess", "trojan", "shadowsocks", "ss", "socks", "socks5",
    "http", "https",
})
_QUIC_PROTOCOLS = frozenset({"hysteria", "hysteria2", "hy2", "tuic"})
_WIREGUARD_PROTOCOLS = frozenset({"wireguard", "awg"})
_UDP_STREAMS = frozenset({"quic", "kcp", "mkcp"})


@dataclass(frozen=True, slots=True)
class ServerEndpoint:
    kind: ServerKind
    hosts: tuple[str, ...]
    ports: tuple[str, ...]

    @property
    def transport(self) -> Transport:
        return KIND_TRANSPORT[self.kind]

    @property
    def port_filter(self) -> str:
        return ",".join(self.ports)


@dataclass(frozen=True, slots=True)
class ResolvedEndpoint:
    endpoint: ServerEndpoint
    ips: tuple[str, ...]


def _port_token(value: Any) -> str:
    text = str(value or "").strip().replace(":", "-")
    if not text:
        return ""
    start_text, _, end_text = text.partition("-")
    try:
        start, end = int(start_text), int(end_text or start_text)
    except (TypeError, ValueError):
        return ""
    if not (1 <= start <= end <= 65535):
        return ""
    return str(start) if start == end else f"{start}-{end}"


def _ports(values: Iterable[Any], fallback: Any = 0) -> tuple[str, ...]:
    tokens = {_port_token(value) for value in values}
    tokens.discard("")
    if not tokens:
        token = _port_token(fallback)
        if token:
            tokens.add(token)
    return tuple(sorted(tokens, key=lambda item: int(item.split("-", 1)[0])))


def _host(value: Any) -> str:
    return str(value or "").strip().strip("[]").rstrip(".")


def endpoint_for_node(node: object | None) -> ServerEndpoint | None:
    """The remote endpoint a node really connects to, or None if not targetable."""

    if node is None:
        return None
    outbound = getattr(node, "outbound", {})
    if not isinstance(outbound, dict):
        outbound = {}
    scheme = str(getattr(node, "scheme", "") or "").strip().lower()
    protocol = str(outbound.get("protocol") or outbound.get("type") or scheme).strip().lower()
    node_port = getattr(node, "port", 0) or 0

    def is_one_of(protocols: frozenset[str]) -> bool:
        return protocol in protocols or scheme in protocols

    if is_one_of(_WIREGUARD_PROTOCOLS):
        hosts: list[str] = []
        port_values: list[Any] = []
        for peer in outbound.get("peers") or ():
            if isinstance(peer, dict):
                if _host(peer.get("address")):
                    hosts.append(_host(peer.get("address")))
                port_values.append(peer.get("port"))
        if not hosts and _host(getattr(node, "server", "")):
            hosts.append(_host(getattr(node, "server", "")))
        ports = _ports(port_values, node_port)
        if not hosts or not ports:
            return None
        return ServerEndpoint("wireguard", tuple(dict.fromkeys(hosts)), ports)

    if is_one_of(_QUIC_PROTOCOLS):
        host = _host(outbound.get("server") or getattr(node, "server", ""))
        hopping = outbound.get("server_ports")
        port_values = hopping if isinstance(hopping, list) else [hopping] if hopping else []
        ports = _ports([*port_values, outbound.get("server_port")], node_port)
        if not host or not ports:
            return None
        return ServerEndpoint("quic", (host,), ports)

    if not is_one_of(_TCP_PROTOCOLS):
        return None
    stream = outbound.get("streamSettings")
    transport = outbound.get("transport")
    if isinstance(stream, dict):
        network = str(stream.get("network") or "tcp").lower()
    elif isinstance(transport, dict):
        network = str(transport.get("type") or "tcp").lower()
    else:
        network = "tcp"
    host = _host(getattr(node, "server", ""))
    port = node_port
    if not host or not port:
        # Native sing-box JSON nodes keep the endpoint in the outbound itself.
        host = _host(outbound.get("server"))
        port = outbound.get("server_port") or 0
    ports = _ports([], port)
    if not host or not ports:
        return None
    # VLESS/VMess over QUIC or mKCP travel as UDP — a UDP rule is what matches.
    return ServerEndpoint("quic" if network in _UDP_STREAMS else "tcp", (host,), ports)


def _ip_sort_key(value: str) -> tuple[int, str]:
    return ipaddress.ip_address(value).version, value


def resolve_host(host: str) -> set[str]:
    """Blocking DNS for one host; a literal IP is returned as is."""

    host = _host(host)
    if not host:
        return set()
    try:
        return {str(ipaddress.ip_address(host))}
    except ValueError:
        pass
    # Тот же доверенный путь, что и у ядра: DoH по IP без SNI, затем системный
    # резолвер, затем запомненный адрес. Одного системного резолвера мало — на
    # заблокированное имя он отвечает NXDOMAIN, и правило сервера не строилось.
    resolved = set(resolve_bootstrap(host).addresses)
    # The server's IPs are masked in logs exactly like its name — register them
    # before anything (the rule log line) can print them.
    register_server_aliases(host, resolved)
    return resolved


def resolve_endpoint(endpoint: ServerEndpoint) -> ResolvedEndpoint:
    """Worker-only: resolve every host of the endpoint afresh."""

    ips: set[str] = set()
    for host in endpoint.hosts:
        ips.update(resolve_host(host))
    if not ips:
        raise OSError(f"не удалось определить IP: {', '.join(endpoint.hosts)}")
    return ResolvedEndpoint(endpoint, tuple(sorted(ips, key=_ip_sort_key)))
