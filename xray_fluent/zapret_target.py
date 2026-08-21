"""Selected-server targeting contracts for the synthetic winws2 profile."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from types import MappingProxyType
from pathlib import Path
from typing import Any, Iterable, Literal, Mapping

from .constants import BASE_DIR
from .models import ZapretTargetSettings
from .zapret_blobs import BUILTIN_BLOBS, blob_names_in_args

log = logging.getLogger(__name__)

TargetGroup = Literal["tcp_proxy", "quic_proxy", "wireguard"]
TargetTransport = Literal["tcp", "udp"]

_TCP_PROTOCOLS = frozenset({
    "vless", "vmess", "trojan", "shadowsocks", "ss", "socks", "socks5",
    "http", "https",
})
_QUIC_PROTOCOLS = frozenset({"hysteria", "hysteria2", "hy2", "tuic"})
_UDP_STREAMS = frozenset({"quic", "kcp", "mkcp"})
_CATALOG_ROOT = BASE_DIR / "zapret" / "strategy_catalogs" / "winws2"


@dataclass(frozen=True, slots=True)
class ZapretEndpointSpec:
    group: TargetGroup
    transport: TargetTransport
    hosts: tuple[str, ...]
    ports: tuple[str, ...]
    node_name: str = ""

    @property
    def host_key(self) -> str:
        return "|".join(self.hosts)

    @property
    def port_filter(self) -> str:
        return ",".join(self.ports)


@dataclass(frozen=True, slots=True)
class ResolvedZapretEndpoint:
    spec: ZapretEndpointSpec
    ips: tuple[str, ...]


#: Catalog labels, ordered from most to least battle-tested.
STRATEGY_LABELS: tuple[str, ...] = (
    "recommended", "stable", "stock", "game", "experimental", "caution",
)
STRATEGY_LABEL_TITLES: dict[str, str] = {
    "recommended": "Рекомендуется",
    "stable": "Стабильная",
    "stock": "Штатная",
    "game": "Для игр",
    "experimental": "Экспериментальная",
    "caution": "Осторожно",
}


@dataclass(frozen=True, slots=True)
class ZapretStrategyEntry:
    strategy_id: str
    transport: TargetTransport
    name: str
    args: tuple[str, ...]
    description: str = ""
    blob_dependencies: tuple[str, ...] = ()
    author: str = ""
    label: str = ""

    @property
    def label_title(self) -> str:
        return STRATEGY_LABEL_TITLES.get(self.label, self.label)

    @property
    def search_haystack(self) -> str:
        return " ".join(
            (self.strategy_id, self.name, self.description, self.author, self.label, *self.args)
        ).casefold()


def _port_token(value: Any) -> str:
    text = str(value or "").strip().replace(":", "-")
    if not text:
        return ""
    if "-" in text:
        start_text, end_text = text.split("-", 1)
    else:
        start_text = end_text = text
    try:
        start, end = int(start_text), int(end_text)
    except (TypeError, ValueError):
        return ""
    if not (1 <= start <= end <= 65535):
        return ""
    return str(start) if start == end else f"{start}-{end}"


def _ports(values: Iterable[Any], fallback: int = 0) -> tuple[str, ...]:
    normalized = {_port_token(value) for value in values}
    normalized.discard("")
    if not normalized and fallback:
        token = _port_token(fallback)
        if token:
            normalized.add(token)
    return tuple(sorted(normalized, key=lambda item: int(item.split("-", 1)[0])))


def _endpoint_host(value: Any) -> str:
    return str(value or "").strip().strip("[]").rstrip(".")


def endpoint_spec_for_node(node: object | None) -> ZapretEndpointSpec | None:
    """Describe the actual remote transport used by a selected node."""

    if node is None:
        return None
    outbound = getattr(node, "outbound", {})
    if not isinstance(outbound, dict):
        outbound = {}
    scheme = str(getattr(node, "scheme", "") or "").strip().lower()
    protocol = str(outbound.get("protocol") or outbound.get("type") or scheme).strip().lower()
    node_name = str(getattr(node, "name", "") or "")

    if protocol in {"wireguard", "awg"} or scheme in {"wireguard", "awg"}:
        hosts: list[str] = []
        port_values: list[Any] = []
        peers = outbound.get("peers")
        if isinstance(peers, list):
            for peer in peers:
                if not isinstance(peer, dict):
                    continue
                host = _endpoint_host(peer.get("address"))
                if host:
                    hosts.append(host)
                port_values.append(peer.get("port"))
        if not hosts:
            host = _endpoint_host(getattr(node, "server", ""))
            if host:
                hosts.append(host)
        ports = _ports(port_values, int(getattr(node, "port", 0) or 0))
        if not hosts or not ports:
            return None
        return ZapretEndpointSpec(
            "wireguard", "udp", tuple(dict.fromkeys(hosts)), ports, node_name,
        )

    if protocol in _QUIC_PROTOCOLS or scheme in _QUIC_PROTOCOLS:
        host = _endpoint_host(outbound.get("server") or getattr(node, "server", ""))
        raw_ports = outbound.get("server_ports")
        port_values = raw_ports if isinstance(raw_ports, list) else [raw_ports] if raw_ports else []
        ports = _ports(
            [*port_values, outbound.get("server_port")],
            int(getattr(node, "port", 0) or 0),
        )
        if not host or not ports:
            return None
        return ZapretEndpointSpec("quic_proxy", "udp", (host,), ports, node_name)

    if protocol not in _TCP_PROTOCOLS and scheme not in _TCP_PROTOCOLS:
        return None

    stream = outbound.get("streamSettings")
    transport_config = outbound.get("transport")
    network = (
        str(stream.get("network") or "tcp").lower()
        if isinstance(stream, dict)
        else str(transport_config.get("type") or "tcp").lower()
        if isinstance(transport_config, dict)
        else "tcp"
    )
    transport: TargetTransport = "udp" if network in _UDP_STREAMS else "tcp"
    group: TargetGroup = "quic_proxy" if transport == "udp" else "tcp_proxy"
    host = _endpoint_host(getattr(node, "server", ""))
    port = int(getattr(node, "port", 0) or 0)
    if not host or port <= 0:
        # Native sing-box TCP proxy JSON stores the endpoint directly.
        host = _endpoint_host(outbound.get("server"))
        try:
            port = int(outbound.get("server_port") or 0)
        except (TypeError, ValueError):
            port = 0
    ports = _ports([], port)
    if not host or not ports:
        return None
    return ZapretEndpointSpec(group, transport, (host,), ports, node_name)


def group_enabled(settings: ZapretTargetSettings, group: TargetGroup) -> bool:
    if group == "tcp_proxy":
        return settings.tcp_proxy_enabled
    if group == "quic_proxy":
        return settings.quic_proxy_enabled
    return settings.wireguard_enabled


def validate_custom_strategy(text: str) -> tuple[str, ...]:
    args: list[str] = []
    for raw in str(text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if (
            not line.startswith("--lua-desync=")
            or not line.removeprefix("--lua-desync=").strip()
            or any(char.isspace() for char in line)
        ):
            raise ValueError("Разрешены только строки --lua-desync=... и комментарии")
        args.append(line)
    if not args:
        raise ValueError("Стратегия не содержит ни одной строки --lua-desync")
    return tuple(args)


def _parse_catalog(path: Path, transport: TargetTransport) -> dict[str, ZapretStrategyEntry]:
    result: dict[str, ZapretStrategyEntry] = {}
    if not path.is_file():
        return result
    current_id = ""
    metadata: dict[str, str] = {}
    args: list[str] = []
    rejected: list[str] = []

    def flush() -> None:
        if not current_id or not args:
            return
        try:
            safe_args = validate_custom_strategy("\n".join(args))
        except ValueError as exc:
            # A dropped entry used to vanish without a trace; catalogs are now
            # vendored wholesale, so a parse failure is worth reporting.
            rejected.append(f"{current_id}: {exc}")
            return
        # ``blobs =`` metadata is incomplete upstream, so declared names are only
        # a hint — the authoritative set comes from the arguments themselves.
        declared = (item.strip() for item in metadata.get("blobs", "").split(","))
        dependencies = dict.fromkeys(
            name for name in declared
            if name and name not in BUILTIN_BLOBS and not name.lower().startswith("0x")
        )
        dependencies.update(dict.fromkeys(blob_names_in_args(safe_args)))
        result[current_id] = ZapretStrategyEntry(
            strategy_id=current_id,
            transport=transport,
            name=metadata.get("name", current_id),
            description=metadata.get("description", ""),
            args=safe_args,
            blob_dependencies=tuple(dependencies),
            author=metadata.get("author", ""),
            label=metadata.get("label", "").strip().lower(),
        )

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            flush()
            current_id = line[1:-1].strip()
            metadata = {}
            args = []
        elif line.startswith("--"):
            args.append(line)
        elif "=" in line and current_id:
            key, value = line.split("=", 1)
            metadata[key.strip().lower()] = value.strip()
    flush()
    if rejected:
        log.warning(
            "Каталог %s: пропущено записей — %d (%s)",
            path.name, len(rejected), "; ".join(rejected[:5]),
        )
    return result


def _catalog_paths(transport: TargetTransport) -> tuple[Path, ...]:
    """Vendored upstream catalog first, local overrides second."""

    return (
        _CATALOG_ROOT / f"{transport}.txt",
        _CATALOG_ROOT / f"{transport}.local.txt",
    )


def _catalog_signature(paths: Iterable[Path]) -> tuple[tuple[str, int, int], ...]:
    signature = []
    for path in paths:
        try:
            stat = path.stat()
        except OSError:
            continue
        signature.append((path.name, stat.st_mtime_ns, stat.st_size))
    return tuple(signature)


_CATALOG_CACHE: dict[
    TargetTransport,
    tuple[tuple[tuple[str, int, int], ...], Mapping[str, ZapretStrategyEntry]],
] = {}


def load_strategy_catalog(transport: TargetTransport) -> Mapping[str, ZapretStrategyEntry]:
    """Merged strategy catalog for one transport, cached on file mtime/size.

    The catalog is ~390 TCP entries, re-read on every combo repaint before —
    caching keeps opening the page cheap.  The result is shared, so it is handed
    out read-only.
    """

    paths = _catalog_paths(transport)
    signature = _catalog_signature(paths)
    cached = _CATALOG_CACHE.get(transport)
    if cached is not None and cached[0] == signature:
        return cached[1]
    merged: dict[str, ZapretStrategyEntry] = {}
    for path in paths:
        merged.update(_parse_catalog(path, transport))
    catalog = MappingProxyType(merged)
    _CATALOG_CACHE[transport] = (signature, catalog)
    return catalog


def strategy_for_target(
    settings: ZapretTargetSettings,
    spec: ZapretEndpointSpec,
) -> ZapretStrategyEntry | None:
    """Return strategy, pass, or None when TCP targeting is disabled."""

    enabled = group_enabled(settings, spec.group)
    if not enabled:
        if spec.transport == "udp":
            return ZapretStrategyEntry("pass", "udp", "pass", ("--lua-desync=pass",))
        return None

    strategy_id = settings.tcp_strategy_id if spec.transport == "tcp" else settings.udp_strategy_id
    custom = settings.tcp_custom_args if spec.transport == "tcp" else settings.udp_custom_args
    if strategy_id == "custom":
        return ZapretStrategyEntry("custom", spec.transport, "Своя стратегия", validate_custom_strategy(custom))
    entry = load_strategy_catalog(spec.transport).get(strategy_id)
    if entry is None:
        kind = "TCP" if spec.transport == "tcp" else "UDP"
        raise ValueError(f"Выберите доступную {kind}-стратегию")
    return entry


def target_requires_zapret(settings: ZapretTargetSettings, node: object | None) -> bool:
    spec = endpoint_spec_for_node(node)
    return bool(spec is not None and group_enabled(settings, spec.group))
