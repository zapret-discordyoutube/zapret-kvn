from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
import hashlib
import ipaddress
from ipaddress import ip_address
import json
import secrets
import socket
from pathlib import Path
from typing import Any

from ...runtime_security import generate_local_proxy_credentials, strip_singbox_proxy_inbounds
from ...constants import (
    DEFAULT_HTTP_PORT,
    DEFAULT_SOCKS_PORT,
    HYSTERIA_PATH_DEFAULT,
    HYSTERIA_SIDECAR_RELAY_PORT,
    PROXY_HOST,
    SINGBOX_CLASH_API_PORT,
    SINGBOX_XRAY_RELAY_PORT,
    SINGBOX_PROVIDER_FILE,
    SS_PROTECT_PORT_END,
    SS_PROTECT_PORT_START,
)
from ...application.outbound_pool_service import (
    SINGBOX_PROVIDER_TAG,
    build_xray_outbound_pool,
    ensure_xray_pool_control_plane,
    singbox_outbound_tag,
)
from ...application.hysteria_runtime_contract import classify_hysteria_uri
from ...application.protocol_core import ProtocolCore, protocol_core
from ...models import Node
from ...runtime_logging import RuntimeNodeIdentity
from ..hysteria.config_adapter import build_uri_client_config
from .config_builder import build_singbox_outbound, is_singbox_endpoint_node


_SS_PROTECT_METHOD = "chacha20-ietf-poly1305"
_APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG = "__app_hybrid_protect_in"
_APP_XRAY_SIDECAR_RELAY_INBOUND_TAG = "__app_hybrid_relay_in"
_APP_XRAY_SIDECAR_PROTECT_OUTBOUND_TAG = "__app_hybrid_protect_out"
_APP_SINGBOX_HYBRID_RELAY_OUTBOUND_TAGS = (
    "__app_hybrid_relay_a",
    "__app_hybrid_relay_b",
)
_PUBLIC_PROXY_LISTEN = "0.0.0.0"


class EndpointProxyDnsPolicy(str, Enum):
    """Политика DNS для нативного endpoint WireGuard в sing-box."""

    CONFIGURED = "configured"
    AMNEZIA_GATEWAY = "amnezia_gateway"


@dataclass(frozen=True, slots=True)
class _ProxyPortSelection:
    requested_socks_port: int
    requested_http_port: int
    socks_port: int
    http_port: int


@dataclass(slots=True)
class SingboxDocumentState:
    source_path: Path
    text: str
    text_hash: str
    has_proxy_outbound: bool
    file_mtime_ns: int = 0
    file_size: int = 0


@dataclass(slots=True)
class ParsedSingboxDocument:
    source_path: Path
    text: str
    text_hash: str
    payload: dict[str, Any]
    has_proxy_outbound: bool


@dataclass(slots=True)
class SingboxXraySidecarPlan:
    relay_port: int
    relay_username: str
    relay_password: str
    protect_port: int
    protect_password: str
    config: dict[str, Any]
    api_port: int = 0
    outbound_pool_tags: dict[str, str] | None = None


@dataclass(slots=True)
class SingboxHysteriaSidecarPlan:
    relay_port: int
    relay_username: str
    relay_password: str
    config: dict[str, Any]
    context: RuntimeNodeIdentity


@dataclass(slots=True)
class SingboxRuntimePlan:
    outcome: str  # native_singbox | hybrid_xray_sidecar | hysteria_sidecar
    source_path: Path
    text_hash: str
    singbox_config: dict[str, Any]
    has_proxy_outbound: bool
    used_selected_node: bool
    xray_sidecar: SingboxXraySidecarPlan | None
    hysteria_sidecar: SingboxHysteriaSidecarPlan | None = None
    requested_socks_port: int = 0
    requested_http_port: int = 0
    socks_port: int = 0
    http_port: int = 0
    clash_api_port: int = 0
    selector_tags: dict[str, str] | None = None
    provider_payload: dict[str, Any] | None = None
    selected_outbound_tag: str = ""
    hybrid_relay_selector_tags: tuple[str, ...] = ()
    hybrid_relay_selected_tag: str = ""

    @property
    def is_hybrid(self) -> bool:
        return self.outcome == "hybrid_xray_sidecar"

    @property
    def is_hysteria_sidecar(self) -> bool:
        return self.outcome == "hysteria_sidecar"

    @property
    def sidecar_kind(self) -> str:
        if self.is_hybrid:
            return "xray"
        if self.is_hysteria_sidecar:
            return "hysteria"
        return ""

    @property
    def proxy_ports_changed(self) -> bool:
        return (
            self.requested_socks_port > 0
            and self.requested_http_port > 0
            and (
                self.socks_port != self.requested_socks_port
                or self.http_port != self.requested_http_port
            )
        )


def inspect_singbox_document_text(source_path: Path, text: str) -> SingboxDocumentState:
    text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    has_proxy_outbound = False
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        has_proxy_outbound = _config_has_proxy_outbound(payload)
    return SingboxDocumentState(
        source_path=source_path,
        text=text,
        text_hash=text_hash,
        has_proxy_outbound=has_proxy_outbound,
    )


def parse_singbox_document(source_path: Path, text: str) -> ParsedSingboxDocument:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{source_path.name}: {_format_json_error_message(text, exc)}") from exc
    if not isinstance(payload, dict):
        raise ValueError(_invalid_json_root_message(source_path.name, payload))
    text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    has_proxy_outbound = _config_has_proxy_outbound(payload)
    return ParsedSingboxDocument(
        source_path=source_path,
        text=text,
        text_hash=text_hash,
        payload=payload,
        has_proxy_outbound=has_proxy_outbound,
    )


def _invalid_json_root_message(source_name: str, payload: Any) -> str:
    if isinstance(payload, list):
        return (
            f"{source_name}: конфиг sing-box начинается с массива […], а должен "
            "начинаться с объекта {...}. Уберите внешние квадратные скобки."
        )
    if isinstance(payload, str):
        return (
            f"{source_name}: весь конфиг sing-box распознан как строка, а должен быть "
            "объектом {...}. Уберите внешние кавычки и экранирование."
        )
    if payload is None:
        return (
            f"{source_name}: вместо полного объекта {{...}} указано null. "
            "Вставьте конфиг sing-box целиком."
        )
    if isinstance(payload, bool):
        return (
            f"{source_name}: вместо объекта {{...}} указано логическое значение. "
            "Вставьте полный конфиг sing-box."
        )
    return (
        f"{source_name}: вместо объекта {{...}} указано число. "
        "Вставьте полный конфиг sing-box."
    )


def classify_node_for_singbox(node: Node | None) -> str:
    if node is None:
        return "native_singbox"
    if is_singbox_endpoint_node(node):
        return "native_singbox_endpoint"
    if protocol_core(node) is ProtocolCore.HYSTERIA:
        return "hysteria_sidecar"
    if protocol_core(node) is ProtocolCore.XRAY:
        return "hybrid_xray_sidecar"
    return "native_singbox"


def plan_singbox_runtime(
    document: ParsedSingboxDocument,
    node: Node | None,
    *,
    preferred_relay_port: int = 0,
    preferred_protect_port: int = 0,
    preferred_protect_password: str = "",
    pool_nodes: list[Node] | None = None,
) -> SingboxRuntimePlan:
    runtime_config = deepcopy(document.payload)
    strip_singbox_proxy_inbounds(runtime_config)
    clash_api_port = _ensure_singbox_metrics_contract(runtime_config)
    _ensure_singbox_tun_runtime_contract(runtime_config)

    return _plan_runtime_outbound(
        document,
        runtime_config=runtime_config,
        node=node,
        preferred_relay_port=preferred_relay_port,
        preferred_protect_port=preferred_protect_port,
        preferred_protect_password=preferred_protect_password,
        clash_api_port=clash_api_port,
        pool_nodes=pool_nodes,
    )


def plan_singbox_proxy_runtime(
    document: ParsedSingboxDocument,
    node: Node | None,
    *,
    allowed_proxy_ports: set[int] | None = None,
    preferred_relay_port: int = 0,
    preferred_protect_port: int = 0,
    preferred_protect_password: str = "",
    pool_nodes: list[Node] | None = None,
) -> SingboxRuntimePlan:
    """Build the app-owned SOCKS/HTTP runtime from a raw sing-box profile."""
    runtime_config = deepcopy(document.payload)
    strip_singbox_proxy_inbounds(runtime_config)
    _strip_singbox_tun_inbounds(runtime_config)
    selection = _ensure_singbox_proxy_runtime_contract(
        runtime_config,
        allowed_proxy_ports=allowed_proxy_ports,
    )
    clash_api_port = _ensure_singbox_metrics_contract(runtime_config)

    return _plan_runtime_outbound(
        document,
        runtime_config=runtime_config,
        node=node,
        preferred_relay_port=preferred_relay_port,
        preferred_protect_port=preferred_protect_port,
        preferred_protect_password=preferred_protect_password,
        requested_socks_port=selection.requested_socks_port,
        requested_http_port=selection.requested_http_port,
        socks_port=selection.socks_port,
        http_port=selection.http_port,
        clash_api_port=clash_api_port,
        pool_nodes=pool_nodes,
    )


def _plan_runtime_outbound(
    document: ParsedSingboxDocument,
    *,
    runtime_config: dict[str, Any],
    node: Node | None,
    preferred_relay_port: int,
    preferred_protect_port: int,
    preferred_protect_password: str,
    requested_socks_port: int = 0,
    requested_http_port: int = 0,
    socks_port: int = 0,
    http_port: int = 0,
    clash_api_port: int = 0,
    pool_nodes: list[Node] | None = None,
) -> SingboxRuntimePlan:

    outbounds = runtime_config.get("outbounds")
    proxy_index = _find_proxy_outbound_index(outbounds)
    if proxy_index is None:
        _validate_runtime_dns_contract(runtime_config)
        return SingboxRuntimePlan(
            outcome="native_singbox",
            source_path=document.source_path,
            text_hash=document.text_hash,
            singbox_config=runtime_config,
            has_proxy_outbound=False,
            used_selected_node=False,
            xray_sidecar=None,
            requested_socks_port=requested_socks_port,
            requested_http_port=requested_http_port,
            socks_port=socks_port,
            http_port=http_port,
            clash_api_port=clash_api_port,
        )

    if node is None:
        raise ValueError("В конфиге есть outbound tag `proxy`. Выберите сервер для запуска sing-box.")

    if is_singbox_endpoint_node(node):
        # WireGuard/AWG живут в top-level `endpoints[]`; плейсхолдер `proxy`
        # из outbounds обязан удаляться, иначе sing-box падает на дубликате тега.
        proxy_endpoint = build_singbox_outbound(node, tag="proxy")
        assert isinstance(outbounds, list)
        del outbounds[proxy_index]
        ensure_awg3_windows_bind_workaround(runtime_config, proxy_endpoint)
        _replace_or_append_tagged(_ensure_list(runtime_config, "endpoints"), "proxy", proxy_endpoint)
        _ensure_proxy_server_bootstrap_contract(runtime_config, proxy_endpoint, node.server)
        # Обычный WireGuard обязан уважать первый DNS из .conf. Только AWG
        # разрешено подменять публичный DNS шлюзом туннеля: Amnezia-серверы
        # могут перехватывать порт 53 и отвечать именно с адреса шлюза.
        node_outbound = node.outbound if isinstance(node.outbound, dict) else {}
        dns_override = select_endpoint_proxy_dns(
            node_outbound.get("_dns"),
            proxy_endpoint.get("address"),
            policy=endpoint_proxy_dns_policy(node_outbound),
        )
        if dns_override:
            _override_proxy_dns_server(runtime_config, dns_override)
        _validate_runtime_dns_contract(runtime_config)
        return SingboxRuntimePlan(
            outcome="native_singbox",
            source_path=document.source_path,
            text_hash=document.text_hash,
            singbox_config=runtime_config,
            has_proxy_outbound=True,
            used_selected_node=True,
            xray_sidecar=None,
            requested_socks_port=requested_socks_port,
            requested_http_port=requested_http_port,
            socks_port=socks_port,
            http_port=http_port,
            clash_api_port=clash_api_port,
        )

    if protocol_core(node) is ProtocolCore.HYSTERIA:
        return _plan_hysteria_sidecar_runtime(
            document,
            runtime_config=runtime_config,
            proxy_index=proxy_index,
            node=node,
            preferred_relay_port=preferred_relay_port,
            requested_socks_port=requested_socks_port,
            requested_http_port=requested_http_port,
            socks_port=socks_port,
            http_port=http_port,
            clash_api_port=clash_api_port,
        )

    if protocol_core(node) is ProtocolCore.XRAY:
        return _plan_hybrid_runtime(
            document,
            runtime_config=runtime_config,
            proxy_index=proxy_index,
            node=node,
            preferred_relay_port=preferred_relay_port,
            preferred_protect_port=preferred_protect_port,
            preferred_protect_password=preferred_protect_password,
            requested_socks_port=requested_socks_port,
            requested_http_port=requested_http_port,
            socks_port=socks_port,
            http_port=http_port,
            clash_api_port=clash_api_port,
            pool_nodes=pool_nodes,
        )

    native_proxy = build_singbox_outbound(node, tag="proxy")
    selector_tags: dict[str, str] = {}
    provider_outbounds: list[dict[str, Any]] = []
    for pooled in pool_nodes or []:
        if is_singbox_endpoint_node(pooled):
            continue
        if protocol_core(pooled) is not ProtocolCore.SINGBOX:
            continue
        tag = singbox_outbound_tag(pooled.id)
        try:
            pooled_outbound = build_singbox_outbound(pooled, tag=tag)
        except ValueError:
            continue
        selector_tags[pooled.id] = f"{SINGBOX_PROVIDER_TAG}/{tag}"
        provider_outbounds.append(pooled_outbound)
        _ensure_proxy_server_bootstrap_contract(runtime_config, pooled_outbound, pooled.server)

    if node.id in selector_tags and provider_outbounds:
        assert isinstance(outbounds, list)
        outbounds[proxy_index] = {
            "type": "selector",
            "tag": "proxy",
            "outbounds": ["direct"],
            "providers": [SINGBOX_PROVIDER_TAG],
            # Provider members are registered after selector construction, so
            # startup uses an inert local target and the controller pins the
            # selected provider member through Clash API before exposing TUN/
            # system-proxy state.
            "default": "direct",
            "interrupt_exist_connections": True,
        }
        providers = _ensure_list(runtime_config, "providers")
        _replace_or_append_tagged(
            providers,
            SINGBOX_PROVIDER_TAG,
            {
                "type": "local",
                "tag": SINGBOX_PROVIDER_TAG,
                "path": str(SINGBOX_PROVIDER_FILE),
            },
        )
        _validate_runtime_dns_contract(runtime_config)
        return SingboxRuntimePlan(
            outcome="native_singbox",
            source_path=document.source_path,
            text_hash=document.text_hash,
            singbox_config=runtime_config,
            has_proxy_outbound=True,
            used_selected_node=True,
            xray_sidecar=None,
            requested_socks_port=requested_socks_port,
            requested_http_port=requested_http_port,
            socks_port=socks_port,
            http_port=http_port,
            clash_api_port=clash_api_port,
            selector_tags=selector_tags,
            provider_payload={"outbounds": provider_outbounds},
            selected_outbound_tag=selector_tags[node.id],
        )

    assert isinstance(outbounds, list)
    outbounds[proxy_index] = native_proxy
    _ensure_proxy_server_bootstrap_contract(runtime_config, native_proxy, node.server)
    _validate_runtime_dns_contract(runtime_config)
    return SingboxRuntimePlan(
        outcome="native_singbox",
        source_path=document.source_path,
        text_hash=document.text_hash,
        singbox_config=runtime_config,
        has_proxy_outbound=True,
        used_selected_node=True,
        xray_sidecar=None,
        requested_socks_port=requested_socks_port,
        requested_http_port=requested_http_port,
        socks_port=socks_port,
        http_port=http_port,
        clash_api_port=clash_api_port,
    )


def _plan_hysteria_sidecar_runtime(
    document: ParsedSingboxDocument,
    *,
    runtime_config: dict[str, Any],
    proxy_index: int,
    node: Node,
    preferred_relay_port: int,
    requested_socks_port: int = 0,
    requested_http_port: int = 0,
    socks_port: int = 0,
    http_port: int = 0,
    clash_api_port: int = 0,
) -> SingboxRuntimePlan:
    raw_link = str(node.link or "").strip()
    if raw_link.partition(":")[0].lower() not in {"hy2", "hysteria2"}:
        raise ValueError(
            "Hysteria2 можно запустить через официальное ядро только из "
            "исходной ссылки hy2:// или hysteria2://. Импортируйте сервер ссылкой."
        )
    capability = classify_hysteria_uri(raw_link, platform="windows")
    if not capability.valid:
        raise ValueError(capability.validation_message or "Hysteria2 URI несовместим с runtime.")
    try:
        relay_port = preferred_relay_port if preferred_relay_port > 0 else _find_free_port(
            preferred=HYSTERIA_SIDECAR_RELAY_PORT,
            allow_ephemeral_fallback=True,
        )
    except RuntimeError as exc:
        raise ValueError(
            "Не удалось подобрать свободный локальный TCP-порт для Hysteria2."
        ) from exc

    relay_username, relay_password = generate_local_proxy_credentials(prefix="hysteria")
    outbounds = runtime_config.setdefault("outbounds", [])
    assert isinstance(outbounds, list)
    outbounds[proxy_index] = {
        "type": "socks",
        "tag": "proxy",
        "server": PROXY_HOST,
        "server_port": relay_port,
        "username": relay_username,
        "password": relay_password,
        "inet4_bind_address": PROXY_HOST,
    }
    _ensure_hysteria_process_direct_route(runtime_config)
    _validate_runtime_dns_contract(runtime_config)

    sidecar = SingboxHysteriaSidecarPlan(
        relay_port=relay_port,
        relay_username=relay_username,
        relay_password=relay_password,
        context=RuntimeNodeIdentity.from_node(node),
        config=build_uri_client_config(
            raw_link,
            node.outbound if isinstance(node.outbound, dict) else {},
            relay_host=PROXY_HOST,
            relay_port=relay_port,
            relay_username=relay_username,
            relay_password=relay_password,
        ),
    )
    return SingboxRuntimePlan(
        outcome="hysteria_sidecar",
        source_path=document.source_path,
        text_hash=document.text_hash,
        singbox_config=runtime_config,
        has_proxy_outbound=True,
        used_selected_node=True,
        xray_sidecar=None,
        hysteria_sidecar=sidecar,
        requested_socks_port=requested_socks_port,
        requested_http_port=requested_http_port,
        socks_port=socks_port,
        http_port=http_port,
        clash_api_port=clash_api_port,
    )


def _ensure_hysteria_process_direct_route(payload: dict[str, Any]) -> None:
    route = _ensure_dict(payload, "route")
    rules = _ensure_list(route, "rules")
    executable = str(HYSTERIA_PATH_DEFAULT.resolve())
    protect_rule = {"process_path": [executable], "outbound": "direct"}
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        paths = rule.get("process_path")
        if isinstance(paths, list) and executable in [str(item) for item in paths]:
            rules[index] = protect_rule
            return
    # This app-owned safety rule must precede user routing so the sidecar's
    # own UDP transport cannot re-enter the sing-box TUN.
    rules.insert(0, protect_rule)


def _plan_hybrid_runtime(
    document: ParsedSingboxDocument,
    *,
    runtime_config: dict[str, Any],
    proxy_index: int,
    node: Node,
    preferred_relay_port: int,
    preferred_protect_port: int,
    preferred_protect_password: str,
    requested_socks_port: int = 0,
    requested_http_port: int = 0,
    socks_port: int = 0,
    http_port: int = 0,
    clash_api_port: int = 0,
    pool_nodes: list[Node] | None = None,
) -> SingboxRuntimePlan:
    try:
        relay_port = preferred_relay_port if preferred_relay_port > 0 else _find_free_port(
            preferred=SINGBOX_XRAY_RELAY_PORT,
            allow_ephemeral_fallback=True,
        )
        excluded_ports = {relay_port}
        protect_port = preferred_protect_port if preferred_protect_port > 0 else _find_free_port(
            preferred=SS_PROTECT_PORT_START,
            port_range=range(SS_PROTECT_PORT_START, SS_PROTECT_PORT_END),
            excluded=excluded_ports,
            allow_ephemeral_fallback=True,
        )
        api_port = _find_free_port(
            preferred=19085,
            excluded={relay_port, protect_port},
            allow_ephemeral_fallback=True,
        )
    except RuntimeError as exc:
        raise ValueError(
            "Не удалось подобрать свободные локальные TCP-порты для "
            "гибридного режима sing-box + Xray."
        ) from exc
    protect_password = preferred_protect_password or _generate_ss_password()
    relay_username, relay_password = generate_local_proxy_credentials(prefix="sidecar")

    outbounds = runtime_config.setdefault("outbounds", [])
    assert isinstance(outbounds, list)
    relay_outbound = {
        "type": "socks",
        "server": PROXY_HOST,
        "server_port": relay_port,
        "username": relay_username,
        "password": relay_password,
        # Keep the relay on loopback so sing-box does not bind it to the
        # physical adapter via auto-detect rules.
        "inet4_bind_address": PROXY_HOST,
    }
    outbounds[proxy_index] = {
        "type": "selector",
        "tag": "proxy",
        "outbounds": list(_APP_SINGBOX_HYBRID_RELAY_OUTBOUND_TAGS),
        "default": _APP_SINGBOX_HYBRID_RELAY_OUTBOUND_TAGS[0],
        # Xray's balancer override affects only new connections.  Alternating
        # between two equivalent loopback relays makes sing-box terminate the
        # old TCP/UDP generation after Xray accepted the new outbound.
        "interrupt_exist_connections": True,
    }
    for relay_tag in _APP_SINGBOX_HYBRID_RELAY_OUTBOUND_TAGS:
        _replace_or_append_tagged(
            outbounds,
            relay_tag,
            {**relay_outbound, "tag": relay_tag},
        )

    _replace_or_append_tagged(
        _ensure_list(runtime_config, "inbounds"),
        _APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG,
        {
            "type": "shadowsocks",
            "tag": _APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG,
            "listen": PROXY_HOST,
            "listen_port": protect_port,
            "method": _SS_PROTECT_METHOD,
            "password": protect_password,
        },
    )
    _ensure_hybrid_protect_route(runtime_config)
    _validate_runtime_dns_contract(runtime_config)

    sidecar_config, sidecar_tags = _build_xray_sidecar_config(
        node,
        pool_nodes=pool_nodes,
        api_port=api_port,
        relay_port=relay_port,
        relay_username=relay_username,
        relay_password=relay_password,
        protect_port=protect_port,
        protect_password=protect_password,
    )
    sidecar = SingboxXraySidecarPlan(
        relay_port=relay_port,
        relay_username=relay_username,
        relay_password=relay_password,
        protect_port=protect_port,
        protect_password=protect_password,
        config=sidecar_config,
        api_port=api_port,
        outbound_pool_tags=sidecar_tags,
    )
    return SingboxRuntimePlan(
        outcome="hybrid_xray_sidecar",
        source_path=document.source_path,
        text_hash=document.text_hash,
        singbox_config=runtime_config,
        has_proxy_outbound=True,
        used_selected_node=True,
        xray_sidecar=sidecar,
        requested_socks_port=requested_socks_port,
        requested_http_port=requested_http_port,
        socks_port=socks_port,
        http_port=http_port,
        clash_api_port=clash_api_port,
        selector_tags=sidecar_tags,
        selected_outbound_tag=sidecar_tags[node.id],
        hybrid_relay_selector_tags=_APP_SINGBOX_HYBRID_RELAY_OUTBOUND_TAGS,
        hybrid_relay_selected_tag=_APP_SINGBOX_HYBRID_RELAY_OUTBOUND_TAGS[0],
    )


def _build_xray_sidecar_config(
    node: Node,
    *,
    pool_nodes: list[Node] | None,
    api_port: int,
    relay_port: int,
    relay_username: str,
    relay_password: str,
    protect_port: int,
    protect_password: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    if not isinstance(node.outbound, dict) or not node.outbound:
        raise ValueError("Выбранный сервер не содержит outbound JSON для xray sidecar.")
    if not str(node.outbound.get("protocol") or "").strip():
        raise ValueError("Выбранный сервер не содержит protocol для xray sidecar.")
    pool = build_xray_outbound_pool(pool_nodes or [node])
    if not pool.contains(node.id):
        raise ValueError("Выбранный сервер нельзя добавить в Xray sidecar pool.")
    proxy_outbounds = pool.outbounds()
    for proxy_outbound in proxy_outbounds:
        stream_settings = proxy_outbound.get("streamSettings")
        if not isinstance(stream_settings, dict):
            stream_settings = {}
            proxy_outbound["streamSettings"] = stream_settings
        sockopt = stream_settings.get("sockopt")
        if not isinstance(sockopt, dict):
            sockopt = {}
            stream_settings["sockopt"] = sockopt
        sockopt["dialerProxy"] = _APP_XRAY_SIDECAR_PROTECT_OUTBOUND_TAG

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": _APP_XRAY_SIDECAR_RELAY_INBOUND_TAG,
                "protocol": "socks",
                "listen": PROXY_HOST,
                "port": relay_port,
                "settings": {
                    "auth": "password",
                    "accounts": [{"user": relay_username, "pass": relay_password}],
                    "udp": True,
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": True,
                },
            },
            {
                "tag": "__app_sidecar_api_in",
                "protocol": "dokodemo-door",
                "listen": PROXY_HOST,
                "port": api_port,
                "settings": {"address": PROXY_HOST},
            },
        ],
        "outbounds": [
            *proxy_outbounds,
            {
                "tag": _APP_XRAY_SIDECAR_PROTECT_OUTBOUND_TAG,
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [
                        {
                            "address": PROXY_HOST,
                            "port": protect_port,
                            "method": _SS_PROTECT_METHOD,
                            "password": protect_password,
                        }
                    ]
                },
            },
            {"tag": "__app_sidecar_api", "protocol": "freedom", "settings": {}},
        ],
        "api": {
            "tag": "__app_sidecar_api",
            "services": ["RoutingService", "HandlerService"],
        },
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": [_APP_XRAY_SIDECAR_RELAY_INBOUND_TAG],
                    "outboundTag": "proxy",
                },
                {
                    "type": "field",
                    "inboundTag": ["__app_sidecar_api_in"],
                    "outboundTag": "__app_sidecar_api",
                },
            ],
        },
    }
    ensure_xray_pool_control_plane(config, pool)
    return config, dict(pool.tags)


def _is_domain_name(value: str) -> bool:
    host = str(value or "").strip()
    if not host:
        return False
    try:
        ip_address(host)
    except ValueError:
        return True
    return False


def _ensure_proxy_server_bootstrap_contract(
    payload: dict[str, Any],
    proxy_outbound: dict[str, Any],
    preferred_server: str,
) -> None:
    server = str(preferred_server or proxy_outbound.get("server") or "").strip()
    if not server:
        # Endpoint-конфиги (wireguard) не имеют top-level `server` — адрес живёт в peers[0].
        peers = proxy_outbound.get("peers")
        if isinstance(peers, list) and peers and isinstance(peers[0], dict):
            server = str(peers[0].get("address") or "").strip()
    if not _is_domain_name(server):
        return

    # Domain-based proxy servers must resolve through bootstrap-dns, otherwise
    # proxy-dns can recurse into the proxy outbound before the tunnel is ready.
    proxy_outbound["domain_resolver"] = "bootstrap-dns"

    route = _ensure_dict(payload, "route")
    rules = _ensure_list(route, "rules")
    direct_rule = {"domain": [server], "action": "route", "outbound": "direct"}

    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        domain_value = rule.get("domain")
        if isinstance(domain_value, list) and server in [str(item) for item in domain_value]:
            rules[index] = direct_rule
            return

    insert_index = 0
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        if rule.get("action") == "sniff" or rule.get("protocol") == "dns":
            insert_index = index + 1
            continue
        break
    rules.insert(insert_index, direct_rule)


def _ensure_hybrid_protect_route(payload: dict[str, Any]) -> None:
    route = _ensure_dict(payload, "route")
    rules = _ensure_list(route, "rules")
    protect_rule = {"inbound": [_APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG], "outbound": "direct"}
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        inbound_value = rule.get("inbound")
        if isinstance(inbound_value, list) and _APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG in [str(item) for item in inbound_value]:
            rules[index] = protect_rule
            return
    rules.insert(0, protect_rule)


def _ensure_singbox_metrics_contract(payload: dict[str, Any]) -> int:
    """Назначить clash_api заведомо доступный порт.

    Windows может зарезервировать 19090 (excluded port ranges Hyper-V/WinNAT),
    тогда bind падает с WSAEACCES и sing-box не стартует вовсе. Порт подбирается
    пробным bind'ом; если свободного нет — clash_api убирается: живые метрики
    вторичны, соединение важнее.
    """
    experimental = _ensure_dict(payload, "experimental")
    try:
        port = _find_free_port(
            preferred=SINGBOX_CLASH_API_PORT,
            port_range=range(SINGBOX_CLASH_API_PORT, SINGBOX_CLASH_API_PORT + 500),
        )
    except RuntimeError:
        experimental.pop("clash_api", None)
        if not experimental:
            payload.pop("experimental", None)
        return 0
    clash_api = _ensure_dict(experimental, "clash_api")
    clash_api["external_controller"] = f"127.0.0.1:{port}"
    return port


def _ensure_singbox_tun_runtime_contract(payload: dict[str, Any]) -> None:
    """Patch app-owned runtime fields for raw sing-box configs.

    The source document may keep a placeholder or stale interface name, but the
    runtime launch should always use a fresh xftun-prefixed adapter name. This
    avoids collisions during reconnect/apply while Windows is still releasing
    the previous wintun interface.
    """
    inbounds = payload.get("inbounds")
    if not isinstance(inbounds, list):
        return
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        if str(inbound.get("type") or "").strip().lower() != "tun":
            continue
        inbound["interface_name"] = _generate_tun_interface_name()


def _strip_singbox_tun_inbounds(payload: dict[str, Any]) -> int:
    inbounds = payload.get("inbounds")
    if not isinstance(inbounds, list):
        return 0
    filtered: list[Any] = []
    removed = 0
    for inbound in inbounds:
        if isinstance(inbound, dict) and str(inbound.get("type") or "").strip().lower() == "tun":
            removed += 1
            continue
        filtered.append(inbound)
    if removed:
        payload["inbounds"] = filtered
    return removed


def _ensure_singbox_proxy_runtime_contract(
    payload: dict[str, Any],
    *,
    allowed_proxy_ports: set[int] | None,
) -> _ProxyPortSelection:
    inbounds = _ensure_list(payload, "inbounds")
    excluded_ports: set[int] = set()
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        try:
            port = int(inbound.get("listen_port") or 0)
        except (TypeError, ValueError):
            port = 0
        if port > 0:
            excluded_ports.add(port)

    allowed = {int(port) for port in (allowed_proxy_ports or set()) if int(port) > 0}

    def port_available(port: int) -> bool:
        if port in excluded_ports:
            return False
        if port in allowed:
            return True
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind((_PUBLIC_PROXY_LISTEN, port))
            return True
        except OSError:
            return False

    selection: _ProxyPortSelection | None = None
    for attempt in range(500):
        socks_port = DEFAULT_SOCKS_PORT + attempt * 2
        http_port = DEFAULT_HTTP_PORT + attempt * 2
        if http_port > 65535:
            break
        if port_available(socks_port) and port_available(http_port):
            selection = _ProxyPortSelection(
                requested_socks_port=DEFAULT_SOCKS_PORT,
                requested_http_port=DEFAULT_HTTP_PORT,
                socks_port=socks_port,
                http_port=http_port,
            )
            break
    if selection is None:
        raise ValueError("Не удалось подобрать свободные локальные SOCKS/HTTP порты для sing-box.")

    inbounds.extend(
        [
            {
                "type": "mixed",
                "tag": "socks-in",
                "listen": _PUBLIC_PROXY_LISTEN,
                "listen_port": selection.socks_port,
            },
            {
                "type": "http",
                "tag": "http-in",
                "listen": _PUBLIC_PROXY_LISTEN,
                "listen_port": selection.http_port,
            },
        ]
    )
    return selection


#: Тег служебного direct-outbound, через который AWG 3.0 обходит дефолтный
#: Windows-bind ядра (см. ensure_awg3_windows_bind_workaround).
AWG3_DIRECT_DETOUR_TAG = "awg3-direct"


def endpoint_needs_windows_bind_workaround(endpoint: dict[str, Any]) -> bool:
    """AWG 3.0 (защита заголовков) на Windows требует обхода дефолтного bind.

    В sing-box extended 2.6.5 дефолтный Windows-bind (WinRingBind) обнуляет
    байты 1-3 каждого принятого UDP-пакета: у обычного WireGuard там всегда
    нули (старшие байты типа сообщения), у AWG 2.0 это безобидный мусорный
    паддинг, а у AWG 3.0 ровно эти байты входят в 12-байтовую соль шифра
    защиты заголовка. Соль расходится с отправителем, заголовок
    расшифровывается в мусор, и ядро молча отбрасывает ответ сервера
    ("received message with unknown type") — туннель не поднимается никогда.

    Ядро выбирает дефолтный bind только когда диалер endpoint'а является
    системным WireGuardListener; с любым detour используется ClientBind,
    свободный от этого дефекта.
    """
    amnezia = endpoint.get("amnezia")
    if not isinstance(amnezia, dict):
        return False
    return bool(str(amnezia.get("header_protection_key") or "").strip())


def ensure_awg3_windows_bind_workaround(
    runtime_config: dict[str, Any], endpoint: dict[str, Any]
) -> bool:
    """Направить AWG 3.0-endpoint через direct-detour. Возвращает True, если применено."""

    if not endpoint_needs_windows_bind_workaround(endpoint):
        return False
    if str(endpoint.get("detour") or "").strip():
        # Пользовательский detour уже уводит endpoint с дефолтного bind.
        return False
    outbounds = _ensure_list(runtime_config, "outbounds")
    if not any(
        isinstance(item, dict) and item.get("tag") == AWG3_DIRECT_DETOUR_TAG
        for item in outbounds
    ):
        outbounds.append({"type": "direct", "tag": AWG3_DIRECT_DETOUR_TAG})
    endpoint["detour"] = AWG3_DIRECT_DETOUR_TAG
    return True


def endpoint_proxy_dns_policy(endpoint: dict[str, Any]) -> EndpointProxyDnsPolicy:
    """Определить DNS-политику по возможностям endpoint, а не имени схемы.

    JSON-импорт может представить AWG как endpoint типа ``wireguard``. Поэтому
    надёжный признак AmneziaWG — непустой объект ``amnezia`` в самом outbound.
    """
    amnezia = endpoint.get("amnezia")
    if isinstance(amnezia, dict) and amnezia:
        return EndpointProxyDnsPolicy.AMNEZIA_GATEWAY
    return EndpointProxyDnsPolicy.CONFIGURED


def select_endpoint_proxy_dns(
    dns_values: list[str] | None,
    endpoint_addresses: list[str] | None,
    *,
    policy: EndpointProxyDnsPolicy,
) -> str | None:
    """Выбрать DNS endpoint-туннеля согласно явной политике протокола.

    Для обычного WireGuard возвращается первый адрес из ``DNS =`` без
    эвристик. Если DNS не задан, шаблонный ``proxy-dns`` остаётся без изменений.

    Для AWG сначала используется явно заданный приватный DNS. Если его нет,
    вычисляется шлюз первого IPv4-адреса интерфейса: Amnezia-сервер может
    перехватывать DNS на порту 53 именно там. Публичный DNS из конфига остаётся
    запасным вариантом, когда IPv4-адреса интерфейса нет.
    """
    cleaned = [str(item).strip() for item in (dns_values or []) if str(item).strip()]

    if policy is EndpointProxyDnsPolicy.CONFIGURED:
        return cleaned[0] if cleaned else None

    for item in cleaned:
        try:
            candidate = ipaddress.ip_address(item)
        except ValueError:
            continue
        if candidate.is_private:
            return item

    for item in endpoint_addresses or []:
        try:
            interface = ipaddress.ip_interface(str(item).strip())
        except ValueError:
            continue
        if interface.version != 4:
            continue
        network = interface.network
        if network.prefixlen >= 31:
            network = ipaddress.ip_network(f"{interface.ip}/24", strict=False)
        try:
            return str(next(network.hosts()))
        except StopIteration:
            continue

    if cleaned:
        return cleaned[0]
    return None


def _override_proxy_dns_server(payload: dict[str, Any], server: str) -> None:
    dns = payload.get("dns")
    if not isinstance(dns, dict):
        return
    servers = dns.get("servers")
    if not isinstance(servers, list):
        return
    for index, item in enumerate(servers):
        if isinstance(item, dict) and str(item.get("tag") or "") == "proxy-dns":
            servers[index] = {
                "tag": "proxy-dns",
                "type": "udp",
                "server": server,
                "detour": "proxy",
            }
            return


def _validate_runtime_dns_contract(payload: dict[str, Any]) -> None:
    dns = payload.get("dns")
    server_tags: set[str] = set()
    if isinstance(dns, dict):
        for server in dns.get("servers") or []:
            if not isinstance(server, dict):
                continue
            tag = str(server.get("tag") or "").strip()
            if tag:
                server_tags.add(tag)

    missing_refs: list[str] = []

    def require_dns_tag(tag: str, owner: str) -> None:
        if not tag or tag in server_tags:
            return
        missing_refs.append(f"{owner} -> {tag}")

    route = payload.get("route")
    if isinstance(route, dict):
        require_dns_tag(_extract_dns_server_tag(route.get("default_domain_resolver")), "route.default_domain_resolver")

    if isinstance(dns, dict):
        require_dns_tag(_extract_dns_server_tag(dns.get("final")), "dns.final")
        for index, rule in enumerate(dns.get("rules") or []):
            if not isinstance(rule, dict):
                continue
            require_dns_tag(_extract_dns_server_tag(rule.get("server")), f"dns.rules[{index}].server")

    for index, outbound in enumerate(payload.get("outbounds") or []):
        if not isinstance(outbound, dict):
            continue
        require_dns_tag(
            _extract_dns_server_tag(outbound.get("domain_resolver")),
            f"outbounds[{index}].domain_resolver",
        )

    for index, endpoint in enumerate(payload.get("endpoints") or []):
        if not isinstance(endpoint, dict):
            continue
        require_dns_tag(
            _extract_dns_server_tag(endpoint.get("domain_resolver")),
            f"endpoints[{index}].domain_resolver",
        )

    if not missing_refs:
        return

    details = "; ".join(dict.fromkeys(missing_refs))
    raise ValueError(
        "В sing-box конфиге отсутствует DNS-сервер с нужным tag. "
        f"Проверьте раздел dns.servers: {details}. "
        "Обычно для стандартного шаблона должны существовать теги `bootstrap-dns` и `proxy-dns`."
    )


def _find_proxy_outbound_index(outbounds: Any) -> int | None:
    if not isinstance(outbounds, list):
        return None
    for index, outbound in enumerate(outbounds):
        if isinstance(outbound, dict) and str(outbound.get("tag") or "") == "proxy":
            return index
    return None


def _config_has_proxy_outbound(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if _find_proxy_outbound_index(payload.get("outbounds")) is not None:
        return True
    # Endpoint с тегом `proxy` (например, wireguard) тоже считается наличием proxy.
    return _find_proxy_outbound_index(payload.get("endpoints")) is not None


def _replace_or_append_tagged(items: list[Any], tag: str, payload: dict[str, Any]) -> None:
    for index, item in enumerate(items):
        if isinstance(item, dict) and str(item.get("tag") or "") == tag:
            items[index] = payload
            return
    items.append(payload)


def _ensure_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if isinstance(value, dict):
        return value
    created: dict[str, Any] = {}
    parent[key] = created
    return created


def _ensure_list(parent: dict[str, Any], key: str) -> list[Any]:
    value = parent.get(key)
    if isinstance(value, list):
        return value
    created: list[Any] = []
    parent[key] = created
    return created


def _extract_dns_server_tag(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        return str(value.get("server") or "").strip()
    return ""


def _find_free_port(
    *,
    preferred: int,
    port_range: range | None = None,
    excluded: set[int] | None = None,
    allow_ephemeral_fallback: bool = False,
) -> int:
    excluded = excluded or set()
    candidates: list[int] = []
    if preferred > 0:
        candidates.append(preferred)
    if port_range is None:
        port_range = range(preferred, preferred + 100)
    for port in port_range:
        if port not in candidates:
            candidates.append(port)
    for port in candidates:
        if port <= 0 or port in excluded:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((PROXY_HOST, port))
                return port
            except OSError:
                continue
    if allow_ephemeral_fallback:
        # Hyper-V/WinNAT may reserve an entire preferred range. Port 0 asks
        # Windows for a currently usable dynamic port outside those exclusions.
        for _ in range(32):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind((PROXY_HOST, 0))
                    port = int(s.getsockname()[1])
                except (OSError, TypeError, ValueError, IndexError):
                    continue
            if port > 0 and port not in excluded:
                return port
    raise RuntimeError(f"No free TCP port available near {preferred}")


def _generate_ss_password(length: int = 24) -> str:
    _, password = generate_local_proxy_credentials(prefix="protect", password_length=length)
    return password


def _generate_tun_interface_name() -> str:
    return f"xftun{secrets.token_hex(3)}"


def _format_json_error_message(text: str, exc: json.JSONDecodeError) -> str:
    lines = text.splitlines()
    line = lines[exc.lineno - 1] if 0 < exc.lineno <= len(lines) else ""
    caret = ""
    if line:
        caret = "\n" + (" " * max(0, exc.colno - 1)) + "^"
    return f"Ошибка синтаксиса JSON: {exc.msg} (строка {exc.lineno}, столбец {exc.colno})\n{line}{caret}".rstrip()
