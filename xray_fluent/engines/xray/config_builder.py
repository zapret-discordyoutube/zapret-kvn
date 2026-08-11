from __future__ import annotations

import ntpath
from copy import deepcopy
from ipaddress import ip_network
from typing import Any

from ...constants import (
    DEFAULT_HTTP_PORT,
    DEFAULT_SOCKS_PORT,
    PROXY_HOST,
    ROUTING_DIRECT,
    ROUTING_GLOBAL,
    ROUTING_RULE,
    DEFAULT_XRAY_STATS_API_PORT,
)
from ...application.rotation_service import (
    BALANCER_TAG,
    OUTBOUND_SELECTOR,
    PRIMARY_OUTBOUND_TAG,
    RotationPlan,
)
from ...application.outbound_pool_service import (
    XrayOutboundPool,
    ensure_xray_pool_control_plane,
)
from ...models import AppSettings, Node, RoutingSettings
from ...service_presets import SERVICE_PRESETS_BY_ID


def _normalize_loglevel(value: str) -> str:
    normalized = value.lower().strip()
    if normalized == "warn":
        return "warning"
    if normalized in {"debug", "info", "warning", "error", "none"}:
        return normalized
    return "warning"


def _split_rule_items(items: list[str]) -> tuple[list[str], list[str]]:
    domains: list[str] = []
    ips: list[str] = []
    for raw in items:
        value = raw.strip()
        if not value:
            continue

        if value.startswith(("domain:", "full:", "regexp:", "keyword:", "geosite:", "ext:")):
            domains.append(value)
            continue
        if value.startswith(("geoip:", "ip:")):
            ips.append(value)
            continue

        try:
            ip_network(value, strict=False)
            ips.append(value)
            continue
        except ValueError:
            pass

        domains.append(f"domain:{value}")

    return domains, ips


def _append_domain_ip_rule(rules: list[dict[str, Any]], items: list[str], outbound_tag: str) -> None:
    domains, ips = _split_rule_items(items)
    if domains:
        rules.append(
            {
                "type": "field",
                "domain": domains,
                "outboundTag": outbound_tag,
            }
        )
    if ips:
        rules.append(
            {
                "type": "field",
                "ip": ips,
                "outboundTag": outbound_tag,
            }
        )


def _resolve_xray_process_name(rule: dict[str, str]) -> str:
    value = str(rule.get("process", "")).strip()
    if not value:
        return ""
    match = str(rule.get("match", "")).strip().lower()
    if match == "path_regex":
        return ""
    if match == "path" or "\\" in value or "/" in value or (len(value) > 1 and value[1] == ":"):
        return ntpath.basename(value)
    return value


def _build_proxy_outbounds(node: Node, rotation: RotationPlan | None) -> list[dict[str, Any]]:
    """Один outbound на выбранную ноду либо весь пул ротации.

    Первым всегда идёт proxy-outbound: при пустом выборе балансировщика xray отдаёт
    трафик в первый элемент массива ``outbounds``, и это не должно быть ``freedom``.
    """

    if rotation is None:
        primary = deepcopy(node.outbound)
        primary["tag"] = PRIMARY_OUTBOUND_TAG
        return [primary]

    outbounds: list[dict[str, Any]] = []
    for pooled in rotation.nodes:
        outbound = deepcopy(pooled.outbound)
        outbound["tag"] = rotation.tag_for(pooled.id)
        outbounds.append(outbound)
    return outbounds


def _route_proxy_rules_to_balancer(rules: list[dict[str, Any]]) -> None:
    """Перевести правила с прокси-выхода на балансировщик.

    ``outboundTag`` имеет приоритет над ``balancerTag``, поэтому его обязательно
    удалять, а не просто дописывать второй ключ.
    """

    for rule in rules:
        if rule.get("outboundTag") == PRIMARY_OUTBOUND_TAG:
            rule.pop("outboundTag")
            rule["balancerTag"] = BALANCER_TAG


def build_xray_config(
    node: Node,
    routing: RoutingSettings,
    settings: AppSettings,
    api_port: int = 0,
    *,
    socks_port: int = DEFAULT_SOCKS_PORT,
    http_port: int = DEFAULT_HTTP_PORT,
    rotation: RotationPlan | None = None,
    outbound_pool: XrayOutboundPool | None = None,
) -> dict[str, Any]:
    if not api_port:
        api_port = DEFAULT_XRAY_STATS_API_PORT
    proxy_outbounds = (
        outbound_pool.outbounds()
        if outbound_pool is not None and outbound_pool.contains(node.id)
        else _build_proxy_outbounds(node, rotation)
    )

    routing_rules: list[dict[str, Any]] = [
        {
            "type": "field",
            "inboundTag": ["api"],
            "outboundTag": "api",
        }
    ]

    if routing.bypass_lan:
        routing_rules.append(
            {
                "type": "field",
                "ip": ["geoip:private"],
                "outboundTag": "direct",
            }
        )
        routing_rules.append(
            {
                "type": "field",
                "domain": ["geosite:private"],
                "outboundTag": "direct",
            }
        )

    if not settings.tun_mode:
        for pr in routing.process_rules:
            name = _resolve_xray_process_name(pr)
            action = pr.get("action", "direct")
            if name:
                routing_rules.append({
                    "type": "field",
                    "process": [name],
                    "network": "tcp,udp",
                    "outboundTag": action if action in ("direct", "proxy", "block") else "direct",
                })

    # Merge service preset domains
    service_direct: list[str] = []
    service_proxy: list[str] = []
    service_block: list[str] = []
    for svc_id, action in routing.service_routes.items():
        preset = SERVICE_PRESETS_BY_ID.get(svc_id)
        if not preset:
            continue
        if action == "direct":
            service_direct.extend(preset.domains)
        elif action == "block":
            service_block.extend(preset.domains)
        else:
            service_proxy.extend(preset.domains)
    _append_domain_ip_rule(routing_rules, service_proxy, "proxy")
    _append_domain_ip_rule(routing_rules, service_direct, "direct")
    _append_domain_ip_rule(routing_rules, service_block, "block")
    _append_domain_ip_rule(routing_rules, routing.direct_domains, "direct")
    _append_domain_ip_rule(routing_rules, routing.block_domains, "block")
    _append_domain_ip_rule(routing_rules, routing.proxy_domains, "proxy")

    mode = routing.mode

    if mode == ROUTING_GLOBAL:
        routing_rules.append(
            {
                "type": "field",
                "network": "tcp,udp",
                "outboundTag": "proxy",
            }
        )
    elif mode == ROUTING_DIRECT:
        routing_rules.append(
            {
                "type": "field",
                "network": "tcp,udp",
                "outboundTag": "direct",
            }
        )
    else:
        routing_rules.append(
            {
                "type": "field",
                "network": "tcp,udp",
                "outboundTag": "proxy",
            }
        )

    config: dict[str, Any] = {
        "log": {
            "loglevel": _normalize_loglevel(settings.log_level),
        },
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": PROXY_HOST,
                "port": int(socks_port),
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": True,
                },
            },
            {
                "tag": "http-in",
                "listen": PROXY_HOST,
                "port": int(http_port),
                "protocol": "http",
                "settings": {},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"],
                    "routeOnly": True,
                },
            },
            {
                "tag": "api",
                "listen": PROXY_HOST,
                "port": api_port,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": PROXY_HOST,
                },
            },
        ],
        "outbounds": [
            *proxy_outbounds,
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {},
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {},
            },
            {
                "tag": "api",
                "protocol": "freedom",
                "settings": {},
            },
        ],
        "policy": {
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            }
        },
        "stats": {},
        "api": {
            "tag": "api",
            "services": ["StatsService"],
        },
        "routing": {
            "domainStrategy": "AsIs",
            "rules": routing_rules,
        },
    }

    if outbound_pool is not None and outbound_pool.contains(node.id):
        ensure_xray_pool_control_plane(config, outbound_pool)
    elif rotation is not None:
        # Стратегия — лишь фолбэк: активный сервер фиксируется командой `xray api bo`,
        # иначе балансировщик раскидывал бы каждое соединение по разным серверам.
        # fallbackTag намеренно не задаётся: без observatory он ломает запуск ядра.
        _route_proxy_rules_to_balancer(routing_rules)
        config["routing"]["balancers"] = [
            {
                "tag": BALANCER_TAG,
                "selector": [OUTBOUND_SELECTOR],
                "strategy": {"type": "random"},
            }
        ]
        config["api"]["services"] = ["StatsService", "RoutingService"]

    if routing.dns_mode == "builtin":
        config["dns"] = {
            "servers": [
                "1.1.1.1",
                "8.8.8.8",
                "localhost",
            ],
            "queryStrategy": "UseIP",
        }

    return config
