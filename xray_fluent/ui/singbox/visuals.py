"""Icons and colour tones of native sing-box objects in the routing editor.

Presentation only: which Fluent icon and which semantic tone a rule action, an
outbound, a DNS server or a field gets. Colours themselves come from
``ui/theme.py`` at paint time, so every glyph follows the theme and accent.
"""

from __future__ import annotations

from dataclasses import dataclass

from PyQt6.QtGui import QColor
from qfluentwidgets import FluentIcon as FIF

from ..theme import accent_color, error_color, info_color, success_color, text_muted_color, warning_color

#: Semantic tones. ``proxy`` follows the accent, ``direct`` stays green.
PROXY, DIRECT, BLOCK, DNS, SPECIAL, NEUTRAL = "proxy", "direct", "block", "dns", "special", "neutral"


def tone_color(tone: str) -> QColor:
    if tone == PROXY:
        return accent_color()
    if tone == DIRECT:
        return success_color()
    if tone == BLOCK:
        return error_color()
    if tone == DNS:
        return info_color()
    if tone == SPECIAL:
        return warning_color()
    return text_muted_color()


@dataclass(frozen=True)
class Visual:
    icon: FIF
    tone: str = NEUTRAL


_OUTBOUND_TAGS = {
    "proxy": Visual(FIF.VPN, PROXY),
    "direct": Visual(FIF.SEND, DIRECT),
    "block": Visual(FIF.CLOSE, BLOCK),
}

_OUTBOUND_TYPES = {
    "direct": Visual(FIF.SEND, DIRECT),
    "block": Visual(FIF.CLOSE, BLOCK),
    "selector": Visual(FIF.MENU, PROXY),
    "urltest": Visual(FIF.SPEED_HIGH, PROXY),
    "fallback": Visual(FIF.SYNC, PROXY),
    "failover": Visual(FIF.SYNC, PROXY),
    "socks": Visual(FIF.CONNECT, PROXY),
    "http": Visual(FIF.GLOBE, PROXY),
    "tor": Visual(FIF.FINGERPRINT, PROXY),
    "ssh": Visual(FIF.COMMAND_PROMPT, PROXY),
}

_ACTIONS = {
    "reject": Visual(FIF.CLOSE, BLOCK),
    "hijack-dns": Visual(FIF.GLOBE, DNS),
    "sniff": Visual(FIF.SEARCH, SPECIAL),
    "resolve": Visual(FIF.TAG, DNS),
    "route-options": Visual(FIF.SETTING, SPECIAL),
    "direct": Visual(FIF.SEND, DIRECT),
    "bypass": Visual(FIF.SHARE, DIRECT),
}

_DNS_ACTIONS = {
    "reject": Visual(FIF.CLOSE, BLOCK),
    "predefined": Visual(FIF.QUICK_NOTE, SPECIAL),
    "route-options": Visual(FIF.SETTING, SPECIAL),
    "evaluate": Visual(FIF.SEARCH, SPECIAL),
    "respond": Visual(FIF.SEND, DNS),
}

_DNS_SERVERS = {
    "https": Visual(FIF.CERTIFICATE, DNS),
    "h3": Visual(FIF.CERTIFICATE, DNS),
    "tls": Visual(FIF.CERTIFICATE, DNS),
    "quic": Visual(FIF.CERTIFICATE, DNS),
    "udp": Visual(FIF.GLOBE, DNS),
    "tcp": Visual(FIF.GLOBE, DNS),
    "local": Visual(FIF.HOME, DIRECT),
    "dhcp": Visual(FIF.WIFI, DIRECT),
    "fallback": Visual(FIF.SYNC, DNS),
    "hosts": Visual(FIF.DICTIONARY, NEUTRAL),
    "fakeip": Visual(FIF.FINGERPRINT, SPECIAL),
    "resolved": Visual(FIF.HOME, DIRECT),
}

_RULE_SETS = {
    "local": Visual(FIF.DOCUMENT, NEUTRAL),
    "remote": Visual(FIF.CLOUD_DOWNLOAD, DNS),
    "inline": Visual(FIF.EMBED, SPECIAL),
}

_INBOUNDS = {
    "tun": Visual(FIF.VPN, PROXY),
    "mixed": Visual(FIF.CONNECT, NEUTRAL),
    "socks": Visual(FIF.CONNECT, NEUTRAL),
    "http": Visual(FIF.GLOBE, NEUTRAL),
    "direct": Visual(FIF.SEND, DIRECT),
}

#: Icons shown before field labels in forms.
FIELD_ICONS = {
    "domain": FIF.GLOBE,
    "domain_suffix": FIF.GLOBE,
    "domain_keyword": FIF.SEARCH,
    "domain_regex": FIF.ASTERISK,
    "ip_cidr": FIF.IOT,
    "source_ip_cidr": FIF.IOT,
    "ip_is_private": FIF.HOME,
    "source_ip_is_private": FIF.HOME,
    "port": FIF.LINK,
    "port_range": FIF.LINK,
    "source_port": FIF.LINK,
    "source_port_range": FIF.LINK,
    "process_name": FIF.APPLICATION,
    "process_path": FIF.FOLDER,
    "process_path_regex": FIF.ASTERISK,
    "rule_set": FIF.LIBRARY,
    "network": FIF.WIFI,
    "protocol": FIF.FINGERPRINT,
    "client": FIF.FINGERPRINT,
    "inbound": FIF.DOWNLOAD,
    "invert": FIF.SYNC,
    "action": FIF.PLAY,
    "outbound": FIF.SEND,
    "server": FIF.GLOBE,
    "tag": FIF.TAG,
    "type": FIF.TILES,
    "mode": FIF.FILTER,
    "rules": FIF.FILTER,
    "final": FIF.FLAG,
    "detour": FIF.SHARE,
    "domain_resolver": FIF.GLOBE,
    "default_domain_resolver": FIF.GLOBE,
    "strategy": FIF.IOT,
    "method": FIF.CLOSE,
    "sniffer": FIF.SEARCH,
    "timeout": FIF.STOP_WATCH,
    "update_interval": FIF.HISTORY,
    "interval": FIF.HISTORY,
    "path": FIF.DOCUMENT,
    "url": FIF.LINK,
    "format": FIF.CODE,
    "address": FIF.IOT,
    "auto_route": FIF.SHARE,
    "strict_route": FIF.FINGERPRINT,
    "stack": FIF.TILES,
    "mtu": FIF.UNIT,
    "listen": FIF.CONNECT,
    "listen_port": FIF.LINK,
    "level": FIF.DOCUMENT,
    "timestamp": FIF.DATE_TIME,
    "cache_file": FIF.SAVE,
    "clash_api": FIF.DEVELOPER_TOOLS,
    "enabled": FIF.ACCEPT,
    "server_port": FIF.LINK,
    "outbounds": FIF.SEND,
    "default": FIF.PIN,
    "auto_detect_interface": FIF.WIFI,
    "find_process": FIF.APPLICATION,
    "query_type": FIF.QUESTION,
    "tls": FIF.CERTIFICATE,
    "transport": FIF.SHARE,
}


def outbound_tag_visual(tag: str) -> Visual:
    return _OUTBOUND_TAGS.get(tag, Visual(FIF.SEND, PROXY))


def rule_visual(rule: dict, *, dns: bool = False) -> Visual:
    """Icon and tone of a route or DNS rule by what it does."""

    if not isinstance(rule, dict):
        return Visual(FIF.FILTER)
    action = rule.get("action") or "route"
    if dns:
        if action == "route":
            return Visual(FIF.GLOBE, DNS)
        return _DNS_ACTIONS.get(action, Visual(FIF.FILTER, DNS))
    if action == "route":
        tag = str(rule.get("outbound") or "")
        return _OUTBOUND_TAGS.get(tag, Visual(FIF.SEND, PROXY))
    return _ACTIONS.get(action, Visual(FIF.FILTER))


def outbound_visual(item: dict) -> Visual:
    tag = str(item.get("tag") or "")
    if tag in _OUTBOUND_TAGS:
        return _OUTBOUND_TAGS[tag]
    kind = str(item.get("type") or "")
    return _OUTBOUND_TYPES.get(kind, Visual(FIF.VPN, PROXY))


def dns_server_visual(item: dict) -> Visual:
    return _DNS_SERVERS.get(str(item.get("type") or ""), Visual(FIF.GLOBE, DNS))


def rule_set_visual(item: dict) -> Visual:
    return _RULE_SETS.get(str(item.get("type") or "inline"), Visual(FIF.LIBRARY))


def inbound_visual(item: dict) -> Visual:
    return _INBOUNDS.get(str(item.get("type") or ""), Visual(FIF.DOWNLOAD))


def endpoint_visual(item: dict) -> Visual:
    return Visual(FIF.VPN, PROXY) if item.get("type") in ("wireguard", "warp") else Visual(FIF.IOT, PROXY)


def enum_icon(field: str, value) -> FIF | None:
    """Icon for a value in a choice list (actions, outbound tags, types)."""

    if field == "action":
        if value == "route":
            return FIF.SEND
        visual = _ACTIONS.get(value) or _DNS_ACTIONS.get(value)
        return visual.icon if visual else None
    if field in ("outbound", "final", "default", "detour"):
        return outbound_tag_visual(str(value)).icon
    return None


def rule_outcomes(document: dict) -> tuple[int, int, int]:
    """How many route rules send traffic to proxy, direct and block.

    ``route`` rules are classified by the target outbound (its tag, or its type
    for user outbounds), ``reject`` counts as block; non-final actions such as
    sniff or hijack-dns are not an outcome and are skipped.
    """

    outbound_types = {
        item.get("tag"): item.get("type")
        for item in (document.get("outbounds") or [])
        if isinstance(item, dict)
    }
    proxy = direct = block = 0
    route = document.get("route") if isinstance(document.get("route"), dict) else {}
    for rule in route.get("rules") or []:
        if not isinstance(rule, dict):
            continue
        action = rule.get("action") or "route"
        if action == "reject":
            block += 1
            continue
        if action not in ("route", "direct", "bypass"):
            continue
        if action in ("direct", "bypass") and not rule.get("outbound"):
            direct += 1
            continue
        tag = rule.get("outbound")
        kind = outbound_types.get(tag)
        if tag == "block" or kind == "block":
            block += 1
        elif tag == "direct" or (kind == "direct" and tag != "proxy"):
            direct += 1
        else:
            proxy += 1
    return proxy, direct, block


def variant_icon(context: str, key: str, value) -> FIF | None:
    """Icon of a ``type``/``action`` choice for the object being edited."""

    if key == "action":
        return enum_icon("action", value)
    if key != "type":
        return None
    item = {"type": value}
    if context == "outbound":
        return _OUTBOUND_TYPES.get(str(value), Visual(FIF.VPN, PROXY)).icon
    if context == "dns_server":
        return dns_server_visual(item).icon
    if context == "rule_set":
        return rule_set_visual(item).icon
    if context == "inbound":
        return inbound_visual(item).icon
    if context == "endpoint":
        return endpoint_visual(item).icon
    if value == "logical":
        return FIF.FILTER
    return None


def tag_icon(kind: str | None, tag: str) -> FIF | None:
    if kind == "outbound":
        return outbound_tag_visual(tag).icon
    if kind == "dns_server":
        return FIF.GLOBE
    if kind == "rule_set":
        return FIF.LIBRARY
    if kind == "inbound":
        return FIF.DOWNLOAD
    return None
