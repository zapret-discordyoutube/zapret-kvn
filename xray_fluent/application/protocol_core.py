"""Fixed protocol ownership shared by planning, pools and runtime modules."""

from enum import Enum


class ProtocolCore(str, Enum):
    SINGBOX = "sing-box"
    XRAY = "xray"
    HYSTERIA = "hysteria"
    AMNEZIA = "amnezia"


# Protocols whose complete native implementation is Xray-core (VLESS is handled first, by name).
XRAY_NATIVE_PROTOCOLS = frozenset({"vmess", "trojan"})


def protocol_core(node) -> ProtocolCore:
    outbound = node.outbound or {}
    protocol = str(outbound.get("protocol", outbound.get("type", node.scheme))).lower()
    if protocol == "vless":
        return ProtocolCore.XRAY
    # VMess and Trojan are native Xray protocols (owner decision 2026-11-16): sing-box has no XHTTP
    # transport for them and only approximates the rest.  A node pasted as a raw sing-box outbound
    # (`type` key, no Xray `protocol` key) is the user's own sing-box JSON and stays with sing-box.
    if protocol in XRAY_NATIVE_PROTOCOLS and "protocol" in outbound:
        return ProtocolCore.XRAY
    if protocol in {"wireguard", "awg"}:
        return ProtocolCore.AMNEZIA
    # The official v2 client cannot consume Hysteria v1 configurations.
    if protocol in {"hy2", "hysteria2"}:
        return ProtocolCore.HYSTERIA
    return ProtocolCore.SINGBOX
