"""Fixed protocol ownership shared by planning, pools and runtime modules."""

from enum import Enum


class ProtocolCore(str, Enum):
    SINGBOX = "sing-box"
    XRAY = "xray"
    HYSTERIA = "hysteria"
    AMNEZIA = "amnezia"


def protocol_core(node) -> ProtocolCore:
    outbound = node.outbound or {}
    protocol = str(outbound.get("protocol", outbound.get("type", node.scheme))).lower()
    if protocol == "vless":
        return ProtocolCore.XRAY
    if protocol in {"wireguard", "awg"}:
        return ProtocolCore.AMNEZIA
    # The official v2 client cannot consume Hysteria v1 configurations.
    if protocol in {"hy2", "hysteria2"}:
        return ProtocolCore.HYSTERIA
    return ProtocolCore.SINGBOX
