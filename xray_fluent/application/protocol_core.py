"""Fixed protocol ownership shared by planning, pools and runtime modules."""

from enum import Enum


class ProtocolCore(str, Enum):
    SINGBOX = "sing-box"
    XRAY = "xray"
    HYSTERIA = "hysteria"


def protocol_core(node) -> ProtocolCore:
    outbound = node.outbound or {}
    protocol = str(outbound.get("protocol", outbound.get("type", node.scheme))).lower()
    if protocol == "vless":
        return ProtocolCore.XRAY
    if protocol in {"hy2", "hysteria2", "hysteria"}:
        return ProtocolCore.HYSTERIA
    return ProtocolCore.SINGBOX
