"""Apply the effective masking to the runtime copies of servers (the stored node is never
edited; masking is re-applied from the current settings on every connect).

Windows keeps each node's native JSON: VLESS nodes hold an Xray outbound, WireGuard/AWG nodes
a sing-box endpoint with an `amnezia` object, the rest sing-box outbounds. Server shapes are
read from that JSON; the same merge as Android decides what each server gets.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlsplit

from . import singbox as singbox_rules
from . import wireguard as wireguard_rules
from . import xray as xray_rules
from .merge import effective
from .model import XRAY_PROTOCOLS, Core, MaskingSettings, ServerShape

_NOT_SERVERS = {"selector", "urltest", "direct", "block", "dns", "tor", "freedom", "blackhole"}


def _security(tls: Any) -> str:
    if not isinstance(tls, dict) or tls.get("enabled") is not True:
        return "none"
    reality = tls.get("reality")
    return "reality" if isinstance(reality, dict) and reality.get("enabled") is True else "tls"


def shape_of(outbound: dict[str, Any]) -> ServerShape | None:
    protocol = str(outbound.get("protocol") or outbound.get("type") or "").lower()
    if not protocol or protocol in _NOT_SERVERS:
        return None
    if protocol == "vless":
        if "streamSettings" in outbound or "settings" in outbound:  # native Xray outbound
            stream = outbound.get("streamSettings") if isinstance(outbound.get("streamSettings"), dict) else {}
            flow = None
            for server in (outbound.get("settings") or {}).get("vnext") or []:
                for user in (server or {}).get("users") or []:
                    flow = flow or (user or {}).get("flow") or None
            return ServerShape(
                Core.XRAY, "vless",
                network=str(stream.get("network") or "tcp").lower(),
                security=str(stream.get("security") or "none").lower(),
                flow=flow,
            )
        uri = str(outbound.get("uri") or "")
        if uri:
            query = {key: values[0] for key, values in parse_qs(urlsplit(uri).query).items() if values}
            return ServerShape(
                Core.XRAY, "vless",
                network=(query.get("type") or "tcp").lower(),
                security=(query.get("security") or "none").lower(),
                flow=query.get("flow") or None,
            )
        transport = outbound.get("transport") if isinstance(outbound.get("transport"), dict) else {}
        return ServerShape(
            Core.XRAY, "vless",
            network=str(transport.get("type") or "tcp").lower(),
            security=_security(outbound.get("tls")),
            flow=outbound.get("flow") or None,
        )
    if protocol in XRAY_PROTOCOLS and "protocol" in outbound:  # Xray-shaped VMess / Trojan
        stream = outbound.get("streamSettings") if isinstance(outbound.get("streamSettings"), dict) else {}
        return ServerShape(
            Core.XRAY, protocol,
            network=str(stream.get("network") or "tcp").lower(),
            security=str(stream.get("security") or "none").lower(),
        )
    if protocol in {"wireguard", "awg"}:
        return ServerShape(Core.AMNEZIA, protocol)
    if protocol in {"hy2", "hysteria2"}:
        return ServerShape(Core.HYSTERIA, protocol)
    return ServerShape(Core.SINGBOX, protocol, security=_security(outbound.get("tls")))


def apply_server(
    outbound: dict[str, Any], settings: MaskingSettings, server_key: str | None,
) -> tuple[dict[str, Any], list[str]]:
    """A masked copy of one server's native JSON and the notes; the input is not modified."""
    shape = shape_of(outbound)
    if shape is None:
        return outbound, []
    result = effective(settings, server_key, shape)
    notes = list(result.notes)
    masking = result.masking
    if shape.core is Core.XRAY and masking.xray is not None:
        block, emit_notes = xray_rules.emit(masking.xray, shape)
        notes += emit_notes
        if block:
            copied = _deep_copy(outbound)
            xray_rules.apply_to_outbound(copied, block)
            return copied, notes
    elif shape.core is Core.AMNEZIA and masking.wireguard is not None:
        current = outbound.get("amnezia") if isinstance(outbound.get("amnezia"), dict) else None
        return {**outbound, "amnezia": wireguard_rules.apply_to(current, masking.wireguard)}, notes
    elif shape.core is Core.SINGBOX and masking.singbox is not None:
        updated, emit_notes = singbox_rules.emit(outbound, masking.singbox, shape)
        return updated, notes + emit_notes
    return outbound, notes


def _deep_copy(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _deep_copy(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_deep_copy(item) for item in value]
    return value


def log_line(enabled: bool, changed: int, notes: list[str]) -> str | None:
    """One compact line per connect; nothing when masking is off and did nothing."""
    if not enabled and changed == 0:
        return None
    counts: dict[str, int] = {}
    for note in notes:
        counts[note] = counts.get(note, 0) + 1
    joined = "; ".join(note if count == 1 else f"{note} (×{count})" for note, count in counts.items())
    line = f"маскировка: {'включена' if enabled else 'выключена'}, изменено серверов: {changed}"
    return f"{line}; {joined}" if joined else line
