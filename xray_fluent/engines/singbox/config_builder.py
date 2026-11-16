from __future__ import annotations

from copy import deepcopy
from typing import Any

from xray_fluent.application.protocol_core import ProtocolCore, protocol_core
from xray_fluent.engines.tls_fingerprint import BROWSER_TLS_FINGERPRINT, tls_over_quic

# VLESS, VMess and Trojan belong to Xray (owner decision 2026-11-16); sing-box converts only these.
_SUPPORTED_NATIVE_PROTOCOLS = {"shadowsocks", "socks", "http"}

# Типы, которые sing-box 1.13+ принимает только в top-level массиве `endpoints[]`,
# а не в `outbounds[]`.
_SINGBOX_ENDPOINT_TYPES = {"wireguard"}


def is_singbox_endpoint_outbound(outbound: dict[str, Any] | None) -> bool:
    """True, если конфиг ноды — sing-box endpoint (например, WireGuard/AWG)."""
    if not isinstance(outbound, dict):
        return False
    native_type = str(outbound.get("type") or "").strip().lower()
    return native_type in _SINGBOX_ENDPOINT_TYPES and not outbound.get("protocol")


def is_singbox_endpoint_node(node) -> bool:
    return node is not None and is_singbox_endpoint_outbound(node.outbound)


def unenforced_tls_pin_warning(node) -> str:
    """Предупреждение, если сервер с pcs уходит в sing-box, где пин не проверяется."""
    outbound = node.outbound if node is not None and isinstance(node.outbound, dict) else {}
    if outbound.get("type") and not outbound.get("protocol"):
        return ""
    if protocol_core(node) is not ProtocolCore.SINGBOX:
        return ""
    stream = outbound.get("streamSettings")
    tls_settings = stream.get("tlsSettings") if isinstance(stream, dict) else None
    if not isinstance(tls_settings, dict) or not str(tls_settings.get("pinnedPeerCertSha256") or "").strip():
        return ""
    name = str(getattr(node, "name", "") or getattr(node, "server", "") or "сервер").strip()
    return (
        f"[warning] {name}: ссылка закрепляет сертификат (pcs), но sing-box не умеет сверять "
        "SHA-256 всего сертификата, поэтому сертификат сервера не проверяется (tls.insecure). "
        "Проверка отпечатка работает только в ядре Xray (VLESS)."
    )


def build_singbox_outbound(node, *, tag: str = "proxy") -> dict[str, Any]:
    """Convert a stored node outbound into a native sing-box outbound (Shadowsocks, SOCKS, HTTP)."""
    source = deepcopy(node.outbound or {})
    protocol = str(source.get("protocol") or "").lower()
    native_type = str(source.get("type") or "").lower()
    if protocol_core(node) is not ProtocolCore.SINGBOX:
        raise ValueError("VLESS, VMess and Trojan belong to Xray; Hysteria2 belongs to the official Hysteria core.")
    if native_type and not protocol:
        # Служебные ключи приложения (`_dns` и прочие с префиксом `_`) не входят
        # в схему sing-box, строгий декодер их отвергает — отбрасываем.
        source = {key: value for key, value in source.items() if not str(key).startswith("_")}
        source["tag"] = tag
        return source

    if protocol not in _SUPPORTED_NATIVE_PROTOCOLS:
        raise ValueError(
            f"Текущий сервер нельзя конвертировать в native sing-box outbound: protocol `{protocol or 'unknown'}`"
        )

    outbound = _convert_outbound(source)

    outbound["tag"] = tag
    return outbound


def _convert_outbound(xray_ob: dict[str, Any]) -> dict[str, Any]:
    protocol = str(xray_ob.get("protocol") or "").lower()
    xray_settings = dict(xray_ob.get("settings") or {})
    stream = dict(xray_ob.get("streamSettings") or {})

    sb: dict[str, Any] = {"type": protocol}

    if protocol == "shadowsocks":
        servers = (xray_settings.get("servers") or [{}])[0]
        sb["server"] = str(servers.get("address") or "")
        sb["server_port"] = int(servers.get("port") or 0)
        sb["method"] = str(servers.get("method") or "")
        sb["password"] = str(servers.get("password") or "")

    elif protocol in ("socks", "http"):
        servers = (xray_settings.get("servers") or [{}])[0]
        sb["server"] = str(servers.get("address") or "")
        sb["server_port"] = int(servers.get("port") or 0)
        user_list = servers.get("users") or []
        if user_list:
            sb["username"] = str(user_list[0].get("user") or "")
            sb["password"] = str(user_list[0].get("pass") or "")

    _apply_tls(sb, stream)
    return sb


def _apply_tls(sb: dict[str, Any], stream: dict[str, Any]) -> None:
    security = str(stream.get("security") or "").lower()
    if security not in ("tls", "reality"):
        return

    tls: dict[str, Any] = {"enabled": True}
    # Без fp в ссылке — рукопожатие Chrome, а не ClientHello библиотеки Go.
    default_fingerprint = "" if tls_over_quic(stream) else BROWSER_TLS_FINGERPRINT

    if security == "reality":
        reality_settings = dict(stream.get("realitySettings") or {})
        tls["server_name"] = str(reality_settings.get("serverName") or "")
        fingerprint = str(reality_settings.get("fingerprint") or "") or default_fingerprint
        if fingerprint:
            tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
        public_key = str(reality_settings.get("publicKey") or "")
        short_id = str(reality_settings.get("shortId") or "")
        tls["reality"] = {"enabled": True, "public_key": public_key, "short_id": short_id}
    else:
        tls_settings = dict(stream.get("tlsSettings") or {})
        server_name = str(tls_settings.get("serverName") or "")
        if server_name:
            tls["server_name"] = server_name
        alpn = tls_settings.get("alpn")
        if alpn:
            tls["alpn"] = list(alpn)
        fingerprint = str(tls_settings.get("fingerprint") or "") or default_fingerprint
        if fingerprint:
            tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
        # sing-box не умеет закреплять SHA-256 всего сертификата (его
        # certificate_public_key_sha256 это хэш SPKI, другое значение), поэтому
        # пин Xray здесь не проверяется. Без insecure самоподписанный сертификат
        # не пройдёт, а ссылка с pcs рассчитана ровно на него; об этом
        # предупреждает unenforced_tls_pin_warning().
        if tls_settings.get("allowInsecure", False) or str(tls_settings.get("pinnedPeerCertSha256") or "").strip():
            tls["insecure"] = True

    sb["tls"] = tls
