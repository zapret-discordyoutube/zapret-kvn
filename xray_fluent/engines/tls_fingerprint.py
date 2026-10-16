"""Отпечаток TLS-рукопожатия с сервером по умолчанию — как у Chrome.

Без ``fp`` в ссылке ядро шлёт ClientHello стандартной библиотеки Go: набор
шифров и порядок расширений, которых нет ни у одного браузера, поэтому
оборудование провайдера отличает такое соединение с первого пакета. Значение
из ссылки (``fp=firefox``, ``randomized`` и т. п.) остаётся как есть; QUIC-путь
(HTTP/3) uTLS не использует, его не трогаем.

Хранимый узел не меняется: отпечаток подставляется только в конфиг ядра.
"""

from __future__ import annotations

from typing import Any

BROWSER_TLS_FINGERPRINT = "chrome"

_QUIC_NETWORKS = {"quic", "kcp", "mkcp"}


def tls_over_quic(stream: dict[str, Any]) -> bool:
    """Рукопожатие идёт по QUIC: uTLS к нему неприменим."""

    network = str(stream.get("network") or "tcp").lower()
    if network in _QUIC_NETWORKS:
        return True
    for key in ("tlsSettings", "realitySettings"):
        settings = stream.get(key)
        if isinstance(settings, dict):
            alpn = settings.get("alpn")
            if isinstance(alpn, list) and alpn and all(str(item).lower() == "h3" for item in alpn):
                return True
    return False


def apply_browser_fingerprint(outbound: dict[str, Any]) -> dict[str, Any]:
    """Подставить ``fingerprint: chrome`` в Xray-outbound без своего отпечатка.

    Меняет переданный словарь (вызывать на копии) и возвращает его же.
    """

    stream = outbound.get("streamSettings")
    if not isinstance(stream, dict) or tls_over_quic(stream):
        return outbound
    security = str(stream.get("security") or "").lower()
    key = {"tls": "tlsSettings", "reality": "realitySettings"}.get(security)
    if key is None:
        return outbound
    settings = stream.get(key)
    if not isinstance(settings, dict):
        settings = {}
        stream[key] = settings
    if not str(settings.get("fingerprint") or "").strip():
        settings["fingerprint"] = BROWSER_TLS_FINGERPRINT
    return outbound
