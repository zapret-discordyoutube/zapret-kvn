"""sing-box's own TLS fragmentation for the TLS protocols sing-box owns (option/tls.go:
`fragment`, `record_fragment`, `fragment_fallback_delay`; client side, std/uTLS engines only,
REALITY ignores it). Same rules as Android `masking/singbox`.

The native `spoof` of the same file needs WinDivert on Windows (common/tlsspoof/raw_windows.go)
and is not offered here.
"""

from __future__ import annotations

from typing import Any

from .model import Core, Problem, ServerShape, SingboxFragment

PROTOCOLS = frozenset({"trojan", "vmess", "anytls", "http", "shadowtls"})
MAX_FALLBACK_DELAY_MS = 10_000


def validate(fragment: SingboxFragment) -> list[Problem]:
    problems: list[Problem] = []
    if fragment.fallback_delay_ms is not None and not 1 <= fragment.fallback_delay_ms <= MAX_FALLBACK_DELAY_MS:
        problems.append(Problem("singbox.fallbackDelayMs", f"Задержка: от 1 до {MAX_FALLBACK_DELAY_MS} мс."))
    if fragment.enabled and not fragment.fragment and not fragment.record_fragment:
        problems.append(Problem("singbox.fragment", "Не выбран ни один способ фрагментации: ничего не изменится.", error=False))
    return problems


def applies(shape: ServerShape) -> bool:
    return shape.core is Core.SINGBOX and shape.protocol in PROTOCOLS and shape.security == "tls"


def emit(outbound: dict[str, Any], fragment: SingboxFragment, shape: ServerShape) -> tuple[dict[str, Any], list[str]]:
    if not fragment.enabled or shape.core is not Core.SINGBOX or shape.protocol not in PROTOCOLS:
        return outbound, []
    tls = outbound.get("tls")
    if not isinstance(tls, dict) or tls.get("enabled") is not True:
        return outbound, ["Фрагментация TLS не применена: у сервера нет TLS."]
    reality = tls.get("reality")
    if isinstance(reality, dict) and reality.get("enabled") is True:
        return outbound, ["Фрагментация TLS не применена: REALITY её обходит."]
    updated = {key: value for key, value in tls.items() if key not in {"fragment", "record_fragment", "fragment_fallback_delay"}}
    if fragment.fragment:
        updated["fragment"] = True
    if fragment.record_fragment:
        updated["record_fragment"] = True
    if fragment.fallback_delay_ms is not None:
        updated["fragment_fallback_delay"] = f"{fragment.fallback_delay_ms}ms"
    return {**outbound, "tls": updated}, []
