"""Storage and exchange format of masking settings, identical to Android `MaskingCodec`:

    {"schema":1, "enabled":false, "global":{...masking...},
     "overrides":{"<server key>":"off" | {"custom":{...masking...}}}}

Reading is tolerant (a malformed field reads as absent, never a crash or an invented value);
unknown top-level keys of the previous document are carried over on write, so settings of a
newer build survive a rollback by the updater.
"""

from __future__ import annotations

import json
from typing import Any

from .model import (
    INHERIT,
    NONE,
    OFF,
    SCHEMA,
    SETTINGS_OFF,
    SIGNATURE_KEYS,
    Masking,
    MaskingOverride,
    MaskingSettings,
    MuxCool,
    OverrideKind,
    SingboxFragment,
    Span,
    WireGuardMasking,
    XrayFragment,
    XrayShaping,
    Xmux,
)


def _bool(data: dict[str, Any], key: str) -> bool | None:
    value = data.get(key)
    return value if isinstance(value, bool) else None


def _int(data: dict[str, Any], key: str) -> int | None:
    value = data.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _str(data: dict[str, Any], key: str) -> str | None:
    value = data.get(key)
    return value if isinstance(value, str) else None


def _span(data: dict[str, Any], key: str) -> Span | None:
    value = data.get(key)
    if isinstance(value, str):
        return Span.parse(value)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return Span.of(value)
    return None


def _obj(data: dict[str, Any], key: str) -> dict[str, Any] | None:
    value = data.get(key)
    return value if isinstance(value, dict) else None


def decode_text(text: str | None) -> MaskingSettings:
    try:
        root = json.loads(text) if text else None
    except (TypeError, ValueError):
        root = None
    return decode(root) if isinstance(root, dict) else SETTINGS_OFF


def encode_text(settings: MaskingSettings, previous: str | None = None) -> str:
    try:
        previous_root = json.loads(previous) if previous else None
    except (TypeError, ValueError):
        previous_root = None
    return json.dumps(
        encode(settings, previous_root if isinstance(previous_root, dict) else None),
        ensure_ascii=False,
        separators=(",", ":"),
    )


def decode(root: dict[str, Any]) -> MaskingSettings:
    overrides: dict[str, MaskingOverride] = {}
    for key, value in (_obj(root, "overrides") or {}).items():
        parsed = _decode_override(value)
        if parsed is not None:
            overrides[str(key)] = parsed
    global_root = _obj(root, "global")
    return MaskingSettings(
        enabled=_bool(root, "enabled") or False,
        global_masking=decode_masking(global_root) if global_root is not None else NONE,
        overrides=overrides,
    )


def encode(settings: MaskingSettings, previous: dict[str, Any] | None = None) -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    for key in sorted(settings.overrides):
        value = settings.overrides[key]
        if value.kind is OverrideKind.OFF:
            overrides[key] = "off"
        elif value.kind is OverrideKind.CUSTOM:
            overrides[key] = {"custom": encode_masking(value.masking)}
    known = {
        "schema": SCHEMA,
        "enabled": settings.enabled,
        "global": encode_masking(settings.global_masking),
        "overrides": overrides,
    }
    carried = {key: value for key, value in (previous or {}).items() if key not in known}
    return {**known, **carried}


def _decode_override(value: Any) -> MaskingOverride | None:
    if value == "off":
        return OFF
    if value == "inherit":
        return INHERIT
    if isinstance(value, dict) and isinstance(value.get("custom"), dict):
        return MaskingOverride(OverrideKind.CUSTOM, decode_masking(value["custom"]))
    return None


def encode_masking(masking: Masking) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if masking.wireguard is not None:
        section = masking.wireguard
        wireguard: dict[str, Any] = {"enabled": section.enabled}
        for key in ("jc", "jmin", "jmax"):
            if getattr(section, key) is not None:
                wireguard[key] = getattr(section, key)
        for key in SIGNATURE_KEYS:
            if key in section.signatures:
                wireguard[key] = section.signatures[key]
        result["wireguard"] = wireguard
    if masking.xray is not None:
        section = masking.xray
        xray: dict[str, Any] = {"enabled": section.enabled}
        if section.mux is not None:
            xray["mux"] = {
                "enabled": section.mux.enabled,
                "concurrency": section.mux.concurrency,
                "xudpConcurrency": section.mux.xudp_concurrency,
                "xudpProxyUDP443": section.mux.xudp_proxy_udp443,
            }
        if section.xmux is not None:
            xmux: dict[str, Any] = {}
            for key, value in (
                ("maxConcurrency", section.xmux.max_concurrency),
                ("maxConnections", section.xmux.max_connections),
                ("cMaxReuseTimes", section.xmux.c_max_reuse_times),
                ("hMaxRequestTimes", section.xmux.h_max_request_times),
                ("hMaxReusableSecs", section.xmux.h_max_reusable_secs),
            ):
                if value is not None:
                    xmux[key] = str(value)
            if section.xmux.h_keep_alive_period is not None:
                xmux["hKeepAlivePeriod"] = section.xmux.h_keep_alive_period
            xray["xmux"] = xmux
        if section.fragment is not None:
            fragment = section.fragment
            encoded = {
                "enabled": fragment.enabled,
                "packets": fragment.packets,
                "length": str(fragment.length),
                "delay": str(fragment.delay),
            }
            if fragment.max_split is not None:
                encoded["maxSplit"] = str(fragment.max_split)
            xray["fragment"] = encoded
        result["xray"] = xray
    if masking.singbox is not None:
        section = masking.singbox
        singbox: dict[str, Any] = {
            "enabled": section.enabled,
            "fragment": section.fragment,
            "recordFragment": section.record_fragment,
        }
        if section.fallback_delay_ms is not None:
            singbox["fallbackDelayMs"] = section.fallback_delay_ms
        result["singbox"] = singbox
    return result


def decode_masking(root: dict[str, Any]) -> Masking:
    wireguard_root = _obj(root, "wireguard")
    xray_root = _obj(root, "xray")
    singbox_root = _obj(root, "singbox")
    wireguard = None
    if wireguard_root is not None:
        wireguard = WireGuardMasking(
            enabled=_bool(wireguard_root, "enabled") if _bool(wireguard_root, "enabled") is not None else True,
            jc=_int(wireguard_root, "jc"),
            jmin=_int(wireguard_root, "jmin"),
            jmax=_int(wireguard_root, "jmax"),
            signatures={key: _str(wireguard_root, key) for key in SIGNATURE_KEYS if _str(wireguard_root, key) is not None},
        )
    xray = None
    if xray_root is not None:
        mux_root, xmux_root, fragment_root = _obj(xray_root, "mux"), _obj(xray_root, "xmux"), _obj(xray_root, "fragment")
        defaults, fragment_defaults = MuxCool(), XrayFragment()
        xray = XrayShaping(
            enabled=_flag(xray_root),
            mux=None if mux_root is None else MuxCool(
                enabled=_flag(mux_root),
                concurrency=_int(mux_root, "concurrency") if _int(mux_root, "concurrency") is not None else defaults.concurrency,
                xudp_concurrency=_int(mux_root, "xudpConcurrency") if _int(mux_root, "xudpConcurrency") is not None else defaults.xudp_concurrency,
                xudp_proxy_udp443=_str(mux_root, "xudpProxyUDP443") or defaults.xudp_proxy_udp443,
            ),
            xmux=None if xmux_root is None else Xmux(
                max_concurrency=_span(xmux_root, "maxConcurrency"),
                max_connections=_span(xmux_root, "maxConnections"),
                c_max_reuse_times=_span(xmux_root, "cMaxReuseTimes"),
                h_max_request_times=_span(xmux_root, "hMaxRequestTimes"),
                h_max_reusable_secs=_span(xmux_root, "hMaxReusableSecs"),
                h_keep_alive_period=_int(xmux_root, "hKeepAlivePeriod"),
            ),
            fragment=None if fragment_root is None else XrayFragment(
                enabled=_flag(fragment_root),
                packets=_str(fragment_root, "packets") or fragment_defaults.packets,
                length=_span(fragment_root, "length") or fragment_defaults.length,
                delay=_span(fragment_root, "delay") or fragment_defaults.delay,
                max_split=_span(fragment_root, "maxSplit"),
            ),
        )
    singbox = None
    if singbox_root is not None:
        singbox = SingboxFragment(
            enabled=_flag(singbox_root),
            fragment=_bool(singbox_root, "fragment") if _bool(singbox_root, "fragment") is not None else True,
            record_fragment=_bool(singbox_root, "recordFragment") or False,
            fallback_delay_ms=_int(singbox_root, "fallbackDelayMs"),
        )
    return Masking(wireguard=wireguard, xray=xray, singbox=singbox)


def _flag(data: dict[str, Any]) -> bool:
    value = _bool(data, "enabled")
    return True if value is None else value
