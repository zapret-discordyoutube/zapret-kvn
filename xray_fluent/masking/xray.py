"""Xray-core connection shaping (mux.cool, XHTTP xmux, finalmask TCP fragment).

Limits from the pinned xray-core (v1.260327.1-0.20261109052709-676eaf66f8f0): mux concurrency
is int16 and 0..128 become 128 (app/proxyman/outbound/handler.go); xudpProxyUDP443 is
reject|allow|skip (infra/conf/xray.go:119); maxConnections with maxConcurrency is refused
(infra/conf/transport_method.go:459); an XHTTP `extra` replaces the whole XHTTP config, so
xmux goes inside it when present; Vision breaks mux connections that carry TCP
(proxy/vless/outbound/outbound.go:259). Same rules as Android `masking/xray`.
"""

from __future__ import annotations

import re
from typing import Any

from .model import (
    DESYNC_MAX_OFFSET,
    DESYNC_MAX_TTL,
    DESYNC_METHODS,
    DESYNC_SAFE_TTL,
    UDP443_MODES,
    Core,
    Desync,
    MuxCool,
    Problem,
    ServerShape,
    Span,
    XrayFragment,
    XrayShaping,
    Xmux,
)

MAX_CONCURRENCY = 1024
CORE_MIN_EFFECTIVE_CONCURRENCY = 128


def validate(shaping: XrayShaping) -> list[Problem]:
    problems: list[Problem] = []
    mux = shaping.mux
    if mux is not None:
        if not 1 <= mux.concurrency <= MAX_CONCURRENCY:
            problems.append(Problem("mux.concurrency", f"Потоков на соединение: от 1 до {MAX_CONCURRENCY}."))
        elif mux.concurrency < CORE_MIN_EFFECTIVE_CONCURRENCY:
            problems.append(Problem(
                "mux.concurrency",
                f"Xray поднимает любое значение до {CORE_MIN_EFFECTIVE_CONCURRENCY}: меньше задать нельзя, "
                "mux либо включён, либо выключен.",
                error=False,
            ))
        if not -1 <= mux.xudp_concurrency <= MAX_CONCURRENCY:
            problems.append(Problem("mux.xudpConcurrency", f"XUDP: -1 (выключен), 0 (внутри mux) или до {MAX_CONCURRENCY}."))
        if mux.xudp_proxy_udp443 not in UDP443_MODES:
            problems.append(Problem("mux.xudpProxyUDP443", "QUIC в mux: reject, allow или skip."))
    xmux = shaping.xmux
    if xmux is not None:
        if (xmux.max_connections and xmux.max_connections.end > 0) and (xmux.max_concurrency and xmux.max_concurrency.end > 0):
            problems.append(Problem("xmux.maxConnections", "maxConnections и maxConcurrency нельзя задать вместе: Xray не запустится."))
        if xmux.h_keep_alive_period is not None and xmux.h_keep_alive_period < 0:
            problems.append(Problem("xmux.hKeepAlivePeriod", "Период keep-alive не может быть отрицательным."))
    fragment = shaping.fragment
    if fragment is not None:
        packets = fragment.packets.strip().lower()
        if packets != "tlshello":
            span = Span.parse(packets)
            if span is None or span.start == 0:
                problems.append(Problem("fragment.packets", "Пакеты: tlshello или номера записей от 1, например 1-3."))
        if fragment.length.start == 0:
            problems.append(Problem("fragment.length", "Длина куска должна быть больше 0."))
    if shaping.desync is not None and shaping.desync.enabled:
        problems += validate_desync(shaping.desync)
    return problems


def emit(shaping: XrayShaping, shape: ServerShape) -> tuple[dict[str, Any] | None, list[str]]:
    """The `{"mux", "xmux", "finalmask"}` block for this server, or None, plus the notes."""
    if not shaping.enabled or shape.core is not Core.XRAY:
        return None, []
    notes: list[str] = []
    block: dict[str, Any] = {}
    if shaping.mux is not None and shaping.mux.enabled:
        if shape.is_multiplexed_transport:
            notes.append(f"Mux не включён: {shape.network} уже мультиплексирует потоки, для XHTTP есть xmux.")
        else:
            block["mux"] = _mux_json(shaping.mux, shape, notes)
    if shaping.xmux is not None:
        if shape.is_xhttp:
            block["xmux"] = _xmux_json(shaping.xmux)
        else:
            notes.append("xmux не применён: сервер не XHTTP.")
    if shaping.fragment is not None and shaping.fragment.enabled:
        if shape.is_tcp_stream:
            block["finalmask"] = _finalmask_json(shaping.fragment)
            if shape.security == "reality":
                notes.append("Фрагментация с REALITY: куски режет ядро ниже REALITY, проверьте подбором.")
        else:
            notes.append(f"Фрагментация не применена: {shape.network} идёт не по TCP.")
    if shaping.desync is not None and shaping.desync.enabled:
        # Never an Xray field: the app's own dialer runs it (Android core patch 0017). The
        # Windows engine is not built yet, so nothing is sent and the log says so.
        notes.append("Пакеты-обманки пока работают только в приложении для Android.")
    return (block or None), notes


def _mux_json(mux: MuxCool, shape: ServerShape, notes: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {"enabled": True}
    if shape.is_vision:
        result["concurrency"] = -1
        notes.append("С XTLS Vision в mux идёт только UDP (XUDP): сервер рвёт TCP внутри mux.")
    else:
        result["concurrency"] = max(1, min(MAX_CONCURRENCY, mux.concurrency))
    result["xudpConcurrency"] = mux.xudp_concurrency
    result["xudpProxyUDP443"] = mux.xudp_proxy_udp443
    if mux.xudp_proxy_udp443 == "reject":
        notes.append("QUIC (UDP 443) в mux отклоняется: приложения перейдут на TCP.")
    return result


def _xmux_json(xmux: Xmux) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in (
        ("maxConcurrency", xmux.max_concurrency),
        ("maxConnections", xmux.max_connections),
        ("cMaxReuseTimes", xmux.c_max_reuse_times),
        ("hMaxRequestTimes", xmux.h_max_request_times),
        ("hMaxReusableSecs", xmux.h_max_reusable_secs),
    ):
        if value is not None:
            result[key] = str(value)
    if xmux.h_keep_alive_period is not None:
        result["hKeepAlivePeriod"] = xmux.h_keep_alive_period
    return result


def _finalmask_json(fragment: XrayFragment) -> dict[str, Any]:
    settings: dict[str, Any] = {
        "packets": fragment.packets.strip().lower(),
        "length": str(fragment.length),
        "delay": str(fragment.delay),
    }
    if fragment.max_split is not None:
        settings["maxSplit"] = str(fragment.max_split)
    return {"tcp": [{"type": "fragment", "settings": settings}]}


def apply_to_outbound(outbound: dict[str, Any], block: dict[str, Any]) -> None:
    """Merge the block into a native Xray outbound in place, by name (same as Android patch 0016)."""
    stream = outbound.setdefault("streamSettings", {})
    for key, value in block.items():
        if key == "mux":
            outbound["mux"] = value
        elif key == "finalmask":
            stream["finalmask"] = value
        elif key == "xmux":
            settings_key = "xhttpSettings" if isinstance(stream.get("xhttpSettings"), dict) else "splithttpSettings"
            xhttp = stream.get(settings_key)
            if not isinstance(xhttp, dict):
                xhttp = stream.setdefault("xhttpSettings", {})
            extra = xhttp.get("extra")
            (extra if isinstance(extra, dict) else xhttp)["xmux"] = value
        else:
            raise ValueError(f"unknown xray masking key: {key}")


_HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def validate_desync(desync: Desync) -> list[Problem]:
    """The limits of Android core patch 0017 `kvndesync.Parse` (same as Android XrayShapingRules)."""
    problems: list[Problem] = []
    if desync.method not in DESYNC_METHODS:
        problems.append(Problem("desync.method", "Способ: fake, disorder, split или oob."))
    split_at = desync.split_at.strip().lower()
    if split_at != "sni" and not (split_at.isdigit() and 1 <= int(split_at) <= DESYNC_MAX_OFFSET):
        problems.append(Problem("desync.splitAt", f"Место разреза: sni или номер байта от 1 до {DESYNC_MAX_OFFSET}."))
    if desync.method == "fake":
        if not 1 <= desync.fake_ttl <= DESYNC_MAX_TTL:
            problems.append(Problem("desync.fakeTtl", f"TTL обманки: от 1 до {DESYNC_MAX_TTL}."))
        elif desync.fake_ttl > DESYNC_SAFE_TTL:
            problems.append(Problem(
                "desync.fakeTtl", f"TTL больше {DESYNC_SAFE_TTL}: обманка может дойти до сервера и сломать подключение.", error=False,
            ))
        if not _HOSTNAME.match(desync.fake_sni.strip().lower()):
            problems.append(Problem("desync.fakeSni", "Имя в обманке: домен, например vk.com."))
    if desync.method == "oob":
        problems.append(Problem("desync.method", "OOB ломает подключение там, где сеть срезает флаг URG: проверьте подбором.", error=False))
    return problems
