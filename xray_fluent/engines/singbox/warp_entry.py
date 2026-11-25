"""WARP as the entry hop to our server (owner decision 2026-11-25).

Device -> Cloudflare WARP -> our server -> internet.  The provider sees only Cloudflare, never the server address.
Hiddify's "Proxy unblocker", improved.  Same design as Android (`WarpEntryHop.kt`, android/docs/ARCHITECTURE.md).

Everything stays in sing-box, the gasket: WARP is the core's `warp` endpoint (core patch 0022 gives it `mtu` and
`profile.cache_path`).  This module only edits the runtime config; the stored node is never touched.

How each protocol owner gets in through the hop, without any change to its native core:

* sing-box native outbounds (Shadowsocks, SOCKS, HTTP, TUIC, ...): `detour` to the hop.
* official `hysteria.exe` sidecar: it dials its server itself, so the planner's rule `process_path: hysteria.exe ->
  direct` points to the hop instead.
* Xray (hybrid): it dials through the protect inbound, whose rule `inbound: protect -> direct` points to the hop.

Owner rule: WARP is an ENTRY only, never an exit and never a server to pick.  `violations` therefore allows exactly
three uses of the hop's tag: a server's `detour`, the endpoint's own tag, and the two sidecar rules above in their exact
planner shape.  Anything else (selector member, other route rule, `route.final`, user JSON) is refused.  Direct traffic
never enters WARP.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Any, Iterable

WARP_ENTRY_TAG = "kvn-warp-entry"

# A direct outbound used only to register the WARP account (`profile.detour`).  The registration call is a plain Go HTTP
# request of sing-box.exe: with the TUN up it would be captured by the TUN, routed to the final proxy and so back toward
# the very hop that waits for the registration.  Through this outbound it leaves on the physical interface directly.
# (Android has the same outbound for a second reason: plain Go has no DNS there; see WarpEntryHop.kt.)
WARP_ENTRY_API_TAG = "kvn-warp-api"

# Hysteria2 sends datagrams with 1252 bytes of payload: a 1300 byte packet over IPv6, which does not fit in the core's
# default 1280.  1330 fits it and stays under 1500 with WireGuard's 80 bytes of IPv6 overhead.
WARP_ENTRY_MTU = 1330

# Types without a server of their own: nothing to lead through the hop.  `warp` is the hop itself.
_LOCAL_TYPES = frozenset({"direct", "block", "dns", "selector", "urltest", "warp"})

# The planner's sidecar rules carry only these keys; a rule with anything more is not ours.
_SIDECAR_RULE_KEYS = frozenset({"process_path", "inbound", "outbound"})


@dataclass(frozen=True)
class EntryHopResult:
    chained: int  # outbounds that now dial through the hop
    rerouted: int  # sidecar rules that now lead into the hop

    @property
    def active(self) -> bool:
        return self.chained + self.rerouted > 0


def apply_entry_hop(
    payload: dict[str, Any],
    profile_path: str,
    *,
    resolver: str | None = None,
    sidecar_process_paths: Iterable[str] = (),
    sidecar_inbounds: Iterable[str] = (),
) -> EntryHopResult:
    """Lead servers through the hop; add the hop endpoint only if something enters through it.

    `resolver` resolves server NAMES outside the tunnel: a detoured outbound hands the name to the hop, whose DNS final
    rule goes through the very servers waiting for the address.  A resolver the config already sets is kept.
    `profile_path` is a private file in the app data folder that keeps the Cloudflare account (core patch 0022).
    """
    paths = _normalized(sidecar_process_paths)
    inbounds = {str(tag) for tag in sidecar_inbounds}

    endpoints = [e for e in _as_list(payload.get("endpoints")) if not _is_hop(e)]
    chained = 0
    outbounds = _as_list(payload.get("outbounds"))
    outbounds[:] = [o for o in outbounds if not (isinstance(o, dict) and o.get("tag") == WARP_ENTRY_API_TAG)]
    for index, outbound in enumerate(outbounds):
        if isinstance(outbound, dict) and _dials_server(outbound):
            outbounds[index] = _chain(outbound, resolver)
            chained += 1

    rerouted = 0
    route = payload.get("route")
    for rule in _as_list(route.get("rules") if isinstance(route, dict) else None):
        if isinstance(rule, dict) and rule.get("outbound") in ("direct", WARP_ENTRY_TAG) and _is_sidecar_rule(rule, paths, inbounds):
            rule["outbound"] = WARP_ENTRY_TAG
            rerouted += 1

    if chained + rerouted:
        api: dict[str, Any] = {"type": "direct", "tag": WARP_ENTRY_API_TAG}
        if resolver:
            api["domain_resolver"] = resolver
        outbounds.append(api)
        payload["outbounds"] = outbounds
        endpoints.append(
            {
                "type": "warp",
                "tag": WARP_ENTRY_TAG,
                "mtu": WARP_ENTRY_MTU,
                "profile": {"cache_path": profile_path, "detour": WARP_ENTRY_API_TAG},
            }
        )
    if endpoints or "endpoints" in payload:
        payload["endpoints"] = endpoints
    return EntryHopResult(chained=chained, rerouted=rerouted)


def violations(
    payload: dict[str, Any],
    *,
    sidecar_process_paths: Iterable[str] = (),
    sidecar_inbounds: Iterable[str] = (),
) -> list[str]:
    """Places where the hop's tag is used as anything but an entry.  Empty means it is an entry only."""
    paths = _normalized(sidecar_process_paths)
    inbounds = {str(tag) for tag in sidecar_inbounds}
    found: list[str] = []

    def walk(node: Any, path: str, allow_detour: bool, allow_tag: bool) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, str) and value == WARP_ENTRY_TAG and (
                    (allow_detour and key == "detour") or (allow_tag and key == "tag")
                ):
                    continue
                walk(value, f"{path}.{key}", allow_detour, allow_tag)
        elif isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, f"{path}[{index}]", allow_detour, allow_tag)
        elif isinstance(node, str) and node == WARP_ENTRY_TAG:
            found.append(path)

    for key, value in payload.items():
        if key == "outbounds":
            walk(value, key, True, False)
        elif key == "endpoints":
            walk(value, key, True, True)
        elif key == "dns":
            walk(value, key, True, False)
        elif key == "route":
            _walk_route(value, key, paths, inbounds, found, walk)
        else:
            walk(value, key, False, False)
    return found


def _walk_route(route: Any, path: str, paths: set[str], inbounds: set[str], found: list[str], walk) -> None:
    if not isinstance(route, dict):
        walk(route, path, False, False)
        return
    for key, value in route.items():
        if key != "rules" or not isinstance(value, list):
            walk(value, f"{path}.{key}", False, False)
            continue
        for index, rule in enumerate(value):
            rule_path = f"{path}.rules[{index}]"
            if isinstance(rule, dict) and rule.get("outbound") == WARP_ENTRY_TAG and _is_sidecar_rule(rule, paths, inbounds):
                continue
            walk(rule, rule_path, False, False)


def _is_sidecar_rule(rule: dict[str, Any], paths: set[str], inbounds: set[str]) -> bool:
    """Exactly the planner's shape: only `process_path` / `inbound` / `outbound`, and every value is one of ours."""
    if not set(rule) <= _SIDECAR_RULE_KEYS:
        return False
    rule_paths = _string_list(rule.get("process_path"))
    rule_inbounds = _string_list(rule.get("inbound"))
    if not rule_paths and not rule_inbounds:
        return False
    return {p.lower() for p in rule_paths} <= paths and set(rule_inbounds) <= inbounds


def _dials_server(outbound: dict[str, Any]) -> bool:
    kind = outbound.get("type")
    if not isinstance(kind, str) or kind in _LOCAL_TYPES or "server" not in outbound:
        return False
    detour = outbound.get("detour")
    # Another detour means this is not the first link of its chain; our own tag is not "another".
    return detour in (None, WARP_ENTRY_TAG)


def _chain(outbound: dict[str, Any], resolver: str | None) -> dict[str, Any]:
    updated = dict(outbound)
    updated["detour"] = WARP_ENTRY_TAG
    if resolver and "domain_resolver" not in updated and not _is_ip_literal(str(updated.get("server", ""))):
        updated["domain_resolver"] = resolver
    return updated


def _is_hop(endpoint: Any) -> bool:
    return isinstance(endpoint, dict) and endpoint.get("tag") == WARP_ENTRY_TAG


def _is_ip_literal(value: str) -> bool:
    host = value.strip().strip("[]")
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    return True


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value] if isinstance(value, list) else []


def _normalized(paths: Iterable[str]) -> set[str]:
    return {str(path).lower() for path in paths}
