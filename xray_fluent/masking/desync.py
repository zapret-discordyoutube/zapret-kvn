"""Packet tricks («Пакеты-обманки») on Windows: where they run and how the sing-box front gets them.

The Xray sidecar dials every VPN server through sing-box (`sockopt.dialerProxy` → the protect
inbound → `direct`), so the server socket belongs to sing-box and the tricks are route options
of that route, one rule per server:

* `fake` → sing-box `tls_spoof` over the WinDivert driver (owner decision 2026-11-16): a decoy
  ClientHello with another name and a wrong TCP sequence number, which the server drops; the
  decoy TTL of Android is not needed;
* `disorder` / `split` → `kvn_desync` (core patch `kvn-desync.patch`, the same engine as
  Android 0017): the first piece with TTL 1, or two segments;
* `oob` is not offered on Windows.

The emitter puts the plan on the masked Xray outbound copy under :data:`CARRY_KEY`; the planner
takes it off (:func:`take`) before the config reaches Xray, which never sees it.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Iterable

from .model import Desync

#: Key of the plan on a masked Xray outbound copy, removed by the planner.
CARRY_KEY = "__kvn_desync"

#: sing-box `tls_spoof_method`: a decoy with a wrong sequence number lies outside the server's
#: window and is dropped there, while in-path DPI reads it.
SPOOF_METHOD = "wrong-sequence"

#: Methods the Windows front runs.
WINDOWS_METHODS = ("fake", "disorder", "split")


def plan_json(desync: Desync) -> dict[str, Any]:
    """The plan in the shared snake_case form (same keys as Android `xray_masking.desync`)."""
    plan: dict[str, Any] = {"method": desync.method, "split_at": desync.split_at.strip().lower()}
    if desync.method == "fake":
        plan["fake_sni"] = desync.fake_sni.strip().lower()
    return plan


def route_options(plan: dict[str, Any]) -> dict[str, Any]:
    """sing-box route options that execute the plan; empty for a method Windows does not run."""
    method = plan.get("method")
    if method == "fake":
        return {"tls_spoof": str(plan.get("fake_sni") or ""), "tls_spoof_method": SPOOF_METHOD}
    if method in {"disorder", "split"}:
        return {"kvn_desync": f"{method}:{plan.get('split_at') or 'sni'}"}
    return {}


def server_hosts(outbound: dict[str, Any]) -> list[str]:
    """Addresses a native Xray outbound dials (VLESS `vnext`, other protocols `servers`)."""
    settings = outbound.get("settings") if isinstance(outbound.get("settings"), dict) else {}
    hosts: list[str] = []
    for key in ("vnext", "servers"):
        for server in settings.get(key) or ():
            host = str((server or {}).get("address") or "").strip().strip("[]").lower() if isinstance(server, dict) else ""
            if host and host not in hosts:
                hosts.append(host)
    return hosts


def take(outbound: dict[str, Any]) -> dict[str, Any] | None:
    """Remove and return the carried plan (Xray must never see it)."""
    plan = outbound.pop(CARRY_KEY, None)
    return plan if isinstance(plan, dict) else None


def route_rules(
    targets: Iterable[tuple[list[str], dict[str, Any]]],
    inbound_tag: str,
    known_addresses=None,
) -> list[dict[str, Any]]:
    """One `route-options` rule per server for the protect inbound.

    A host that is a name matches by `domain` and also by its already known addresses
    (`known_addresses(host)`), for a server outbound that resolves the name itself.
    """
    rules: list[dict[str, Any]] = []
    for hosts, plan in targets:
        options = route_options(plan)
        if not options or not hosts:
            continue
        domains: list[str] = []
        cidrs: list[str] = []
        for host in hosts:
            addresses: list[str] = []
            try:
                addresses = [str(ipaddress.ip_address(host))]
            except ValueError:
                domains.append(host)
                addresses = list(known_addresses(host) if known_addresses else ())
            for address in addresses:
                try:
                    parsed = ipaddress.ip_address(address)
                except ValueError:
                    continue
                cidr = f"{parsed}/{parsed.max_prefixlen}"
                if cidr not in cidrs:
                    cidrs.append(cidr)
        rule: dict[str, Any] = {"inbound": [inbound_tag]}
        if domains:
            rule["domain"] = domains
        if cidrs:
            rule["ip_cidr"] = cidrs
        rules.append({**rule, "action": "route-options", **options})
    return rules


def uses_windivert(config: dict[str, Any]) -> bool:
    """The sing-box config opens WinDivert: some route rule or TLS outbound asks for `tls_spoof`."""
    route = config.get("route") if isinstance(config.get("route"), dict) else {}
    for rule in route.get("rules") or ():
        if isinstance(rule, dict) and rule.get("tls_spoof"):
            return True
    for outbound in config.get("outbounds") or ():
        tls = outbound.get("tls") if isinstance(outbound, dict) else None
        if isinstance(tls, dict) and tls.get("spoof"):
            return True
    return False
