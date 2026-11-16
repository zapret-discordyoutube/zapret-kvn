"""Writes the service slots into the active sing-box JSON (owner decision 2026-11-16, docs/SERVICE_SLOTS.md).

The user ticks a service and the app writes the slot selector, its route rules and its DNS into the native JSON
itself, so the raw config stays the routing source of truth and the blocks are visible on the «Маршрутизация» pages.
Unticking removes exactly what the app wrote: every block is recognised by its `zapret-slot-` tag.

At rest a slot selector has only the member `proxy` (it follows the main server), so the file is valid on its own;
the runtime adds the server pool at launch, the same app-owned contract as the `proxy` replacement.

Pure functions on parsed JSON, no I/O.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable
from typing import Any

from .catalog import BUILT_IN, SlotSpec

SELECTOR_PREFIX = "zapret-slot-"
DNS_PREFIX = "zapret-slot-dns-"
PROXY_TAG = "proxy"


def selector_tag(slot_id: str) -> str:
    return f"{SELECTOR_PREFIX}{slot_id}"


def dns_tag(slot_id: str) -> str:
    return f"{DNS_PREFIX}{slot_id}"


def enabled_slots(config: dict[str, Any]) -> set[str]:
    """Slots whose selector is in the config: what the card shows as ticked."""
    known = {spec.id for spec in BUILT_IN}
    found = set()
    for outbound in config.get("outbounds") or []:
        tag = outbound.get("tag") if isinstance(outbound, dict) else None
        if isinstance(tag, str) and tag.startswith(SELECTOR_PREFIX) and not tag.startswith(DNS_PREFIX):
            slot_id = tag[len(SELECTOR_PREFIX):]
            if slot_id in known:
                found.add(slot_id)
    return found


def apply_slots(config: dict[str, Any], enabled: Iterable[str]) -> dict[str, Any]:
    """The config with exactly the [enabled] built-in slots written; the input is not changed.

    Idempotent: a slot that is already written keeps its blocks and their place (the user may have moved or edited
    them in the editor); only missing blocks are added.
    """
    wanted = [spec for spec in BUILT_IN if spec.id in set(enabled)]
    wanted_ids = {spec.id for spec in wanted}
    result = copy.deepcopy(config)
    _remove_unwanted(result, wanted_ids)
    if not wanted:
        return result
    outbounds = result.setdefault("outbounds", [])
    present = {o.get("tag") for o in outbounds if isinstance(o, dict)}
    for spec in wanted:
        if selector_tag(spec.id) not in present:
            outbounds.append(_selector(spec))
    route = result.setdefault("route", {})
    rules = route.setdefault("rules", [])
    missing = [spec for spec in wanted if not any(_routes_to(rule, selector_tag(spec.id)) for rule in rules)]
    if missing:
        at = _route_insert_index(rules)
        rules[at:at] = _route_rules(missing)
    _write_dns(result, wanted)
    return result


def _selector(spec: SlotSpec) -> dict[str, Any]:
    return {
        "type": "selector",
        "tag": selector_tag(spec.id),
        "outbounds": [PROXY_TAG],
        "default": PROXY_TAG,
        # Switching this slot's server cuts only this service's connections.
        "interrupt_exist_connections": True,
    }


def _route_rules(specs: list[SlotSpec]) -> list[dict[str, Any]]:
    # sing-box ANDs different match fields inside one rule, so apps, names and ranges are separate rules, in the
    # router's order (apps, then names, then ranges), as on Android (SlotRoutes.kt).
    rules: list[dict[str, Any]] = []
    for field, values in (("process_name", "process_names"), ("domain_suffix", "domain_suffixes"), ("ip_cidr", "ip_cidrs")):
        for spec in specs:
            items = getattr(spec, values)
            if items:
                rules.append({field: list(items), "action": "route", "outbound": selector_tag(spec.id)})
    return rules


def _route_insert_index(rules: list[Any]) -> int:
    """Before the first rule that sends traffic to the main server.

    The leading sniff, DNS hijack, rejects and the user's direct rules stay first; the always-proxy names, the
    blocked-sites rule set and the RU-direct rules come after, so a Russian address cannot take a slot's traffic out
    of the tunnel.
    """
    for index, rule in enumerate(rules):
        if _routes_to(rule, PROXY_TAG):
            return index
    for index, rule in enumerate(rules):
        if isinstance(rule, dict) and rule.get("action", "route") == "route" and rule.get("outbound") == "direct" and "rule_set" in rule:
            return index
    return len(rules)


def _routes_to(rule: Any, outbound: str) -> bool:
    return isinstance(rule, dict) and rule.get("action", "route") == "route" and rule.get("outbound") == outbound


def _node_dns(dns: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """The node DNS of the main server: plain servers with `detour: proxy`, and the fallback that races them."""
    servers = [s for s in dns.get("servers") or [] if isinstance(s, dict)]
    plain = [s for s in servers if s.get("detour") == PROXY_TAG and s.get("type") in ("udp", "tcp")]
    plain_tags = {s.get("tag") for s in plain}
    race = next(
        (s for s in servers if s.get("type") == "fallback" and plain_tags and set(s.get("servers") or []) <= plain_tags),
        None,
    )
    return plain, race


def _write_dns(config: dict[str, Any], specs: list[SlotSpec]) -> None:
    """A slot's names are resolved through the slot's own server (Android 0.6.2 lesson: a googlevideo address chosen
    by the main node can be unreachable from the slot's node). Only when the profile's DNS goes through the node; a
    profile with its own DNS is left alone."""
    dns = config.get("dns")
    if not isinstance(dns, dict):
        return
    plain, race = _node_dns(dns)
    if not plain:
        return
    servers = dns.setdefault("servers", [])
    present = {s.get("tag") for s in servers if isinstance(s, dict)}
    rules = dns.setdefault("rules", [])
    missing_rules: list[dict[str, Any]] = []
    for spec in specs:
        slot = dns_tag(spec.id)
        members = []
        for server in plain:
            copy_ = dict(server)
            copy_["tag"] = f"{slot}-{server.get('type')}"
            copy_["detour"] = selector_tag(spec.id)
            members.append(copy_["tag"])
            if copy_["tag"] not in present:
                servers.append(copy_)
        if slot not in present:
            servers.append({
                "type": "fallback",
                "tag": slot,
                "servers": members,
                "strategy": (race or {}).get("strategy", "parallel"),
                "timeout": (race or {}).get("timeout", "6s"),
            })
        if not any(isinstance(r, dict) and r.get("server") == slot for r in rules):
            missing_rules.extend(_dns_rules(spec, dns.get("strategy")))
    if missing_rules:
        node_tags = {s.get("tag") for s in plain} | ({race.get("tag")} if race else set())
        at = next((i for i, r in enumerate(rules) if isinstance(r, dict) and r.get("server") in node_tags), len(rules))
        rules[at:at] = missing_rules


def _dns_rules(spec: SlotSpec, strategy: Any) -> list[dict[str, Any]]:
    rules = []
    for field, items in (("process_name", spec.process_names), ("domain_suffix", spec.domain_suffixes)):
        if not items:
            continue
        rule: dict[str, Any] = {field: list(items), "action": "route", "server": dns_tag(spec.id)}
        # The slot's server can change: a cached answer of the previous node would bring the mismatch back.
        rule["disable_cache"] = True
        if strategy:
            rule["strategy"] = strategy
        rules.append(rule)
    return rules


def _remove_unwanted(config: dict[str, Any], wanted_ids: set[str]) -> None:
    keep_selectors = {selector_tag(i) for i in wanted_ids}
    keep_dns = {dns_tag(i) for i in wanted_ids}

    def app_selector(tag: Any) -> bool:
        return isinstance(tag, str) and tag.startswith(SELECTOR_PREFIX) and not tag.startswith(DNS_PREFIX)

    def app_dns(tag: Any) -> bool:
        return isinstance(tag, str) and tag.startswith(DNS_PREFIX)

    def dns_slot(tag: str) -> str:
        # zapret-slot-dns-youtube-udp -> zapret-slot-dns-youtube
        for keep in keep_dns:
            if tag == keep or tag.startswith(keep + "-"):
                return keep
        return tag

    if isinstance(config.get("outbounds"), list):
        config["outbounds"] = [
            o for o in config["outbounds"]
            if not (isinstance(o, dict) and app_selector(o.get("tag")) and o.get("tag") not in keep_selectors)
        ]
    route = config.get("route")
    if isinstance(route, dict) and isinstance(route.get("rules"), list):
        route["rules"] = [
            r for r in route["rules"]
            if not (isinstance(r, dict) and app_selector(r.get("outbound")) and r.get("outbound") not in keep_selectors)
        ]
    dns = config.get("dns")
    if isinstance(dns, dict):
        if isinstance(dns.get("servers"), list):
            dns["servers"] = [
                s for s in dns["servers"]
                if not (isinstance(s, dict) and app_dns(s.get("tag")) and dns_slot(s["tag"]) not in keep_dns)
            ]
        if isinstance(dns.get("rules"), list):
            dns["rules"] = [
                r for r in dns["rules"]
                if not (isinstance(r, dict) and app_dns(r.get("server")) and r.get("server") not in keep_dns)
            ]
