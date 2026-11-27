"""«Мимо TUN»: addresses that never enter the TUN adapter, written into the user's own sing-box JSON.

Owner request 2026-11-27: "configure games to go directly or not even through the tun adapter". A rule can send a program
«Напрямую», but its packets still pass the adapter. What keeps an address out of the adapter is the native field
``route_exclude_address`` of the TUN inbound (sing-box ``auto_route``): Windows then sends those prefixes through the physical
network card by an ordinary route. There is no per-program form of it on Windows TUN, so the unit is an ADDRESS.

Nothing here is hidden policy: the field lives in the TUN inbound of the active JSON, the routing editor shows and edits it
(«Кроме этих адресов»), and this module only reads and writes that list. Pure functions, no Qt, no state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
from typing import Iterable, NamedTuple

from .simple_rule import process_pattern

FIELD = "route_exclude_address"

#: A prefix shorter than this would take a large part of the internet out of the VPN by accident (``0.0.0.0/0`` is "no VPN").
MIN_PREFIX_V4 = 8
MIN_PREFIX_V6 = 16

_SPLIT = re.compile(r"[\s,;]+")
_DOMAIN_LIKE = re.compile(r"[A-Za-z]")


@dataclass(slots=True)
class ParsedAddresses:
    cidrs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def tun_inbounds(document: dict) -> list[dict]:
    items = document.get("inbounds") if isinstance(document, dict) else None
    return [item for item in items or [] if isinstance(item, dict) and item.get("type") == "tun"]


def is_excludable(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str | None:
    """None when the prefix may leave the TUN, otherwise why not (shown to the user)."""
    if network.is_loopback or network.is_link_local or network.is_multicast or network.is_unspecified:
        return "служебный адрес: он и так не идёт через TUN"
    if network.is_private:
        return "локальная сеть: она и так не идёт через TUN"
    floor = MIN_PREFIX_V4 if network.version == 4 else MIN_PREFIX_V6
    if network.prefixlen < floor:
        return f"подсеть шире /{floor}: так из VPN уйдёт слишком много адресов"
    return None


def parse_addresses(text: str) -> ParsedAddresses:
    """IP addresses and subnets, separated by lines, commas or spaces: ``203.0.113.7``, ``24.105.0.0/18``, ``2001:db8::/32``."""
    result = ParsedAddresses()
    seen: set[str] = set()
    lines = (line.split("#", 1)[0] for line in str(text or "").splitlines())  # a comment runs to the end of its line
    for token in (item for line in lines for item in _SPLIT.split(line) if item):
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            if _DOMAIN_LIKE.search(token) and "." in token and ":" not in token:
                result.errors.append(f"«{token}»: нужен IP-адрес, а не имя сайта (в TUN нельзя исключить домен)")
            else:
                result.errors.append(f"«{token}»: не похоже на IP-адрес или подсеть")
            continue
        reason = is_excludable(network)
        if reason:
            result.errors.append(f"«{token}»: {reason}")
            continue
        text_form = str(network)
        if text_form not in seen:
            seen.add(text_form)
            result.cidrs.append(text_form)
    result.cidrs = collapse(result.cidrs)
    return result


def collapse(cidrs: Iterable[str]) -> list[str]:
    """Drops duplicates and entries that a broader entry already covers; keeps IPv4 before IPv6, each sorted."""
    v4: list[ipaddress.IPv4Network] = []
    v6: list[ipaddress.IPv6Network] = []
    for item in cidrs:
        try:
            network = ipaddress.ip_network(str(item).strip(), strict=False)
        except ValueError:
            continue
        (v4 if network.version == 4 else v6).append(network)  # type: ignore[arg-type]
    merged = list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))
    return [str(network) for network in merged]


def widen_to_subnet(addresses: Iterable[str]) -> list[str]:
    """Single IPv4 addresses to their /24 (IPv6 to /64): game servers of one realm usually sit side by side."""
    widened: list[str] = []
    for item in addresses:
        try:
            network = ipaddress.ip_network(str(item).strip(), strict=False)
        except ValueError:
            continue
        if network.prefixlen == network.max_prefixlen:
            prefix = 24 if network.version == 4 else 64
            network = ipaddress.ip_network(f"{network.network_address}/{prefix}", strict=False)
        widened.append(str(network))
    return collapse(widened)


def current(document: dict) -> list[str]:
    """What the TUN inbound already keeps out of the adapter."""
    found: list[str] = []
    for inbound in tun_inbounds(document):
        value = inbound.get(FIELD)
        if isinstance(value, str):
            value = [value]
        found.extend(str(item) for item in value or [] if isinstance(item, str))
    return collapse(found)


def _target_inbound(document: dict) -> dict | None:
    inbounds = tun_inbounds(document)
    return next((item for item in inbounds if item.get("tag") == "tun-in"), inbounds[0] if inbounds else None)


def add_to_document(document: dict, cidrs: Iterable[str]) -> list[str]:
    """Adds the prefixes to the TUN inbound; returns the ones that were new. Raises LookupError when there is no TUN inbound."""
    inbound = _target_inbound(document)
    if inbound is None:
        raise LookupError("В конфиге нет входа TUN: добавьте его в «Система → Входящие» или выберите шаблон с TUN")
    existing = inbound.get(FIELD)
    if isinstance(existing, str):
        existing = [existing]
    before = collapse(existing or [])
    merged = collapse([*before, *cidrs])
    added = [item for item in merged if item not in before]
    # keep what the user wrote verbatim when nothing new came: no rewriting of their list for a no-op
    if added or not isinstance(inbound.get(FIELD), list):
        inbound[FIELD] = merged
    return added


def remove_from_document(document: dict, cidrs: Iterable[str] | None = None) -> list[str]:
    """Removes the given prefixes (all of them when ``cidrs`` is None) from every TUN inbound; drops an emptied field."""
    wanted = None if cidrs is None else set(collapse(cidrs))
    removed: list[str] = []
    for inbound in tun_inbounds(document):
        value = inbound.get(FIELD)
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            continue
        kept: list[str] = []
        for item in value:
            if wanted is None or str(item) in wanted:
                removed.append(str(item))
            else:
                kept.append(item)
        if kept:
            inbound[FIELD] = kept
        else:
            inbound.pop(FIELD, None)
    return removed


class Connection(NamedTuple):
    """One established connection of a running program: the program's image path and the remote address."""

    path: str
    remote: str


def remote_addresses_of_programs(connections: Iterable[Connection], entries: Iterable[str]) -> list[str]:
    """The public remote addresses the listed programs are connected to right now (as /32 and /128, sorted).

    An entry is whatever the programs list of a rule accepts: a program name, a full path, or a folder (trailing slash). It is
    matched with the very regular expression the routing rule would use, so the helper and the rule never disagree.
    """
    patterns = []
    for entry in entries:
        entry = str(entry).strip()
        if entry and not entry.startswith("#"):
            patterns.append(re.compile(process_pattern(entry)))
    found: dict[str, ipaddress.IPv4Network | ipaddress.IPv6Network] = {}
    for path, remote in connections:
        if not any(pattern.search(path) for pattern in patterns):
            continue
        try:
            network = ipaddress.ip_network(remote)
        except ValueError:
            continue
        if is_excludable(network) is None:
            found[str(network)] = network
    return collapse(found)


def _plural(count: int) -> str:
    tail = count % 100 >= 11 and count % 100 <= 19 or count % 10 == 0 or count % 10 >= 5
    return "адресов" if tail else ("адрес" if count % 10 == 1 else "адреса")


def summary(cidrs: list[str]) -> str:
    if not cidrs:
        return "адресов нет"
    tail = "…" if len(cidrs) > 3 else ""
    return f"{len(cidrs)} {_plural(len(cidrs))}: " + ", ".join(cidrs[:3]) + tail
