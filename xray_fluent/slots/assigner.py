"""Which server each ticked slot uses (pure, as Android's SlotPlanner, docs/SERVICE_SLOTS.md "Phase 3 plan").

Order of choice for a slot: the user's pin while that server exists and has not just failed for the slot; otherwise
the best server of the pool that the main server and the slots before it do not use (owner 2026-11-14: separate
servers per service while the pool allows); otherwise the main server (the slot follows `proxy`).
"Best" = measured alive first, then the faster speed test, then the lower ping; AWG servers are skipped (no slot helper
for them yet).

A "server" here is the machine, not the list entry: one provider machine often comes as several entries (VLESS gRPC,
VLESS WS, Hysteria2 ... with their own host names, 2026-11-16 e2e on vpnbot nodes: five entries, one address). Entries
whose host keys meet (`host_keys`: the resolved addresses plus the host name) count as one server, so a slot never sits
on the main server's machine or another slot's machine through a sibling entry. A pin is still honoured as it is.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from ..application.protocol_core import ProtocolCore, protocol_core
from ..profiles.models import Node


@dataclass(frozen=True, slots=True)
class SlotAssignment:
    slot_id: str
    node: Node | None
    pinned: bool = False
    reason: str = ""


def slot_capable(node: Node) -> bool:
    """Whether a server can carry a slot: AWG has no slot helper yet. The card lists only these servers."""
    return protocol_core(node) is not ProtocolCore.AMNEZIA


def default_host_keys(node: Node) -> frozenset[str]:
    """The host name only (no DNS): an entry without a server is its own machine."""
    host = str(node.server or "").strip().lower().strip("[]")
    return frozenset({host}) if host else frozenset({f"id:{node.id}"})


def off_machines(
    candidates: Iterable[Node],
    nodes: Iterable[Node],
    node_ids: Iterable[str | None],
    host_keys: Callable[[Node], frozenset[str]] = default_host_keys,
) -> list[Node]:
    """`candidates` without the entries on the machines of `node_ids` (looked up in the full list `nodes`)."""
    wanted = {i for i in node_ids if i}
    blocked: set[str] = set()
    for n in nodes:
        if n.id in wanted:
            blocked |= host_keys(n)
    return [n for n in candidates if n.id in wanted or not (host_keys(n) & blocked)]


def _rank(node: Node) -> tuple:
    alive = 0 if node.is_alive is True else (2 if node.is_alive is False else 1)
    speed = -(node.speed_mbps or 0.0)
    ping = node.ping_ms if node.ping_ms is not None and node.ping_ms > 0 else 1_000_000
    return (alive, speed, ping, node.sort_order, node.id)


def assign_slots(
    slot_ids: Iterable[str],
    pool: Iterable[Node],
    *,
    main_node_id: str | None,
    pins: Mapping[str, str],
    failed: Mapping[str, set[str]] | None = None,
    host_keys: Callable[[Node], frozenset[str]] = default_host_keys,
) -> list[SlotAssignment]:
    pool = list(pool)
    keys = {n.id: host_keys(n) for n in pool}
    taken_hosts: set[str] = set()

    def take(node_id: str | None) -> None:
        if node_id:
            used.add(node_id)
            taken_hosts.update(keys.get(node_id, ()))

    nodes = [n for n in pool if slot_capable(n)]
    awg = {n.id for n in pool if not slot_capable(n)}
    by_id = {n.id: n for n in nodes}
    failed = failed or {}
    used: set[str] = set()
    take(main_node_id)
    slot_ids = list(slot_ids)
    # Pins are reserved first: a slot on «Авто» earlier in the order must not take another slot's pinned server.
    for slot_id in slot_ids:
        pin = pins.get(slot_id)
        if pin and pin in by_id and pin not in failed.get(slot_id, set()):
            take(pin)
    result: list[SlotAssignment] = []
    for slot_id in slot_ids:
        bad = failed.get(slot_id, set())
        pin = pins.get(slot_id)
        if pin and pin in by_id and pin not in bad:
            result.append(SlotAssignment(slot_id, by_id[pin], pinned=True))
            continue
        reason = ""
        if pin and pin in awg:
            reason = "серверы AmneziaWG для сервисов пока не поддерживаются"
        elif pin and pin not in by_id:
            reason = "закреплённого сервера нет в списке"
        elif pin:
            reason = "закреплённый сервер не отвечал"
        free = [
            n for n in nodes
            if n.id not in used and n.id not in bad and n.is_alive is not False and not (keys[n.id] & taken_hosts)
        ]
        if free:
            choice = min(free, key=_rank)
            take(choice.id)
            result.append(SlotAssignment(slot_id, choice, reason=reason))
        else:
            result.append(SlotAssignment(slot_id, None, reason=reason or "свободного сервера нет, как у основного"))
    return result
