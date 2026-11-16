"""Which server each ticked slot uses (pure, as Android's SlotPlanner, docs/SERVICE_SLOTS.md "Phase 3 plan").

Order of choice for a slot: the user's pin while that server exists and has not just failed for the slot; otherwise
the best server of the pool that the main server and the slots before it do not use (owner 2026-11-14: separate
servers per service while the pool allows); otherwise the main server (the slot follows `proxy`).
"Best" = measured alive first, then the faster speed test, then the lower ping; AWG servers are skipped (no slot helper
for them yet).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from ..application.protocol_core import ProtocolCore, protocol_core
from ..profiles.models import Node


@dataclass(frozen=True, slots=True)
class SlotAssignment:
    slot_id: str
    node: Node | None
    pinned: bool = False
    reason: str = ""


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
) -> list[SlotAssignment]:
    nodes = [n for n in pool if protocol_core(n) is not ProtocolCore.AMNEZIA]
    by_id = {n.id: n for n in nodes}
    failed = failed or {}
    used = {main_node_id} if main_node_id else set()
    slot_ids = list(slot_ids)
    # Pins are reserved first: a slot on «Авто» earlier in the order must not take another slot's pinned server.
    for slot_id in slot_ids:
        pin = pins.get(slot_id)
        if pin and pin in by_id and pin not in failed.get(slot_id, set()):
            used.add(pin)
    result: list[SlotAssignment] = []
    for slot_id in slot_ids:
        bad = failed.get(slot_id, set())
        pin = pins.get(slot_id)
        if pin and pin in by_id and pin not in bad:
            result.append(SlotAssignment(slot_id, by_id[pin], pinned=True))
            used.add(pin)
            continue
        reason = ""
        if pin and pin not in by_id:
            reason = "закреплённого сервера нет в списке"
        elif pin:
            reason = "закреплённый сервер не отвечал"
        free = [n for n in nodes if n.id not in used and n.id not in bad and n.is_alive is not False]
        if free:
            choice = min(free, key=_rank)
            used.add(choice.id)
            result.append(SlotAssignment(slot_id, choice, reason=reason))
        else:
            result.append(SlotAssignment(slot_id, None, reason=reason or "свободного сервера нет, как у основного"))
    return result
