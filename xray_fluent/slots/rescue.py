"""YouTube slot rescue on Windows (pure; docs/SERVICE_SLOTS.md, phase 4).

With the YouTube slot ticked, a dead YouTube cache cluster moves the YouTube SLOT, not the main server (Android:
YoutubeSlotSwitchHost): the cluster is picked by the address the request leaves from, so another server gets another
cluster, and every other app stays where it is. The server the video died on is remembered for the slot; the move goes
to the best free server that can be reached without restarting sing-box; one move per cooldown, so a cluster that is
dead everywhere does not walk the whole list.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from ..profiles.models import Node
from .assigner import assign_slots
from .catalog import YOUTUBE

COOLDOWN_SEC = 90.0


@dataclass(frozen=True, slots=True)
class RescueDecision:
    move: bool
    node: Node | None = None
    reason: str = ""


def youtube_rescue(
    *,
    current_id: str | None,
    nodes: Iterable[Node],
    main_node_id: str | None,
    other_slots: Mapping[str, str],
    failed: Mapping[str, set[str]],
    reachable: Callable[[Node], bool],
    now: float,
    last_move_at: float | None,
) -> RescueDecision:
    if last_move_at is not None and now - last_move_at < COOLDOWN_SEC:
        return RescueDecision(False, reason="слот YouTube недавно менял сервер")
    bad = set(failed.get(YOUTUBE, set()))
    if current_id:
        bad.add(current_id)
    taken = set(other_slots.values())
    pool = [n for n in nodes if n.id not in taken and reachable(n)]
    [choice] = assign_slots([YOUTUBE], pool, main_node_id=main_node_id, pins={}, failed={YOUTUBE: bad})
    if choice.node is None:
        if current_id and current_id != main_node_id:
            # No free server of its own: the slot goes back to following the main server.
            return RescueDecision(True, None, reason="свободного сервера нет, слот YouTube идёт через основной")
        return RescueDecision(False, reason="свободного сервера для YouTube нет")
    return RescueDecision(True, choice.node)
