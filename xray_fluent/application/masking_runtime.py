"""Glue between a connect and the pure `xray_fluent.masking` package.

The planners and the stored nodes are never edited: a connect gets masked COPIES of the
selected node, of the pool nodes, or of the Xray pool outbounds (by node id), built from the
current settings. Turning masking off therefore needs no re-import.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from ..masking import codec
from ..masking import desync as desync_rules
from ..masking.apply import apply_server, log_line, shape_of
from ..masking.merge import effective
from ..masking.model import NONE, Core, Desync, MaskingOverride, MaskingSettings
from ..profiles.models import Node


@dataclass(frozen=True, slots=True)
class _Trial:
    node_id: str
    override: MaskingOverride
    title: str


# "Подбор" (MaskingTuneRunner): the one candidate the next connect runs with. In memory only, like
# Android `MaskingTrial`: a crash in the middle of a run leaves the stored masking as it was.
_trial: _Trial | None = None


def begin_trial(node_id: str, override: MaskingOverride, title: str) -> None:
    global _trial
    _trial = _Trial(node_id, override, title)


def end_trial() -> None:
    global _trial
    _trial = None


def trial_signature() -> dict[str, Any] | None:
    """Part of the transition signature while a trial runs, so each candidate really reconnects."""
    if _trial is None:
        return None
    return codec.encode(MaskingSettings(True, NONE, {_trial.node_id: _trial.override}))["overrides"]


def trial_log_line() -> str | None:
    return None if _trial is None else f"маскировка: подбор, вариант «{_trial.title}»"


def stored_settings_of(app_settings: Any) -> MaskingSettings:
    document = getattr(app_settings, "masking", None)
    return codec.decode(document) if isinstance(document, dict) and document else MaskingSettings()


def settings_of(app_settings: Any) -> MaskingSettings:
    """What a connect runs with: the stored settings, with the trial's server replaced."""
    stored = stored_settings_of(app_settings)
    trial = _trial
    return stored if trial is None else stored.with_trial(trial.node_id, trial.override)


def masked_node(node: Node | None, settings: MaskingSettings, notes: list[str] | None = None) -> Node | None:
    if node is None or not settings.enabled or not isinstance(node.outbound, dict) or not node.outbound:
        return node
    outbound, node_notes = apply_server(node.outbound, settings, node.id)
    if notes is not None:
        notes.extend(node_notes)
    return node if outbound is node.outbound else replace(node, outbound=outbound)


def masked_nodes(nodes: list[Node], settings: MaskingSettings) -> list[Node]:
    if not settings.enabled:
        return nodes
    return [masked_node(node, settings) or node for node in nodes]


def mask_pool_outbounds(
    outbounds: list[dict[str, Any]], tags_by_node: dict[str, str], settings: MaskingSettings,
) -> tuple[list[dict[str, Any]], int, list[str]]:
    """Masked copies of Xray pool outbounds; `tags_by_node` is the pool's node id -> tag map."""
    if not settings.enabled:
        return outbounds, 0, []
    node_by_tag = {tag: node_id for node_id, tag in tags_by_node.items()}
    result: list[dict[str, Any]] = []
    changed = 0
    notes: list[str] = []
    for outbound in outbounds:
        masked, outbound_notes = apply_server(outbound, settings, node_by_tag.get(str(outbound.get("tag") or "")))
        changed += masked is not outbound
        notes.extend(outbound_notes)
        result.append(masked)
    return result, changed, notes


#: Note of the connect log when the plan cannot run: a raw Xray config has no sing-box front.
DESYNC_WITHOUT_FRONT = "Пакеты-обманки не применены: свой конфиг Xray запускается без sing-box."


def carries_desync(node: Node | None) -> bool:
    outbound = getattr(node, "outbound", None)
    return isinstance(outbound, dict) and desync_rules.CARRY_KEY in outbound


def strip_desync(outbounds: list[Any]) -> int:
    """Remove carried packet-trick plans from outbounds that go to Xray as they are."""
    return sum(desync_rules.take(outbound) is not None for outbound in outbounds if isinstance(outbound, dict))


def desync_of(node: Node | None, settings: MaskingSettings) -> Desync | None:
    """The packet tricks a connect runs on this node's server socket, or None."""
    if node is None or not settings.enabled or not isinstance(node.outbound, dict):
        return None
    shape = shape_of(node.outbound)
    if shape is None or shape.core is not Core.XRAY or not shape.is_tcp_stream:
        return None
    xray = effective(settings, node.id, shape).masking.xray
    if xray is None or not xray.enabled or xray.desync is None or not xray.desync.enabled:
        return None
    return xray.desync if xray.desync.method in desync_rules.WINDOWS_METHODS else None


def describe(settings: MaskingSettings, changed: int, notes: list[str]) -> str | None:
    return log_line(settings.enabled, changed, notes)
