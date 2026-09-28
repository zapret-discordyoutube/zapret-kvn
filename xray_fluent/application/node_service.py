from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from PyQt6.QtCore import QTimer

from ..diagnostics.runtime_logging import node_ref
from ..profiles.geoip import normalize_country
from ..importer.link_parser import parse_links_text, validate_node_outbound
from .selection_source import SelectionSource
from .smart_switch_service import note_manual_selection

if TYPE_CHECKING:
    from .controller import AppController


@dataclass(frozen=True)
class SelectionSnapshot:
    """Выбранный сервер до изменения: удалённый сервер уже не найти по id."""

    node_id: str | None
    name: str

    def describe(self) -> str:
        if not self.node_id:
            return "нет"
        return f"«{self.name}» node_ref={node_ref(self.node_id)}"


def selection_snapshot(controller: AppController, node_id: str | None = None) -> SelectionSnapshot:
    """Снимок сервера ``node_id`` (по умолчанию — выбранного) до изменения списка."""

    if node_id is None:
        node_id = controller.state.selected_node_id
    node = next((item for item in controller.state.nodes if item.id == node_id), None) if node_id else None
    return SelectionSnapshot(node_id or None, node.name if node is not None else "?")


def log_selection_change(
    controller: AppController,
    source: SelectionSource,
    before: SelectionSnapshot,
    new_id: str | None,
) -> None:
    """Единая строка лога о смене выбранного сервера (см. ``selection_source``).

    ``node_ref`` — та же метка, что в ``[runtime-map]`` и строках ядер, поэтому
    смену можно сопоставить с логами ядер; сам id в логе скрывается.
    """

    if before.node_id == (new_id or None):
        return
    after = selection_snapshot(controller, new_id) if new_id else SelectionSnapshot(None, "")
    controller._log(
        f"[select] source={source.code} ({source.label}): {before.describe()} → {after.describe()}"
    )


def import_nodes_from_text(controller: AppController, text: str) -> tuple[int, list[str]]:
    nodes, errors = parse_links_text(text)
    if not nodes:
        return 0, errors

    existing_links = {node.link for node in controller.state.nodes if node.link}
    max_order = max((node.sort_order for node in controller.state.nodes), default=0)
    first_new_id: str | None = None
    added = 0
    for node in nodes:
        problem = validate_node_outbound(node)
        if problem:
            errors.append(problem)
            continue
        if node.link and node.link in existing_links:
            continue
        max_order += 1
        node.sort_order = max_order
        controller.state.nodes.append(node)
        if node.link:
            existing_links.add(node.link)
        if first_new_id is None:
            first_new_id = node.id
        added += 1

    selected_before = selection_snapshot(controller)
    if first_new_id:
        controller.state.selected_node_id = first_new_id
    elif not controller.state.selected_node_id and controller.state.nodes:
        controller.state.selected_node_id = controller.state.nodes[0].id
    log_selection_change(
        controller, SelectionSource.NODES_IMPORTED, selected_before, controller.state.selected_node_id
    )

    controller.nodes_changed.emit(controller.state.nodes)
    controller.selection_changed.emit(controller.selected_node)
    controller.save()
    QTimer.singleShot(500, controller._start_country_ip_resolution)

    if added:
        controller._desired_connected = True
        controller._request_transition("new node imported")

    return added, errors


def remove_nodes(controller: AppController, node_ids: set[str]) -> None:
    if not node_ids:
        return
    removed_selected = controller.state.selected_node_id in node_ids
    selected_before = selection_snapshot(controller)
    should_reconcile = removed_selected and (controller.connected or controller._desired_connected)
    controller.state.nodes = [node for node in controller.state.nodes if node.id not in node_ids]
    if removed_selected:
        controller.state.selected_node_id = controller.state.nodes[0].id if controller.state.nodes else None
        log_selection_change(
            controller, SelectionSource.NODE_REMOVED, selected_before, controller.state.selected_node_id
        )
        controller._reset_auto_switch_state(reset_cooldown=True, reset_cycle=True)
    controller.nodes_changed.emit(controller.state.nodes)
    controller.selection_changed.emit(controller.selected_node)
    controller.save()
    if not should_reconcile:
        return
    if controller.state.selected_node_id is None:
        if controller._can_connect_without_selected_node():
            controller._request_transition("active node removed")
            return
        controller._desired_connected = False
        controller._request_transition("active node removed")
        return
    controller._desired_connected = True
    controller._request_transition("active node removed")


def update_node(controller: AppController, node_id: str, updates: dict) -> bool:
    node = controller._get_node_by_id(node_id)
    if not node:
        return False
    if "is_favorite" in updates:
        node.is_favorite = bool(updates["is_favorite"])
    if "country_override" in updates:
        node.country_override = normalize_country(updates["country_override"])
        node.country_code = node.country_override
        controller._start_country_ip_resolution()
    if "name" in updates:
        node.name = updates["name"]
    if "group" in updates:
        node.group = updates["group"]
    if "tags" in updates:
        node.tags = list(updates["tags"])
    controller.nodes_changed.emit(controller.state.nodes)
    controller.save()
    return True


def bulk_update_nodes(controller: AppController, node_ids: set[str], operations: dict) -> int:
    group = operations.get("group", "")
    add_tags = operations.get("add_tags", [])
    remove_tags = set(operations.get("remove_tags", []))
    updated = 0
    for node in controller.state.nodes:
        if node.id not in node_ids:
            continue
        if group:
            node.group = group
        if add_tags:
            existing = set(node.tags)
            for tag in add_tags:
                if tag not in existing:
                    node.tags.append(tag)
        if remove_tags:
            node.tags = [tag for tag in node.tags if tag not in remove_tags]
        updated += 1
    if updated:
        controller.nodes_changed.emit(controller.state.nodes)
        controller.save()
    return updated


def get_all_groups(controller: AppController) -> list[str]:
    return sorted({node.group for node in controller.state.nodes if node.group})


def get_all_tags(controller: AppController) -> list[str]:
    tags: set[str] = set()
    for node in controller.state.nodes:
        tags.update(node.tags)
    return sorted(tags)


def reorder_nodes(controller: AppController, node_id: str, direction: str) -> None:
    ordered = sorted(controller.state.nodes, key=lambda node: node.sort_order)
    idx = next((i for i, node in enumerate(ordered) if node.id == node_id), None)
    if idx is None:
        return
    if direction == "up" and idx > 0:
        ordered[idx], ordered[idx - 1] = ordered[idx - 1], ordered[idx]
    elif direction == "down" and idx < len(ordered) - 1:
        ordered[idx], ordered[idx + 1] = ordered[idx + 1], ordered[idx]
    elif direction == "top" and idx > 0:
        node = ordered.pop(idx)
        ordered.insert(0, node)
    elif direction == "bottom" and idx < len(ordered) - 1:
        node = ordered.pop(idx)
        ordered.append(node)
    else:
        return
    for index, node in enumerate(ordered):
        node.sort_order = index + 1
    controller.nodes_changed.emit(controller.state.nodes)
    controller.save()


def set_selected_node(controller: AppController, node_id: str, *, source: SelectionSource) -> None:
    """Единственный путь смены сервера по команде (пользователь или автоматика).

    ``source`` обязателен: каждая смена пишет ``[select] source=…``, а ручной
    источник (``source.manual``) сбрасывает учёт авто-переключения.
    """
    from .protocol_core import ProtocolCore, protocol_core
    target = next((node for node in controller.state.nodes if node.id == node_id), None)
    session = getattr(controller, "_active_session", None)
    # Re-selecting the current or already requested row is idempotent.
    pending = getattr(controller, "_pending_transport_node_id", None)
    current_id = pending or controller.state.selected_node_id
    if node_id == current_id:
        return
    # До ветвления: и Amnezia-путь (через pending), и обычный пишут источник.
    # Пишется и без подключения — сохранённый выбор определяет следующий запуск.
    log_selection_change(controller, source, selection_snapshot(controller, current_id), node_id)
    manual = source.manual
    if controller.connected and target is not None and (
        protocol_core(target) is ProtocolCore.AMNEZIA or
        (session is not None and session.sidecar_kind == "amnezia")
    ):
        controller._pending_transport_node_id = node_id
        if manual:
            controller._reset_auto_switch_state(reset_cooldown=True, reset_cycle=True)
            controller._auto_switch_manual_hold = True
            note_manual_selection(controller)
        controller._desired_connected = True
        controller._request_transition("transport node switched")
        return
    if controller.state.selected_node_id == node_id:
        return
    controller.state.selected_node_id = node_id
    if manual:
        # Ручной выбор сбрасывает cooldown/cycle авто-переключения; автоматика
        # (source.manual=False) свой учёт анти-дребезга не обнуляет (П4/A6).
        # Заодно ручной выбор
        # фиксирует сервер до явного повторного включения авто-переключения
        # (для переключения при отказе); умное переключение при низкой
        # скорости держит ручной выбор SMART_SWITCH_MANUAL_HOLD_SEC.
        controller._reset_auto_switch_state(reset_cooldown=True, reset_cycle=True)
        controller._auto_switch_manual_hold = True
        note_manual_selection(controller)
    controller.selection_changed.emit(controller.selected_node)
    controller.schedule_save()
    if controller.connected or controller._desired_connected:
        controller._desired_connected = True
        if controller.connected and controller._try_hot_switch_selected_node():
            return
        controller._request_transition("node switched")
