from __future__ import annotations

from typing import TYPE_CHECKING

from ..network.country_resolver import CountryResolver
from ..profiles.geoip import endpoint_hosts, normalize_country
from ..importer.link_parser import is_native_singbox_outbound, repair_node_outbound_from_link, validate_node_outbound

if TYPE_CHECKING:
    from .controller import AppController
    from ..profiles.models import Node


def detect_countries_sync(controller: AppController) -> None:
    # Old persisted guesses are discarded by Node.from_dict. No I/O here.
    for node in controller.state.nodes:
        if node.country_override:
            node.country_code = normalize_country(node.country_override)


def remember_country_addresses(controller, node, addresses) -> None:
    """Passively consume an existing runtime resolution; never initiate one."""
    if node is None:
        return
    known = getattr(controller, "_country_known_addresses", {})
    known[node.id] = (endpoint_hosts(node), tuple(addresses))
    controller._country_generation = getattr(controller, "_country_generation", 0) + 1
    controller._country_known_addresses = known
    start_country_ip_resolution(controller)


def start_country_ip_resolution(controller: AppController) -> None:
    if getattr(controller, "_country_shutdown", False):
        return
    worker = getattr(controller, "_country_resolver", None)
    if worker is not None and worker.isRunning():
        controller._country_refresh_pending = True
        return
    known = getattr(controller, "_country_known_addresses", {})
    needs = []
    for node in controller.state.nodes:
        if node.country_override:
            node.country_code = normalize_country(node.country_override)
            continue
        fingerprint = endpoint_hosts(node)
        cached = known.get(node.id)
        addresses = cached[1] if cached and cached[0] == fingerprint else fingerprint
        needs.append((node.id, fingerprint, addresses))
    if not needs:
        return
    worker = CountryResolver(needs, parent=controller)
    controller._country_resolver = worker
    generation = getattr(controller, "_country_generation", 0)
    worker.resolved.connect(lambda results: controller._on_countries_resolved(results) if generation == getattr(controller, "_country_generation", 0) and not getattr(controller, "_country_shutdown", False) else None)
    def finished():
        if controller._country_resolver is worker:
            controller._country_resolver = None
        worker.deleteLater()
        if getattr(controller, "_country_refresh_pending", False):
            controller._country_refresh_pending = False
            start_country_ip_resolution(controller)
    worker.finished.connect(finished)
    worker.start()


def on_countries_resolved(controller: AppController, results: dict) -> None:
    if getattr(controller, "_country_shutdown", False):
        return
    changed = False
    for node in controller.state.nodes:
        result = results.get(node.id)
        if result is None or node.country_override or result[0] != endpoint_hosts(node):
            continue
        code = result[1]
        if node.country_code != code:
            node.country_code = code
            changed = True
    if changed:
        controller.nodes_changed.emit(controller.state.nodes)


def get_node_by_id(controller: AppController, node_id: str | None) -> Node | None:
    if not node_id:
        return None
    nodes = controller.state.nodes
    source_id = id(nodes)
    if controller._node_lookup_source_id != source_id or controller._node_lookup_size != len(nodes):
        controller._node_by_id = {node.id: node for node in nodes}
        controller._node_lookup_source_id = source_id
        controller._node_lookup_size = len(nodes)
    return controller._node_by_id.get(node_id)


def prepare_node_for_runtime(controller: AppController, node: Node | None) -> str | None:
    if node is None:
        return None
    if repair_node_outbound_from_link(node):
        controller.schedule_save()
    problem = validate_node_outbound(node)
    if problem:
        return problem
    if is_native_singbox_outbound(node) and not controller.is_singbox_editor_mode():
        protocol = str(node.outbound.get("type") or node.scheme or "native").upper()
        return (
            f"Протокол {protocol} использует native sing-box outbound и поддерживается только "
            "ядром sing-box. Выберите Настройки → Движок прокси → sing-box extended "
            "или TUN с ядром sing-box."
        )
    return None


def get_fastest_alive_node(controller: AppController) -> Node | None:
    alive_nodes = [node for node in controller.state.nodes if node.is_alive is True]
    if not alive_nodes:
        alive_nodes = [node for node in controller.state.nodes if node.ping_ms is not None]
    if not alive_nodes:
        return controller.selected_node
    with_speed = [node for node in alive_nodes if node.speed_mbps is not None and node.speed_mbps > 0]
    if with_speed:
        return max(with_speed, key=lambda node: node.speed_mbps)
    return min(alive_nodes, key=lambda node: node.ping_ms if node.ping_ms is not None else float("inf"))
