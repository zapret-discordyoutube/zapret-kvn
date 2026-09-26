from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..constants import DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT, HYSTERIA_PATH_DEFAULT
from ..engines.singbox import classify_node_for_singbox
from ..importer.link_parser import hysteria2_uri_fingerprint

if TYPE_CHECKING:
    from .controller import AppController
    from ..profiles.models import AppSettings, Node, RoutingSettings


@dataclass(frozen=True, slots=True)
class SingboxPlanFacts:
    """The plan fields a signature/preflight needs (never the ports)."""

    selector_tags: dict[str, str]
    provider_payload: object
    used_selected_node: bool


def signature(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def node_identity(
    controller: AppController,
    node: Node | None,
    settings: AppSettings | None = None,
) -> object:
    """Что именно в конфиге зависит от выбора сервера.

    Ротация ничего сюда не добавляет: она переключает сервер штатным путём, а тот
    сначала пробует горячий свитч по тегу пула и лишь при неудаче просит переход —
    и вот тогда `selected` обязан быть частью сигнатуры, иначе переход сочтёт, что
    менять нечего, и смена сервера потеряется.
    """

    pool_factory = getattr(controller, "xray_outbound_pool", None)
    if callable(pool_factory):
        pool = pool_factory()
        if node is not None and pool.contains(node.id):
            return {"outbound_pool": pool.signature_payload(), "selected": node.id}
    return node.id if node else None


def routing_signature(controller: AppController, routing: RoutingSettings | None = None) -> str:
    routing = routing or controller.state.routing
    return signature(routing.to_dict())


def system_proxy_bypass_lan(controller: AppController, settings: AppSettings | None = None) -> bool:
    settings = settings or controller.state.settings
    return bool(settings.system_proxy_bypass_lan)


def _singbox_runtime_signature_payload(
    controller: AppController,
    node: Node | None,
    settings: AppSettings,
) -> dict[str, object]:
    source_path, config_hash, has_proxy_outbound = controller._inspect_active_singbox_config()
    planner_outcome = "native_singbox"
    if has_proxy_outbound and node is not None:
        planner_outcome = classify_node_for_singbox(node)
    selector_pool: object | None = None
    if has_proxy_outbound and node is not None and planner_outcome == "hybrid_xray_sidecar":
        # Initial capture and all later comparisons must describe the same
        # runtime.  Previously the pool appeared in the signature only after
        # _active_session existed, so a successful connect immediately looked
        # stale and scheduled another full proxy-hot-swap.
        pool = controller.xray_outbound_pool()
        selector_pool = {"xray_sidecar": pool.signature_payload()}
    if has_proxy_outbound and node is not None and planner_outcome == "native_singbox":
        tun = bool(controller.is_singbox_tun_mode(settings))
        facts_getter = getattr(controller, "_singbox_plan_facts", None)
        if callable(facts_getter):
            # Полный план (сборка outbound'ов всего пула, пробы портов) нужен
            # сигнатуре только ради тегов селектора и провайдера — они
            # кэшируются по документу, ноде и составу пула.
            facts = facts_getter(node, tun=tun)
        else:
            try:
                plan = (
                    controller._plan_runtime_singbox(node)
                    if tun
                    else controller._plan_proxy_runtime_singbox(node)
                )
            except ValueError:
                plan = None
            facts = (
                SingboxPlanFacts(
                    selector_tags=dict(plan.selector_tags or {}),
                    provider_payload=plan.provider_payload,
                    used_selected_node=bool(plan.used_selected_node),
                )
                if plan is not None
                else None
            )
        if facts is not None and facts.selector_tags and node.id in facts.selector_tags:
            selector_pool = {
                "tags": [[node_id, tag] for node_id, tag in sorted(facts.selector_tags.items())],
                "provider": facts.provider_payload,
            }
    payload: dict[str, object] = {
        "mode": "singbox-tun" if controller.is_singbox_tun_mode(settings) else "singbox-proxy",
        "singbox_path": str(settings.singbox_path),
        "config_file": str(source_path.name),
        "config_hash": config_hash,
        "has_proxy_outbound": has_proxy_outbound,
        "planner_outcome": planner_outcome,
        "node_id": node.id if has_proxy_outbound and node else None,
        "node_outbound": node.outbound if has_proxy_outbound and node and selector_pool is None else None,
        "selector_pool": selector_pool,
    }
    if planner_outcome == "hysteria_sidecar" and node is not None:
        payload["hysteria_path"] = str(HYSTERIA_PATH_DEFAULT)
        payload["sidecar_uri_fingerprint"] = hysteria2_uri_fingerprint(node.link)
    if planner_outcome == "hybrid_xray_sidecar":
        payload["xray_path"] = str(settings.xray_path)
    if controller.is_singbox_proxy_mode(settings):
        payload.update(
            {
                "proxy_engine": "singbox",
                "socks_port": int(DEFAULT_SOCKS_PORT),
                "http_port": int(DEFAULT_HTTP_PORT),
            }
        )
    return payload


def transition_signature(
    controller: AppController,
    node: Node | None = None,
    settings: AppSettings | None = None,
    routing: RoutingSettings | None = None,
) -> str:
    settings = settings or controller.state.settings
    node = node or controller.selected_node
    payload = _singbox_runtime_signature_payload(controller, node, settings)
    if not settings.tun_mode:
        payload.update(
            proxy_enabled=bool(settings.enable_system_proxy),
            proxy_bypass_lan=system_proxy_bypass_lan(controller, settings),
        )
    return signature(payload)


def xray_layer_signature(
    controller: AppController,
    node: Node | None = None,
    settings: AppSettings | None = None,
    routing: RoutingSettings | None = None,
) -> str:
    settings = settings or controller.state.settings
    return signature(_singbox_runtime_signature_payload(
        controller, node or controller.selected_node, settings,
    ))


def tun_layer_signature(
    controller: AppController,
    node: Node | None = None,
    settings: AppSettings | None = None,
    routing: RoutingSettings | None = None,
) -> str:
    settings = settings or controller.state.settings
    return transition_signature(controller, node, settings) if settings.tun_mode else ""
