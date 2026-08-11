"""App-owned transport pools used for zero-restart node switching.

The active raw JSON still owns DNS and routing.  A pool only replaces the
transport behind the conventional ``proxy`` destination with a core-native
selector/balancer, so the data plane (inbounds, TUN and routes) can stay alive.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
from typing import Iterable

from ..link_parser import is_native_singbox_outbound
from ..models import Node


XRAY_BALANCER_TAG = "__app_proxy_selector"
XRAY_OUTBOUND_PREFIX = "__app_proxy_"
SINGBOX_PROVIDER_TAG = "__app_nodes"
SINGBOX_SELECTOR_TAG = "proxy"
SINGBOX_OUTBOUND_PREFIX = "node_"


def _stable_suffix(node_id: str) -> str:
    return hashlib.sha256(str(node_id).encode("utf-8")).hexdigest()[:20]


def xray_outbound_tag(node_id: str) -> str:
    return f"{XRAY_OUTBOUND_PREFIX}{_stable_suffix(node_id)}"


def singbox_outbound_tag(node_id: str) -> str:
    return f"{SINGBOX_OUTBOUND_PREFIX}{_stable_suffix(node_id)}"


def is_xray_pool_node(node: Node) -> bool:
    outbound = node.outbound if isinstance(node.outbound, dict) else {}
    return bool(str(outbound.get("protocol") or "").strip()) and not is_native_singbox_outbound(node)


@dataclass(slots=True)
class XrayOutboundPool:
    nodes: list[Node] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)

    def contains(self, node_id: str | None) -> bool:
        return str(node_id or "") in self.tags

    def tag_for(self, node_id: str | None) -> str:
        return self.tags.get(str(node_id or ""), "")

    def outbounds(self) -> list[dict]:
        result: list[dict] = []
        for node in self.nodes:
            outbound = deepcopy(node.outbound)
            outbound["tag"] = self.tags[node.id]
            result.append(outbound)
        return result

    def signature_payload(self) -> list[list[object]]:
        return [[self.tags[node.id], node.outbound] for node in self.nodes]


def build_xray_outbound_pool(nodes: Iterable[Node]) -> XrayOutboundPool:
    eligible = [node for node in nodes if is_xray_pool_node(node)]
    eligible.sort(key=lambda item: (item.sort_order, item.id))
    return XrayOutboundPool(
        nodes=eligible,
        tags={node.id: xray_outbound_tag(node.id) for node in eligible},
    )


def route_xray_proxy_rules_to_balancer(rules: list[object]) -> int:
    """Retarget only explicit ``proxy`` rules; never invent routing policy."""

    changed = 0
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("outboundTag") != "proxy":
            continue
        rule.pop("outboundTag", None)
        rule["balancerTag"] = XRAY_BALANCER_TAG
        changed += 1
    return changed


def ensure_xray_pool_control_plane(config: dict, pool: XrayOutboundPool) -> None:
    routing = config.setdefault("routing", {})
    if not isinstance(routing, dict):
        raise ValueError("Секция routing Xray должна быть JSON-объектом.")
    rules = routing.setdefault("rules", [])
    if not isinstance(rules, list):
        raise ValueError("Секция routing.rules Xray должна быть массивом.")
    route_xray_proxy_rules_to_balancer(rules)

    balancers = routing.setdefault("balancers", [])
    if not isinstance(balancers, list):
        raise ValueError("Секция routing.balancers Xray должна быть массивом.")
    balancer = {
        "tag": XRAY_BALANCER_TAG,
        "selector": [XRAY_OUTBOUND_PREFIX],
        # The controller pins the exact target immediately after startup.
        "strategy": {"type": "random"},
    }
    for index, current in enumerate(balancers):
        if isinstance(current, dict) and current.get("tag") == XRAY_BALANCER_TAG:
            balancers[index] = balancer
            break
    else:
        balancers.append(balancer)

    api = config.setdefault("api", {})
    if not isinstance(api, dict):
        raise ValueError("Секция api Xray должна быть JSON-объектом.")
    services = api.setdefault("services", [])
    if not isinstance(services, list):
        services = []
    for service in ("StatsService", "RoutingService", "HandlerService"):
        if service not in services:
            services.append(service)
    api["services"] = services
