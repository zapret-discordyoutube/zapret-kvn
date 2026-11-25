"""How each ticked slot reaches its server at launch (docs/SERVICE_SLOTS.md, "Phase 3 plan").

Pure: it edits the runtime COPY of the sing-box config (app-owned launch artifact, never the user's file) and says
which helper process each slot needs. The controller starts the helpers and pins the selectors.

- The slot follows the main server (no server of its own, or the same server): member `proxy`.
- A sing-box-core server: a member of the launch provider when it is there (hot moves between such servers), otherwise
  its native outbound `zapret-slot-out-<id>`.
- A server with its own native core (Hysteria2, VLESS): a stable loopback SOCKS relay `zapret-slot-relay-<id>`, and
  behind it that core's own process (owner 2026-11-16: «one per server»). Moving the slot to another server of the
  same kind restarts only that helper on the same port.
- AWG (Amnezia) slots are not supported yet: the slot follows the main server and says why.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from ..application.protocol_core import ProtocolCore, protocol_core
from ..profiles.models import Node
from .config_writer import DNS_PREFIX, PROXY_TAG, SELECTOR_PREFIX

RELAY_PREFIX = "zapret-slot-relay-"
OUT_PREFIX = "zapret-slot-out-"
LOOPBACK = "127.0.0.1"
# The helper would dial its server outside sing-box and show the address to the provider (WARP entry, proxy mode).
SLOT_HELPER_FOLLOWS_MAIN = "вход через WARP: в режиме «Прокси» сервер этого сервиса идёт мимо sing-box, сервис использует основной сервер"


@dataclass(frozen=True, slots=True)
class SlotHelper:
    """A native-core process behind the slot's relay."""

    core: ProtocolCore
    node: Node
    relay_port: int
    username: str
    password: str


@dataclass(frozen=True, slots=True)
class SlotRelay:
    """The slot's stable loopback SOCKS relay: present for every slot, so a later move to a Hysteria2 or VLESS server
    only starts a helper behind it (no sing-box restart)."""

    tag: str
    port: int
    username: str
    password: str

    def helper(self, core: ProtocolCore, node: Node) -> SlotHelper:
        return SlotHelper(core, node, self.port, self.username, self.password)


@dataclass(frozen=True, slots=True)
class SlotRuntimePlan:
    slot_id: str
    member_tag: str
    """The selector member to pin through the Clash API (`proxy`, a provider member, the relay or the native out)."""
    helper: SlotHelper | None = None
    note: str = ""
    """Why the slot follows the main server although it has a server (shown in the log)."""
    server_id: str | None = field(default=None)
    relay: SlotRelay | None = None


def slot_selector_ids(config: Mapping[str, Any]) -> list[str]:
    ids = []
    for outbound in config.get("outbounds") or []:
        tag = outbound.get("tag") if isinstance(outbound, dict) else None
        if isinstance(tag, str) and tag.startswith(SELECTOR_PREFIX) and not tag.startswith((DNS_PREFIX, RELAY_PREFIX, OUT_PREFIX)):
            ids.append(tag[len(SELECTOR_PREFIX):])
    return ids


def plan_slots(
    runtime_config: dict[str, Any],
    assignments: Mapping[str, Node | None],
    *,
    main_node_id: str | None,
    provider_tags: Mapping[str, str],
    provider_tag: str,
    allocate_port: Callable[[], int],
    credentials: Callable[[str], tuple[str, str]],
    build_native_outbound: Callable[[Node, str], dict[str, Any]],
    helpers_allowed: bool = True,
) -> list[SlotRuntimePlan]:
    """Edits [runtime_config] in place and returns one plan per slot selector found in it.

    [provider_tags] maps a node id to its provider member (`__app_nodes/node_<hash>`) when the launch provider exists.
    """
    outbounds = runtime_config.setdefault("outbounds", [])
    by_tag = {o.get("tag"): o for o in outbounds if isinstance(o, dict)}
    plans: list[SlotRuntimePlan] = []
    for slot_id in slot_selector_ids(runtime_config):
        selector = by_tag[f"{SELECTOR_PREFIX}{slot_id}"]
        node = assignments.get(slot_id)
        username, password = credentials(f"slot-{slot_id}")
        relay = SlotRelay(f"{RELAY_PREFIX}{slot_id}", allocate_port(), username, password)
        _replace_or_append(outbounds, {
            "type": "socks",
            "tag": relay.tag,
            "server": LOOPBACK,
            "server_port": relay.port,
            "username": relay.username,
            "password": relay.password,
            "inet4_bind_address": LOOPBACK,
        })
        plan = replace(_plan_one(slot_id, node, main_node_id, provider_tags, relay, build_native_outbound, outbounds, helpers_allowed), relay=relay)
        members = [PROXY_TAG, relay.tag]
        if plan.member_tag not in members and not plan.member_tag.startswith(f"{provider_tag}/"):
            members.append(plan.member_tag)
        selector["type"] = "selector"
        selector["outbounds"] = members
        if provider_tags:
            selector["providers"] = [provider_tag]
        else:
            selector.pop("providers", None)
        # A provider member is registered after the selector is built, so it cannot be the default: the controller
        # pins it through the Clash API before traffic is exposed, as it does for `proxy`.
        selector["default"] = plan.member_tag if plan.member_tag in members else PROXY_TAG
        selector["interrupt_exist_connections"] = True
        plans.append(plan)
    return plans


def _plan_one(
    slot_id: str,
    node: Node | None,
    main_node_id: str | None,
    provider_tags: Mapping[str, str],
    relay: SlotRelay,
    build_native_outbound: Callable[[Node, str], dict[str, Any]],
    outbounds: list[Any],
    helpers_allowed: bool = True,
) -> SlotRuntimePlan:
    if node is None or node.id == main_node_id:
        return SlotRuntimePlan(slot_id, PROXY_TAG, server_id=node.id if node else None)
    core = protocol_core(node)
    if core is ProtocolCore.SINGBOX:
        member = provider_tags.get(node.id)
        if member:
            return SlotRuntimePlan(slot_id, member, server_id=node.id)
        tag = f"{OUT_PREFIX}{slot_id}"
        try:
            native = build_native_outbound(node, tag)
        except ValueError as error:
            return SlotRuntimePlan(slot_id, PROXY_TAG, note=f"сервер не собрать для sing-box: {error}", server_id=node.id)
        _replace_or_append(outbounds, native)
        return SlotRuntimePlan(slot_id, tag, server_id=node.id)
    if core in (ProtocolCore.HYSTERIA, ProtocolCore.XRAY):
        if not helpers_allowed:
            return SlotRuntimePlan(slot_id, PROXY_TAG, note=SLOT_HELPER_FOLLOWS_MAIN, server_id=node.id)
        return SlotRuntimePlan(slot_id, relay.tag, relay.helper(core, node), server_id=node.id)
    return SlotRuntimePlan(slot_id, PROXY_TAG, note="серверы AWG для отдельных сервисов пока не поддерживаются", server_id=node.id)


def _replace_or_append(outbounds: list[Any], payload: dict[str, Any]) -> None:
    for index, item in enumerate(outbounds):
        if isinstance(item, dict) and item.get("tag") == payload["tag"]:
            outbounds[index] = payload
            return
    outbounds.append(payload)


def xray_helper_config(helper: SlotHelper, outbound: dict[str, Any]) -> dict[str, Any]:
    """The config of a slot's own Xray: the slot relay in, that one server out.

    Its connection to the server leaves the TUN by the process rule of the Xray executable (app-owned safety
    contract, like the Hysteria sidecar's `process_path -> direct`).
    """
    server = dict(outbound)
    server["tag"] = "proxy"
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "slot-relay-in",
            "protocol": "socks",
            "listen": LOOPBACK,
            "port": helper.relay_port,
            "settings": {"auth": "password", "accounts": [{"user": helper.username, "pass": helper.password}], "udp": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
        }],
        "outbounds": [server, {"tag": "direct", "protocol": "freedom", "settings": {}}],
        "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": ["slot-relay-in"], "outboundTag": "proxy"}]},
    }


def ensure_helper_direct_routes(
    runtime_config: dict[str, Any],
    plans: list[SlotRuntimePlan],
    executable: Callable[[ProtocolCore, str], str],
) -> None:
    """A slot helper's own connection to its server must not re-enter the TUN (the same app-owned safety contract as
    the main Hysteria sidecar's `process_path -> direct`): one rule ahead of the user's routing, for the executables of
    the helpers this launch runs (each slot helper runs from its own copy, `executable(core, slot_id)`)."""
    executables = sorted({executable(p.helper.core, p.slot_id) for p in plans if p.helper is not None})
    if not executables:
        return
    route = runtime_config.setdefault("route", {})
    rules = route.setdefault("rules", [])
    for rule in rules:
        if isinstance(rule, dict) and rule.get("outbound") == "direct" and isinstance(rule.get("process_path"), list):
            known = {str(item) for item in rule["process_path"]}
            executables = [e for e in executables if e not in known]
    if executables:
        rules.insert(0, {"process_path": executables, "action": "route", "outbound": "direct"})
