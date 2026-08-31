from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .hysteria_runtime_contract import HysteriaFailureCode


@dataclass(slots=True)
class ActiveSessionSnapshot:
    node_id: str | None
    node_server: str
    active_core: str
    tun_mode: bool
    tun_engine: str
    proxy_enabled: bool
    proxy_bypass_lan: bool
    xray_path: str
    singbox_path: str
    socks_port: int
    http_port: int
    routing_signature: str
    transition_signature: str
    xray_layer_signature: str
    tun_layer_signature: str
    hybrid: bool
    api_port: int
    xray_inbound_tags: tuple[str, ...]
    sidecar_relay_port: int
    protect_ss_port: int
    protect_ss_password: str
    ping_host: str
    ping_port: int
    outbound_pool_tags: dict[str, str] | None = None
    hybrid_relay_selector_tags: tuple[str, ...] = ()
    hybrid_relay_selected_tag: str = ""
    sidecar_kind: str = ""
    session_generation: int = 0
    runtime_kind: str = ""
    sidecar_process_generation: int = 0
    relay_host: str = "127.0.0.1"
    relay_credentials_generation: int = 0
    front_process_generation: int = 0
    front_target_generation: int = 0
    started_at_monotonic: float = 0.0
    ready_at_monotonic: float = 0.0
    failure_episode_id: int = 0
    last_failure_code: HysteriaFailureCode | None = None
    automatic_switch_attempted: bool = False


@dataclass(slots=True)
class XrayRuntimeConfig:
    config: dict[str, Any]
    source_path: Path
    has_proxy_outbound: bool
    used_selected_node: bool
    requested_socks_port: int
    requested_http_port: int
    socks_port: int
    http_port: int
    api_port: int
    tun_interface_name: str
    loop_prevention_interface: str
    loop_prevention_patched_outbounds: int
    inbound_tags: tuple[str, ...]
    ping_host: str
    ping_port: int
    outbound_pool_tags: dict[str, str] | None = None

    @property
    def proxy_ports_changed(self) -> bool:
        return (
            self.requested_socks_port > 0
            and self.requested_http_port > 0
            and (
                self.socks_port != self.requested_socks_port
                or self.http_port != self.requested_http_port
            )
        )


def build_active_session_snapshot(
    *,
    node_id: str | None,
    node_server: str,
    active_core: str,
    tun_mode: bool,
    tun_engine: str,
    proxy_enabled: bool,
    proxy_bypass_lan: bool,
    xray_path: str,
    singbox_path: str,
    socks_port: int,
    http_port: int,
    routing_signature: str,
    transition_signature: str,
    xray_layer_signature: str,
    tun_layer_signature: str,
    hybrid: bool,
    api_port: int,
    xray_inbound_tags: tuple[str, ...],
    sidecar_relay_port: int,
    protect_ss_port: int,
    protect_ss_password: str,
    ping_host: str,
    ping_port: int,
    outbound_pool_tags: dict[str, str] | None = None,
    hybrid_relay_selector_tags: tuple[str, ...] = (),
    hybrid_relay_selected_tag: str = "",
    sidecar_kind: str = "",
    session_generation: int = 0,
    runtime_kind: str = "",
    sidecar_process_generation: int = 0,
    relay_host: str = "127.0.0.1",
    relay_credentials_generation: int = 0,
    front_process_generation: int = 0,
    front_target_generation: int = 0,
    started_at_monotonic: float = 0.0,
    ready_at_monotonic: float = 0.0,
    failure_episode_id: int = 0,
    last_failure_code: HysteriaFailureCode | None = None,
    automatic_switch_attempted: bool = False,
) -> ActiveSessionSnapshot:
    return ActiveSessionSnapshot(
        node_id=node_id,
        node_server=node_server,
        active_core=active_core,
        tun_mode=tun_mode,
        tun_engine=tun_engine,
        proxy_enabled=proxy_enabled,
        proxy_bypass_lan=proxy_bypass_lan,
        xray_path=xray_path,
        singbox_path=singbox_path,
        socks_port=socks_port,
        http_port=http_port,
        routing_signature=routing_signature,
        transition_signature=transition_signature,
        xray_layer_signature=xray_layer_signature,
        tun_layer_signature=tun_layer_signature,
        hybrid=hybrid,
        api_port=api_port,
        xray_inbound_tags=xray_inbound_tags,
        sidecar_relay_port=sidecar_relay_port,
        protect_ss_port=protect_ss_port,
        protect_ss_password=protect_ss_password,
        ping_host=ping_host,
        ping_port=ping_port,
        outbound_pool_tags=dict(outbound_pool_tags or {}),
        hybrid_relay_selector_tags=tuple(hybrid_relay_selector_tags),
        hybrid_relay_selected_tag=str(hybrid_relay_selected_tag),
        sidecar_kind=str(sidecar_kind),
        session_generation=int(session_generation),
        runtime_kind=str(runtime_kind),
        sidecar_process_generation=int(sidecar_process_generation),
        relay_host=str(relay_host),
        relay_credentials_generation=int(relay_credentials_generation),
        front_process_generation=int(front_process_generation),
        front_target_generation=int(front_target_generation),
        started_at_monotonic=float(started_at_monotonic),
        ready_at_monotonic=float(ready_at_monotonic),
        failure_episode_id=int(failure_episode_id),
        last_failure_code=last_failure_code,
        automatic_switch_attempted=bool(automatic_switch_attempted),
    )
