"""sing-box engine helpers."""

from .config_builder import build_singbox_outbound
from .manager import SingBoxManager, get_singbox_version
from .operations import (
    restart_proxy_runtime,
    restart_proxy_runtime_steps,
    restart_runtime,
    restart_runtime_steps,
    start_proxy,
    start_proxy_steps,
    start_tun,
    start_tun_steps,
)
from .runtime_planner import (
    ParsedSingboxDocument,
    SingboxDocumentState,
    SingboxHysteriaSidecarPlan,
    SingboxRuntimePlan,
    SingboxXraySidecarPlan,
    classify_node_for_singbox,
    inspect_singbox_document_text,
    parse_singbox_document,
    plan_singbox_proxy_runtime,
    plan_singbox_runtime,
)
from .selector_api import (
    build_selector_url,
    select_outbound,
    select_outbound_when_ready,
    select_outbound_when_ready_steps,
)

__all__ = [
    "build_singbox_outbound",
    "SingBoxManager",
    "get_singbox_version",
    "restart_runtime",
    "restart_runtime_steps",
    "restart_proxy_runtime",
    "restart_proxy_runtime_steps",
    "start_proxy",
    "start_proxy_steps",
    "start_tun",
    "start_tun_steps",
    "ParsedSingboxDocument",
    "SingboxDocumentState",
    "SingboxHysteriaSidecarPlan",
    "SingboxRuntimePlan",
    "SingboxXraySidecarPlan",
    "classify_node_for_singbox",
    "inspect_singbox_document_text",
    "parse_singbox_document",
    "plan_singbox_proxy_runtime",
    "plan_singbox_runtime",
    "build_selector_url",
    "select_outbound",
    "select_outbound_when_ready",
    "select_outbound_when_ready_steps",
]
