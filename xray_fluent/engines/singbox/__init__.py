"""sing-box engine helpers."""

from .config_builder import build_singbox_outbound
from .manager import SingBoxManager, get_singbox_version
from .operations import restart_proxy_runtime, restart_runtime, start_proxy, start_tun
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
from .selector_api import build_selector_url, select_outbound, select_outbound_when_ready

__all__ = [
    "build_singbox_outbound",
    "SingBoxManager",
    "get_singbox_version",
    "restart_runtime",
    "restart_proxy_runtime",
    "start_proxy",
    "start_tun",
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
]
