from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..app_controller import AppController
    from ..models import Node


AUTO_SWITCH_HIGH_TICKS_REQUIRED = 10
AUTO_SWITCH_IDLE_BPS = 1024.0
# Hysteria/TUIC use UDP/QUIC.  A TCP connect to their server port is not a
# functional health check for the tunnel and must not be used as a dead-link
# verdict.
UDP_NATIVE_TYPES = frozenset({"hysteria", "hysteria2", "tuic", "wireguard"})
AUTO_SWITCH_WARMUP_SEC = 20.0
AUTO_SWITCH_UDP_WARMUP_SEC = 45.0
AUTO_SWITCH_HYSTERIA_LOW_SEC = 60.0
AUTO_SWITCH_HYSTERIA_COOLDOWN_SEC = 300.0
AUTO_SWITCH_HYSTERIA_LOW_RATIO = 0.5
# A dead server produces down_bps == 0, which the speed path reads as "user
# is idle" — so a full outage can never trigger the speed-drop switch. The
# metrics worker TCP-pings the active node every ~3s; this many seconds of
# continuously failing pings with no payload traffic mean a TCP link is dead.
# UDP/QUIC nodes are deliberately excluded from this path below.
AUTO_SWITCH_DEAD_LINK_SEC = 15.0


def transport_kind_for_node(node: Node | None) -> str:
    """Return the transport family used by auto-switch health policy.

    Hysteria 2 and TUIC are native UDP/QUIC outbounds.  Their URI still has a
    server and port, but opening that port over TCP does not prove that the
    actual tunnel works.  Keep this small classifier local to the policy layer
    so metrics and switching share the same contract.
    """

    outbound = node.outbound if node is not None and isinstance(node.outbound, dict) else {}
    native_type = str(outbound.get("type") or "").strip().lower()
    if native_type in UDP_NATIVE_TYPES:
        return "udp"

    protocol = str(outbound.get("protocol") or "").strip().lower()
    if protocol in UDP_NATIVE_TYPES:
        return "udp"
    if protocol:
        stream = outbound.get("streamSettings")
        stream = stream if isinstance(stream, dict) else {}
        network = str(stream.get("network") or "tcp").strip().lower()
        if network in {"kcp", "quic"}:
            return "udp"
    return "tcp"


def is_hysteria_node(node: Node | None) -> bool:
    outbound = node.outbound if node is not None and isinstance(node.outbound, dict) else {}
    native_type = str(outbound.get("type") or "").strip().lower()
    return native_type in {"hysteria", "hysteria2", "tuic"}


def begin_auto_switch_warmup(controller: AppController, node: Node | None = None) -> None:
    """Start a fresh health observation window for a newly active node.

    This intentionally preserves the cycle/cooldown accounting and manual hold;
    it only discards samples belonging to the previous runtime generation.
    """

    now = time.monotonic()
    warmup = AUTO_SWITCH_UDP_WARMUP_SEC if transport_kind_for_node(node) == "udp" else AUTO_SWITCH_WARMUP_SEC
    controller._auto_switch_warmup_until = now + warmup
    controller._auto_switch_health_node_id = getattr(node, "id", None)
    controller._auto_switch_low_since = 0.0
    controller._auto_switch_link_down_since = 0.0
    controller._auto_switch_high_ticks = 0
    controller._auto_switch_active_download = False


def _transition_in_progress(controller: AppController) -> bool:
    """Return true while any connection transition owns the runtime."""

    return bool(
        getattr(controller, "_auto_switch_transitioning", False)
        or getattr(controller, "_transition_active", False)
        or getattr(controller, "_transition_pending", False)
        or getattr(controller, "_transition_runner", None) is not None
        or getattr(controller, "_hot_switch_runner", None) is not None
        or getattr(controller, "_connecting", False)
        or getattr(controller, "_disconnecting", False)
    )


def check_auto_switch(
    controller: AppController,
    down_bps: float,
    link_alive: bool | None = None,
    *,
    traffic_valid: bool = True,
) -> None:
    """React to live metrics: speed drops and dead links.

    ``link_alive`` is the last TCP-ping verdict for the active node:
    True/False when the worker probes it, None when no probe is configured.
    """
    settings = controller.state.settings
    if not settings.auto_switch_enabled:
        return
    if not controller.connected or controller._switching or controller._reconnecting:
        return
    if _transition_in_progress(controller):
        return
    if getattr(controller, "_auto_switch_manual_hold", False):
        return
    if len(controller.state.nodes) < 2:
        return
    if controller._auto_switch_exhausted:
        return

    now = time.monotonic()
    if now < float(getattr(controller, "_auto_switch_warmup_until", 0.0) or 0.0):
        return

    # A failed stats/API read is not an idle sample.  Keep confirmed activity
    # (it may resume after one missing read), but force a fresh low-speed window
    # and never let an observability gap trigger a switch.
    if not traffic_valid:
        controller._auto_switch_low_since = 0.0
        controller._auto_switch_link_down_since = 0.0
        controller._auto_switch_high_ticks = 0
        return

    node = getattr(controller, "selected_node", None)
    is_udp = transport_kind_for_node(node) == "udp"
    is_hysteria = is_hysteria_node(node)

    # TCP reachability is intentionally not a dead-link verdict for Hysteria,
    # TUIC, WireGuard, or any other UDP/QUIC transport.
    if not is_udp and link_alive is False and down_bps < AUTO_SWITCH_IDLE_BPS:
        if controller._auto_switch_link_down_since == 0.0:
            controller._auto_switch_link_down_since = now
            return
        down_duration = now - controller._auto_switch_link_down_since
        if down_duration < AUTO_SWITCH_DEAD_LINK_SEC:
            return
        if now - controller._auto_switch_last_switch < settings.auto_switch_cooldown_sec:
            return
        controller._auto_switch_link_down_since = 0.0
        _execute_auto_switch(
            controller,
            now,
            f"[auto-switch] active server unreachable for {down_duration:.0f}s → switching",
        )
        return
    controller._auto_switch_link_down_since = 0.0

    threshold_bps = settings.auto_switch_threshold_kbps * 1024.0
    low_threshold_bps = threshold_bps
    low_delay_sec = float(settings.auto_switch_delay_sec)
    cooldown_sec = float(settings.auto_switch_cooldown_sec)
    if is_hysteria:
        # Hysteria traffic is bursty.  Require a real degradation band below
        # half of the configured active-download threshold and hold it for a
        # full minute before considering a switch.
        low_threshold_bps = max(AUTO_SWITCH_IDLE_BPS, threshold_bps * AUTO_SWITCH_HYSTERIA_LOW_RATIO)
        low_delay_sec = max(low_delay_sec, AUTO_SWITCH_HYSTERIA_LOW_SEC)
        cooldown_sec = max(cooldown_sec, AUTO_SWITCH_HYSTERIA_COOLDOWN_SEC)

    if down_bps >= threshold_bps:
        controller._auto_switch_high_ticks += 1
        if controller._auto_switch_high_ticks >= AUTO_SWITCH_HIGH_TICKS_REQUIRED:
            controller._auto_switch_active_download = True
        controller._auto_switch_low_since = 0.0
        return

    if not controller._auto_switch_active_download:
        controller._auto_switch_high_ticks = 0
        return

    if down_bps < AUTO_SWITCH_IDLE_BPS:
        controller._auto_switch_low_since = 0.0
        controller._auto_switch_high_ticks = 0
        controller._auto_switch_active_download = False
        return

    controller._auto_switch_high_ticks = 0

    # A value between the high and low thresholds is neither healthy enough to
    # confirm recovery nor bad enough to start a degradation window.
    if down_bps >= low_threshold_bps:
        controller._auto_switch_low_since = 0.0
        return

    if controller._auto_switch_low_since == 0.0:
        controller._auto_switch_low_since = now
        return

    low_duration = now - controller._auto_switch_low_since
    if low_duration < low_delay_sec:
        return

    if now - controller._auto_switch_last_switch < cooldown_sec:
        return

    _execute_auto_switch(
        controller,
        now,
        f"[auto-switch] speed {down_bps / 1024:.0f} KB/s < {settings.auto_switch_threshold_kbps} KB/s "
        f"for {low_duration:.0f}s → switching",
    )


def _execute_auto_switch(controller: AppController, now: float, log_message: str) -> None:
    """Shared tail of both triggers: exhaustion guard, node pick, switch."""
    max_attempts = max(1, len(controller.state.nodes) - 1)
    if controller._auto_switch_cycle_attempts >= max_attempts:
        controller._auto_switch_exhausted = True
        controller._auto_switch_low_since = 0.0
        controller._auto_switch_active_download = False
        controller.status.emit("warning", "Автопереключение остановлено: все серверы уже проверены")
        controller._log("[auto-switch] exhausted all nodes for current session")
        return

    next_node = get_next_node_for_auto_switch(controller)
    if not next_node:
        controller._auto_switch_low_since = 0.0
        controller._log("[auto-switch] no eligible node for current session")
        return

    controller._auto_switch_low_since = 0.0
    controller._auto_switch_last_switch = now
    controller._auto_switch_active_download = False
    controller._auto_switch_high_ticks = 0
    controller._auto_switch_cycle_attempts += 1
    controller._auto_switch_transitioning = True
    controller._log(f"{log_message} to {next_node.name}")
    controller.auto_switch_triggered.emit(next_node.name)

    # П4 (AC11/AC12): единый путь переключения — set_selected_node сам делает
    # selection_changed/schedule_save, пробует горячий свитч и при неудаче
    # честно падает в очередь переходов. reset_auto_switch=False сохраняет
    # учёт cooldown/cycle (анти-дребезг, A6), выставленный выше.
    controller.set_selected_node(next_node.id, reset_auto_switch=False)


def get_next_node_for_auto_switch(controller: AppController) -> Node | None:
    current_id = controller.state.selected_node_id
    nodes = controller.state.nodes
    if not nodes:
        return None

    candidates = [
        node
        for node in nodes
        if node.id != current_id and node.is_alive is True and node.speed_mbps is not None and node.speed_mbps > 0
    ]
    if candidates:
        return max(candidates, key=lambda node: node.speed_mbps)

    candidates = [node for node in nodes if node.id != current_id and node.is_alive is True]
    if candidates:
        return min(candidates, key=lambda node: node.ping_ms if node.ping_ms is not None else float("inf"))

    current_idx: int | None = None
    for idx, node in enumerate(nodes):
        if node.id == current_id:
            current_idx = idx
            break
    if current_idx is None:
        return nodes[0]
    next_idx = (current_idx + 1) % len(nodes)
    if nodes[next_idx].id == current_id:
        return None
    return nodes[next_idx]
