from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .runtime_planner import SingboxRuntimePlan
from ..hysteria.runtime_contract import SECURITY_FAILURES, HysteriaFailureCode, HysteriaRuntimeState

if TYPE_CHECKING:
    from ...application.controller import AppController
    from ...profiles.models import Node


@dataclass(slots=True)
class SingboxStartResult:
    plan: SingboxRuntimePlan
    session_label: str


def _proxy_session_label(plan: SingboxRuntimePlan, node: Node | None) -> str:
    if plan.used_selected_node and node is not None:
        return f"{plan.source_path.name} / {node.name}"
    return plan.source_path.name


def _runtime_suffix(plan: SingboxRuntimePlan) -> str:
    if plan.is_hybrid:
        return " (sing-box + Xray sidecar)"
    if plan.is_hysteria_sidecar:
        return " (sing-box + Hysteria2)"
    if getattr(plan, "amnezia_sidecar", None) is not None:
        return " (sing-box + Amnezia WG/AWG)"
    return " (sing-box extended)"


def _notify_proxy_port_change(controller: AppController, plan: SingboxRuntimePlan) -> None:
    if not plan.proxy_ports_changed:
        return
    message = (
        "Локальные порты sing-box изменены: "
        f"SOCKS {plan.requested_socks_port} -> {plan.socks_port}, "
        f"HTTP {plan.requested_http_port} -> {plan.http_port}. "
        "Исходные порты заняты или зарезервированы Windows."
    )
    controller._log(f"[sing-box] {message}")
    controller.status.emit("warning-long", message)


def _apply_system_proxy(controller: AppController, plan: SingboxRuntimePlan) -> bool:
    if controller.state.settings.enable_system_proxy:
        try:
            controller.proxy.enable(
                plan.http_port,
                plan.socks_port,
                bypass_lan=controller._system_proxy_bypass_lan(),
            )
        except Exception as exc:
            controller._set_connection_status(
                "error",
                f"Не удалось включить системный прокси: {exc}",
                level="error",
            )
            return False
    else:
        controller.proxy.disable(restore_previous=True)
    return True


def start_proxy(
    controller: AppController,
    node: Node | None,
    *,
    prev_active_core: str,
) -> SingboxStartResult | None:
    controller._active_core = "singbox"
    try:
        plan = controller._plan_proxy_runtime_singbox(node)
    except ValueError as exc:
        controller._active_core = prev_active_core
        controller._set_connection_status("error", str(exc), level="error")
        return None

    session_label = _proxy_session_label(plan, node)
    suffix = _runtime_suffix(plan)
    controller._set_connection_status("starting", f"Запуск прокси: {session_label}{suffix}...", level="info")
    _notify_proxy_port_change(controller, plan)
    controller._log(f"[proxy] sing-box planner outcome: {plan.outcome} from {plan.source_path}")

    controller._xray_api_port = 0
    if not controller._start_singbox_runtime_plan(plan):
        controller._set_connection_status(
            "error",
            "Не удалось запустить sing-box proxy runtime. Смотрите причину в последних строках лога sing-box.",
            level="error",
        )
        controller._active_core = prev_active_core
        return None

    if not _apply_system_proxy(controller, plan):
        controller.singbox.stop()
        if getattr(controller, "amnezia", None) is not None:
            controller.amnezia.stop()
        if controller.xray.is_running:
            controller.xray.stop()
        if controller.hysteria.is_running:
            controller.hysteria.stop()
        controller._protect_ss_port = 0
        controller._protect_ss_password = ""
        controller._active_core = prev_active_core
        return None

    return SingboxStartResult(plan=plan, session_label=session_label)


def start_tun(
    controller: AppController,
    node: Node | None,
    *,
    prev_active_core: str,
) -> SingboxStartResult | None:
    controller._active_core = "singbox"
    try:
        plan = controller._plan_runtime_singbox(node)
    except ValueError as exc:
        controller._active_core = prev_active_core
        controller._set_connection_status("error", str(exc), level="error")
        return None

    session_label = plan.source_path.name
    if plan.used_selected_node and node is not None:
        session_label = f"{plan.source_path.name} / {node.name}"
    start_message = f"Запуск VPN: {session_label}{_runtime_suffix(plan)}..."
    controller._set_connection_status("starting", start_message, level="info")
    controller._log(f"[tun] sing-box planner outcome: {plan.outcome} from {plan.source_path}")
    if plan.used_selected_node and node is not None:
        if plan.is_hybrid:
            controller._log(
                f"[tun] outbound tag 'proxy' replaced with local xray relay for unsupported node: {node.name}"
            )
        elif plan.is_hysteria_sidecar:
            controller._log(
                f"[tun] outbound tag 'proxy' replaced with local official Hysteria2 relay: {node.name}"
            )
        else:
            controller._log(f"[tun] outbound tag 'proxy' replaced from selected node: {node.name}")

    if not controller._start_singbox_runtime_plan(plan):
        controller._set_connection_status(
            "error",
            (
                "Не удалось запустить sing-box sidecar runtime. Смотрите причину в последних строках лога."
                if plan.sidecar_kind
                else "Не удалось запустить sing-box TUN runtime. Смотрите причину в последних строках лога sing-box."
            ),
            level="error",
        )
        controller._active_core = prev_active_core
        return None

    return SingboxStartResult(plan=plan, session_label=session_label)


def _abort_security_recovery(controller: AppController, recovery: bool, replacement=None) -> bool:
    if not recovery or getattr(controller, "_hysteria_last_failure_code", None) not in SECURITY_FAILURES:
        return False
    # QProcess events are pumped while replacement/HTTP readiness is pending.
    # A security escalation from the still-owned old target forbids commit or
    # rollback, even when the initial timeout already requested a replacement.
    controller._desired_connected = False
    if replacement is not None:
        replacement.stop(expected=True)
    controller._clear_pending_hysteria_selection()
    controller._handle_unexpected_disconnect()
    return True


def _abort_superseded_transition(
    controller: AppController, generation: int, replacement=None, *, old_plan=None, front_changed=False,
) -> bool:
    if controller._transition_generation == generation and controller._desired_connected:
        return False
    # Readiness and process stop pump Qt events. A newer selection/disconnect
    # invalidates this candidate before it can publish or persist a session.
    if replacement is not None:
        replacement.stop(expected=True)
    if front_changed:
        if not controller._desired_connected or not controller._rollback_singbox_front(old_plan):
            controller._handle_unexpected_disconnect()
    controller._log("[transport-transition] superseded candidate discarded")
    return True


def restart_runtime(controller: AppController, reason: str) -> bool:
    node = controller._runtime_selected_node()
    requested_generation = controller._transition_generation
    hysteria_recovery = bool(controller._hysteria_recovery_active)
    replacement_amnezia = None
    amnezia_committed = False
    controller._switching = True
    try:
        if _abort_security_recovery(controller, hysteria_recovery):
            return False
        controller._log(f"[tun-hot-swap] {reason}")
        try:
            plan = controller._plan_runtime_singbox(node, replacement=True)
        except ValueError as exc:
            controller._set_connection_status("error", str(exc), level="error")
            return False
        session_label = plan.source_path.name
        if plan.used_selected_node and node is not None:
            session_label = f"{plan.source_path.name} / {node.name}"
        start_message = (
            f"Переключение на {session_label} (sing-box + xray sidecar)..."
            if plan.is_hybrid
            else f"Переключение на {session_label}..."
        )
        controller._set_connection_status("starting", start_message, level="info")
        controller._stop_metrics_worker()

        old_plan = getattr(controller, "_active_singbox_plan", None)
        old_hysteria = controller.hysteria
        old_amnezia = getattr(controller, "amnezia", None)
        if getattr(plan, "amnezia_sidecar", None) is not None:
            replacement_amnezia = controller._prepare_amnezia_replacement(plan)
            if replacement_amnezia is None:
                controller._set_connection_status("error", "Новый WG/AWG не прошёл проверку; прежний runtime сохранён.", level="error")
                return False
        replacement_hysteria = None
        if plan.hysteria_sidecar is not None:
            controller._hysteria_contract.advance(
                HysteriaRuntimeState.PREPARING_REPLACEMENT,
                generation=controller._hysteria_contract.session.session_generation,
            )
            replacement_hysteria = controller._prepare_hysteria_replacement(plan)
            if _abort_security_recovery(controller, hysteria_recovery, replacement_hysteria):
                return False
            if replacement_hysteria is None:
                controller._set_connection_status(
                    "error",
                    "Новый Hysteria sidecar не доказал readiness; прежний runtime сохранён.",
                    level="error",
                )
                if controller._hysteria_recovery_active:
                    controller._handle_unexpected_disconnect()
                return False

        if _abort_superseded_transition(controller, requested_generation, replacement_hysteria):
            return False
        if controller.singbox.is_running and not controller.singbox.stop():
            if replacement_hysteria is not None:
                replacement_hysteria.stop(expected=True)
            controller._set_connection_status("error", "Не удалось остановить предыдущий процесс sing-box", level="error")
            return False
        if controller.xray.is_running and not controller.xray.stop():
            if replacement_hysteria is not None:
                replacement_hysteria.stop(expected=True)
            controller._set_connection_status("error", "Не удалось остановить предыдущий процесс Xray sidecar", level="error")
            return False
        controller._xray_api_port = 0
        controller._protect_ss_port = 0
        controller._protect_ss_password = ""
        if _abort_security_recovery(controller, hysteria_recovery, replacement_hysteria):
            return False
        if _abort_superseded_transition(controller, requested_generation, replacement_hysteria, old_plan=old_plan, front_changed=True):
            return False
        controller._hysteria_contract.advance(
            HysteriaRuntimeState.COMMITTING_SWITCH,
            generation=controller._hysteria_contract.session.session_generation,
        )
        front_ready = controller._start_singbox_runtime_plan(
            plan,
            prepared_hysteria=replacement_hysteria,
            **({"prepared_amnezia": replacement_amnezia} if replacement_amnezia is not None else {}),
        )
        if _abort_security_recovery(controller, hysteria_recovery, replacement_hysteria):
            return False
        if _abort_superseded_transition(controller, requested_generation, replacement_hysteria, old_plan=old_plan, front_changed=True):
            return False
        if not front_ready:
            rolled_back = controller._rollback_singbox_front(old_plan)
            controller._hysteria_contract.terminal(
                HysteriaFailureCode.LOCAL_FRONT_NOT_READY,
                generation=controller._hysteria_contract.session.session_generation,
                degraded=rolled_back,
            )
            controller._set_connection_status(
                "error",
                (
                    "Новый front не запустился; прежняя generation восстановлена."
                    if rolled_back
                    else "Новый front не запустился и rollback прежней generation не удался."
                ),
                level="error",
            )
            if not rolled_back:
                controller._handle_unexpected_disconnect()
            return False

        if replacement_hysteria is not None:
            if not controller._commit_hysteria_replacement(replacement_hysteria):
                controller._hysteria_last_failure_code = (
                    HysteriaFailureCode.TRANSITION_ROLLBACK_FAILED
                )
                controller._log(
                    "[hysteria-transition] new generation committed, but the old "
                    "process did not confirm shutdown"
                )
        elif old_hysteria.is_running:
            old_hysteria.stop(expected=True)
        controller._hysteria_contract.advance(
            HysteriaRuntimeState.STOPPING_OLD,
            generation=controller._hysteria_contract.session.session_generation,
        )

        session_node = node if plan.used_selected_node else None
        if session_node is not None:
            session_node.last_used_at = datetime.now(timezone.utc).isoformat()

        ping_host, ping_port = controller._infer_singbox_ping_target(plan.singbox_config, session_node)
        controller._capture_active_session(
            session_node,
            tun=True,
            core="singbox",
            api_port=0,
            hybrid=plan.is_hybrid,
            sidecar_kind=plan.sidecar_kind,
            xray_inbound_tags=(),
            sidecar_relay_port=(
                plan.xray_sidecar.relay_port
                if plan.xray_sidecar
                else plan.hysteria_sidecar.relay_port
                if plan.hysteria_sidecar
                else plan.amnezia_sidecar.relay_port
                if getattr(plan, "amnezia_sidecar", None)
                else 0
            ),
            protect_ss_port=controller._protect_ss_port,
            protect_ss_password=controller._protect_ss_password,
            ping_host=ping_host,
            ping_port=ping_port,
            outbound_pool_tags=plan.selector_tags,
            hybrid_relay_selector_tags=plan.hybrid_relay_selector_tags,
            hybrid_relay_selected_tag=plan.hybrid_relay_selected_tag,
        )
        pending = getattr(controller, "_pending_amnezia_node_id", None)
        if replacement_amnezia is not None:
            controller.amnezia = replacement_amnezia
        amnezia_committed = True
        if isinstance(pending, str) and pending:
            if session_node is None or session_node.id != pending:
                controller._handle_unexpected_disconnect()
                return False
            controller.state.selected_node_id = pending
            controller._pending_amnezia_node_id = None
            controller.selection_changed.emit(session_node)
        if old_amnezia is not None and (old_amnezia is not controller.amnezia or getattr(plan, "amnezia_sidecar", None) is None):
            old_amnezia.stop()
            if old_amnezia is not controller.amnezia:
                old_amnezia.deleteLater()
        if hysteria_recovery and not controller._commit_pending_hysteria_selection(session_node):
            controller._set_connection_status(
                "error",
                "Новый runtime готов, но selection commit отклонён.",
                level="error",
            )
            controller._handle_unexpected_disconnect()
            return False
        if hysteria_recovery:
            controller._record_hysteria_switch_commit()
        controller._set_connection_status(
            "running",
            f"Переключено: {session_label}" + (
                f" (TUN, {plan.sidecar_kind} sidecar)" if plan.sidecar_kind else " (TUN)"
            ),
            level="success",
        )
        controller.schedule_save()
        return True
    finally:
        if replacement_amnezia is not None and not amnezia_committed:
            replacement_amnezia.stop()
            replacement_amnezia.deleteLater()
        if controller._transition_generation == requested_generation and node is not None and getattr(controller, "_pending_amnezia_node_id", None) == node.id:
            controller._pending_amnezia_node_id = None
        if hysteria_recovery and controller._pending_hysteria_replacement_node_id:
            controller._clear_pending_hysteria_selection()
        controller._switching = False
        controller._auto_switch_transitioning = False
        controller._hysteria_recovery_active = False
        _, controller.connected = controller._refresh_connected_state()
        controller.connection_changed.emit(controller.connected)
        if controller.connected:
            controller._start_metrics_worker()
        else:
            controller._stop_metrics_worker()


def restart_proxy_runtime(controller: AppController, reason: str) -> bool:
    node = controller._runtime_selected_node()
    requested_generation = controller._transition_generation
    hysteria_recovery = bool(controller._hysteria_recovery_active)
    replacement_amnezia = None
    amnezia_committed = False
    controller._switching = True
    try:
        if _abort_security_recovery(controller, hysteria_recovery):
            return False
        controller._log(f"[proxy-hot-swap] {reason}")
        try:
            plan = controller._plan_proxy_runtime_singbox(node, replacement=True)
        except ValueError as exc:
            controller._set_connection_status("error", str(exc), level="error")
            return False
        session_label = _proxy_session_label(plan, node)
        controller._set_connection_status("starting", f"Переключение на {session_label}...", level="info")
        _notify_proxy_port_change(controller, plan)
        controller._stop_metrics_worker()

        old_plan = getattr(controller, "_active_singbox_plan", None)
        old_hysteria = controller.hysteria
        old_amnezia = getattr(controller, "amnezia", None)
        if getattr(plan, "amnezia_sidecar", None) is not None:
            replacement_amnezia = controller._prepare_amnezia_replacement(plan)
            if replacement_amnezia is None:
                controller._set_connection_status("error", "Новый WG/AWG не прошёл проверку; прежний runtime сохранён.", level="error")
                return False
        replacement_hysteria = None
        if plan.hysteria_sidecar is not None:
            controller._hysteria_contract.advance(
                HysteriaRuntimeState.PREPARING_REPLACEMENT,
                generation=controller._hysteria_contract.session.session_generation,
            )
            replacement_hysteria = controller._prepare_hysteria_replacement(plan)
            if _abort_security_recovery(controller, hysteria_recovery, replacement_hysteria):
                return False
            if replacement_hysteria is None:
                controller._set_connection_status(
                    "error",
                    "Новый Hysteria sidecar не доказал readiness; прежний runtime сохранён.",
                    level="error",
                )
                if controller._hysteria_recovery_active:
                    controller._handle_unexpected_disconnect()
                return False

        if _abort_superseded_transition(controller, requested_generation, replacement_hysteria):
            return False
        if controller.singbox.is_running and not controller.singbox.stop():
            if replacement_hysteria is not None:
                replacement_hysteria.stop(expected=True)
            controller._set_connection_status("error", "Не удалось остановить предыдущий процесс sing-box", level="error")
            return False
        if controller.xray.is_running and not controller.xray.stop():
            if replacement_hysteria is not None:
                replacement_hysteria.stop(expected=True)
            controller._set_connection_status("error", "Не удалось остановить предыдущий процесс Xray sidecar", level="error")
            return False
        controller._xray_api_port = 0
        controller._protect_ss_port = 0
        controller._protect_ss_password = ""
        if _abort_security_recovery(controller, hysteria_recovery, replacement_hysteria):
            return False
        if _abort_superseded_transition(controller, requested_generation, replacement_hysteria, old_plan=old_plan, front_changed=True):
            return False
        controller._hysteria_contract.advance(
            HysteriaRuntimeState.COMMITTING_SWITCH,
            generation=controller._hysteria_contract.session.session_generation,
        )
        front_ready = controller._start_singbox_runtime_plan(
            plan,
            prepared_hysteria=replacement_hysteria,
            **({"prepared_amnezia": replacement_amnezia} if replacement_amnezia is not None else {}),
        )
        if _abort_security_recovery(controller, hysteria_recovery, replacement_hysteria):
            return False
        if _abort_superseded_transition(controller, requested_generation, replacement_hysteria, old_plan=old_plan, front_changed=True):
            return False
        if not front_ready:
            rolled_back = controller._rollback_singbox_front(old_plan)
            controller._hysteria_contract.terminal(
                HysteriaFailureCode.LOCAL_FRONT_NOT_READY,
                generation=controller._hysteria_contract.session.session_generation,
                degraded=rolled_back,
            )
            controller._set_connection_status(
                "error",
                (
                    "Новый front не запустился; прежняя generation восстановлена."
                    if rolled_back
                    else "Новый front не запустился и rollback прежней generation не удался."
                ),
                level="error",
            )
            if not rolled_back:
                controller._handle_unexpected_disconnect()
            return False
        if replacement_hysteria is not None:
            if not controller._commit_hysteria_replacement(replacement_hysteria):
                controller._hysteria_last_failure_code = (
                    HysteriaFailureCode.TRANSITION_ROLLBACK_FAILED
                )
                controller._log(
                    "[hysteria-transition] new generation committed, but the old "
                    "process did not confirm shutdown"
                )
        elif old_hysteria.is_running:
            old_hysteria.stop(expected=True)
        controller._hysteria_contract.advance(
            HysteriaRuntimeState.STOPPING_OLD,
            generation=controller._hysteria_contract.session.session_generation,
        )
        if not _apply_system_proxy(controller, plan):
            controller._handle_unexpected_disconnect()
            return False
        if _abort_superseded_transition(controller, requested_generation, replacement_hysteria, old_plan=old_plan, front_changed=True):
            return False

        session_node = node if plan.used_selected_node else None
        if session_node is not None:
            session_node.last_used_at = datetime.now(timezone.utc).isoformat()
        ping_host, ping_port = controller._infer_singbox_ping_target(plan.singbox_config, session_node)
        controller._capture_active_session(
            session_node,
            tun=False,
            core="singbox",
            api_port=0,
            hybrid=plan.is_hybrid,
            sidecar_kind=plan.sidecar_kind,
            socks_port=plan.socks_port,
            http_port=plan.http_port,
            xray_inbound_tags=(),
            sidecar_relay_port=(
                plan.xray_sidecar.relay_port
                if plan.xray_sidecar
                else plan.hysteria_sidecar.relay_port
                if plan.hysteria_sidecar
                else plan.amnezia_sidecar.relay_port
                if getattr(plan, "amnezia_sidecar", None)
                else 0
            ),
            protect_ss_port=controller._protect_ss_port,
            protect_ss_password=controller._protect_ss_password,
            ping_host=ping_host,
            ping_port=ping_port,
            outbound_pool_tags=plan.selector_tags,
            hybrid_relay_selector_tags=plan.hybrid_relay_selector_tags,
            hybrid_relay_selected_tag=plan.hybrid_relay_selected_tag,
        )
        pending = getattr(controller, "_pending_amnezia_node_id", None)
        if replacement_amnezia is not None:
            controller.amnezia = replacement_amnezia
        amnezia_committed = True
        if isinstance(pending, str) and pending:
            if session_node is None or session_node.id != pending:
                controller._handle_unexpected_disconnect()
                return False
            controller.state.selected_node_id = pending
            controller._pending_amnezia_node_id = None
            controller.selection_changed.emit(session_node)
        if old_amnezia is not None and (old_amnezia is not controller.amnezia or getattr(plan, "amnezia_sidecar", None) is None):
            old_amnezia.stop()
            if old_amnezia is not controller.amnezia:
                old_amnezia.deleteLater()
        if hysteria_recovery and not controller._commit_pending_hysteria_selection(session_node):
            controller._set_connection_status(
                "error",
                "Новый runtime готов, но selection commit отклонён.",
                level="error",
            )
            controller._handle_unexpected_disconnect()
            return False
        if hysteria_recovery:
            controller._record_hysteria_switch_commit()
        suffix = _runtime_suffix(plan)
        controller._set_connection_status("running", f"Переключено: {session_label}{suffix}", level="success")
        controller.schedule_save()
        return True
    finally:
        if replacement_amnezia is not None and not amnezia_committed:
            replacement_amnezia.stop()
            replacement_amnezia.deleteLater()
        if controller._transition_generation == requested_generation and node is not None and getattr(controller, "_pending_amnezia_node_id", None) == node.id:
            controller._pending_amnezia_node_id = None
        if hysteria_recovery and controller._pending_hysteria_replacement_node_id:
            controller._clear_pending_hysteria_selection()
        controller._switching = False
        controller._auto_switch_transitioning = False
        controller._hysteria_recovery_active = False
        _, controller.connected = controller._refresh_connected_state()
        controller.connection_changed.emit(controller.connected)
        if controller.connected:
            controller._start_metrics_worker()
        else:
            controller._stop_metrics_worker()
