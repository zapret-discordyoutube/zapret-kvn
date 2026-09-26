from __future__ import annotations

import ctypes
import socket
from typing import TYPE_CHECKING

from ..constants import DEFAULT_XRAY_STATS_API_PORT
from ..engines.singbox.operations import (
    capture_runtime_session,
    start_proxy_steps as start_singbox_proxy_steps,
    start_tun_steps as start_singbox_tun_steps,
)
from ..engines.singbox import SingboxRuntimePlan
from .async_steps import TransitionSteps, run_steps_blocking

if TYPE_CHECKING:
    from .controller import AppController


def find_free_api_port(preferred: int | None = None, excluded: set[int] | None = None) -> int:
    if preferred is None:
        preferred = DEFAULT_XRAY_STATS_API_PORT
    for port in range(preferred, preferred + 100):
        if excluded and port in excluded:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"No free port in range {preferred}-{preferred + 100}")


def connect_selected(controller: AppController, allow_during_reconnect: bool = False) -> bool:
    """Синхронный драйвер (shutdown/тесты). Переходы — ``connect_selected_steps``."""
    return bool(run_steps_blocking(connect_selected_steps(controller, allow_during_reconnect)))


def connect_selected_steps(controller: AppController, allow_during_reconnect: bool = False) -> TransitionSteps:
    if controller._connecting:
        return False
    controller._connecting = True
    generation = controller._transition_generation
    try:
        if controller._reconnecting and not allow_during_reconnect:
            controller._set_connection_status("starting", "Переподключение...", level="info")
            return False

        if controller.locked:
            controller._set_connection_status(
                "error",
                "Приложение заблокировано. Разблокируйте для подключения.",
                level="warning",
            )
            return False

        node = controller._runtime_selected_node()
        if node is None and not controller._can_connect_without_selected_node():
            message = "В конфиге есть outbound tag `proxy`. Сначала выберите сервер."
            controller._set_connection_status("error", message, level="warning")
            return False

        controller._reset_auto_switch_state(
            reset_cooldown=not controller._auto_switch_transitioning,
            reset_cycle=not controller._auto_switch_transitioning,
        )

        prev_active_core = controller._active_core
        tun = controller.state.settings.tun_mode
        controller._xray_api_port = 0
        session_label = node.name if node else controller.get_active_singbox_config_name()

        if tun:
            controller._log(f"[tun] attempting TUN connect, admin={_is_admin()}")
            controller._set_connection_status("starting", f"Запуск VPN: {session_label}...", level="info")

            if not _is_admin():
                controller._log("[tun] NOT admin — aborting")
                controller._set_connection_status(
                    "error",
                    "Режим TUN требует прав Администратора. Запустите приложение от имени Администратора.",
                    level="error",
                )
                return False

            # Перед TUN принудительно убираем только НАШ системный прокси
            # (или восстанавливаем бэкап); чужой прокси не отключаем.
            yield from controller._proxy_steps("release_if_owned", restore_previous=True)

            controller._tun_log_count = 0
            result = yield from start_singbox_tun_steps(controller, node, prev_active_core=prev_active_core)
        else:
            result = yield from start_singbox_proxy_steps(controller, node, prev_active_core=prev_active_core)
        if result is None:
            return False
        if generation != controller._transition_generation or not controller._desired_connected:
            yield from controller._stop_active_connection_processes_steps(
                disable_proxy=not controller._desired_connected
            )
            controller._refresh_connected_state()
            return False
        singbox_plan: SingboxRuntimePlan = result.plan
        session_label = result.session_label

        session_node = node
        if not singbox_plan.used_selected_node:
            session_node = None

        # Выбор активного сервера уже закреплён в _start_singbox_runtime_plan_steps
        # тем же тегом plan.selected_outbound_tag == selector_tags[node.id] (для
        # гибрида — в Xray-сайдкаре, для нативного пула — в селекторе sing-box).
        # Повторный PUT был дублем и лишним control-plane вызовом на connect.

        controller._set_connection_status(
            "running",
            f"Подключено: {session_label}"
            + (
                " (TUN, xray sidecar)"
                if tun and singbox_plan is not None and singbox_plan.is_hybrid
                else " (TUN, Hysteria2)"
                if tun and singbox_plan is not None and singbox_plan.is_hysteria_sidecar
                else " (sing-box + Xray sidecar)"
                if not tun and singbox_plan is not None and singbox_plan.is_hybrid
                else " (sing-box + Hysteria2)"
                if not tun and singbox_plan is not None and singbox_plan.is_hysteria_sidecar
                else " (sing-box extended)"
                if not tun and singbox_plan is not None
                else " (TUN)" if tun else ""
            ),
            level="success",
        )
        capture_runtime_session(controller, singbox_plan, node, tun=tun)
        if not controller._commit_pending_transport_selection(session_node):
            yield from controller._handle_unexpected_disconnect_steps()
            return False
        controller.schedule_save()
        controller._traffic_history.start_session(session_label, "singbox")
        # П5 (AC13): подключение состоялось (сессия зафиксирована, статус
        # running) — фоновый прогрев DNS-кэша zapret для всех нод пула.
        controller._start_proxy_dns_prewarm()
        return True
    finally:
        controller._connecting = False


def disconnect_current(controller: AppController, disable_proxy: bool = True, emit_status: bool = True) -> bool:
    """Синхронный драйвер (shutdown/обновление ядра). Переходы — ``disconnect_current_steps``."""
    return bool(run_steps_blocking(disconnect_current_steps(controller, disable_proxy, emit_status)))


def disconnect_current_steps(
    controller: AppController, disable_proxy: bool = True, emit_status: bool = True,
) -> TransitionSteps:
    controller._disconnecting = True
    # A pending recovery may have set switching before a runner was started.
    # A user disconnect owns that state too; otherwise callbacks stay muted.
    if not controller._reconnecting:
        controller._switching = False
        controller._hysteria_recovery_active = False
    try:
        controller._cleanup_connection_runtime_state(
            end_traffic_session=True,
            reset_auto_switch_cycle=not controller._auto_switch_transitioning,
            reset_auto_switch_cooldown=not controller._reconnecting and not controller._auto_switch_transitioning,
        )
        active_tun = controller._active_session.tun_mode if controller._active_session is not None else controller.state.settings.tun_mode
        if emit_status and active_tun:
            controller.status.emit("info", "Остановка VPN...")
        stopped = yield from controller._stop_active_connection_processes_steps(disable_proxy=disable_proxy)
        if stopped:
            controller._active_core = "singbox"
            controller._clear_active_session()
        was_connected, connected = controller._refresh_connected_state()
        if was_connected != connected and not controller._switching:
            controller.connection_changed.emit(connected)
        if emit_status:
            if stopped:
                controller._set_connection_status("idle", "Отключено", level="info")
            else:
                controller._set_connection_status("error", "Не удалось корректно остановить подключение", level="error")
        return stopped
    finally:
        controller._disconnecting = False


def reconnect(controller: AppController, reason: str) -> bool:
    """Синхронный драйвер (тесты). Переходы — ``reconnect_steps``."""
    return bool(run_steps_blocking(reconnect_steps(controller, reason)))


def reconnect_steps(controller: AppController, reason: str) -> TransitionSteps:
    if controller._reconnecting:
        return False
    controller._reconnecting = True
    controller._switching = True
    try:
        controller._log(f"[reconnect] {reason}")
        controller._set_connection_status("starting", "Переподключение...", level="info")
        stopped = yield from disconnect_current_steps(controller, disable_proxy=False, emit_status=False)
        if not stopped:
            controller._set_connection_status("error", "Не удалось остановить предыдущий процесс Xray", level="error")
            if controller.state.settings.enable_system_proxy:
                yield from controller._proxy_steps("disable", restore_previous=True)
            return False

        ok = yield from connect_selected_steps(controller, allow_during_reconnect=True)
        if not ok and controller.state.settings.enable_system_proxy:
            yield from controller._proxy_steps("disable", restore_previous=True)
        return ok
    finally:
        controller._reconnecting = False
        controller._switching = False
        controller._auto_switch_transitioning = False
        _, controller.connected = controller._refresh_connected_state()
        controller.connection_changed.emit(controller.connected)
        if controller.connected:
            controller._start_metrics_worker()
        else:
            controller._stop_metrics_worker()


def _is_admin() -> bool:
    if not hasattr(ctypes, "windll"):
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
