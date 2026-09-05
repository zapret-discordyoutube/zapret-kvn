from __future__ import annotations

import ctypes
import socket
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..constants import DEFAULT_XRAY_STATS_API_PORT
from ..engines.singbox import (
    SingboxRuntimePlan,
    start_proxy as start_singbox_proxy,
    start_tun as start_singbox_tun,
)

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
    if controller._connecting:
        return False
    controller._connecting = True
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

        node = controller.selected_node
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
            controller.proxy.release_if_owned(restore_previous=True)

            controller._tun_log_count = 0
            result = start_singbox_tun(controller, node, prev_active_core=prev_active_core)
        else:
            result = start_singbox_proxy(controller, node, prev_active_core=prev_active_core)
        if result is None:
            return False
        singbox_plan: SingboxRuntimePlan = result.plan
        session_label = result.session_label

        session_node = node
        if not singbox_plan.used_selected_node:
            session_node = None

        if session_node is not None:
            session_node.last_used_at = datetime.now(timezone.utc).isoformat()

        outbound_pool_tags = singbox_plan.selector_tags
        control_core = "xray" if singbox_plan.is_hybrid else "singbox"
        if not controller._pin_started_outbound(session_node, control_core, outbound_pool_tags):
            controller._set_connection_status(
                "error",
                "Ядро запущено, но не подтвердило выбор активного сервера.",
                level="error",
            )
            controller._stop_active_connection_processes(disable_proxy=True)
            return False

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
        controller._capture_active_session(
            session_node,
            tun=tun,
            core=controller._active_core,
            api_port=controller._xray_api_port,
            hybrid=bool(singbox_plan is not None and singbox_plan.is_hybrid),
            sidecar_kind=singbox_plan.sidecar_kind if singbox_plan is not None else "",
            socks_port=singbox_plan.socks_port or None,
            http_port=singbox_plan.http_port or None,
            sidecar_relay_port=(
                singbox_plan.xray_sidecar.relay_port
                if singbox_plan and singbox_plan.xray_sidecar
                else singbox_plan.hysteria_sidecar.relay_port
                if singbox_plan and singbox_plan.hysteria_sidecar
                else singbox_plan.amnezia_sidecar.relay_port
                if singbox_plan and singbox_plan.amnezia_sidecar
                else 0
            ),
            protect_ss_port=controller._protect_ss_port,
            protect_ss_password=controller._protect_ss_password,
            ping_host=(
                controller._infer_singbox_ping_target(
                    singbox_plan.singbox_config,
                    session_node,
                )[0]
            ),
            ping_port=(
                controller._infer_singbox_ping_target(
                    singbox_plan.singbox_config,
                    session_node,
                )[1]
            ),
            outbound_pool_tags=outbound_pool_tags,
            hybrid_relay_selector_tags=(
                singbox_plan.hybrid_relay_selector_tags if singbox_plan is not None else ()
            ),
            hybrid_relay_selected_tag=(
                singbox_plan.hybrid_relay_selected_tag if singbox_plan is not None else ""
            ),
        )
        controller.schedule_save()
        controller._traffic_history.start_session(session_label, "singbox")
        # П5 (AC13): подключение состоялось (сессия зафиксирована, статус
        # running) — фоновый прогрев DNS-кэша zapret для всех нод пула.
        controller._start_proxy_dns_prewarm()
        return True
    finally:
        controller._connecting = False


def disconnect_current(controller: AppController, disable_proxy: bool = True, emit_status: bool = True) -> bool:
    controller._disconnecting = True
    try:
        controller._cleanup_connection_runtime_state(
            end_traffic_session=True,
            reset_auto_switch_cycle=not controller._auto_switch_transitioning,
            reset_auto_switch_cooldown=not controller._reconnecting and not controller._auto_switch_transitioning,
        )
        active_tun = controller._active_session.tun_mode if controller._active_session is not None else controller.state.settings.tun_mode
        if emit_status and active_tun:
            controller.status.emit("info", "Остановка VPN...")
        stopped = controller._stop_active_connection_processes(disable_proxy=disable_proxy)
        if stopped:
            controller._active_core = "singbox"
            controller._clear_active_session()
        if emit_status:
            if stopped:
                controller._set_connection_status("idle", "Отключено", level="info")
            else:
                controller._set_connection_status("error", "Не удалось корректно остановить подключение", level="error")
        return stopped
    finally:
        controller._disconnecting = False


def reconnect(controller: AppController, reason: str) -> bool:
    if controller._reconnecting:
        return False
    controller._reconnecting = True
    controller._switching = True
    try:
        controller._log(f"[reconnect] {reason}")
        controller._set_connection_status("starting", "Переподключение...", level="info")
        stopped = disconnect_current(controller, disable_proxy=False, emit_status=False)
        if not stopped:
            controller._set_connection_status("error", "Не удалось остановить предыдущий процесс Xray", level="error")
            if controller.state.settings.enable_system_proxy:
                controller.proxy.disable(restore_previous=True)
            return False

        ok = connect_selected(controller, allow_during_reconnect=True)
        if not ok and controller.state.settings.enable_system_proxy:
            controller.proxy.disable(restore_previous=True)
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
