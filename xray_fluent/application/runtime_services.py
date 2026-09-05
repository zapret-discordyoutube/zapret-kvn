from __future__ import annotations

from typing import TYPE_CHECKING

from ..constants import SINGBOX_CLASH_API_PORT
from .auto_switch_service import transport_kind_for_node

if TYPE_CHECKING:
    from .controller import AppController


def start_metrics_worker(controller: AppController) -> None:
    # Ленивая загрузка: live_metrics_worker тянет Windows-only win_proc_monitor.
    from ..diagnostics.live_metrics_worker import LiveMetricsWorker

    session = controller._active_session
    node = controller.selected_node
    ping_host = session.ping_host if session is not None else (node.server if node else "")
    ping_port = session.ping_port if session is not None else (node.port if node else 0)
    transport_kind = transport_kind_for_node(node)
    controller._log(f"[metrics] starting worker, active_core={controller._active_core}")

    stop_metrics_worker(controller)
    if controller._active_core == "singbox":
        mode = "singbox"
    elif controller._active_session is not None and controller._active_session.tun_mode:
        mode = "xray-tun"
    else:
        mode = "xray"
    socks_port, http_port = controller.get_effective_proxy_ports()
    inbound_tags = controller._active_session.xray_inbound_tags if controller._active_session else ()
    controller._metrics_worker = LiveMetricsWorker(
        controller.state.settings.xray_path,
        controller._xray_api_port,
        ping_host=ping_host,
        ping_port=ping_port,
        mode=mode,
        clash_api_port=controller._singbox_clash_api_port or SINGBOX_CLASH_API_PORT,
        socks_port=socks_port,
        http_port=http_port,
        xray_inbound_tags=list(inbound_tags),
        transport_kind=transport_kind,
    )
    controller._metrics_worker.metrics.connect(controller._on_live_metrics)
    controller._metrics_worker.start()


def stop_metrics_worker(controller: AppController, *, wait: bool = False) -> None:
    worker = controller._metrics_worker
    controller._metrics_worker = None
    if not worker:
        return
    try:
        worker.metrics.disconnect(controller._on_live_metrics)
    except (TypeError, RuntimeError):
        pass
    if not worker.isRunning():
        return
    worker.stop()
    if wait:
        # Блокирующий путь — только для shutdown приложения.
        worker.wait(1200)
        return
    # Горячий путь (hot-swap): не блокируем GUI-поток ожиданием потока —
    # воркер доживает в списке retiring и удаляется по своему finished.
    retiring = _retiring_metrics_workers(controller)
    retiring.append(worker)

    def _release(_done: list[bool] = []) -> None:
        if _done:
            return
        _done.append(True)
        try:
            retiring.remove(worker)
        except ValueError:
            pass
        worker.deleteLater()

    worker.finished.connect(_release)
    if not worker.isRunning():
        _release()


def _retiring_metrics_workers(controller: AppController) -> list:
    workers = getattr(controller, "_retiring_metrics_workers", None)
    if workers is None:
        workers = []
        controller._retiring_metrics_workers = workers
    return workers


def cleanup_connection_runtime_state(
    controller: AppController,
    *,
    end_traffic_session: bool,
    reset_auto_switch_cycle: bool,
    reset_auto_switch_cooldown: bool,
) -> None:
    controller._xray_tun_routes.cleanup()
    controller._xray_api_port = 0
    controller._singbox_clash_api_port = 0
    controller._protect_ss_port = 0
    controller._protect_ss_password = ""
    controller._traffic_save_counter = 0
    controller._active_singbox_plan = None
    controller._hysteria_failure_started_at = 0.0
    controller._reset_auto_switch_state(
        reset_cooldown=reset_auto_switch_cooldown,
        reset_cycle=reset_auto_switch_cycle,
    )
    if end_traffic_session:
        controller._traffic_history.end_session()
    from ..platform.windows.process_traffic_collector import reset_connection_tracking
    from ..platform.windows.win_proc_monitor import clear_pid_cache
    reset_connection_tracking()
    clear_pid_cache()


def stop_active_connection_processes(controller: AppController, *, disable_proxy: bool) -> bool:
    stopped = True

    # Close traffic admission before stopping its transport.
    for manager in (controller.singbox, controller.xray, controller.hysteria, getattr(controller, "amnezia", None)):
        if manager is None:
            continue
        if manager.is_running:
            stopped = manager.stop() and stopped

    if disable_proxy and controller.state.settings.enable_system_proxy:
        controller.proxy.disable(restore_previous=True)

    return stopped


def handle_unexpected_disconnect(controller: AppController) -> None:
    if controller._cleaning_connection_state:
        return
    controller._cleaning_connection_state = True
    try:
        cleanup_connection_runtime_state(
            controller,
            end_traffic_session=True,
            reset_auto_switch_cycle=not controller._auto_switch_transitioning,
            reset_auto_switch_cooldown=True,
        )
        stop_active_connection_processes(controller, disable_proxy=not controller._reconnecting)
        controller._active_core = (
            "singbox"
            if not controller.state.settings.tun_mode
            and str(controller.state.settings.proxy_engine) == "singbox"
            else "xray"
        )
        controller._clear_active_session()
        if not controller._reconnecting:
            controller._desired_connected = False
    finally:
        controller._auto_switch_transitioning = False
        controller._cleaning_connection_state = False


def on_core_state_changed(controller: AppController, _running: bool) -> None:
    if (
        not _running
        and getattr(controller, "_hysteria_recovery_active", False)
        and getattr(controller, "_switching", False)
    ):
        # The Hysteria transition coordinator owns this failure episode.  Keep
        # the logical old session long enough for the normal hot-swap planner
        # to prepare a generation-specific replacement.  Generic cleanup here
        # would cancel that transition and could tear down generation N+1.
        stop_metrics_worker(controller)
        return
    was_connected, is_connected = controller._refresh_connected_state()
    if not controller._switching and was_connected != is_connected:
        controller.connection_changed.emit(is_connected)
    if is_connected and not controller._switching and not was_connected:
        start_metrics_worker(controller)
    elif not is_connected:
        stop_metrics_worker(controller)
        if was_connected and not controller._switching:
            controller.live_metrics_updated.emit(
                {
                    "down_bps": None,
                    "up_bps": None,
                    "traffic_valid": False,
                    "latency_ms": None,
                    "probe_kind": "none",
                    "probe_valid": None,
                }
            )
            if not controller._disconnecting:
                handle_unexpected_disconnect(controller)
    if (
        not is_connected
        and controller.state.settings.enable_system_proxy
        and not controller._reconnecting
        and not controller._switching
    ):
        controller.proxy.disable(restore_previous=True)


def on_live_metrics(controller: AppController, payload: dict[str, object]) -> None:
    controller.live_metrics_updated.emit(payload)
    raw_down_bps = payload.get("down_bps")
    traffic_valid = bool(payload.get("traffic_valid", raw_down_bps is not None))
    # Keep an invalid sample distinct from a real zero-speed sample.  The UI
    # may still render the fallback zero, but auto-switch receives the validity
    # bit and will not treat a failed stats/API read as degradation.
    down_bps = float(raw_down_bps) if raw_down_bps is not None else 0.0
    # link_alive: вердикт TCP-пинга активной ноды; None — пинг не настроен,
    # тогда детектор мёртвого сервера не участвует в решении.
    link_alive: bool | None = None
    worker = controller._metrics_worker
    if worker is not None and worker.pings_active_node():
        link_alive = payload.get("latency_ms") is not None
    controller._check_auto_switch(down_bps, link_alive, traffic_valid=traffic_valid)
    process_stats = payload.get("process_stats")
    if process_stats:
        stats_dict = {}
        for ps in process_stats:
            stats_dict[ps.exe] = (ps.upload, ps.download, ps.route)
        controller._traffic_history.update_session(stats_dict)
        controller._traffic_save_counter += 1
        if controller._traffic_save_counter >= 15:
            controller._traffic_history.save_periodic()
            controller._traffic_save_counter = 0


def shutdown(controller: AppController) -> None:
    if controller._transition_timer.isActive():
        controller._transition_timer.stop()
    if controller._subscription_timer.isActive():
        controller._subscription_timer.stop()
    controller._subscription_update_queue.clear()
    controller._subscription_queued_ids.clear()
    controller._subscription_check_ids.clear()
    for worker in list(controller._subscription_workers.values()):
        if worker.isRunning():
            # Auto mode may perform one 15-second direct attempt and one proxy retry.
            worker.wait(32000)
    for worker in list(controller._proxy_protection_workers.values()):
        if worker.isRunning():
            worker.wait(5000)
    manual_zapret_worker = controller._manual_zapret_worker
    if manual_zapret_worker is not None and manual_zapret_worker.isRunning():
        manual_zapret_worker.wait(5000)
    controller._country_shutdown = True
    if controller._country_resolver and controller._country_resolver.isRunning():
        controller._country_resolver.requestInterruption()
        controller._country_resolver.wait(2000)
    if controller._ping_worker and controller._ping_worker.isRunning():
        controller._ping_worker.cancel()
        controller._ping_worker.wait(500)
    if controller._connectivity_worker and controller._connectivity_worker.isRunning():
        controller._connectivity_worker.wait(1000)
    stop_metrics_worker(controller, wait=True)
    for worker in list(_retiring_metrics_workers(controller)):
        if worker.isRunning():
            worker.wait(1200)
    if controller._speed_worker and controller._speed_worker.isRunning():
        controller._speed_worker.cancel()
        controller._speed_worker.wait(20000)
    if controller._xray_update_worker and controller._xray_update_worker.isRunning():
        controller._xray_update_worker.wait(1000)

    controller.disconnect_current()
    if getattr(controller, "amnezia", None) is not None:
        controller.amnezia.stop()
    if controller.hysteria.is_running:
        controller.hysteria.stop()
    if controller.singbox.is_running:
        controller.singbox.stop()
    if controller.xray.is_running:
        controller.xray.stop()
    controller._xray_tun_routes.cleanup()
    if controller.zapret.running:
        controller.zapret.stop()
    # Выключаем только наш прокси (или восстанавливаем из бэкапа):
    # чужой/корпоративный прокси при завершении не трогаем.
    controller.proxy.release_if_owned(restore_previous=True)
    controller._cleanup_tun_adapter()
    controller.network_monitor.stop()
    controller._lock_timer.stop()
    controller.save()
