from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import logging
import random
import socket
import time
from datetime import datetime, timezone
import json
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import TYPE_CHECKING, Any

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from .config import (
    SingboxDocumentCache,
    apply_singbox_config_text as apply_singbox_config_text_operation,
    apply_xray_config_text as apply_xray_config_text_operation,
    apply_xray_tun_loop_prevention as apply_xray_tun_loop_prevention_operation,
    build_runtime_xray_config as build_runtime_xray_config_operation,
    collect_xray_inbound_ports,
    config_has_proxy_outbound,
    default_singbox_config_text,
    default_xray_config_text,
    ensure_active_config as ensure_active_config_operation,
    ensure_dict,
    ensure_list,
    ensure_xray_metrics_contract as ensure_xray_metrics_contract_operation,
    ensure_xray_tun_contract as ensure_xray_tun_contract_operation,
    extract_xray_runtime_ports,
    format_json_error_message,
    get_active_config_name as get_active_config_name_operation,
    get_active_config_path as get_active_config_path_operation,
    get_active_template_path as get_active_template_path_operation,
    import_template as import_template_operation,
    infer_singbox_outbound_endpoint,
    infer_singbox_ping_target,
    infer_xray_outbound_endpoint,
    infer_xray_ping_target,
    inspect_active_xray_config as inspect_active_xray_config_operation,
    is_local_runtime_host,
    load_active_config_text as load_active_config_text_operation,
    load_config_text as load_config_text_operation,
    normalize_relative_json_path,
    replace_or_append_tagged,
    reset_active_config_to_template as reset_active_config_to_template_operation,
    resolve_profile_path,
    save_config_text as save_config_text_operation,
    validate_json_text,
    xray_outbound_is_loop_protected as xray_outbound_is_loop_protected_operation,
)
from .nodes import (
    bulk_update_nodes as bulk_update_nodes_operation,
    check_auto_switch as check_auto_switch_operation,
    detect_countries_sync as detect_countries_sync_operation,
    get_all_groups as get_all_groups_operation,
    get_all_tags as get_all_tags_operation,
    get_fastest_alive_node as get_fastest_alive_node_operation,
    get_next_node_for_auto_switch as get_next_node_for_auto_switch_operation,
    get_node_by_id as get_node_by_id_operation,
    import_nodes_from_text as import_nodes_from_text_operation,
    on_countries_resolved as on_countries_resolved_operation,
    prepare_node_for_runtime as prepare_node_for_runtime_operation,
    remove_nodes as remove_nodes_operation,
    reorder_nodes as reorder_nodes_operation,
    set_selected_node as set_selected_node_operation,
    start_country_ip_resolution as start_country_ip_resolution_operation,
    update_node as update_node_operation,
)
from .auto_switch_service import (
    begin_auto_switch_warmup,
    transport_kind_for_node,
)
from ..diagnostics.runtime_errors import RuntimeErrorJournal, core_failure, is_core_error_line
from ..engines.hysteria.runtime_contract import (
    AUTOMATIC_SWITCH_FAILURES,
    SECURITY_FAILURES,
    HysteriaFailureCode,
    HysteriaRuntimeState,
    HysteriaTransitionContract,
    classify_hysteria_uri,
    node_is_maintenance,
)
from .singbox_config_recovery import (
    SingboxConfigRepair,
    repair_singbox_config_file,
    try_repair_singbox_config_text,
)
from .runtime import (
    ActiveSessionSnapshot,
    TransitionContext,
    XrayRuntimeConfig,
    build_active_session_snapshot,
    can_apply_proxy_runtime_change as can_apply_proxy_runtime_change_rule,
    can_proxy_hot_swap as can_proxy_hot_swap_rule,
    can_tun_hot_swap as can_tun_hot_swap_rule,
    cancel_speed_test as cancel_speed_test_operation,
    cleanup_connection_runtime_state as cleanup_connection_runtime_state_operation,
    compute_transition_action,
    connect_selected as connect_selected_operation,
    disconnect_current as disconnect_current_operation,
    handle_unexpected_disconnect as handle_unexpected_disconnect_operation,
    needs_transition,
    on_connectivity_result as on_connectivity_result_operation,
    on_core_state_changed as on_core_state_changed_operation,
    on_live_metrics as on_live_metrics_operation,
    on_ping_complete as on_ping_complete_operation,
    on_ping_progress as on_ping_progress_operation,
    on_ping_result as on_ping_result_operation,
    on_speed_complete as on_speed_complete_operation,
    on_speed_node_progress as on_speed_node_progress_operation,
    on_speed_progress as on_speed_progress_operation,
    on_speed_result as on_speed_result_operation,
    on_xray_update_worker_done as on_xray_update_worker_done_operation,
    ping_nodes as ping_nodes_operation,
    reconnect as reconnect_operation,
    routing_signature as routing_signature_operation,
    run_xray_core_update as run_xray_core_update_operation,
    shutdown as shutdown_operation,
    signature as signature_operation,
    speed_test_nodes as speed_test_nodes_operation,
    start_metrics_worker as start_metrics_worker_operation,
    stop_active_connection_processes as stop_active_connection_processes_operation,
    stop_metrics_worker as stop_metrics_worker_operation,
    system_proxy_bypass_lan as system_proxy_bypass_lan_operation,
    test_connectivity as test_connectivity_operation,
    transition_request_delay_ms,
    transition_signature as transition_signature_operation,
    transition_status_text,
    tun_layer_signature as tun_layer_signature_operation,
    xray_layer_signature as xray_layer_signature_operation,
)
from .subscription_service import (
    apply_not_modified,
    hide_subscription_node as hide_subscription_node_operation,
    mark_subscription_failure,
    reconcile_subscription,
    remove_subscription as remove_subscription_operation,
    subscription_due,
)
from .async_steps import TransitionRunner, TransitionSteps, run_in_worker, run_steps_blocking
from .rotation_service import (
    RotationPlan,
    build_rotation_plan,
    pick_next_node,
    rotation_interval_ms,
)
from .outbound_pool_service import (
    SINGBOX_SELECTOR_TAG,
    XRAY_BALANCER_TAG,
    XrayOutboundPool,
    build_xray_outbound_pool,
)
from ..profiles.country_flags import CountryResolver
from ..network.background_workers import (
    ProxyProtectionResolver,
    StateSaveWorker,
    SubscriptionUpdateWorker,
    TargetProfileResolver,
)
from ..engines.xray import (
    XrayManager,
    XrayTunRouteManager,
    apply_balancer_override,
    build_xray_config,
    get_windows_default_route_context,
    get_xray_version,
)
from ..engines.hysteria import HysteriaManager
from ..engines.amnezia.manager import AmneziaManager
from ..engines.singbox import (
    SingBoxManager,
    classify_node_for_singbox,
    get_singbox_version,
    parse_singbox_document,
    plan_singbox_proxy_runtime,
    plan_singbox_runtime,
    restart_proxy_runtime as restart_singbox_proxy_runtime_operation,
    restart_runtime as restart_singbox_runtime_operation,
    SingboxDocumentState,
    SingboxRuntimePlan,
    select_outbound as select_singbox_outbound,
    select_outbound_when_ready as select_singbox_outbound_when_ready,
)
from ..constants import (
    APP_NAME,
    DEFAULT_HTTP_PORT,
    DEFAULT_SOCKS_PORT,
    DEFAULT_XRAY_STATS_API_PORT,
    LOG_DIR,
    PROXY_HOST,
    ROUTING_MODES,
    SINGBOX_CLASH_API_PORT,
    SINGBOX_PROVIDER_FILE,
    SINGBOX_CONFIGS_DIR,
    SINGBOX_DEFAULT_CONFIG_NAME,
    SINGBOX_TEMPLATES_DIR,
    XRAY_CONFIGS_DIR,
    XRAY_DEFAULT_CONFIG_NAME,
    XRAY_TUN_DEFAULT_INTERFACE_NAME,
    XRAY_TEMPLATES_DIR,
    STATE_SCHEMA_VERSION,
)
from ..diagnostics.export import collect_runtime_diagnostics, export_diagnostics
from ..profiles.models import (
    AppSettings,
    AppState,
    Node,
    RoutingSettings,
    Subscription,
    SubscriptionUpdateResult,
    clamp_subscriptions_check_interval,
    normalize_subscription_warnings,
    utc_now_iso,
)
from ..importer.subscription_http import (
    normalize_client_profile,
    resolve_subscription_source,
    validate_hwid,
)
from ..importer.subscription_parser import validate_filter_patterns
from ..network.network_monitor import NetworkMonitor
from ..platform.windows.proxy_manager import ProxyManager, SystemProxyState
from ..platform.windows.security import create_password_hash, get_idle_seconds, verify_password
from ..diagnostics.runtime_logging import (
    RuntimeLogContext,
    RuntimeNodeIdentity,
    contextualize_runtime_log,
    identities_for_tags,
    runtime_mapping_lines,
)
from ..profiles.storage import PassphraseRequired, StateStorage
from ..platform.windows.startup import build_startup_command, set_startup_enabled
from ..platform.windows.subprocess_utils import result_output_text, run_text, sleep_with_events
from ..diagnostics.traffic_history import TrafficHistoryStorage
from .zapret_prewarm_service import start_proxy_dns_prewarm
from ..engines.zapret.manager import ZapretManager
from ..engines.zapret.target import ZapretEndpointSpec

if TYPE_CHECKING:
    from ..profiles.country_flags import CountryResolver as CountryResolverType
    from ..network.connectivity_test import ConnectivityTestWorker
    from ..engines.xray import XrayCoreUpdateResult, XrayCoreUpdateWorker
    from ..diagnostics.live_metrics_worker import LiveMetricsWorker
    from ..network.ping_worker import PingWorker
    from ..network.speed_test_worker import SpeedTestWorker


def _increment_int(value: object) -> int:
    """Advance a generation counter, including lightweight Mock controllers in tests."""

    return value + 1 if isinstance(value, int) else 1


def _find_free_api_port(preferred: int | None = None, excluded: set[int] | None = None) -> int:
    """Find a free TCP port near *preferred* for the xray stats API."""
    if preferred is None:
        preferred = DEFAULT_XRAY_STATS_API_PORT
    for port in range(preferred, preferred + 100):
        if excluded and port in excluded:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"No free port in range {preferred}-{preferred + 100}")


# AC6 (startup-subscription-settings): hard fallback for the
# "after_subscriptions" startup order — auto-connect proceeds after this delay
# even if startup subscription updates hang or fail (spec limit: <= 30 s).
STARTUP_CONNECT_FALLBACK_MS = 20_000

_XRAY_METRICS_API_TAG = "__app_metrics_api"
_XRAY_METRICS_API_INBOUND_TAG = "__app_metrics_api_in"
_XRAY_TUN_INBOUND_TAG = "__app_tun_in"


@dataclass(slots=True)
class HotSwitchPlan:
    """Immutable outcome of the pure hot-switch feasibility checks (П2).

    Captured on the GUI thread in the same tick the switch attempt starts, so
    the async steps operate on a consistent snapshot of session/pool state.
    """

    node: Node
    session: ActiveSessionSnapshot
    tags: dict[str, str]
    tag: str
    control_core: str
    previous_tag: str


class AppController(QObject):
    runtime_errors_changed = pyqtSignal(object)
    nodes_changed = pyqtSignal(object)
    subscriptions_changed = pyqtSignal(object)
    subscription_update_started = pyqtSignal(str)
    subscription_update_progress = pyqtSignal(str, str)
    subscription_update_finished = pyqtSignal(object)
    selection_changed = pyqtSignal(object)
    connection_changed = pyqtSignal(bool)
    connection_status_changed = pyqtSignal(str, str)
    routing_changed = pyqtSignal(object)
    settings_changed = pyqtSignal(object)
    log_line = pyqtSignal(str)
    status = pyqtSignal(str, str)
    bulk_task_progress = pyqtSignal(str, int, int, bool)  # task, current, total, completed
    ping_updated = pyqtSignal(str, object)
    speed_updated = pyqtSignal(str, object, bool)  # node_id, speed_mbps, is_alive
    speed_progress_updated = pyqtSignal(str, int)  # node_id, percent
    speed_test_cancelled = pyqtSignal(int, int)  # completed, total
    connectivity_test_done = pyqtSignal(bool, str, object)
    live_metrics_updated = pyqtSignal(object)
    xray_update_result = pyqtSignal(object)
    lock_state_changed = pyqtSignal(bool)
    passphrase_required = pyqtSignal()
    auto_switch_triggered = pyqtSignal(str)  # node name we're switching to
    transition_state_changed = pyqtSignal(bool, str)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self.storage = StateStorage()
        self.xray = XrayManager(self)
        self.singbox = SingBoxManager(self)
        self.hysteria = HysteriaManager(self)
        self.amnezia = self._new_amnezia_manager()
        self._amnezia_target_generation = 0
        self._pending_amnezia_node_id = None
        self._xray_tun_routes = XrayTunRouteManager(self)
        self.zapret = ZapretManager(self)
        self.proxy = ProxyManager()
        self.network_monitor = NetworkMonitor(parent=self)

        self.state = AppState()
        self._node_lookup_source_id = 0
        self._node_lookup_size = -1
        self._node_by_id: dict[str, Node] = {}
        self.recent_logs: list[str] = []
        self.runtime_errors = RuntimeErrorJournal()
        self.connected = False
        self.locked = False

        # --- File logger (5 MB × 3 rotated files in data/logs/) ---
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger("xray_fluent")
        self._logger.setLevel(logging.DEBUG)
        if not self._logger.handlers:
            handler = RotatingFileHandler(
                LOG_DIR / "app.log",
                maxBytes=5 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(asctime)s  %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
            self._logger.addHandler(handler)

        self._country_resolver: CountryResolver | None = None
        self._ping_worker: PingWorker | None = None
        self._speed_worker: SpeedTestWorker | None = None
        self._connectivity_worker: ConnectivityTestWorker | None = None
        self._metrics_worker: LiveMetricsWorker | None = None
        self._xray_update_worker: XrayCoreUpdateWorker | None = None
        self._state_save_worker: StateSaveWorker | None = None
        self._subscription_workers: dict[str, SubscriptionUpdateWorker] = {}
        self._subscription_update_queue: list[
            tuple[Subscription, str, bool, bool, bool]
        ] = []
        self._subscription_queued_ids: set[str] = set()
        self._pending_subscription_additions: dict[str, Subscription] = {}
        self._subscription_check_ids: set[str] = set()
        self._proxy_protection_workers: dict[int, TargetProfileResolver] = {}
        self._manual_zapret_worker: TargetProfileResolver | None = None
        self._manual_zapret_generation = 0
        self._proxy_protection_wait_generation = 0
        self._proxy_protection_wait_token = 0
        self._singbox_documents = SingboxDocumentCache()
        self._ping_total = 0
        self._ping_completed = 0
        self._speed_total = 0
        self._speed_completed = 0
        self._xray_update_silent = False
        self._reconnect_after_xray_update = False
        self._reconnecting = False
        self._connecting = False
        self._disconnecting = False
        self._cleaning_connection_state = False
        self._switching = False  # suppress intermediate UI updates during stop→start
        self._active_core: str = "singbox"  # "xray" | "singbox" | "tun2socks"
        self._protect_ss_port: int = 0
        self._protect_ss_password: str = ""
        self._tun2socks_proxy_username: str = ""
        self._tun2socks_proxy_password: str = ""
        self._xray_api_port: int = 0
        self._singbox_clash_api_port: int = 0
        self._traffic_history = TrafficHistoryStorage(load=False)
        self._traffic_save_counter = 0

        # --- Auto-switch state ---
        self._auto_switch_low_since: float = 0.0  # monotonic timestamp when speed first dropped
        self._auto_switch_last_switch: float = 0.0  # monotonic timestamp of last auto-switch
        self._auto_switch_high_ticks: int = 0  # consecutive readings above threshold
        self._auto_switch_active_download: bool = False  # True after sustained traffic
        self._auto_switch_cycle_attempts: int = 0
        self._auto_switch_exhausted: bool = False
        self._auto_switch_transitioning: bool = False
        self._auto_switch_link_down_since: float = 0.0  # monotonic ts of first failed active-node ping
        self._auto_switch_manual_hold: bool = False
        self._auto_switch_warmup_until: float = 0.0
        self._auto_switch_health_node_id: str | None = None
        self._active_session: ActiveSessionSnapshot | None = None
        self._desired_connected = False
        self._transition_active = False
        self._transition_scheduled = False
        self._transition_pending = False
        self._transition_reason = ""
        self._transition_generation = 0
        self._blocked_transition_signature = ""
        self._transition_runner: TransitionRunner | None = None
        # П2 (AC5/AC8): асинхронный горячий свитч — control-plane I/O в воркере,
        # generation-сериализация запросов, устаревший результат отбрасывается.
        self._hot_switch_runner: TransitionRunner | None = None
        self._hot_switch_generation = 0
        self._hot_switch_pending = False
        # П3 (AC9/AC10): кэш пула outbound'ов по идентичности списка нод.
        self._xray_outbound_pool_cache: XrayOutboundPool | None = None
        self._xray_outbound_pool_cache_key: tuple | None = None
        self._core_log_contexts: dict[str, RuntimeLogContext] = {}
        self._active_singbox_plan: SingboxRuntimePlan | None = None
        self._session_generation = 0
        self._front_process_generation = 0
        self._front_target_generation = 0
        self._relay_credentials_generation = 0
        self._hysteria_process_generation = 0
        self._hysteria_active_generation = 0
        self._hysteria_failure_episode_id = 0
        self._hysteria_last_failure_code: HysteriaFailureCode | None = None
        self._hysteria_automatic_switch_attempted = False
        self._hysteria_recovery_active = False
        self._pending_hysteria_replacement_node_id: str | None = None
        self._hysteria_cooldown_until: dict[str, float] = {}
        self._hysteria_failure_started_at = 0.0
        self._hysteria_contract = HysteriaTransitionContract()

        self.xray.log_received.connect(self._on_xray_log)
        self.xray.error.connect(self._on_xray_error)
        self.xray.state_changed.connect(self._on_core_state_changed)
        self.xray.stopped.connect(lambda code: self._on_core_stopped("xray", code))

        self.singbox.log_received.connect(lambda line: self._on_core_log("sing-box", line))
        self.singbox.error.connect(lambda message: self._on_core_error("sing-box", message))
        self.singbox.state_changed.connect(self._on_core_state_changed)
        self.singbox.stopped.connect(lambda code: self._on_core_stopped("singbox", code))

        self._bind_hysteria_manager(self.hysteria)

        self._xray_tun_routes.log_received.connect(self._on_xray_log)
        self.zapret.target_profile_ready.connect(self._on_proxy_protection_ready)
        self.zapret.target_profile_failed.connect(self._on_proxy_protection_failed)
        self.zapret.stopped.connect(self._on_zapret_stopped_safety)

        self.network_monitor.network_changed.connect(self._on_network_changed)
        self.connection_changed.connect(lambda _: self._sync_rotation_timer())
        # П3 (AC10): любое изменение нод инвалидирует кэш пула явно — идентичность
        # списка не видит in-place правок содержимого outbound-словаря.
        self.nodes_changed.connect(lambda _nodes: self._invalidate_xray_outbound_pool_cache())

        self._lock_timer = QTimer(self)
        self._lock_timer.setInterval(15_000)
        self._lock_timer.timeout.connect(self._check_auto_lock)
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(250)
        self._save_timer.timeout.connect(self._flush_scheduled_save)
        self._save_pending = False
        self._transition_timer = QTimer(self)
        self._transition_timer.setSingleShot(True)
        self._transition_timer.timeout.connect(self._drain_transition_queue)
        self._subscription_timer = QTimer(self)
        self._subscription_timer.setInterval(15 * 60 * 1000)
        self._subscription_timer.timeout.connect(self._check_due_subscriptions)
        # AC6: deferred auto-connect for startup_connect_order="after_subscriptions"
        self._startup_connect_pending = False
        self._startup_connect_timer = QTimer(self)
        self._startup_connect_timer.setSingleShot(True)
        self._startup_connect_timer.setInterval(STARTUP_CONNECT_FALLBACK_MS)
        self._startup_connect_timer.timeout.connect(self._finish_startup_connect)
        self._rotation_timer = QTimer(self)
        self._rotation_timer.setSingleShot(True)
        self._rotation_timer.timeout.connect(self._on_rotation_tick)
        self._rotation_rng = random.Random()
        self._rotation_pool_logged = ""
        self._rotation_running = False

    def load(self, state=None, history=None) -> bool:
        try:
            self.state = state if state is not None else self.storage.load()
            self._traffic_history = history if history is not None else TrafficHistoryStorage()
        except PassphraseRequired:
            self.passphrase_required.emit()
            return False

        self.zapret.set_target_settings(self.state.settings.zapret_target)
        self._detect_countries_sync()
        self._migrate_sort_order()
        if self.state.schema_version != STATE_SCHEMA_VERSION:
            self.state.schema_version = STATE_SCHEMA_VERSION
            self.schedule_save()
        self.nodes_changed.emit(self.state.nodes)
        self.subscriptions_changed.emit(self.state.subscriptions)
        self.selection_changed.emit(self.selected_node)
        self.routing_changed.emit(self.state.routing)
        self.settings_changed.emit(self.state.settings)
        QTimer.singleShot(500, self._start_country_ip_resolution)

        self.network_monitor.start()
        self._lock_timer.start()
        self._apply_subscription_timer_interval()
        self._subscription_timer.start()
        if self._startup_subscription_check_enabled():
            QTimer.singleShot(30_000, self._check_due_subscriptions)
        return True

    def set_data_passphrase(self, passphrase: str) -> None:
        self.storage.passphrase = passphrase
        self.save()
        self.status.emit("success", "Шифрование данных включено")

    def clear_data_passphrase(self) -> None:
        self.storage.passphrase = ""
        self.save()
        self.status.emit("info", "Шифрование данных отключено (портативный режим)")

    def is_data_encrypted(self) -> bool:
        return self.storage.is_encrypted()

    def save(self) -> None:
        if self._save_timer.isActive():
            self._save_timer.stop()
        self._save_pending = False
        worker = self._state_save_worker
        if worker is not None and worker.isRunning():
            worker.wait(5000)
        if self._state_save_worker is worker:
            self._state_save_worker = None
            if worker is not None:
                worker.deleteLater()
        self.storage.save(self.state)

    def schedule_save(self) -> None:
        self._save_pending = True
        self._save_timer.start()

    def _flush_scheduled_save(self) -> None:
        if not self._save_pending:
            return
        if self._state_save_worker is not None and self._state_save_worker.isRunning():
            return
        self._save_pending = False
        worker = StateSaveWorker(self.storage, deepcopy(self.state), parent=self)
        self._state_save_worker = worker
        worker.failed.connect(lambda message: self._log(f"[storage] background save failed: {message}"))
        worker.finished.connect(lambda worker=worker: self._on_scheduled_save_finished(worker))
        worker.start()

    def _on_scheduled_save_finished(self, worker: StateSaveWorker) -> None:
        if self._state_save_worker is worker:
            self._state_save_worker = None
        worker.deleteLater()
        if self._save_pending and not self._save_timer.isActive():
            QTimer.singleShot(0, self._flush_scheduled_save)

    @staticmethod
    def _signature(payload: object) -> str:
        return signature_operation(payload)

    def _routing_signature(self, routing: RoutingSettings | None = None) -> str:
        return routing_signature_operation(self, routing)

    def is_singbox_tun_mode(self, settings: AppSettings | None = None) -> bool:
        settings = settings or self.state.settings
        return bool(settings.tun_mode)

    def is_singbox_proxy_mode(self, settings: AppSettings | None = None) -> bool:
        settings = settings or self.state.settings
        return not settings.tun_mode

    def is_singbox_editor_mode(self, settings: AppSettings | None = None) -> bool:
        return True

    def is_xray_tun_mode(self, settings: AppSettings | None = None) -> bool:
        return False

    def is_tun2socks_mode(self, settings: AppSettings | None = None) -> bool:
        return False

    def uses_xray_raw_config(self, settings: AppSettings | None = None) -> bool:
        return False

    def _can_connect_without_selected_node(self, settings: AppSettings | None = None) -> bool:
        _, _, has_proxy_outbound = self._inspect_active_singbox_config()
        return not has_proxy_outbound

    def _system_proxy_bypass_lan(self, settings: AppSettings | None = None) -> bool:
        return system_proxy_bypass_lan_operation(self, settings)

    def get_singbox_config_dir(self) -> Path:
        SINGBOX_CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
        return SINGBOX_CONFIGS_DIR

    def get_xray_config_dir(self) -> Path:
        XRAY_CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
        return XRAY_CONFIGS_DIR

    def get_singbox_template_dir(self) -> Path:
        SINGBOX_TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
        return SINGBOX_TEMPLATES_DIR

    def get_xray_template_dir(self) -> Path:
        XRAY_TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
        return XRAY_TEMPLATES_DIR

    def _normalize_singbox_config_relative_path(self, value: str | Path | None) -> str:
        return normalize_relative_json_path(value, SINGBOX_DEFAULT_CONFIG_NAME)

    def _normalize_singbox_template_relative_path(self, value: str | Path | None) -> str:
        return self._normalize_singbox_config_relative_path(value)

    def _resolve_singbox_config_path(self, path: str | Path | None = None) -> Path:
        value = self.state.settings.singbox_config_file if path is None or not str(path).strip() else path
        return resolve_profile_path(
            self.get_singbox_config_dir(),
            value,
            SINGBOX_DEFAULT_CONFIG_NAME,
            label="sing-box",
        )

    def _resolve_singbox_template_path(self, path: str | Path | None = None) -> Path:
        value = self.state.settings.singbox_template_file if path is None or not str(path).strip() else path
        return resolve_profile_path(
            self.get_singbox_template_dir(),
            value,
            SINGBOX_DEFAULT_CONFIG_NAME,
            label="sing-box template",
        )

    def _normalize_xray_config_relative_path(self, value: str | Path | None) -> str:
        return normalize_relative_json_path(value, XRAY_DEFAULT_CONFIG_NAME)

    def _normalize_xray_template_relative_path(self, value: str | Path | None) -> str:
        return self._normalize_xray_config_relative_path(value)

    def _resolve_xray_config_path(self, path: str | Path | None = None) -> Path:
        value = self.state.settings.xray_config_file if path is None or not str(path).strip() else path
        return resolve_profile_path(
            self.get_xray_config_dir(),
            value,
            XRAY_DEFAULT_CONFIG_NAME,
            label="xray",
        )

    def _resolve_xray_template_path(self, path: str | Path | None = None) -> Path:
        value = self.state.settings.xray_template_file if path is None or not str(path).strip() else path
        return resolve_profile_path(
            self.get_xray_template_dir(),
            value,
            XRAY_DEFAULT_CONFIG_NAME,
            label="xray template",
        )

    def _set_active_singbox_config_path(self, path: Path, *, emit_signal: bool = True) -> Path:
        resolved = self._resolve_singbox_config_path(path)
        relative = resolved.relative_to(self.get_singbox_config_dir().resolve()).as_posix()
        if self.state.settings.singbox_config_file == relative:
            return resolved
        self.state.settings.singbox_config_file = relative
        if emit_signal:
            self.settings_changed.emit(self.state.settings)
        self.schedule_save()
        return resolved

    def _set_active_singbox_template_path(self, path: Path, *, emit_signal: bool = True) -> Path:
        resolved = self._resolve_singbox_template_path(path)
        relative = resolved.relative_to(self.get_singbox_template_dir().resolve()).as_posix()
        if self.state.settings.singbox_template_file == relative:
            return resolved
        self.state.settings.singbox_template_file = relative
        if emit_signal:
            self.settings_changed.emit(self.state.settings)
        self.schedule_save()
        return resolved

    def _set_active_xray_config_path(self, path: Path, *, emit_signal: bool = True) -> Path:
        resolved = self._resolve_xray_config_path(path)
        relative = resolved.relative_to(self.get_xray_config_dir().resolve()).as_posix()
        if self.state.settings.xray_config_file == relative:
            return resolved
        self.state.settings.xray_config_file = relative
        if emit_signal:
            self.settings_changed.emit(self.state.settings)
        self.schedule_save()
        return resolved

    def _set_active_xray_template_path(self, path: Path, *, emit_signal: bool = True) -> Path:
        resolved = self._resolve_xray_template_path(path)
        relative = resolved.relative_to(self.get_xray_template_dir().resolve()).as_posix()
        if self.state.settings.xray_template_file == relative:
            return resolved
        self.state.settings.xray_template_file = relative
        if emit_signal:
            self.settings_changed.emit(self.state.settings)
        self.schedule_save()
        return resolved

    @staticmethod
    def _default_singbox_config_text() -> str:
        return default_singbox_config_text()

    @staticmethod
    def _default_xray_config_text() -> str:
        return default_xray_config_text(
            proxy_host=PROXY_HOST,
            socks_port=DEFAULT_SOCKS_PORT,
            http_port=DEFAULT_HTTP_PORT,
            api_port=DEFAULT_XRAY_STATS_API_PORT,
        )

    def get_active_singbox_config_path(self) -> Path:
        return get_active_config_path_operation(self, "singbox")

    def get_active_singbox_config_name(self) -> str:
        return get_active_config_name_operation(self, "singbox")

    def get_active_singbox_template_path(self) -> Path | None:
        return get_active_template_path_operation(self, "singbox")

    def get_active_xray_config_path(self) -> Path:
        return get_active_config_path_operation(self, "xray")

    def get_active_xray_config_name(self) -> str:
        return get_active_config_name_operation(self, "xray")

    def get_active_xray_template_path(self) -> Path | None:
        return get_active_template_path_operation(self, "xray")

    def query_system_proxy_state(self) -> SystemProxyState:
        """Быстрый снимок реального состояния системного прокси Windows.

        Только чтение реестра (без WinINet/RAS) — безопасно для UI-потока.
        На не-Windows возвращает ``supported=False``.
        """
        return self.proxy.query_state()

    def get_effective_proxy_ports(self) -> tuple[int, int]:
        session = self._active_session
        if session is not None and session.socks_port > 0 and session.http_port > 0:
            return session.socks_port, session.http_port
        if self.is_singbox_proxy_mode():
            return DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT
        try:
            _, _, _, socks_port, http_port, _ = self._inspect_active_xray_config()
        except Exception:
            socks_port = 0
            http_port = 0
        if socks_port > 0 and http_port > 0:
            return socks_port, http_port
        return DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT

    def get_effective_http_proxy_port(self) -> int | None:
        session = self._active_session
        if session is not None:
            return session.http_port if session.http_port > 0 else None
        _, http_port = self.get_effective_proxy_ports()
        return http_port if http_port > 0 else None

    def _cache_singbox_document_state(self, path: Path, text: str) -> SingboxDocumentState:
        return self._singbox_documents.cache_state(path, text)

    def _persist_singbox_config_repair(
        self,
        path: Path,
        text: str,
    ) -> tuple[SingboxDocumentState, SingboxConfigRepair] | None:
        try:
            repair = repair_singbox_config_file(path, text)
        except OSError as exc:
            raise ValueError(
                f"{path.name}: удалось определить безопасное исправление, "
                f"но не удалось сохранить резервную копию или исправленный конфиг: {exc}"
            ) from exc
        if repair is None:
            return None

        repaired_state = self._cache_singbox_document_state(path, repair.repaired_text)
        message = repair.notice(path.name)
        self._log(f"[sing-box] {message}")
        self.status.emit("warning-long", message)
        return repaired_state, repair

    def _recover_singbox_document_state(self, state: SingboxDocumentState) -> SingboxDocumentState:
        result = self._persist_singbox_config_repair(state.source_path, state.text)
        return result[0] if result is not None else state

    def _get_singbox_document_state(self) -> SingboxDocumentState:
        path = self._ensure_active_singbox_config()
        state = self._singbox_documents.get_state(path)
        return self._recover_singbox_document_state(state)

    def _default_singbox_template_path_for_config(self, config_path: Path) -> Path | None:
        relative = config_path.relative_to(self.get_singbox_config_dir().resolve()).as_posix()
        template = self._resolve_singbox_template_path(relative)
        return template if template.exists() else None

    def _default_xray_template_path_for_config(self, config_path: Path) -> Path | None:
        relative = config_path.relative_to(self.get_xray_config_dir().resolve()).as_posix()
        template = self._resolve_xray_template_path(relative)
        return template if template.exists() else None

    def _ensure_active_singbox_config(self, path: str | Path | None = None) -> Path:
        return ensure_active_config_operation(self, "singbox", path)

    def _ensure_active_xray_config(self, path: str | Path | None = None) -> Path:
        return ensure_active_config_operation(self, "xray", path)

    def load_active_singbox_config_text(self) -> tuple[Path, str]:
        state = self._get_singbox_document_state()
        return state.source_path, state.text

    def load_active_xray_config_text(self) -> tuple[Path, str]:
        return load_active_config_text_operation(self, "xray")

    def load_singbox_config_text(self, path: str | Path) -> tuple[Path, str]:
        load_config_text_operation(self, "singbox", path)
        state = self._get_singbox_document_state()
        return state.source_path, state.text

    def load_xray_config_text(self, path: str | Path) -> tuple[Path, str]:
        return load_config_text_operation(self, "xray", path)

    def import_singbox_template(self, path: str | Path) -> tuple[Path, str]:
        return import_template_operation(self, "singbox", path)

    def import_xray_template(self, path: str | Path) -> tuple[Path, str]:
        return import_template_operation(self, "xray", path)

    def reset_active_singbox_config_to_template(self) -> tuple[bool, Path | None, str]:
        return reset_active_config_to_template_operation(self, "singbox")

    def reset_active_xray_config_to_template(self) -> tuple[bool, Path | None, str]:
        return reset_active_config_to_template_operation(self, "xray")

    def save_singbox_config_text(self, text: str, path: str | Path | None = None) -> Path:
        return save_config_text_operation(self, "singbox", text, path)

    def save_xray_config_text(self, text: str, path: str | Path | None = None) -> Path:
        return save_config_text_operation(self, "xray", text, path)

    @staticmethod
    def _format_json_error_message(text: str, exc: json.JSONDecodeError) -> str:
        return format_json_error_message(text, exc)

    def validate_json_text(self, text: str) -> tuple[bool, str]:
        return validate_json_text(text)

    def validate_singbox_json_text(self, text: str) -> tuple[bool, str]:
        try:
            parse_singbox_document(self.get_active_singbox_config_path(), text)
        except ValueError as exc:
            return False, str(exc)
        return True, "JSON корректен и имеет допустимую структуру конфига sing-box."

    @staticmethod
    def try_repair_singbox_json_text(text: str) -> SingboxConfigRepair | None:
        return try_repair_singbox_config_text(text)

    def validate_xray_json_text(self, text: str) -> tuple[bool, str]:
        ok, message = self.validate_json_text(text)
        if not ok:
            return False, message
        if "fakedns" in text.lower():
            return (
                True,
                "JSON корректен. Внимание: в конфиге есть FakeDNS; некоторые версии Xray-core могут падать на старте. "
                "Если запуск завершается с panic, отключите FakeDNS или обновите Xray core.",
            )
        return True, message

    def apply_singbox_config_text(self, text: str) -> tuple[bool, Path | None, str]:
        return apply_singbox_config_text_operation(self, text)

    def apply_xray_config_text(self, text: str) -> tuple[bool, Path | None, str]:
        return apply_xray_config_text_operation(self, text)

    @staticmethod
    def _config_has_proxy_outbound(payload: Any) -> bool:
        return config_has_proxy_outbound(payload)

    @staticmethod
    def _is_local_runtime_host(value: str) -> bool:
        return is_local_runtime_host(value)

    @staticmethod
    def _infer_singbox_outbound_endpoint(outbound: dict[str, Any]) -> tuple[str, int]:
        return infer_singbox_outbound_endpoint(outbound)

    @staticmethod
    def _infer_xray_outbound_endpoint(outbound: dict[str, Any]) -> tuple[str, int]:
        return infer_xray_outbound_endpoint(outbound)

    @staticmethod
    def _infer_singbox_ping_target(payload: dict[str, Any], node: Node | None) -> tuple[str, int]:
        return infer_singbox_ping_target(payload, node)

    @staticmethod
    def _infer_xray_ping_target(payload: dict[str, Any], node: Node | None) -> tuple[str, int]:
        return infer_xray_ping_target(payload, node)

    @staticmethod
    def _ensure_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
        return ensure_dict(parent, key)

    @staticmethod
    def _ensure_list(parent: dict[str, Any], key: str) -> list[Any]:
        return ensure_list(parent, key)

    @staticmethod
    def _replace_or_append_tagged(items: list[Any], tag: str, payload: dict[str, Any]) -> None:
        replace_or_append_tagged(items, tag, payload)

    @staticmethod
    def _collect_xray_inbound_ports(payload: Any) -> set[int]:
        return collect_xray_inbound_ports(payload)

    def _ensure_xray_metrics_contract(
        self,
        payload: dict[str, Any],
        *,
        allocate_port: bool,
    ) -> tuple[int, tuple[str, ...]]:
        return ensure_xray_metrics_contract_operation(self, payload, allocate_port=allocate_port)

    def _ensure_xray_tun_contract(self, payload: dict[str, Any]) -> str:
        return ensure_xray_tun_contract_operation(self, payload)

    @staticmethod
    def _xray_outbound_is_loop_protected(outbound: dict[str, Any]) -> bool:
        return xray_outbound_is_loop_protected_operation(outbound)

    def _apply_xray_tun_loop_prevention(self, payload: dict[str, Any], interface_alias: str) -> int:
        return apply_xray_tun_loop_prevention_operation(self, payload, interface_alias)

    def _inspect_active_singbox_config(self) -> tuple[Path, str, bool]:
        state = self._get_singbox_document_state()
        return state.source_path, state.text_hash, state.has_proxy_outbound

    @staticmethod
    def _extract_xray_runtime_ports(payload: Any) -> tuple[int, int, int]:
        return extract_xray_runtime_ports(payload)

    def _inspect_active_xray_config(self) -> tuple[Path, str, bool, int, int, int]:
        return inspect_active_xray_config_operation(self)

    def _plan_runtime_singbox(
        self,
        node: Node | None = None,
        *,
        replacement: bool = False,
    ) -> SingboxRuntimePlan:
        state = self._get_singbox_document_state()
        document = parse_singbox_document(state.source_path, state.text)
        preferred_relay_port = 0
        preferred_protect_port = 0
        preferred_protect_password = ""
        session = self._active_session
        if session is not None and session.active_core == "singbox" and not replacement:
            if session.hybrid:
                preferred_relay_port = session.sidecar_relay_port
                preferred_protect_port = session.protect_ss_port
                preferred_protect_password = session.protect_ss_password
            elif session.sidecar_kind == "hysteria":
                preferred_relay_port = session.sidecar_relay_port
        return plan_singbox_runtime(
            document,
            node,
            preferred_relay_port=preferred_relay_port,
            preferred_protect_port=preferred_protect_port,
            preferred_protect_password=preferred_protect_password,
            pool_nodes=self.state.nodes,
        )

    def _plan_proxy_runtime_singbox(
        self,
        node: Node | None = None,
        *,
        replacement: bool = False,
    ) -> SingboxRuntimePlan:
        state = self._get_singbox_document_state()
        document = parse_singbox_document(state.source_path, state.text)
        preferred_relay_port = 0
        preferred_protect_port = 0
        preferred_protect_password = ""
        allowed_proxy_ports: set[int] = set()
        session = self._active_session
        if session is not None and session.active_core == "singbox":
            if session.socks_port > 0:
                allowed_proxy_ports.add(int(session.socks_port))
            if session.http_port > 0:
                allowed_proxy_ports.add(int(session.http_port))
            if session.hybrid and not replacement:
                preferred_relay_port = session.sidecar_relay_port
                preferred_protect_port = session.protect_ss_port
                preferred_protect_password = session.protect_ss_password
            elif session.sidecar_kind == "hysteria" and not replacement:
                preferred_relay_port = session.sidecar_relay_port
        return plan_singbox_proxy_runtime(
            document,
            node,
            allowed_proxy_ports=allowed_proxy_ports,
            preferred_relay_port=preferred_relay_port,
            preferred_protect_port=preferred_protect_port,
            preferred_protect_password=preferred_protect_password,
            pool_nodes=self.state.nodes,
        )

    def _configure_singbox_log_contexts(self, plan: SingboxRuntimePlan) -> None:
        """Freeze tag-to-node mappings before any runtime process starts."""

        mode = "tun" if self.state.settings.tun_mode else "proxy"
        generation = int(self._transition_generation)
        nodes_by_id = {node.id: node for node in self.state.nodes}
        selected_node = self._runtime_selected_node() if plan.used_selected_node else None
        selected = RuntimeNodeIdentity.from_node(selected_node) if selected_node is not None else None

        singbox_nodes = identities_for_tags(plan.selector_tags, nodes_by_id)
        if selected is not None:
            singbox_nodes.setdefault("proxy", selected)
        singbox_context = RuntimeLogContext(
            engine="sing-box",
            role="front",
            mode=mode,
            generation=generation,
            selected=selected,
            outbound_nodes=singbox_nodes,
        )
        self._core_log_contexts["sing-box"] = singbox_context

        if plan.hysteria_sidecar is not None:
            self._core_log_contexts["hysteria"] = RuntimeLogContext(
                engine="hysteria",
                role="sidecar",
                mode=mode,
                generation=generation,
                selected=plan.hysteria_sidecar.context,
                outbound_nodes={"proxy": plan.hysteria_sidecar.context},
            )
        else:
            self._core_log_contexts.pop("hysteria", None)

        if plan.xray_sidecar is not None:
            xray_nodes = identities_for_tags(plan.xray_sidecar.outbound_pool_tags, nodes_by_id)
            if selected is not None:
                xray_nodes.setdefault("proxy", selected)
            self._core_log_contexts["xray"] = RuntimeLogContext(
                engine="xray",
                role="sidecar",
                mode=mode,
                generation=generation,
                selected=selected,
                outbound_nodes=xray_nodes,
            )
        else:
            self._core_log_contexts.pop("xray", None)

        for context in (
            singbox_context,
            self._core_log_contexts.get("hysteria"),
            self._core_log_contexts.get("xray") if plan.xray_sidecar is not None else None,
        ):
            if context is None:
                continue
            for line in runtime_mapping_lines(context):
                self._log(line)

    def _configure_core_log_context(
        self,
        engine: str,
        *,
        node: Node | None,
        outbound_tags: dict[str, str] | None = None,
        role: str = "core",
        used_selected_node: bool = True,
    ) -> None:
        """Freeze a secret-safe node mapping before starting a standalone core."""

        selected_node = node if used_selected_node else None
        selected = RuntimeNodeIdentity.from_node(selected_node) if selected_node is not None else None
        nodes_by_id = {item.id: item for item in self.state.nodes}
        mapped = identities_for_tags(outbound_tags or {}, nodes_by_id)
        if selected is not None:
            mapped.setdefault("proxy", selected)
        context = RuntimeLogContext(
            engine=engine,
            role=role,
            mode="tun" if self.state.settings.tun_mode else "proxy",
            generation=int(self._transition_generation),
            selected=selected,
            outbound_nodes=mapped,
        )
        self._core_log_contexts[engine] = context
        for line in runtime_mapping_lines(context):
            self._log(line)

    def _start_singbox_runtime_plan(
        self,
        plan: SingboxRuntimePlan,
        *,
        prepared_hysteria: HysteriaManager | None = None,
        prepared_amnezia: AmneziaManager | None = None,
    ) -> bool:
        amnezia_request_generation = getattr(self, "_transition_generation", None)
        owned_amnezia = prepared_amnezia or getattr(self, "amnezia", None)

        def amnezia_request_cancelled() -> bool:
            return getattr(plan, "amnezia_sidecar", None) is not None and (
                getattr(self, "_desired_connected", True) is False or
                getattr(self, "_transition_generation", None) != amnezia_request_generation
            )

        if amnezia_request_cancelled():
            return False
        runtime_node = self._runtime_selected_node()
        gate = getattr(self, "target_profile_allows_core_start", None)
        if gate is not None and not gate(
            runtime_node,
            used_selected_node=bool(getattr(plan, "used_selected_node", True)),
        ):
            return False
        self._configure_singbox_log_contexts(plan)
        if plan.provider_payload is not None:
            SINGBOX_PROVIDER_FILE.parent.mkdir(parents=True, exist_ok=True)
            temporary = SINGBOX_PROVIDER_FILE.with_suffix(".json.tmp")
            temporary.write_text(
                json.dumps(plan.provider_payload, ensure_ascii=True, indent=2),
                encoding="utf-8",
            )
            temporary.replace(SINGBOX_PROVIDER_FILE)
        if getattr(plan, "amnezia_sidecar", None) is not None:
            target_amnezia = owned_amnezia
            if prepared_amnezia is not None:
                if not target_amnezia.is_running:
                    return False
            elif not self._start_amnezia_manager(target_amnezia, plan):
                return False
            if amnezia_request_cancelled():
                target_amnezia.stop()
                return False
        if plan.hysteria_sidecar is not None:
            self._protect_ss_port = 0
            self._protect_ss_password = ""
            self._log(
                "[sing-box] starting official Hysteria2 sidecar "
                f"relay=127.0.0.1:{plan.hysteria_sidecar.relay_port}"
            )
            target_manager = prepared_hysteria or self.hysteria
            if prepared_hysteria is not None:
                if not prepared_hysteria.is_running:
                    return False
            else:
                contract = getattr(self, "_hysteria_contract", None)
                if isinstance(contract, HysteriaTransitionContract):
                    planned_generation = _increment_int(
                        getattr(self, "_session_generation", 0)
                    )
                    contract.begin(
                        planned_generation,
                        runtime_node.id if runtime_node else None,
                        "official_hysteria_sidecar",
                    )
                    contract.advance(
                        HysteriaRuntimeState.STARTING_SIDECAR,
                        generation=planned_generation,
                    )
                    contract.advance(
                        HysteriaRuntimeState.WAITING_RELAY,
                        generation=planned_generation,
                    )
                self._hysteria_process_generation = _increment_int(
                    getattr(self, "_hysteria_process_generation", 0)
                )
                self._hysteria_active_generation = self._hysteria_process_generation
                if not target_manager.start(
                    plan.hysteria_sidecar.config,
                    plan.hysteria_sidecar.relay_port,
                    context=plan.hysteria_sidecar.context,
                    process_generation=self._hysteria_process_generation,
                ):
                    return False
        elif plan.xray_sidecar is not None:
            self._protect_ss_port = plan.xray_sidecar.protect_port
            self._protect_ss_password = plan.xray_sidecar.protect_password
            self._log(
                "[sing-box] starting hybrid xray sidecar "
                f"relay=127.0.0.1:{plan.xray_sidecar.relay_port} "
                f"protect=127.0.0.1:{plan.xray_sidecar.protect_port}"
            )
            if not self.xray.start(self.state.settings.xray_path, plan.xray_sidecar.config):
                self._protect_ss_port = 0
                self._protect_ss_password = ""
                return False
            self._xray_api_port = plan.xray_sidecar.api_port
            if plan.selected_outbound_tag and not self._apply_core_outbound_tag(
                "xray", plan.selected_outbound_tag
            ):
                self.xray.stop()
                self._xray_api_port = 0
                self._protect_ss_port = 0
                self._protect_ss_password = ""
                return False
        else:
            self._protect_ss_port = 0
            self._protect_ss_password = ""

        if plan.clash_api_port <= 0:
            self._log(
                "[sing-box] clash_api отключён: свободный порт метрик не найден "
                f"(диапазон {SINGBOX_CLASH_API_PORT}+ зарезервирован Windows)"
            )
        elif plan.clash_api_port != SINGBOX_CLASH_API_PORT:
            self._log(
                f"[sing-box] clash_api порт изменён: {SINGBOX_CLASH_API_PORT} -> {plan.clash_api_port} "
                "(исходный зарезервирован Windows)"
            )
        if gate is not None and not gate(
            runtime_node,
            used_selected_node=bool(getattr(plan, "used_selected_node", True)),
        ):
            if plan.xray_sidecar is not None and self.xray.is_running:
                self.xray.stop()
            if plan.hysteria_sidecar is not None:
                target_manager = prepared_hysteria or self.hysteria
                if target_manager.is_running:
                    target_manager.stop()
            if getattr(plan, "amnezia_sidecar", None) is not None:
                (prepared_amnezia or self.amnezia).stop()
            return False
        singbox_start_tag = (
            plan.hybrid_relay_selected_tag if plan.is_hybrid else plan.selected_outbound_tag
        )
        if plan.hysteria_sidecar is not None:
            contract = getattr(self, "_hysteria_contract", None)
            if isinstance(contract, HysteriaTransitionContract):
                contract.advance(
                    HysteriaRuntimeState.STARTING_FRONT,
                    generation=contract.session.session_generation,
                )
        for start_attempt in range(2):
            if amnezia_request_cancelled():
                break
            sb_ok = self.singbox.start(self.state.settings.singbox_path, plan.singbox_config)
            self._log(f"[sing-box] start result: {sb_ok}")
            if amnezia_request_cancelled():
                self.singbox.stop()
                break
            if not sb_ok:
                retryable = getattr(
                    self.singbox,
                    "last_start_failure_retryable",
                    False,
                ) is True
                if start_attempt == 0 and retryable:
                    self._log(
                        "[sing-box] self-heal: control plane did not become ready; "
                        "restarting sing-box once"
                    )
                    sleep_with_events(0.5)
                    continue
                break
            self._singbox_clash_api_port = plan.clash_api_port
            if not singbox_start_tag or self._apply_core_outbound_tag(
                "singbox", singbox_start_tag, startup=True
            ):
                if getattr(plan, "amnezia_sidecar", None) is not None:
                    if not owned_amnezia.verify_front_dns(plan.amnezia_sidecar.config) or amnezia_request_cancelled():
                        self.singbox.stop()
                        break
                self._front_process_generation = _increment_int(
                    getattr(self, "_front_process_generation", 0)
                )
                self._front_target_generation = _increment_int(
                    getattr(self, "_front_target_generation", 0)
                )
                self._active_singbox_plan = plan
                return True

            self.singbox.stop()
            self._singbox_clash_api_port = 0
            if start_attempt == 0:
                self._log(
                    "[sing-box] self-heal: control plane did not become ready; "
                    "restarting sing-box once"
                )
                sleep_with_events(0.5)

        if plan.xray_sidecar is not None and self.xray.is_running:
            self.xray.stop()
        if getattr(plan, "amnezia_sidecar", None) is not None:
            owned_amnezia.stop()
        if plan.hysteria_sidecar is not None:
            target_manager = prepared_hysteria or self.hysteria
            if target_manager.is_running:
                target_manager.stop()
        self._protect_ss_port = 0
        self._protect_ss_password = ""
        self._singbox_clash_api_port = 0
        self._xray_api_port = 0
        return False

    def _new_amnezia_manager(self) -> AmneziaManager:
        manager = AmneziaManager(self)
        manager.log_received.connect(self._log)
        manager.failure.connect(lambda event, owned=manager: self._on_amnezia_failure(owned, event))
        return manager

    def _on_amnezia_failure(self, manager, event) -> None:
        self.runtime_errors.record(event)
        self.runtime_errors_changed.emit(self.runtime_errors.snapshot())
        # Retain old/candidate evidence, but only the committed manager owns
        # admission. Never let a retired process close the replacement.
        session = self._active_session
        if manager is not self.amnezia or session is None or session.sidecar_kind != "amnezia":
            return
        self._set_connection_status("error", event.message, level="error")
        if event.stage in {"core_error", "process", "observer", "handshake_failed"}:
            def close_owned():
                if manager is self.amnezia and self._active_session is session:
                    self._desired_connected = False
                    self._handle_unexpected_disconnect()
            QTimer.singleShot(0, close_owned)

    def _start_amnezia_manager(self, manager, plan: SingboxRuntimePlan) -> bool:
        sidecar = plan.amnezia_sidecar
        if sidecar is None:
            return False
        self._amnezia_target_generation = _increment_int(getattr(self, "_amnezia_target_generation", 0))
        return manager.start(sidecar.config, sidecar.relay_port, context=sidecar.context,
                             session_generation=_increment_int(getattr(self, "_session_generation", 0)),
                             target_generation=self._amnezia_target_generation)

    def _prepare_amnezia_replacement(self, plan: SingboxRuntimePlan):
        candidate = self._new_amnezia_manager()
        if self._start_amnezia_manager(candidate, plan):
            return candidate
        candidate.stop()
        candidate.deleteLater()
        return None

    def _prepare_hysteria_replacement(self, plan: SingboxRuntimePlan) -> HysteriaManager | None:
        sidecar = plan.hysteria_sidecar
        if sidecar is None:
            return None
        self._hysteria_process_generation = _increment_int(
            getattr(self, "_hysteria_process_generation", 0)
        )
        generation = self._hysteria_process_generation
        replacement = HysteriaManager(self)
        self._bind_hysteria_manager(replacement)
        self._hysteria_contract.advance(
            HysteriaRuntimeState.STARTING_SIDECAR,
            generation=self._hysteria_contract.session.session_generation,
        )
        self._hysteria_contract.advance(
            HysteriaRuntimeState.WAITING_RELAY,
            generation=self._hysteria_contract.session.session_generation,
        )
        if not replacement.start(
            sidecar.config,
            sidecar.relay_port,
            context=sidecar.context,
            process_generation=generation,
            allow_parallel=True,
        ):
            failure = replacement.last_failure_code or HysteriaFailureCode.LOCAL_RELAY_NOT_READY
            self._hysteria_last_failure_code = failure
            self._hysteria_contract.terminal(
                failure,
                generation=self._hysteria_contract.session.session_generation,
            )
            replacement.deleteLater()
            return None
        self._relay_credentials_generation = _increment_int(
            getattr(self, "_relay_credentials_generation", 0)
        )
        self._hysteria_contract.session.sidecar_process_generation = generation
        self._hysteria_contract.session.relay_port = sidecar.relay_port
        self._hysteria_contract.session.relay_credentials_generation = self._relay_credentials_generation
        self._hysteria_contract.advance(
            HysteriaRuntimeState.REPLACEMENT_READY,
            generation=self._hysteria_contract.session.session_generation,
        )
        return replacement

    def _commit_hysteria_replacement(self, replacement: HysteriaManager | None) -> bool:
        old = self.hysteria
        if replacement is not None:
            self.hysteria = replacement
            self._hysteria_active_generation = replacement.process_generation
        stopped = True
        if old is not replacement and old.is_running:
            stopped = old.stop(expected=True)
        if old is not replacement and stopped:
            old.deleteLater()
        elif old is not replacement:
            old.stopped.connect(old.deleteLater)
        return stopped

    def _rollback_singbox_front(self, plan: SingboxRuntimePlan | None) -> bool:
        if plan is None:
            return False
        if plan.hysteria_sidecar is not None and not self.hysteria.is_running:
            return False
        if getattr(plan, "amnezia_sidecar", None) is not None and not self.amnezia.is_running:
            return False
        if plan.xray_sidecar is not None and not self.xray.is_running:
            return False
        self._log("[transport-transition] replacement front failed; restoring previous generation")
        if not self.singbox.start(self.state.settings.singbox_path, plan.singbox_config):
            return False
        self._singbox_clash_api_port = plan.clash_api_port
        selected = plan.hybrid_relay_selected_tag if plan.is_hybrid else plan.selected_outbound_tag
        if selected and not self._apply_core_outbound_tag("singbox", selected, startup=True):
            self.singbox.stop()
            return False
        self._active_singbox_plan = plan
        return True

    def _bind_hysteria_manager(self, manager: HysteriaManager) -> None:
        manager.log_received.connect(lambda line: self._on_core_log("hysteria", line))
        manager.error.connect(lambda message: self._on_core_error("hysteria", message))
        manager.failure.connect(
            lambda code, message, generation, current=manager: self._on_hysteria_failure(
                current,
                code,
                message,
                generation,
            )
        )
        manager.state_changed.connect(
            lambda running, current=manager: self._on_hysteria_state_changed(current, running)
        )
        manager.stopped.connect(
            lambda code, current=manager: self._on_hysteria_stopped(current, code)
        )

    def _on_hysteria_state_changed(self, manager: HysteriaManager, running: bool) -> None:
        if manager is not self.hysteria or manager.process_generation != self._hysteria_active_generation:
            self._log(
                "[hysteria-transition] ignored stale state callback "
                f"generation={manager.process_generation} running={running}"
            )
            return
        self._on_core_state_changed(running)

    def _on_hysteria_stopped(self, manager: HysteriaManager, exit_code: int) -> None:
        suffix = ""
        if manager.last_failure_code is not None:
            suffix = f" original_failure={manager.last_failure_code.value}"
        self._log(
            f"[hysteria] process stopped with code {exit_code} "
            f"generation={manager.process_generation}{suffix}"
        )

    def _on_hysteria_failure(
        self,
        manager: HysteriaManager,
        code_text: str,
        message: str,
        process_generation: int,
    ) -> None:
        try:
            code = HysteriaFailureCode(code_text)
        except ValueError:
            code = HysteriaFailureCode.CORE_UNCLASSIFIED
        self._log(
            f"[hysteria-failure] code={code.value} process_generation={process_generation}"
        )
        if manager is not self.hysteria or process_generation != self._hysteria_active_generation:
            self._log("[hysteria-failure] stale generation ignored")
            return
        self._hysteria_last_failure_code = code
        if code in SECURITY_FAILURES and self.connected and not self._disconnecting:
            if getattr(self, "_hysteria_recovery_active", False):
                self._hysteria_contract.terminal(
                    code,
                    generation=self._hysteria_contract.session.session_generation,
                )
            else:
                self._hysteria_contract.fail(
                    code,
                    generation=self._hysteria_contract.session.session_generation,
                    automatic_switch=False,
                )
            self._set_connection_status(
                "error",
                message,
                level="error",
            )
            self._desired_connected = False
            # Fail closed: do not leave the front admitting connections into a
            # transport whose pin/CA/auth/obfs contract was rejected.
            if self.singbox.is_running:
                self.singbox.stop(expected=True)
            return
        if (
            code not in AUTOMATIC_SWITCH_FAILURES
            or not self.connected
            or self._hysteria_recovery_active
            or self._disconnecting
        ):
            return

        failed = self.selected_node
        failed_id = failed.id if failed is not None else ""
        now = time.monotonic()
        self._hysteria_failure_started_at = now
        if failed_id:
            self._hysteria_cooldown_until[failed_id] = now + 300.0

        replacement: Node | None = None
        for candidate in sorted(self.state.nodes, key=lambda item: item.sort_order):
            if candidate.id == failed_id or node_is_maintenance(candidate):
                continue
            if self._hysteria_cooldown_until.get(candidate.id, 0.0) > now:
                continue
            raw_uri = str(candidate.link or "")
            if raw_uri.partition(":")[0].lower() in {"hy2", "hysteria2"}:
                if not classify_hysteria_uri(raw_uri, platform="windows").valid:
                    continue
            elif classify_node_for_singbox(candidate) not in {
                "native_singbox",
                "native_singbox_endpoint",
                "hybrid_xray_sidecar",
            }:
                continue
            replacement = candidate
            break

        self._hysteria_failure_episode_id += 1
        self._hysteria_automatic_switch_attempted = replacement is not None
        self._hysteria_contract.fail(
            code,
            generation=self._hysteria_contract.session.session_generation,
            automatic_switch=replacement is not None,
        )
        if replacement is None:
            self._hysteria_last_failure_code = HysteriaFailureCode.NO_COMPATIBLE_FALLBACK
            self._hysteria_contract.terminal(
                HysteriaFailureCode.NO_COMPATIBLE_FALLBACK,
                generation=self._hysteria_contract.session.session_generation,
            )
            self._set_connection_status(
                "error",
                "Hysteria2: совместимый резервный сервер не найден.",
                level="error",
            )
            # Stop admission immediately; otherwise front keeps opening new
            # connections against an already dead loopback relay.
            if self.singbox.is_running:
                self.singbox.stop(expected=True)
            self._desired_connected = False
            return

        self._hysteria_recovery_active = True
        self._pending_hysteria_replacement_node_id = replacement.id
        self._auto_switch_transitioning = True
        self._switching = True
        self._desired_connected = True
        self._log(
            f"[hysteria-recovery] episode={self._hysteria_failure_episode_id} "
            f"failed={failed_id} replacement={replacement.id} code={code.value}"
        )
        self.auto_switch_triggered.emit(replacement.name)
        # The committed selection remains authoritative until replacement
        # sidecar readiness, front readiness and active-session capture all
        # succeed.  Transition planners read the pending node explicitly.
        self._request_transition("node switched")
        # Close admission to the failed loopback relay once.  The recovery
        # state fence above keeps the logical old session available to the
        # full-transition planner while no connection-refused storm is created.
        if self.singbox.is_running and not self.singbox.stop(expected=True):
            self._log("[hysteria-recovery] failed to close front admission")

    def _record_hysteria_switch_commit(self) -> None:
        started = float(getattr(self, "_hysteria_failure_started_at", 0.0))
        if started <= 0:
            return
        elapsed_ms = int(max(0.0, time.monotonic() - started) * 1000)
        self._log(f"[hysteria-recovery] switch committed in {elapsed_ms} ms")
        self._hysteria_failure_started_at = 0.0

    def _build_runtime_xray_config(self, node: Node | None = None, *, tun_mode: bool = False) -> XrayRuntimeConfig:
        return build_runtime_xray_config_operation(self, node, tun_mode=tun_mode)

    def _transition_signature(
        self,
        node: Node | None = None,
        settings: AppSettings | None = None,
        routing: RoutingSettings | None = None,
    ) -> str:
        return transition_signature_operation(self, node, settings, routing)

    def _xray_layer_signature(
        self,
        node: Node | None = None,
        settings: AppSettings | None = None,
        routing: RoutingSettings | None = None,
    ) -> str:
        return xray_layer_signature_operation(self, node, settings, routing)

    def _tun_layer_signature(
        self,
        node: Node | None = None,
        settings: AppSettings | None = None,
        routing: RoutingSettings | None = None,
    ) -> str:
        return tun_layer_signature_operation(self, node, settings, routing)

    def _capture_active_session(
        self,
        node: Node | None,
        *,
        tun: bool,
        core: str,
        api_port: int,
        hybrid: bool = False,
        socks_port: int | None = None,
        http_port: int | None = None,
        xray_inbound_tags: tuple[str, ...] | None = None,
        sidecar_relay_port: int = 0,
        protect_ss_port: int = 0,
        protect_ss_password: str = "",
        ping_host: str = "",
        ping_port: int = 0,
        outbound_pool_tags: dict[str, str] | None = None,
        hybrid_relay_selector_tags: tuple[str, ...] = (),
        hybrid_relay_selected_tag: str = "",
        sidecar_kind: str = "",
    ) -> None:
        settings = self.state.settings
        routing = self.state.routing
        if socks_port is None:
            socks_port = int(DEFAULT_SOCKS_PORT)
        if http_port is None:
            http_port = int(DEFAULT_HTTP_PORT)
        if xray_inbound_tags is None:
            xray_inbound_tags = ()
        if not ping_host and node is not None:
            ping_host = node.server
        if ping_port <= 0 and node is not None:
            ping_port = int(node.port)
        proxy_bypass_lan = bool(routing.bypass_lan) if tun else self._system_proxy_bypass_lan(settings)
        if outbound_pool_tags is None:
            # П1 (AC1): самодостаточный дефолт — теги выводятся из единого
            # источника (пула контроллера), а не из памяти вызывающего.
            # Явно переданный параметр (в т.ч. пустой dict) всегда сильнее.
            outbound_pool_tags = self._derive_outbound_pool_tags(node, core=core)
        self._session_generation = _increment_int(getattr(self, "_session_generation", 0))
        contract = getattr(self, "_hysteria_contract", None)
        contract_session = getattr(contract, "session", None)
        started_at = (
            float(getattr(contract_session, "started_at_monotonic", 0.0))
            or time.monotonic()
        )
        ready_at = time.monotonic()
        runtime_kind = (
            "official_hysteria_sidecar"
            if sidecar_kind == "hysteria"
            else "native"
        )
        self._active_session = build_active_session_snapshot(
            node_id=node.id if node else None,
            node_server=node.server if node else "",
            active_core=core,
            tun_mode=bool(tun),
            tun_engine=str(settings.tun_engine),
            proxy_enabled=bool(settings.enable_system_proxy),
            proxy_bypass_lan=proxy_bypass_lan,
            xray_path=str(settings.xray_path),
            singbox_path=str(settings.singbox_path),
            socks_port=int(socks_port),
            http_port=int(http_port),
            routing_signature=self._routing_signature(routing),
            transition_signature=self._transition_signature(node, settings, routing),
            xray_layer_signature=self._xray_layer_signature(node, settings, routing),
            tun_layer_signature=self._tun_layer_signature(node, settings, routing),
            hybrid=hybrid,
            api_port=int(api_port),
            xray_inbound_tags=tuple(xray_inbound_tags),
            sidecar_relay_port=int(sidecar_relay_port),
            protect_ss_port=int(protect_ss_port),
            protect_ss_password=str(protect_ss_password),
            ping_host=str(ping_host),
            ping_port=int(ping_port),
            outbound_pool_tags=outbound_pool_tags,
            hybrid_relay_selector_tags=hybrid_relay_selector_tags,
            hybrid_relay_selected_tag=hybrid_relay_selected_tag,
            sidecar_kind=sidecar_kind,
            session_generation=self._session_generation,
            runtime_kind=runtime_kind,
            sidecar_process_generation=(
                int(getattr(self, "_hysteria_active_generation", 0))
                if sidecar_kind == "hysteria"
                else 0
            ),
            relay_host=PROXY_HOST,
            relay_credentials_generation=int(getattr(self, "_relay_credentials_generation", 0)),
            front_process_generation=int(getattr(self, "_front_process_generation", 0)),
            front_target_generation=int(getattr(self, "_front_target_generation", 0)),
            started_at_monotonic=started_at,
            ready_at_monotonic=ready_at,
            failure_episode_id=int(getattr(self, "_hysteria_failure_episode_id", 0)),
            last_failure_code=getattr(self, "_hysteria_last_failure_code", None),
            automatic_switch_attempted=bool(
                getattr(self, "_hysteria_automatic_switch_attempted", False)
            ),
        )
        if isinstance(contract, HysteriaTransitionContract):
            if contract.session.session_generation != self._session_generation:
                contract.begin(
                    self._session_generation,
                    node.id if node else None,
                    runtime_kind,
                    preserve_failure_episode=bool(
                        getattr(self, "_hysteria_recovery_active", False)
                    ),
                )
            contract.session.ready_at_monotonic = ready_at
            contract.session.state = HysteriaRuntimeState.READY
        if hasattr(self, "_hysteria_recovery_active"):
            self._hysteria_recovery_active = False
        if hasattr(self, "_hysteria_automatic_switch_attempted"):
            self._hysteria_automatic_switch_attempted = False
        self._blocked_transition_signature = ""
        begin_auto_switch_warmup(self, node)

    def _derive_outbound_pool_tags(self, node: Node | None, *, core: str) -> dict[str, str] | None:
        """П1 (AC1/A2): вывести дефолтные outbound_pool_tags из пула контроллера.

        Теги честны относительно того, что реально загрузило запущенное ядро:
        xray/tun2socks встраивают пул в конфиг ровно тогда, когда выбранная нода
        входит в пул (условие сборщиков конфига). Если пул не загружался (нет
        ноды, нода вне пула) — тегов нет. Для sing-box действует другая схема
        тегов (selector_tags): их вызывающие обязаны передавать явно, выводить
        их из Xray-пула нельзя.
        """

        if node is None or core not in {"xray", "tun2socks"}:
            return None
        pool = self.xray_outbound_pool()
        if not pool.contains(node.id):
            return None
        return dict(pool.tags)

    def _clear_active_session(self) -> None:
        self._active_session = None
        self._core_log_contexts.clear()

    def _apply_proxy_runtime_change(self) -> bool:
        settings = self.state.settings
        bypass_lan = self._system_proxy_bypass_lan()
        if self._active_session is not None:
            socks_port = self._active_session.socks_port
            http_port = self._active_session.http_port
        else:
            socks_port, http_port = self.get_effective_proxy_ports()
        try:
            if settings.enable_system_proxy:
                self.proxy.enable(
                    http_port,
                    socks_port,
                    bypass_lan=bypass_lan,
                )
            else:
                self.proxy.disable(restore_previous=True)
        except Exception as exc:
            self._set_connection_status(
                "error",
                f"Не удалось применить системный прокси: {exc}",
                level="error",
            )
            return False

        node = self.selected_node
        if self.connected:
            session = self._active_session
            self._capture_active_session(
                node,
                tun=False,
                core=session.active_core if session is not None else self._active_core,
                api_port=session.api_port if session is not None else self._xray_api_port,
                hybrid=session.hybrid if session is not None else False,
                sidecar_kind=session.sidecar_kind if session is not None else "",
                socks_port=socks_port,
                http_port=http_port,
                xray_inbound_tags=session.xray_inbound_tags if session is not None else (),
                sidecar_relay_port=session.sidecar_relay_port if session is not None else 0,
                protect_ss_port=session.protect_ss_port if session is not None else 0,
                protect_ss_password=session.protect_ss_password if session is not None else "",
                ping_host=session.ping_host if session is not None else "",
                ping_port=session.ping_port if session is not None else 0,
                # A2/AC4: без снапшота сессии нельзя утверждать, что ядро грузило
                # пул — пустое переопределение честнее выведенного дефолта.
                outbound_pool_tags=session.outbound_pool_tags if session is not None else {},
                hybrid_relay_selector_tags=(
                    session.hybrid_relay_selector_tags if session is not None else ()
                ),
                hybrid_relay_selected_tag=(
                    session.hybrid_relay_selected_tag if session is not None else ""
                ),
            )
        return True

    def _needs_transition(self) -> bool:
        node = self._runtime_selected_node()
        context = TransitionContext(
            desired_connected=self._desired_connected,
            locked=self.locked,
            has_selected_node=node is not None,
            can_connect_without_selected_node=self._can_connect_without_selected_node(),
            connected=self.connected,
            blocked_transition_signature=self._blocked_transition_signature,
            current_transition_signature=self._transition_signature(node),
            active_session=self._active_session,
            can_apply_proxy_runtime_change=False,
            can_tun_hot_swap=False,
            can_proxy_hot_swap=False,
        )
        return needs_transition(context)

    def _can_apply_proxy_runtime_change(self, session: ActiveSessionSnapshot) -> bool:
        settings = self.state.settings
        desired_core = "singbox" if self.is_singbox_proxy_mode(settings) else "xray"
        if session.active_core != desired_core:
            return False
        return can_apply_proxy_runtime_change_rule(
            session=session,
            settings_tun_mode=bool(settings.tun_mode),
            current_xray_layer_signature=self._xray_layer_signature(),
            proxy_enabled=bool(settings.enable_system_proxy),
            proxy_bypass_lan=self._system_proxy_bypass_lan(),
        )

    def _can_proxy_hot_swap(self, session: ActiveSessionSnapshot) -> bool:
        settings = self.state.settings
        desired_core = "singbox" if self.is_singbox_proxy_mode(settings) else "xray"
        if session.active_core != desired_core:
            return False
        if desired_core == "singbox":
            socks_port, http_port = session.socks_port, session.http_port
        else:
            _, _, _, socks_port, http_port, _ = self._inspect_active_xray_config()
        return can_proxy_hot_swap_rule(
            session=session,
            settings_tun_mode=bool(settings.tun_mode),
            socks_port=int(socks_port),
            http_port=int(http_port),
            current_xray_layer_signature=self._xray_layer_signature(),
        )

    def _can_tun_hot_swap(self, session: ActiveSessionSnapshot) -> bool:
        settings = self.state.settings
        node = self._runtime_selected_node()
        return can_tun_hot_swap_rule(
            session=session,
            settings_tun_mode=bool(settings.tun_mode),
            settings_tun_engine=str(settings.tun_engine),
            has_selected_node=node is not None,
            current_tun_layer_signature=self._tun_layer_signature(node, settings, self.state.routing),
        )

    def _compute_transition_action(self) -> str | None:
        node = self._runtime_selected_node()
        session = self._active_session
        context = TransitionContext(
            desired_connected=self._desired_connected,
            locked=self.locked,
            has_selected_node=node is not None,
            can_connect_without_selected_node=self._can_connect_without_selected_node(),
            connected=self.connected,
            blocked_transition_signature=self._blocked_transition_signature,
            current_transition_signature=self._transition_signature(node),
            active_session=session,
            can_apply_proxy_runtime_change=self._can_apply_proxy_runtime_change(session) if session is not None else False,
            can_tun_hot_swap=self._can_tun_hot_swap(session) if session is not None else False,
            can_proxy_hot_swap=self._can_proxy_hot_swap(session) if session is not None else False,
        )
        return compute_transition_action(context)

    def _transition_status_text(self, action: str) -> str:
        return transition_status_text(action)

    def _request_transition(self, reason: str) -> None:
        self._blocked_transition_signature = ""
        self._transition_pending = True
        self._transition_reason = reason
        self._transition_generation += 1
        generation = self._transition_generation
        self._proxy_protection_wait_generation = 0
        self._proxy_protection_wait_token = 0
        if self._desired_connected and self._prepare_proxy_protection(generation):
            if self._transition_timer.isActive():
                self._transition_timer.stop()
            self._transition_scheduled = False
            return
        if self._transition_active:
            return
        self._schedule_transition_drain(transition_request_delay_ms(reason))

    def _prepare_proxy_protection(self, generation: int) -> bool:
        """Resolve and activate the selected-server profile before core start.

        This method is deliberately entered for every connection transition;
        a previous DNS answer is never accepted as readiness proof.
        """
        node = self._runtime_selected_node()
        self.zapret.set_target_settings(self.state.settings.zapret_target)
        if not self._active_config_uses_selected_node(node):
            self.zapret.clear_target_profile()
            return False
        spec = self.zapret.target_spec(node)
        if spec is None:
            self.zapret.clear_target_profile()
            return False
        if not isinstance(spec, ZapretEndpointSpec):
            # Compatibility path for integrations still exposing the former
            # UDP-only resolver contract.
            if self.zapret.apply_cached_proxy_node(node):
                if self.zapret.proxy_protection_is_ready(node):
                    return False
                self._wait_for_proxy_protection(generation)
                return True
            server = self.zapret.proxy_protection_server(node)
            if not server:
                return False
            worker = ProxyProtectionResolver(
                generation,
                server,
                self.zapret._resolve_server_ips,
                parent=self if isinstance(self, QObject) else None,
            )
            self._proxy_protection_workers[generation] = worker
            self._proxy_protection_wait_generation = generation
            worker.resolved.connect(self._on_proxy_protection_resolved)
            worker.start()
            return True
        requires_zapret = self.zapret.target_requires_zapret(node)
        if self.connected and not self.zapret.target_profile_is_ready(node):
            # A server/strategy change must stop the old data plane before DNS
            # and before winws2 can be rebuilt.  This also disables core-owned
            # retry loops while the new endpoint is not protected yet.
            self.transition_state_changed.emit(True, "Остановка VPN перед DNS...")
            if not self.disconnect_current(disable_proxy=False, emit_status=False):
                self._cancel_target_transition(
                    "Не удалось остановить VPN перед обновлением профиля Zapret"
                )
                return True
            self._desired_connected = True
        if requires_zapret and not self.state.settings.zapret_preset:
            fallback = self.zapret.default_preset()
            if not fallback:
                self._cancel_target_transition(
                    "Для обхода выбранного сервера сначала выберите пресет Zapret"
                )
                return True
            self._logger.info("Zapret preset not chosen, falling back to %r", fallback)
            self.state.settings.zapret_preset = fallback
            self.schedule_save()
            self.transition_state_changed.emit(
                True, f"Zapret: пресет по умолчанию «{fallback}»"
            )

        worker = TargetProfileResolver(
            generation,
            spec,
            self.zapret.resolve_target,
            parent=self,
        )
        self._proxy_protection_workers[generation] = worker
        self._proxy_protection_wait_generation = generation
        self._proxy_protection_wait_token = 0
        worker.resolved.connect(self._on_proxy_protection_resolved)
        worker.finished.connect(
            lambda generation=generation, worker=worker: self._forget_proxy_protection_worker(generation, worker)
        )
        self.transition_state_changed.emit(True, "DNS выбранного VPN-сервера...")
        worker.start()
        return True

    def _active_config_uses_selected_node(self, node: Node | None) -> bool:
        """Avoid targeting a node ignored by the active raw JSON document."""
        if node is None:
            return False
        try:
            if self.is_singbox_editor_mode():
                plan = (
                    self._plan_runtime_singbox(node)
                    if self.state.settings.tun_mode
                    else self._plan_proxy_runtime_singbox(node)
                )
                return bool(plan.used_selected_node)
            if self.uses_xray_raw_config():
                runtime = self._build_runtime_xray_config(
                    node,
                    tun_mode=bool(self.state.settings.tun_mode),
                )
                return bool(runtime.used_selected_node)
        except (OSError, ValueError):
            # The normal planner will show its specific error later.  Do not
            # accidentally weaken the gate because preflight itself failed.
            return True
        return True

    def _cancel_target_transition(self, message: str) -> None:
        self._proxy_protection_wait_generation = 0
        self._proxy_protection_wait_token = 0
        self._transition_pending = False
        if self._hysteria_recovery_active:
            self._clear_pending_hysteria_selection()
            self._hysteria_recovery_active = False
            self._desired_connected = False
            self._handle_unexpected_disconnect()
        else:
            self._desired_connected = self.connected
        self._blocked_transition_signature = self._transition_signature()
        self._set_connection_status("error", message, level="warning")
        self.transition_state_changed.emit(False, "")

    def _wait_for_proxy_protection(self, generation: int) -> None:
        self._proxy_protection_wait_generation = generation
        self._proxy_protection_wait_token = self.zapret.target_profile_generation
        self.transition_state_changed.emit(True, "Запуск Zapret для выбранного сервера...")

    def _on_proxy_protection_resolved(
        self,
        generation: int,
        spec: object,
        resolved: object,
        error: Exception | None,
    ) -> None:
        runtime_node = self._runtime_selected_node()
        if isinstance(spec, str):
            if error is None:
                self.zapret.cache_proxy_resolution(spec, resolved)
            if generation != self._transition_generation:
                return
            self._proxy_protection_wait_generation = 0
            self._proxy_protection_wait_token = 0
            if error is not None:
                self._log(
                    f"[zapret] DNS выбранного сервера host={spec} "
                    f"завершился ошибкой: {error}"
                )
            if error is not None and self.zapret.running:
                if self._hysteria_recovery_active:
                    self._cancel_target_transition(
                        "Не удалось подготовить UDP-защиту replacement target"
                    )
                    return
                self._transition_pending = False
                self._blocked_transition_signature = self._transition_signature()
                self._desired_connected = self.connected
                self.status.emit(
                    "warning",
                    "Не удалось подготовить UDP-защиту: адрес сервера не определён",
                )
                self.transition_state_changed.emit(False, "")
                return
            if error is None and self.zapret.apply_cached_proxy_node(runtime_node):
                if not self.zapret.proxy_protection_is_ready(runtime_node):
                    self._wait_for_proxy_protection(generation)
                    return
            if not self._transition_active:
                self._schedule_transition_drain(0)
            return
        if generation != self._transition_generation:
            return
        self._proxy_protection_wait_generation = 0
        self._proxy_protection_wait_token = 0
        if not self._desired_connected:
            self.transition_state_changed.emit(False, "")
            return
        if spec != self.zapret.target_spec(runtime_node):
            return
        requires_zapret = self.zapret.target_requires_zapret(runtime_node)
        if error is not None:
            hosts = ", ".join(spec.hosts)
            self._log(
                f"[zapret] DNS выбранного сервера host={hosts} "
                f"завершился ошибкой: {error}"
            )
            if requires_zapret or self.zapret.running:
                self._cancel_target_transition(
                    "Подключение отменено: не удалось определить IP выбранного сервера"
                )
            else:
                self.zapret.clear_target_profile()
                self._schedule_transition_drain(0)
            return

        previous_target = self.zapret.resolved_target
        profile_was_ready = self.zapret.target_profile_is_ready(runtime_node)
        if self.connected and (previous_target != resolved or not profile_was_ready):
            if self._hysteria_recovery_active:
                # Admission was already closed by the Hysteria failure
                # coordinator.  Preserve the old sidecar process/generation
                # while winws2 prepares protection for the replacement; the
                # normal sidecar transition will retire it only after readiness.
                self._log(
                    "[hysteria-recovery] preparing Zapret target without "
                    "stopping the old Hysteria generation"
                )
            else:
                # Stop data-plane retries before winws2 loses the old profile.
                self.transition_state_changed.emit(True, "Остановка VPN перед Zapret...")
                self.disconnect_current(disable_proxy=False, emit_status=False)
                self._desired_connected = True
        if not self.zapret.apply_resolved_target(runtime_node, resolved):
            self._cancel_target_transition("Не удалось подготовить стратегию выбранного сервера")
            return

        from .node_runtime_service import remember_country_addresses
        remember_country_addresses(self, runtime_node, resolved.ips)

        if requires_zapret and not self.zapret.running:
            preset = self.state.settings.zapret_preset
            self._wait_for_proxy_protection(generation)
            self.zapret.start_with_target(preset)
            return
        if not self.zapret.target_profile_is_ready(runtime_node):
            self._wait_for_proxy_protection(generation)
            return
        if not self._transition_active:
            self._schedule_transition_drain(transition_request_delay_ms(self._transition_reason))

    def _on_proxy_protection_ready(self, protection_generation: int) -> None:
        transition_generation = self._proxy_protection_wait_generation
        if not transition_generation:
            return
        if transition_generation != self._transition_generation:
            return
        if protection_generation != self._proxy_protection_wait_token:
            return
        if not self._desired_connected:
            self._proxy_protection_wait_generation = 0
            self._proxy_protection_wait_token = 0
            self.transition_state_changed.emit(False, "")
            return
        if not self.zapret.target_profile_is_ready(self._runtime_selected_node()):
            return

        self._proxy_protection_wait_generation = 0
        self._proxy_protection_wait_token = 0
        if not self._transition_active:
            self._schedule_transition_drain(transition_request_delay_ms(self._transition_reason))

    def _on_proxy_protection_failed(self, protection_generation: int, reason: str) -> None:
        transition_generation = self._proxy_protection_wait_generation
        if not transition_generation:
            return
        if transition_generation != self._transition_generation:
            return
        if protection_generation != self._proxy_protection_wait_token:
            return

        self._proxy_protection_wait_generation = 0
        self._proxy_protection_wait_token = 0
        self._transition_pending = False
        self._blocked_transition_signature = self._transition_signature(
            self._runtime_selected_node()
        )
        if self._hysteria_recovery_active:
            self._clear_pending_hysteria_selection()
            self._hysteria_recovery_active = False
        legacy_contract = not isinstance(self.zapret, ZapretManager)
        self._desired_connected = self.connected if legacy_contract else False
        if legacy_contract:
            self.status.emit("warning", "Не удалось подтвердить UDP-защиту; переход отменён")
            self.transition_state_changed.emit(False, "")
            return
        if self.connected:
            self.disconnect_current(disable_proxy=True, emit_status=False)
        self._log(f"[zapret] точечный профиль не подтверждён: {reason}; подключение отменено")
        self._set_connection_status(
            "error",
            "Zapret не подтвердил профиль выбранного сервера; подключение отменено",
            level="warning",
        )
        self.transition_state_changed.emit(False, "")

    def _forget_proxy_protection_worker(
        self,
        generation: int,
        worker: TargetProfileResolver,
    ) -> None:
        if self._proxy_protection_workers.get(generation) is worker:
            self._proxy_protection_workers.pop(generation, None)
        worker.deleteLater()

    def target_profile_allows_core_start(
        self,
        node: Node | None,
        *,
        used_selected_node: bool = True,
    ) -> bool:
        """Last-moment fence immediately before any VPN process start."""
        if not used_selected_node:
            self.zapret.clear_target_profile()
            return True
        if self.zapret.target_profile_is_ready(node):
            return True
        self._set_connection_status(
            "error",
            "Запуск VPN заблокирован: профиль Zapret для выбранного сервера не готов",
            level="warning",
        )
        return False

    def _on_zapret_stopped_safety(self) -> None:
        """Fail closed if a protected session loses its WinDivert process."""
        if not self.connected or not self.zapret.target_requires_zapret(self.selected_node):
            return
        self._log("[zapret] процесс остановлен во время защищённой VPN-сессии")
        self._desired_connected = False
        self._transition_pending = False
        self._transition_generation += 1
        self.disconnect_current(disable_proxy=True, emit_status=False)
        self._set_connection_status(
            "error",
            "VPN остановлен: Zapret больше не защищает выбранный сервер",
            level="error",
        )

    def _start_proxy_dns_prewarm(self) -> None:
        """П5 (AC13/AC14): фоновый прогрев DNS-кэша zapret после подключения.

        Батч-резолв всех UDP-прокси нод текущего пула в существующем
        воркер-пуле; наполняется только ``_proxy_resolution_cache``, winws2 не
        трогается, ошибки — молча, GUI-поток не блокируется.
        """

        try:
            start_proxy_dns_prewarm(self)
        except Exception:
            pass

    def start_zapret(self, preset_name: str) -> None:
        """Start a preset with a freshly resolved selected-server profile."""
        self.state.settings.zapret_preset = preset_name
        self.zapret.set_target_settings(self.state.settings.zapret_target)
        self.schedule_save()
        node = self.selected_node
        if not self._active_config_uses_selected_node(node):
            self.zapret.clear_target_profile()
            self.zapret.start(preset_name)
            return
        spec = self.zapret.target_spec(node)
        if spec is None:
            self.zapret.clear_target_profile()
            self.zapret.start(preset_name)
            return
        self._manual_zapret_generation += 1
        generation = self._manual_zapret_generation
        worker = TargetProfileResolver(generation, spec, self.zapret.resolve_target, parent=self)
        self._manual_zapret_worker = worker
        self.transition_state_changed.emit(True, "DNS выбранного VPN-сервера...")

        def resolved_callback(result_generation, result_spec, endpoint, error) -> None:
            if result_generation != self._manual_zapret_generation:
                return
            self._manual_zapret_worker = None
            if error is not None or result_spec != self.zapret.target_spec(self.selected_node):
                self.transition_state_changed.emit(False, "")
                self._set_connection_status(
                    "error",
                    "Zapret не запущен: не удалось определить IP выбранного сервера",
                    level="warning",
                )
                return
            if not self.zapret.apply_resolved_target(self.selected_node, endpoint):
                self.transition_state_changed.emit(False, "")
                self._set_connection_status(
                    "error",
                    "Zapret не запущен: проверьте выбранную стратегию",
                    level="warning",
                )
                return
            self.transition_state_changed.emit(True, "Запуск Zapret...")
            self.zapret.start_with_target(preset_name)

        worker.resolved.connect(resolved_callback)
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _schedule_transition_drain(self, delay_ms: int) -> None:
        if self._transition_active or self._proxy_protection_wait_generation == self._transition_generation:
            return
        self._transition_scheduled = True
        self._transition_timer.start(max(0, int(delay_ms)))

    def _drain_transition_queue(self) -> None:
        self._transition_scheduled = False
        if self._transition_active:
            return
        if self._proxy_protection_wait_generation == self._transition_generation:
            return

        if not self._transition_pending and not self._needs_transition():
            self.transition_state_changed.emit(False, "")
            return

        action = self._compute_transition_action()
        if action is None:
            self._transition_pending = False
            self.transition_state_changed.emit(False, "")
            return

        self._transition_pending = False
        reason = self._transition_reason or action
        self._transition_active = True
        self.transition_state_changed.emit(True, self._transition_status_text(action))
        # Переход выполняется генератором через TransitionRunner: блокирующие шаги
        # (ожидание QProcess, subprocess-вызовы, паузы) не держат GUI-поток, а на
        # каждом резюме проверяется _transition_generation — устаревший переход
        # (пришёл новый запрос) закрывается, его оставшиеся шаги не выполняются.
        generation = self._transition_generation
        runner = TransitionRunner(
            self._transition_action_steps(action, reason),
            is_current=lambda: self._transition_generation == generation,
            on_finished=self._on_transition_runner_finished,
            parent=self,
        )
        self._transition_runner = runner
        runner.start()

    def _on_transition_runner_finished(self, runner: TransitionRunner) -> None:
        if self._transition_runner is runner:
            self._transition_runner = None
        runner.deleteLater()
        try:
            if not runner.cancelled:
                if runner.error is not None:
                    self._log(f"[transition] failed with error: {runner.error!r}")
                ok = bool(runner.result) and runner.error is None
                if ok:
                    self._blocked_transition_signature = ""
                else:
                    self._blocked_transition_signature = self._transition_signature(
                        self._runtime_selected_node()
                    )
                    self._desired_connected = self.connected
            else:
                # Отменённый переход не трогает blocked-сигнатуру и desired_connected
                # (актуальное действие пересчитает следующий drain), но обязан
                # оставить связку процессов консистентной.
                self._reconcile_cancelled_transition()
        finally:
            self._transition_active = False
            if self._pending_hysteria_replacement_node_id:
                self._clear_pending_hysteria_selection()
                self._hysteria_recovery_active = False
            if self._transition_pending or self._needs_transition():
                self._schedule_transition_drain(0)
            else:
                self.transition_state_changed.emit(False, "")

    def _reconcile_cancelled_transition(self) -> None:
        """Привести процессы к консистентному виду после отменённого перехода.

        Отмена по generation может остановить hot-swap между шагами: например
        транспорт уже остановлен, а sing-box ещё жив (connected=False).
        Тогда очередь не вычислит disconnect (connected=False), и без уборки
        остался бы частично работающий runtime. Такая связка гасится,
        сессия очищается; следующий drain пересчитает актуальное действие
        (connect при desired_connected=True даёт полный переезд на новую ноду).
        """
        if self.connected:
            return
        any_running = (
            self.xray.is_running
            or self.singbox.is_running
            or self.hysteria.is_running
        )
        if any_running:
            self._log("[transition] cancelled mid-swap — stopping partial connection processes")
            self._stop_active_connection_processes(disable_proxy=not self._desired_connected)
        if self._active_session is not None:
            self._clear_active_session()
            if not self._desired_connected:
                self._set_connection_status("idle", "Отключено", level="info")

    def _transition_action_steps(self, action: str, reason: str) -> TransitionSteps:
        """Generator executed by TransitionRunner for one transition action.

        Горячие пути (tun_hot_swap, proxy_hot_swap) полностью генераторные.
        Холодные пути (connect/disconnect/reconnect/proxy_update) пока выполняются
        синхронно одним шагом: полная миграция connect-цепочки (sing-box, zapret,
        TUN-роуты) отложена как слишком рискованная за один заход (частичный AC22).
        """
        if action == "tun_hot_swap":
            return (yield from self._hot_swap_node_steps(reason))
        if action == "proxy_hot_swap":
            return (yield from self._restart_proxy_core_steps(reason))
        return self._run_transition_action(action, reason)

    def _run_transition_action(self, action: str, reason: str) -> bool:
        if action == "disconnect":
            return self.disconnect_current()
        if action == "connect":
            return self.connect_selected()
        if action == "proxy_update":
            return self._apply_proxy_runtime_change()
        if action == "proxy_hot_swap":
            return self._restart_proxy_core(reason)
        if action == "tun_hot_swap":
            return self._hot_swap_node(reason)
        return self._reconnect(reason)

    # ── Country detection helpers ──

    def _detect_countries_sync(self) -> None:
        detect_countries_sync_operation(self)

    def _start_country_ip_resolution(self) -> None:
        start_country_ip_resolution_operation(self)

    def _on_countries_resolved(self, results: dict[str, str]) -> None:
        on_countries_resolved_operation(self, results)

    def shutdown(self) -> None:
        # Незавершённый асинхронный переход закрывается (finally-блоки операций
        # выполняются) до остановки процессов при выходе.
        self._cancel_hot_switch_runner()
        runner = self._transition_runner
        if runner is not None:
            runner.cancel()
        shutdown_operation(self)

    @staticmethod
    def _cleanup_tun_adapter() -> None:
        """Remove the wintun TUN adapter if it was left behind."""
        import subprocess as _sp
        try:
            result = run_text(
                ["netsh", "interface", "show", "interface"],
                timeout=5,
                creationflags=0x08000000,
            )
            if "ZapretKVN_TUN" in result_output_text(result):
                _sp.run(
                    ["netsh", "interface", "set", "interface", "ZapretKVN_TUN", "admin=disable"],
                    capture_output=True, timeout=5,
                    creationflags=0x08000000,
                )
        except Exception:
            pass

    @property
    def selected_node(self) -> Node | None:
        return self._get_node_by_id(self.state.selected_node_id)

    def _runtime_selected_node(self) -> Node | None:
        amnezia_pending = getattr(self, "_pending_amnezia_node_id", None)
        if isinstance(amnezia_pending, str) and amnezia_pending:
            return self._get_node_by_id(amnezia_pending)
        pending_id = getattr(self, "_pending_hysteria_replacement_node_id", None)
        if getattr(self, "_hysteria_recovery_active", False) and pending_id:
            pending = self._get_node_by_id(pending_id)
            if pending is not None:
                return pending
        return self.selected_node

    def _commit_pending_hysteria_selection(self, node: Node | None) -> bool:
        pending_id = getattr(self, "_pending_hysteria_replacement_node_id", None)
        if not pending_id:
            return True
        if node is None or node.id != pending_id:
            self._log(
                "[hysteria-transition] refused selection commit: active session "
                f"node={node.id if node else ''} pending={pending_id}"
            )
            return False
        self.state.selected_node_id = pending_id
        self._pending_hysteria_replacement_node_id = None
        self.selection_changed.emit(node)
        return True

    def _clear_pending_hysteria_selection(self) -> None:
        self._pending_hysteria_replacement_node_id = None

    def _get_node_by_id(self, node_id: str | None) -> Node | None:
        return get_node_by_id_operation(self, node_id)

    def _prepare_node_for_runtime(self, node: Node | None) -> str | None:
        return prepare_node_for_runtime_operation(self, node)

    def export_node_outbound_json(self, node_id: str | None = None) -> str | None:
        node = self._get_node_by_id(node_id) if node_id else self.selected_node
        if not node:
            return None
        return json.dumps(node.outbound, ensure_ascii=True, indent=2)

    def export_runtime_config_json(self, node_id: str | None = None) -> str | None:
        node = self._get_node_by_id(node_id) if node_id else self.selected_node
        try:
            if self.is_singbox_editor_mode():
                plan = (
                    self._plan_runtime_singbox(node)
                    if self.is_singbox_tun_mode()
                    else self._plan_proxy_runtime_singbox(node)
                )
                return json.dumps(plan.singbox_config, ensure_ascii=True, indent=2)
            if self.uses_xray_raw_config():
                runtime = self._build_runtime_xray_config(node, tun_mode=self.is_xray_tun_mode())
                return json.dumps(runtime.config, ensure_ascii=True, indent=2)
            if not node:
                return None
            problem = self._prepare_node_for_runtime(node)
            if problem:
                return None
            cfg = build_xray_config(
                node,
                self.state.routing,
                self.state.settings,
                socks_port=DEFAULT_SOCKS_PORT,
                http_port=DEFAULT_HTTP_PORT,
            )
            return json.dumps(cfg, ensure_ascii=True, indent=2)
        except ValueError:
            return None

    def import_nodes_from_text(self, text: str) -> tuple[int, list[str]]:
        return import_nodes_from_text_operation(self, text)

    def get_subscription(self, subscription_id: str | None) -> Subscription | None:
        if not subscription_id:
            return None
        return next((item for item in self.state.subscriptions if item.id == subscription_id), None)

    def _unique_subscription_name(self, name: str, *, exclude_id: str | None = None) -> str:
        base = name.strip() or "Подписка"
        used = {
            item.name.casefold()
            for item in self.state.subscriptions
            if item.id != exclude_id and item.name.strip()
        }
        if base.casefold() not in used:
            return base
        index = 2
        while f"{base} ({index})".casefold() in used:
            index += 1
        return f"{base} ({index})"

    def add_subscription(self, subscription: Subscription, *, mode: str = "auto") -> bool:
        subscription.url, profile_hint = resolve_subscription_source(subscription.url)
        if profile_hint and normalize_client_profile(subscription.client_profile) == "zapret":
            subscription.client_profile = profile_hint
        self._normalize_subscription_identity(subscription)
        validate_filter_patterns(subscription.include_pattern, subscription.exclude_pattern)
        if any(item.url == subscription.url for item in self.state.subscriptions):
            self.status.emit("warning", "Эта подписка уже добавлена")
            return False
        if subscription.id in self._subscription_workers or subscription.id in self._subscription_queued_ids:
            return False
        self._pending_subscription_additions[subscription.id] = subscription
        self._enqueue_subscription_update(subscription, mode, pending_add=True, apply_result=True)
        return True

    def update_subscription_definition(self, subscription_id: str, updates: dict[str, Any]) -> bool:
        subscription = self.get_subscription(subscription_id)
        if (
            subscription is None
            or subscription_id in self._subscription_workers
            or subscription_id in self._subscription_queued_ids
        ):
            return False
        url = str(updates.get("url", subscription.url)).strip()
        include_pattern = str(updates.get("include_pattern", subscription.include_pattern)).strip()
        exclude_pattern = str(updates.get("exclude_pattern", subscription.exclude_pattern)).strip()
        url, profile_hint = resolve_subscription_source(url)
        validate_filter_patterns(include_pattern, exclude_pattern)
        if any(item.id != subscription_id and item.url == url for item in self.state.subscriptions):
            self.status.emit("warning", "Эта подписка уже добавлена")
            return False
        old_url = subscription.url
        old_include_pattern = subscription.include_pattern
        old_exclude_pattern = subscription.exclude_pattern
        old_identity = (
            subscription.client_profile,
            subscription.user_agent,
            subscription.send_hwid,
            subscription.hwid,
        )
        requested_profile = str(updates.get("client_profile", subscription.client_profile))
        normalized_profile = normalize_client_profile(
            profile_hint
            if profile_hint and normalize_client_profile(requested_profile) == "zapret"
            else requested_profile
        )
        send_hwid = bool(updates.get("send_hwid", subscription.send_hwid))
        hwid = str(updates.get("hwid", subscription.hwid)).strip()
        if send_hwid:
            hwid = validate_hwid(hwid or self.state.subscription_device_id)
        interval = updates.get("update_interval_hours", subscription.update_interval_hours)
        normalized_interval = int(interval) if interval else None

        requested_name = str(updates.get("name", subscription.name)).strip()
        subscription.name = self._unique_subscription_name(requested_name, exclude_id=subscription_id)
        subscription.url = url
        subscription.user_agent = str(updates.get("user_agent", subscription.user_agent)).strip()
        subscription.client_profile = normalized_profile
        subscription.send_hwid = send_hwid
        subscription.hwid = hwid
        subscription.auto_update = bool(updates.get("auto_update", subscription.auto_update))
        subscription.update_interval_hours = normalized_interval
        subscription.include_pattern = include_pattern
        subscription.exclude_pattern = exclude_pattern
        if (
            old_url != url
            or old_include_pattern != include_pattern
            or old_exclude_pattern != exclude_pattern
            or old_identity
            != (
                subscription.client_profile,
                subscription.user_agent,
                subscription.send_hwid,
                subscription.hwid,
            )
        ):
            subscription.etag = ""
            subscription.last_modified = ""
            subscription.pending_url = ""
        self.subscriptions_changed.emit(self.state.subscriptions)
        self.save()
        return True

    def _normalize_subscription_identity(self, subscription: Subscription) -> None:
        subscription.client_profile = normalize_client_profile(subscription.client_profile)
        if not subscription.send_hwid:
            subscription.hwid = subscription.hwid.strip()
            return
        subscription.hwid = validate_hwid(
            subscription.hwid or self.state.subscription_device_id
        )

    def update_subscription(
        self,
        subscription_id: str,
        *,
        mode: str = "auto",
        force_refresh: bool = False,
    ) -> bool:
        subscription = self.get_subscription(subscription_id)
        if subscription is None:
            return False
        return self._enqueue_subscription_update(
            subscription,
            mode,
            pending_add=False,
            apply_result=True,
            force_refresh=force_refresh,
        )

    def check_subscription(self, subscription_id: str, *, mode: str = "auto") -> bool:
        subscription = self.get_subscription(subscription_id)
        if subscription is None:
            return False
        return self._enqueue_subscription_update(subscription, mode, pending_add=False, apply_result=False)

    def update_all_subscriptions(self, *, mode: str = "auto") -> int:
        count = 0
        for subscription in sorted(self.state.subscriptions, key=lambda item: item.sort_order):
            if self._enqueue_subscription_update(
                subscription, mode, pending_add=False, apply_result=True
            ):
                count += 1
        return count

    def remove_subscription(self, subscription_id: str, *, keep_nodes: bool = False) -> bool:
        if subscription_id in self._subscription_workers:
            self.status.emit("warning", "Дождитесь завершения обновления подписки")
            return False
        if subscription_id in self._subscription_queued_ids:
            self._subscription_update_queue = [
                item for item in self._subscription_update_queue if item[0].id != subscription_id
            ]
            self._subscription_queued_ids.discard(subscription_id)
        previous_selected = self.state.selected_node_id
        if not remove_subscription_operation(self.state, subscription_id, keep_nodes=keep_nodes):
            return False
        self.subscriptions_changed.emit(self.state.subscriptions)
        self.nodes_changed.emit(self.state.nodes)
        self.selection_changed.emit(self.selected_node)
        self.save()
        if previous_selected != self.state.selected_node_id and (self.connected or self._desired_connected):
            if self.state.selected_node_id is None and not self._can_connect_without_selected_node():
                self._desired_connected = False
            self._request_transition("subscription removed")
        return True

    def hide_subscription_node(self, node_id: str) -> bool:
        return self.hide_subscription_nodes({node_id}) > 0

    def hide_subscription_nodes(self, node_ids: set[str]) -> int:
        previous_selected = self.state.selected_node_id
        hidden = 0
        for node_id in set(node_ids):
            if hide_subscription_node_operation(self.state, node_id) is not None:
                hidden += 1
        if not hidden:
            return 0
        self.subscriptions_changed.emit(self.state.subscriptions)
        self.nodes_changed.emit(self.state.nodes)
        self.selection_changed.emit(self.selected_node)
        self.save()
        if previous_selected != self.state.selected_node_id and (self.connected or self._desired_connected):
            if self.state.selected_node_id is None and not self._can_connect_without_selected_node():
                self._desired_connected = False
            self._request_transition("subscription node hidden")
        return hidden

    def reset_subscription_hidden_nodes(self, subscription_id: str) -> bool:
        subscription = self.get_subscription(subscription_id)
        if (
            subscription is None
            or subscription_id in self._subscription_workers
            or subscription_id in self._subscription_queued_ids
        ):
            return False
        subscription.hidden_source_keys.clear()
        subscription.etag = ""
        subscription.last_modified = ""
        self.subscriptions_changed.emit(self.state.subscriptions)
        self.save()
        return True

    def accept_subscription_pending_url(self, subscription_id: str) -> bool:
        subscription = self.get_subscription(subscription_id)
        if subscription is None or not subscription.pending_url:
            return False
        subscription.url = subscription.pending_url
        subscription.pending_url = ""
        subscription.etag = ""
        subscription.last_modified = ""
        self.subscriptions_changed.emit(self.state.subscriptions)
        self.save()
        return True

    def _enqueue_subscription_update(
        self,
        subscription: Subscription,
        mode: str,
        pending_add: bool,
        apply_result: bool,
        force_refresh: bool = False,
    ) -> bool:
        if subscription.id in self._subscription_workers or subscription.id in self._subscription_queued_ids:
            return False
        self._subscription_update_queue.append(
            (deepcopy(subscription), mode, pending_add, apply_result, bool(force_refresh))
        )
        self._subscription_queued_ids.add(subscription.id)
        self._drain_subscription_update_queue()
        return True

    def _drain_subscription_update_queue(self) -> None:
        while self._subscription_update_queue and len(self._subscription_workers) < 3:
            subscription, mode, pending_add, apply_result, force_refresh = (
                self._subscription_update_queue.pop(0)
            )
            self._subscription_queued_ids.discard(subscription.id)
            if not pending_add and self.get_subscription(subscription.id) is None:
                continue
            proxy_port = self.get_effective_http_proxy_port() if self.connected else None
            worker = SubscriptionUpdateWorker(
                subscription,
                mode=mode,
                proxy_port=proxy_port,
                force_refresh=force_refresh,
                parent=self,
            )
            self._subscription_workers[subscription.id] = worker
            if not apply_result:
                self._subscription_check_ids.add(subscription.id)
            worker.progress.connect(self.subscription_update_progress.emit)
            worker.completed.connect(self._on_subscription_update_completed)
            worker.failed.connect(self._on_subscription_update_failed)
            worker.finished.connect(
                lambda sid=subscription.id, current=worker: self._on_subscription_worker_finished(sid, current)
            )
            self.subscription_update_started.emit(subscription.id)
            worker.start()

    def _on_subscription_update_completed(self, worker_subscription, fetched, parsed) -> None:
        subscription = self.get_subscription(worker_subscription.id)
        pending_add = subscription is None and worker_subscription.id in self._pending_subscription_additions
        if pending_add:
            if fetched.not_modified or parsed is None:
                self._pending_subscription_additions.pop(worker_subscription.id, None)
                self.subscription_update_finished.emit(
                    SubscriptionUpdateResult(
                        subscription_id=worker_subscription.id,
                        success=False,
                        message="Новая подписка вернула 304 без локального снимка",
                    )
                )
                return
            subscription = self._pending_subscription_additions[worker_subscription.id]
            subscription.name = self._unique_subscription_name(
                subscription.name or parsed.metadata.title or "Подписка"
            )
        if subscription is None:
            return
        if parsed is not None and subscription.hidden_source_keys:
            hidden = set(subscription.hidden_source_keys)
            parsed.nodes = [node for node in parsed.nodes if node.source_key not in hidden]
        if subscription.id in self._subscription_check_ids:
            subscription.last_checked_at = datetime.now(timezone.utc).isoformat()
            subscription.last_error = ""
            subscription.failure_count = 0
            subscription.backoff_until = None
            node_count = len(
                [node for node in self.state.nodes if node.subscription_id == subscription.id]
                if fetched.not_modified
                else parsed.nodes
            )
            stored_count = len(
                [node for node in self.state.nodes if node.subscription_id == subscription.id]
            )
            result = SubscriptionUpdateResult(
                subscription_id=subscription.id,
                success=True,
                message=f"Проверка успешна: в подписке серверов {node_count}",
                skipped=(subscription.skipped_count if parsed is None else parsed.skipped),
                warnings=(
                    list(subscription.warnings)
                    if parsed is None
                    else normalize_subscription_warnings(parsed.warnings)
                ),
                not_modified=fetched.not_modified,
                check_only=True,
                source_count=node_count,
                stored_count=stored_count,
            )
            self.subscriptions_changed.emit(self.state.subscriptions)
            self.save()
            self.subscription_update_finished.emit(result)
            return
        if fetched.not_modified:
            result = apply_not_modified(subscription, fetched)
        else:
            outcome = reconcile_subscription(self.state, subscription, parsed, fetched)
            result = outcome.result
            if pending_add:
                self.state.subscriptions.append(subscription)
            if pending_add and self.state.selected_node_id is None:
                first = next((node for node in self.state.nodes if node.subscription_id == subscription.id), None)
                self.state.selected_node_id = first.id if first else None
            self._detect_countries_sync()
            QTimer.singleShot(0, self._start_country_ip_resolution)
            self.nodes_changed.emit(self.state.nodes)
            self.selection_changed.emit(self.selected_node)
            if result.reconnect_required and (self.connected or self._desired_connected):
                if self.state.selected_node_id is None and not self._can_connect_without_selected_node():
                    self._desired_connected = False
                else:
                    self._desired_connected = True
                self._request_transition("subscription updated")
            QTimer.singleShot(500, self._start_country_ip_resolution)
        self._pending_subscription_additions.pop(subscription.id, None)
        self.subscriptions_changed.emit(self.state.subscriptions)
        self.save()
        self.subscription_update_finished.emit(result)

    def _on_subscription_update_failed(self, worker_subscription, message: str) -> None:
        subscription = self.get_subscription(worker_subscription.id)
        if subscription is not None:
            result = mark_subscription_failure(subscription, message)
            self.subscriptions_changed.emit(self.state.subscriptions)
            self.save()
        else:
            self._pending_subscription_additions.pop(worker_subscription.id, None)
            result = SubscriptionUpdateResult(
                subscription_id=worker_subscription.id,
                success=False,
                message=message,
            )
        self.subscription_update_finished.emit(result)

    def _on_subscription_worker_finished(self, subscription_id: str, worker) -> None:
        if self._subscription_workers.get(subscription_id) is worker:
            self._subscription_workers.pop(subscription_id, None)
        self._subscription_check_ids.discard(subscription_id)
        worker.deleteLater()
        self._drain_subscription_update_queue()
        self._maybe_finish_startup_connect()

    def _check_due_subscriptions(self) -> None:
        # AC3: global toggle is an outer AND-gate on top of per-subscription
        # auto_update/backoff (subscription_due semantics unchanged).
        if self.locked or not self.state.settings.subscriptions_auto_update:
            return
        for subscription in self.state.subscriptions:
            if subscription_due(subscription):
                self._enqueue_subscription_update(
                    subscription, "auto", pending_add=False, apply_result=True
                )

    def _startup_subscription_check_enabled(self) -> bool:
        """AC4: gate for the one-shot startup check (load() and startup unlock)."""
        settings = self.state.settings
        return bool(settings.subscriptions_auto_update and settings.subscriptions_check_on_startup)

    def _apply_subscription_timer_interval(self) -> None:
        """AC5: subscription timer interval from settings (minutes, clamped 5..1440)."""
        interval_ms = clamp_subscriptions_check_interval(
            self.state.settings.subscriptions_check_interval_min
        ) * 60_000
        if self._subscription_timer.interval() != interval_ms:
            # setInterval on a running QTimer restarts it with the new period.
            self._subscription_timer.setInterval(interval_ms)

    def remove_nodes(self, node_ids: set[str]) -> None:
        remove_nodes_operation(self, node_ids)

    def update_node(self, node_id: str, updates: dict) -> bool:
        return update_node_operation(self, node_id, updates)

    def bulk_update_nodes(self, node_ids: set[str], operations: dict) -> int:
        return bulk_update_nodes_operation(self, node_ids, operations)

    def get_all_groups(self) -> list[str]:
        return get_all_groups_operation(self)

    def get_all_tags(self) -> list[str]:
        return get_all_tags_operation(self)

    def _migrate_sort_order(self) -> None:
        if self.state.nodes and all(n.sort_order == 0 for n in self.state.nodes):
            for i, node in enumerate(self.state.nodes):
                node.sort_order = i + 1
            self.schedule_save()

    def reorder_nodes(self, node_id: str, direction: str) -> None:
        reorder_nodes_operation(self, node_id, direction)

    def set_selected_node(self, node_id: str, *, reset_auto_switch: bool = True) -> None:
        set_selected_node_operation(self, node_id, reset_auto_switch=reset_auto_switch)

    def _set_connection_status(self, phase: str, message: str, level: str | None = None) -> None:
        self.connection_status_changed.emit(phase, message)
        if level is not None:
            self.status.emit(level, message)

    def _compute_connected_state(self) -> bool:
        if self._active_session is not None and self._active_session.sidecar_kind == "amnezia":
            return self.singbox.is_running and self.amnezia.is_running
        if self._active_session is not None and self._active_session.hybrid:
            return self.singbox.is_running and self.xray.is_running
        if self._active_session is not None and self._active_session.sidecar_kind == "hysteria":
            return self.singbox.is_running and self.hysteria.is_running
        return self.singbox.is_running

    def _refresh_connected_state(self) -> tuple[bool, bool]:
        previous = self.connected
        self.connected = self._compute_connected_state()
        return previous, self.connected

    # --- Rotation -----------------------------------------------------------

    def xray_outbound_pool(self) -> XrayOutboundPool:
        """All Xray-compatible nodes loaded into the persistent data plane.

        П3 (AC9/AC10): пул кэшируется по идентичности списка нод. Ключ ловит
        замену списка, смену состава, переупорядочивание (sort_order) и замену
        объекта ``node.outbound``; in-place правки содержимого outbound-словаря
        покрываются явной инвалидацией по сигналу ``nodes_changed``.
        """

        nodes = self.state.nodes
        key = (
            id(nodes),
            tuple((id(node), id(node.outbound), node.sort_order) for node in nodes),
        )
        if self._xray_outbound_pool_cache is None or self._xray_outbound_pool_cache_key != key:
            self._xray_outbound_pool_cache = build_xray_outbound_pool(nodes)
            self._xray_outbound_pool_cache_key = key
        return self._xray_outbound_pool_cache

    def _invalidate_xray_outbound_pool_cache(self) -> None:
        self._xray_outbound_pool_cache = None
        self._xray_outbound_pool_cache_key = None

    def _apply_core_outbound_tag(
        self,
        core: str,
        outbound_tag: str,
        *,
        startup: bool = False,
    ) -> bool:
        if core == "singbox":
            selector = (
                select_singbox_outbound_when_ready if startup else select_singbox_outbound
            )
            kwargs = {"wait": sleep_with_events} if startup else {}
            ok, output = selector(
                self._singbox_clash_api_port,
                SINGBOX_SELECTOR_TAG,
                outbound_tag,
                **kwargs,
            )
        else:
            xray_path = getattr(self.xray, "_exe_path", None) or self.state.settings.xray_path
            ok, output = apply_balancer_override(
                xray_path,
                self._xray_api_port,
                XRAY_BALANCER_TAG,
                outbound_tag,
            )
        if not ok:
            self._log(f"[core-switch] {core} control plane rejected {outbound_tag}: {output}")
        return ok

    def _pin_started_outbound(
        self,
        node: Node | None,
        core: str,
        tags: dict[str, str] | None,
    ) -> bool:
        if node is None or not tags:
            return True
        tag = tags.get(node.id, "")
        return bool(tag) and self._apply_core_outbound_tag(core, tag)

    def _hot_switch_precheck(self) -> HotSwitchPlan | None:
        """Чистые (in-memory) проверки применимости горячего свитча (A3).

        Никакого I/O: control-plane вызовы выполняются воркер-шагами в
        ``_hot_switch_selected_node_steps``. ``None`` означает фолбэк в очередь
        переходов (``_request_transition``).
        """

        node = self.selected_node
        session = self._active_session
        if node is None:
            self._log("[core-switch] fallback: selected node is missing")
            return None
        if session is None:
            self._log("[core-switch] fallback: active session is missing")
            return None
        if not self.connected:
            self._log("[core-switch] fallback: controller is not connected")
            return None
        tags = session.outbound_pool_tags or {}
        tag = tags.get(node.id, "")
        if not tag:
            self._log(
                f"[core-switch] fallback: node {node.id} is not loaded in "
                f"{session.active_core} pool ({len(tags)} tags)"
            )
            return None
        control_core = "xray" if session.hybrid else session.active_core
        if control_core != "singbox" and not session.hybrid:
            # Xray's RoutingService only changes the balancer choice for new
            # connections.  Without a sing-box selector in front there is no
            # API capable of invalidating the existing TCP/UDP generation, so
            # use the normal process transition instead of reporting a false
            # successful cut-over.
            self._log("[core-switch] fallback: Xray cannot interrupt existing connections")
            return None
        target_ready = getattr(self.zapret, "target_profile_is_ready", None)
        if target_ready is not None and not target_ready(node):
            self._log(f"[core-switch] waiting for selected-server Zapret profile: {node.server}")
            return None
        legacy_ready = getattr(self.zapret, "proxy_protection_is_ready", None)
        if legacy_ready is not None and not legacy_ready(node):
            self._log(f"[core-switch] waiting for legacy UDP pass profile: {node.server}")
            return None
        return HotSwitchPlan(
            node=node,
            session=session,
            tags=dict(tags),
            tag=tag,
            control_core=control_core,
            previous_tag=tags.get(session.node_id or "", ""),
        )

    def _try_hot_switch_selected_node(self) -> bool:
        """Request a hot switch of the core's proxy transport (data plane stays alive).

        П2 (AC5/AC8): чистые проверки выполняются синхронно в GUI-потоке,
        control-plane I/O — шагами ``run_in_worker`` через TransitionRunner.
        ``True`` = «горячий путь принят» (свитч запущен либо поставлен за уже
        идущим); ``False`` = вызывающий обязан идти через очередь переходов.
        Отказ control-plane после принятия сам уводит в ``_request_transition``
        (см. ``_on_hot_switch_runner_finished``).
        """

        plan = self._hot_switch_precheck()
        if plan is None:
            return False
        self._hot_switch_generation += 1
        if self._hot_switch_runner is not None:
            # AC8: сериализация — не больше одного control-plane вызова в
            # полёте. Текущий runner устареет по generation (его результат не
            # применится), а этот запрос диспетчеризуется по его завершении.
            self._hot_switch_pending = True
            return True
        self._start_hot_switch_runner(plan)
        return True

    def _start_hot_switch_runner(self, plan: HotSwitchPlan) -> None:
        generation = self._hot_switch_generation
        transition_generation = self._transition_generation
        runner = TransitionRunner(
            self._hot_switch_selected_node_steps(plan),
            # Устаревание (AC8): новый свитч, любой новый полный переход или
            # потеря соединения отменяют текущий свитч до следующего шага;
            # его результат (сессия/статус) не применяется.
            is_current=lambda: (
                self._hot_switch_generation == generation
                and self._transition_generation == transition_generation
                and self.connected
            ),
            on_finished=self._on_hot_switch_runner_finished,
        )
        self._hot_switch_runner = runner
        runner.start()

    def _on_hot_switch_runner_finished(self, runner: TransitionRunner) -> None:
        if self._hot_switch_runner is runner:
            self._hot_switch_runner = None
        runner.deleteLater()
        pending = self._hot_switch_pending
        self._hot_switch_pending = False
        if runner.cancelled:
            if pending:
                self._dispatch_hot_switch_request()
            return
        if runner.error is not None:
            self._log(f"[core-switch] failed with error: {runner.error!r}")
        ok = bool(runner.result) and runner.error is None
        if not ok:
            # AC7/C2: отказ control-plane честно падает в очередь переходов.
            self._request_transition("node switched")
            return
        if pending:
            self._dispatch_hot_switch_request()

    def _dispatch_hot_switch_request(self) -> None:
        """Выполнить отложенный (superseded) свитч для актуально выбранной ноды."""

        if not self.connected or not self._desired_connected:
            return
        node = self.selected_node
        session = self._active_session
        if node is not None and session is not None and session.node_id == node.id:
            return  # обгоняющий запрос уже удовлетворён завершившимся свитчем
        if self._try_hot_switch_selected_node():
            return
        self._request_transition("node switched")

    def _cancel_hot_switch_runner(self) -> None:
        self._hot_switch_pending = False
        runner = self._hot_switch_runner
        if runner is not None:
            runner.cancel()

    def _apply_core_outbound_tag_steps(self, core: str, outbound_tag: str) -> TransitionSteps:
        """Control-plane вызов на воркере (AC5); лог — в GUI-потоке; без pump (AC6).

        Параметры (порты, путь к xray) снимаются в GUI-потоке, воркеру уходит
        чистый callable без обращения к состоянию контроллера.
        """

        if core == "singbox":
            api_port = self._singbox_clash_api_port
            call = lambda: select_singbox_outbound(api_port, SINGBOX_SELECTOR_TAG, outbound_tag)  # noqa: E731
        else:
            xray_path = getattr(self.xray, "_exe_path", None) or self.state.settings.xray_path
            api_port = self._xray_api_port
            call = lambda: apply_balancer_override(  # noqa: E731
                xray_path,
                api_port,
                XRAY_BALANCER_TAG,
                outbound_tag,
                pump=False,
            )
        ok, output = yield run_in_worker(call)
        if not ok:
            self._log(f"[core-switch] {core} control plane rejected {outbound_tag}: {output}")
        return bool(ok)

    def _hot_switch_selected_node_steps(self, plan: HotSwitchPlan) -> TransitionSteps:
        """Switch only the core's proxy transport, preserving the live data plane."""

        started_at = time.perf_counter()
        node, session, tags, tag = plan.node, plan.session, plan.tags, plan.tag
        if not (yield from self._apply_core_outbound_tag_steps(plan.control_core, tag)):
            return False

        hybrid_relay_selected_tag = session.hybrid_relay_selected_tag
        if session.hybrid:
            relay_tags = session.hybrid_relay_selector_tags
            if len(relay_tags) < 2:
                self._log("[core-switch] fallback: hybrid relay generations are unavailable")
                if plan.previous_tag and plan.previous_tag != tag:
                    yield from self._apply_core_outbound_tag_steps("xray", plan.previous_tag)
                return False
            hybrid_relay_selected_tag = next(
                (relay_tag for relay_tag in relay_tags if relay_tag != session.hybrid_relay_selected_tag),
                relay_tags[0],
            )
            if not (yield from self._apply_core_outbound_tag_steps("singbox", hybrid_relay_selected_tag)):
                self._log("[core-switch] hybrid cut-over rejected; restoring previous Xray outbound")
                if plan.previous_tag and plan.previous_tag != tag:
                    yield from self._apply_core_outbound_tag_steps("xray", plan.previous_tag)
                return False

        # AC7: коммит сессии/GUI-статуса — только после подтверждения ядром.
        self._capture_hot_switched_session(
            node,
            session,
            tags,
            tag,
            hybrid_relay_selected_tag=hybrid_relay_selected_tag,
        )
        self._log(f"[core-switch-perf] total={(time.perf_counter() - started_at) * 1000:.1f}ms")
        return True

    def _capture_hot_switched_session(
        self,
        node: Node,
        session: ActiveSessionSnapshot,
        tags: dict[str, str],
        tag: str,
        *,
        hybrid_relay_selected_tag: str = "",
    ) -> None:
        """Commit GUI/session state only after the core accepted the cut-over."""

        node.last_used_at = utc_now_iso()
        self._capture_active_session(
            node,
            tun=session.tun_mode,
            core=session.active_core,
            api_port=session.api_port,
            hybrid=session.hybrid,
            sidecar_kind=session.sidecar_kind,
            socks_port=session.socks_port,
            http_port=session.http_port,
            xray_inbound_tags=session.xray_inbound_tags,
            sidecar_relay_port=session.sidecar_relay_port,
            protect_ss_port=session.protect_ss_port,
            protect_ss_password=session.protect_ss_password,
            ping_host=node.server,
            ping_port=node.port,
            outbound_pool_tags=tags,
            hybrid_relay_selector_tags=session.hybrid_relay_selector_tags,
            hybrid_relay_selected_tag=hybrid_relay_selected_tag,
        )
        self._set_connection_status("running", f"Переключено: {node.name}", level="success")
        # П4: авто-переключение, завершившееся горячим свитчем (без reconnect),
        # тоже обязано снять флаг «переход в процессе».
        self._auto_switch_transitioning = False
        self._auto_switch_link_down_since = 0.0
        # Воркер метрик переживает горячий свитч — перенацелить его TCP-пинг,
        # иначе детектор мёртвого сервера продолжит мерить прежнюю ноду.
        worker = self._metrics_worker
        if worker is not None:
            worker.set_ping_target(
                node.server,
                int(node.port),
                transport_kind_for_node(node),
            )
        self._log(f"[core-switch] {session.active_core} -> {node.name} ({tag})")

    def is_rotation_supported(self, settings: AppSettings | None = None) -> bool:
        """Ротация опирается на пул outbound'ов, загруженный в работающее ядро."""

        settings = settings or self.state.settings
        return bool(settings.rotation_enabled)

    def _rotation_available_ids(self) -> set[str] | None:
        """Ноды, которые запущенное ядро реально держит в своём пуле.

        Переключение идёт по тегу, полученному ядром при старте, поэтому предлагать
        ноду вне этого набора нельзя: свитч просто не состоится.
        """

        session = self._active_session
        if session is None:
            return None
        return set(session.outbound_pool_tags or {})

    def rotation_plan(self, settings: AppSettings | None = None) -> RotationPlan | None:
        settings = settings or self.state.settings
        if not self.is_rotation_supported(settings):
            return None
        plan = build_rotation_plan(
            settings,
            self.state.nodes,
            self.state.selected_node_id,
            available_ids=self._rotation_available_ids(),
        )
        if plan is not None and plan.truncated:
            # Метод вызывается часто (в т.ч. при расчёте сигнатур) — логируем факт
            # усечения один раз на каждый новый размер пула, а не на каждый вызов.
            mark = f"{plan.candidates}->{len(plan.nodes)}"
            if mark != self._rotation_pool_logged:
                self._rotation_pool_logged = mark
                self._log(
                    f"[rotation] пул усечён: подходящих серверов {plan.candidates}, "
                    f"в ротации {len(plan.nodes)} (лимит настройки)"
                )
        return plan

    @staticmethod
    def _rotation_settings_signature(settings: AppSettings) -> tuple:
        return (
            bool(settings.rotation_enabled),
            str(settings.rotation_mode),
            int(settings.rotation_interval_sec),
            int(settings.rotation_jitter_pct),
        )

    def _sync_rotation_timer(self) -> None:
        plan = self.rotation_plan()
        if plan is None or not self.connected:
            self._rotation_timer.stop()
            if self._rotation_running:
                self._rotation_running = False
                self._log("[rotation] остановлена")
            return
        if not self._rotation_running:
            self._rotation_running = True
            self._log(
                f"[rotation] запущена: серверов в ротации {len(plan.nodes)}, "
                f"режим {self.state.settings.rotation_mode}"
            )
        self._rotation_timer.start(rotation_interval_ms(self.state.settings, self._rotation_rng))

    def _on_rotation_tick(self) -> None:
        # Собственный слот single-shot таймера: isActive() здесь уже False, поэтому
        # состояние «ротация идёт» отслеживается флагом, а не таймером — иначе каждый
        # тик заново логировался бы как запуск.
        self.rotate_now()
        self._sync_rotation_timer()

    def rotate_now(self) -> bool:
        """Переключиться на следующий сервер ротации без перезапуска ядра."""

        plan = self.rotation_plan()
        if plan is None or not self.connected:
            return False
        node = pick_next_node(
            plan,
            self.state.selected_node_id,
            self.state.settings.rotation_mode,
            self._rotation_rng,
        )
        if node is None or node.id == self.state.selected_node_id:
            return False

        self._log(f"[rotation] переключение -> {node.name}")
        # Штатный путь смены сервера: он сам делает горячий свитч по тегу, который
        # ядро получило при запуске, а при неудаче честно переподключается.
        self.set_selected_node(node.id, reset_auto_switch=False)
        self.status.emit("info", f"Ротация: {node.name}")
        return True

    def _reset_auto_switch_state(self, *, reset_cooldown: bool = False, reset_cycle: bool = True) -> None:
        self._auto_switch_low_since = 0.0
        self._auto_switch_high_ticks = 0
        self._auto_switch_active_download = False
        self._auto_switch_link_down_since = 0.0
        if reset_cycle:
            self._auto_switch_cycle_attempts = 0
            self._auto_switch_exhausted = False
        if reset_cooldown:
            self._auto_switch_last_switch = 0.0

    def _handle_auto_switch_setting_change(self, old_enabled: bool, new_enabled: bool) -> None:
        """Apply the explicit auto-switch toggle to the session guard."""

        if bool(old_enabled) == bool(new_enabled):
            return
        if new_enabled:
            # Re-enabling the setting is the explicit user action that releases
            # the manual-selection hold.  A threshold/cooldown edit alone must
            # not silently override a manually chosen server.
            self._auto_switch_manual_hold = False
            self._reset_auto_switch_state(reset_cooldown=True, reset_cycle=True)
            if self.connected:
                begin_auto_switch_warmup(self, self.selected_node)
            return
        self._reset_auto_switch_state(reset_cooldown=False, reset_cycle=True)

    def _cleanup_connection_runtime_state(
        self,
        *,
        end_traffic_session: bool,
        reset_auto_switch_cycle: bool,
        reset_auto_switch_cooldown: bool,
    ) -> None:
        cleanup_connection_runtime_state_operation(
            self,
            end_traffic_session=end_traffic_session,
            reset_auto_switch_cycle=reset_auto_switch_cycle,
            reset_auto_switch_cooldown=reset_auto_switch_cooldown,
        )

    def _stop_active_connection_processes(self, *, disable_proxy: bool) -> bool:
        return stop_active_connection_processes_operation(self, disable_proxy=disable_proxy)

    def _handle_unexpected_disconnect(self) -> None:
        handle_unexpected_disconnect_operation(self)

    def connect_selected(self, allow_during_reconnect: bool = False) -> bool:
        return connect_selected_operation(self, allow_during_reconnect=allow_during_reconnect)

    def disconnect_current(self, disable_proxy: bool = True, emit_status: bool = True) -> bool:
        return disconnect_current_operation(self, disable_proxy=disable_proxy, emit_status=emit_status)

    def _restart_proxy_core(self, reason: str) -> bool:
        return restart_singbox_proxy_runtime_operation(self, reason)

    def _restart_proxy_core_steps(self, reason: str) -> TransitionSteps:
        """Keep the transition runner interface for the single front runtime."""
        yield from ()
        return restart_singbox_proxy_runtime_operation(self, reason)

    def _restart_singbox_runtime(self, reason: str) -> bool:
        return restart_singbox_runtime_operation(self, reason)

    @property
    def traffic_history(self) -> TrafficHistoryStorage:
        return self._traffic_history

    def toggle_connection(self) -> None:
        current_target = self._desired_connected if (self._transition_active or self._transition_pending) else self.connected
        self._desired_connected = not current_target
        self._request_transition("toggle connection")

    def switch_next_node(self) -> None:
        if not self.state.nodes:
            return
        current_id = self.state.selected_node_id
        index = 0
        if current_id:
            for idx, node in enumerate(self.state.nodes):
                if node.id == current_id:
                    index = idx
                    break
        index = (index + 1) % len(self.state.nodes)
        self.set_selected_node(self.state.nodes[index].id)

    def switch_prev_node(self) -> None:
        if not self.state.nodes:
            return
        current_id = self.state.selected_node_id
        index = 0
        if current_id:
            for idx, node in enumerate(self.state.nodes):
                if node.id == current_id:
                    index = idx
                    break
        index = (index - 1) % len(self.state.nodes)
        self.set_selected_node(self.state.nodes[index].id)

    def update_routing(self, routing: RoutingSettings) -> None:
        if routing.mode not in ROUTING_MODES:
            routing.mode = "rule"
        self.state.routing = routing
        self.routing_changed.emit(self.state.routing)
        self.schedule_save()

        if self.connected or self._desired_connected:
            if not self.is_tun2socks_mode():
                return
            self._request_transition("routing changed")

    def update_settings(self, settings: AppSettings) -> None:
        settings.proxy_engine = "singbox"
        settings.tun_engine = "singbox"
        old_settings = self.state.settings
        old_launch = old_settings.launch_on_startup
        old_tun = old_settings.tun_mode
        old_proxy_engine = old_settings.proxy_engine
        old_tun_engine = old_settings.tun_engine
        old_rotation = self._rotation_settings_signature(old_settings)
        old_auto_switch_enabled = old_settings.auto_switch_enabled
        self.state.settings = settings
        self.zapret.set_target_settings(settings.zapret_target)
        self.settings_changed.emit(self.state.settings)
        self.schedule_save()
        self._apply_subscription_timer_interval()

        self._handle_auto_switch_setting_change(
            old_auto_switch_enabled,
            settings.auto_switch_enabled,
        )

        if old_rotation != self._rotation_settings_signature(settings):
            # Смена интервала/режима не трогает конфиг — достаточно перепланировать таймер.
            self._rotation_timer.stop()
            self._sync_rotation_timer()

        if old_launch != settings.launch_on_startup:
            try:
                set_startup_enabled(APP_NAME, settings.launch_on_startup, build_startup_command())
            except Exception as exc:
                self.status.emit("error", f"Ошибка настройки автозапуска: {exc}")

        if self.connected or self._desired_connected:
            if old_tun != settings.tun_mode:
                self._desired_connected = True
                self._request_transition("TUN mode toggled")
                return
            if settings.tun_mode and old_tun_engine != settings.tun_engine:
                self._desired_connected = True
                self._request_transition("TUN engine changed")
                return
            if not settings.tun_mode and old_proxy_engine != settings.proxy_engine:
                self._desired_connected = True
                self._request_transition("proxy engine changed")
                return
            self._request_transition("settings changed")

    def ping_nodes(self, node_ids: set[str] | None = None) -> None:
        ping_nodes_operation(self, node_ids)

    def speed_test_nodes(self, node_ids: set[str] | None = None) -> bool:
        return speed_test_nodes_operation(self, node_ids)

    def cancel_speed_test(self) -> bool:
        return cancel_speed_test_operation(self)

    def get_fastest_alive_node(self) -> Node | None:
        return get_fastest_alive_node_operation(self)

    def test_connectivity(self, url: str | None = None) -> None:
        test_connectivity_operation(self, url)

    def run_xray_core_update(self, apply_update: bool, silent: bool = False) -> None:
        run_xray_core_update_operation(self, apply_update, silent=silent)

    def _start_metrics_worker(self) -> None:
        start_metrics_worker_operation(self)

    def _stop_metrics_worker(self) -> None:
        stop_metrics_worker_operation(self)

    def set_master_password(self, password: str) -> None:
        password_hash, salt = create_password_hash(password)
        self.state.security.enabled = True
        self.state.security.password_hash = password_hash
        self.state.security.salt = salt
        self.save()

    def disable_master_password(self) -> None:
        self.state.security.enabled = False
        self.state.security.password_hash = ""
        self.state.security.salt = ""
        self.locked = False
        self.lock_state_changed.emit(False)
        self.save()

    def unlock(self, password: str) -> bool:
        if not self.state.security.enabled:
            self.locked = False
            self.lock_state_changed.emit(False)
            if self._startup_subscription_check_enabled():
                QTimer.singleShot(0, self._check_due_subscriptions)
            return True

        ok = verify_password(password, self.state.security.password_hash, self.state.security.salt)
        if ok:
            self.locked = False
            self.lock_state_changed.emit(False)
            if self._startup_subscription_check_enabled():
                QTimer.singleShot(0, self._check_due_subscriptions)
        return ok

    def lock(self) -> None:
        if not self.state.security.enabled:
            return
        self.locked = True
        self.lock_state_changed.emit(True)
        self._desired_connected = False
        self.disconnect_current()

    def build_diagnostics(self) -> Path:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = LOG_DIR / f"diagnostics_{stamp}.zip"
        return export_diagnostics(output, self.state, self.recent_logs,
                                  runtime_errors=self.runtime_errors.snapshot(),
                                  runtime=collect_runtime_diagnostics(self))

    def auto_connect_if_needed(self) -> None:
        if not self.state.settings.auto_connect_last or self.locked:
            return
        if self.selected_node is None and not self._can_connect_without_selected_node():
            return
        if (
            self.state.settings.startup_connect_order == "after_subscriptions"
            and self._begin_startup_connect_wait()
        ):
            return
        self._perform_auto_connect()

    def _perform_auto_connect(self) -> None:
        if not self.state.settings.auto_connect_last or self.locked:
            return
        if self.selected_node is not None or self._can_connect_without_selected_node():
            self._desired_connected = True
            self._request_transition("auto connect")

    def _begin_startup_connect_wait(self) -> bool:
        """AC6: try deferring auto-connect until startup subscription refresh ends.

        Returns True only when a startup check actually queued work; the armed
        fallback timer (STARTUP_CONNECT_FALLBACK_MS <= 30 s) guarantees that a
        failed or hanging subscription update never blocks auto-connect.
        """
        if not self._startup_subscription_check_enabled():
            return False
        self._check_due_subscriptions()
        if not self._subscription_workers and not self._subscription_update_queue:
            return False  # nothing to update -> degenerate to immediate connect
        self._startup_connect_pending = True
        self._startup_connect_timer.start()
        return True

    def _maybe_finish_startup_connect(self) -> None:
        if (
            self._startup_connect_pending
            and not self._subscription_workers
            and not self._subscription_update_queue
        ):
            self._finish_startup_connect()

    def _finish_startup_connect(self) -> None:
        if not self._startup_connect_pending:
            return
        self._startup_connect_pending = False
        self._startup_connect_timer.stop()
        self._perform_auto_connect()

    def _log(self, line: str) -> None:
        """Send a log line to the UI and write it to the log file."""
        self.recent_logs.append(line)
        if len(self.recent_logs) > 5000:
            self.recent_logs = self.recent_logs[-5000:]
        self._logger.info(line)
        self.log_line.emit(line)

    def _on_xray_log(self, line: str) -> None:
        self._on_core_log("xray", line)

    def _on_core_log(self, engine: str, line: str) -> None:
        if is_core_error_line(line):
            self._record_core_failure(engine, "runtime", line)
        context = self._core_log_contexts.get(engine)
        if context is None:
            context = RuntimeLogContext(
                engine=engine,
                role="core",
                mode="tun" if self.state.settings.tun_mode else "proxy",
                generation=int(self._transition_generation),
            )
        line = contextualize_runtime_log(line, context=context)
        # In TUN mode, throttle noisy per-connection logs to prevent UI freeze
        if self.state.settings.tun_mode and "accepted" in line:
            self._tun_log_count = getattr(self, "_tun_log_count", 0) + 1
            # Only log to file, skip UI — emit summary every 100 lines
            self._logger.info(line)
            self.recent_logs.append(line)
            if len(self.recent_logs) > 5000:
                self.recent_logs = self.recent_logs[-5000:]
            if self._tun_log_count % 100 == 0:
                self.log_line.emit(f"[tun] {self._tun_log_count} connections routed...")
            return
        self._log(line)

    def _on_xray_error(self, message: str) -> None:
        self._on_core_error("xray", message)

    def _on_core_error(self, engine: str, message: str) -> None:
        self._record_core_failure(engine, "operation", message)
        context = self._core_log_contexts.get(engine)
        if context is None:
            context = RuntimeLogContext(
                engine=engine,
                role="core",
                mode="tun" if self.state.settings.tun_mode else "proxy",
                generation=int(self._transition_generation),
            )
        detailed = contextualize_runtime_log(message, context=context, error=True)
        self._log(detailed)
        self._set_connection_status("error", detailed, level="error")

    def _record_core_failure(self, engine: str, stage: str, message: str) -> None:
        journal = getattr(self, "runtime_errors", None)
        if journal is None:
            self.runtime_errors = journal = RuntimeErrorJournal()
        context = self._core_log_contexts.get(engine)
        journal.record(core_failure(
            engine, stage, message,
            session_generation=context.generation if context else 0,
            # A shared log stream does not prove which pooled target emitted it.
            # Never attribute late output to the currently selected node.
        ))
        self.runtime_errors_changed.emit(journal.snapshot())

    def _on_singbox_error(self, message: str) -> None:
        self._on_core_error("sing-box", message)

    def _on_core_stopped(self, core: str, exit_code: int) -> None:
        self._log(f"[{core}] process stopped with code {exit_code}")

    def _on_core_state_changed(self, _running: bool) -> None:
        on_core_state_changed_operation(self, _running)

    def _on_ping_result(self, node_id: str, ping_ms: int | None) -> None:
        on_ping_result_operation(self, node_id, ping_ms)

    def _on_ping_progress(self, current: int, total: int) -> None:
        on_ping_progress_operation(self, current, total)

    def _on_ping_complete(self) -> None:
        on_ping_complete_operation(self)

    def _on_speed_result(self, node_id: str, speed_mbps: float | None, is_alive: bool) -> None:
        on_speed_result_operation(self, node_id, speed_mbps, is_alive)

    def _on_speed_progress(self, current: int, total: int) -> None:
        on_speed_progress_operation(self, current, total)

    def _on_speed_node_progress(self, node_id: str, percent: int) -> None:
        on_speed_node_progress_operation(self, node_id, percent)

    def _on_speed_complete(self) -> None:
        on_speed_complete_operation(self)

    def _on_connectivity_result(self, ok: bool, message: str, elapsed_ms: int | None) -> None:
        on_connectivity_result_operation(self, ok, message, elapsed_ms)

    def _on_live_metrics(self, payload: dict[str, object]) -> None:
        on_live_metrics_operation(self, payload)

    # Require N consecutive high-speed readings to confirm "active download"
    _AUTO_SWITCH_HIGH_TICKS_REQUIRED = 10  # ~10s of sustained traffic above threshold
    # Minimum speed to count as "traffic exists" (1 KB/s) vs idle (0)
    _AUTO_SWITCH_IDLE_BPS = 1024.0

    def _check_auto_switch(
        self,
        down_bps: float,
        link_alive: bool | None = None,
        *,
        traffic_valid: bool = True,
    ) -> None:
        check_auto_switch_operation(
            self,
            down_bps,
            link_alive,
            traffic_valid=traffic_valid,
        )

    def _get_next_node_for_auto_switch(self) -> Node | None:
        return get_next_node_for_auto_switch_operation(self)

    def _on_xray_update_worker_done(self, result: XrayCoreUpdateResult) -> None:
        on_xray_update_worker_done_operation(self, result)

    def _on_network_changed(self, old: str, new: str) -> None:
        self._log(f"[network] changed: {old} -> {new}")
        # TUN mode creates a virtual adapter which triggers network change —
        # reconnecting would kill the TUN and cause an infinite loop
        if self.state.settings.tun_mode:
            self._log("[network] ignoring change in TUN mode")
            return
        if self.connected and self.state.settings.reconnect_on_network_change:
            self._desired_connected = True
            self._request_transition("network changed")

    def _hot_swap_node(self, reason: str) -> bool:
        """Handle node switch while TUN is active (синхронный совместимый путь)."""
        return bool(run_steps_blocking(self._hot_swap_node_steps(reason)))

    def _hot_swap_node_steps(self, reason: str) -> TransitionSteps:
        """Handle node switch while TUN is active."""
        yield from ()
        session = self._active_session
        if session is None:
            self._auto_switch_transitioning = False
            return False

        self._xray_api_port = session.api_port
        self._protect_ss_port = session.protect_ss_port
        self._protect_ss_password = session.protect_ss_password

        try:
            return self._restart_singbox_runtime(reason)
        finally:
            self._auto_switch_transitioning = False

    def _reconnect(self, reason: str) -> bool:
        return reconnect_operation(self, reason)

    def export_backup(self, path: Path, passphrase: str = "") -> None:
        self.storage.export_backup(path, passphrase)

    def import_backup(self, path: Path, passphrase: str = "") -> None:
        self.state = self.storage.import_backup(path, passphrase)
        self.zapret.set_target_settings(self.state.settings.zapret_target)
        self.save()
        self.nodes_changed.emit(self.state.nodes)
        self.selection_changed.emit(self.selected_node)
        self.routing_changed.emit(self.state.routing)
        self.settings_changed.emit(self.state.settings)

    def _check_auto_lock(self) -> None:
        if not self.state.security.enabled:
            return
        if self.locked:
            return
        minutes = max(1, self.state.security.auto_lock_minutes)
        if get_idle_seconds() >= minutes * 60:
            self.lock()
