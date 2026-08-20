from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import re
import uuid

from .constants import DEFAULT_ACCENT_COLOR, ROUTING_RULE, STATE_SCHEMA_VERSION

# Model-level accent validation (no Qt imports here, D2): the color picker
# only ever produces "#RRGGBB" strings; anything else falls back to the
# default.  Full QColor-based normalization lives in ui/theme.py.
_ACCENT_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")


def normalize_accent_color(value: Any) -> str:
    """Return *value* if it looks like "#RRGGBB", else the default accent."""
    text = str(value or "")
    return text if _ACCENT_COLOR_RE.fullmatch(text) else DEFAULT_ACCENT_COLOR


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _int_mapping(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, int] = {}
    for key, item in value.items():
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            continue
        result[str(key)] = int(item)
    return result


@dataclass(slots=True)
class Node:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    scheme: str = ""
    server: str = ""
    port: int = 0
    link: str = ""
    outbound: dict[str, Any] = field(default_factory=dict)
    group: str = "Default"
    tags: list[str] = field(default_factory=list)
    ping_ms: int | None = None
    last_used_at: str | None = None
    created_at: str = field(default_factory=utc_now_iso)
    country_code: str = ""
    speed_mbps: float | None = None
    is_alive: bool | None = None
    ping_history: list[tuple[str, int | None]] = field(default_factory=list)
    speed_history: list[tuple[str, float | None]] = field(default_factory=list)
    sort_order: int = 0
    subscription_id: str | None = None
    source_key: str = ""
    provider_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "scheme": self.scheme,
            "server": self.server,
            "port": self.port,
            "link": self.link,
            "outbound": self.outbound,
            "group": self.group,
            "tags": list(self.tags),
            "ping_ms": self.ping_ms,
            "last_used_at": self.last_used_at,
            "created_at": self.created_at,
            "country_code": self.country_code,
            "speed_mbps": self.speed_mbps,
            "is_alive": self.is_alive,
            "ping_history": self.ping_history,
            "speed_history": self.speed_history,
            "sort_order": self.sort_order,
            "subscription_id": self.subscription_id,
            "source_key": self.source_key,
            "provider_name": self.provider_name,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Node":
        return Node(
            id=str(data.get("id") or uuid.uuid4()),
            name=str(data.get("name") or ""),
            scheme=str(data.get("scheme") or ""),
            server=str(data.get("server") or ""),
            port=int(data.get("port") or 0),
            link=str(data.get("link") or ""),
            outbound=dict(data.get("outbound") or {}),
            group=str(data.get("group") or "Default"),
            tags=list(data.get("tags") or []),
            ping_ms=data.get("ping_ms"),
            last_used_at=data.get("last_used_at"),
            created_at=str(data.get("created_at") or utc_now_iso()),
            country_code=str(data.get("country_code") or ""),
            speed_mbps=data.get("speed_mbps"),
            is_alive=data.get("is_alive"),
            ping_history=data.get("ping_history", []),
            speed_history=data.get("speed_history", []),
            sort_order=int(data.get("sort_order", 0)),
            subscription_id=(str(data.get("subscription_id")) if data.get("subscription_id") else None),
            source_key=str(data.get("source_key") or ""),
            provider_name=str(data.get("provider_name") or data.get("name") or ""),
        )


@dataclass(slots=True)
class SubscriptionInfo:
    upload: int = 0
    download: int = 0
    total: int = 0
    expire: int = 0
    web_page_url: str = ""
    support_url: str = ""

    @property
    def used(self) -> int:
        return max(0, self.upload) + max(0, self.download)

    def to_dict(self) -> dict[str, Any]:
        return {
            "upload": self.upload,
            "download": self.download,
            "total": self.total,
            "expire": self.expire,
            "web_page_url": self.web_page_url,
            "support_url": self.support_url,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "SubscriptionInfo":
        def _number(key: str) -> int:
            try:
                return max(0, int(data.get(key) or 0))
            except (TypeError, ValueError):
                return 0

        return SubscriptionInfo(
            upload=_number("upload"),
            download=_number("download"),
            total=_number("total"),
            expire=_number("expire"),
            web_page_url=str(data.get("web_page_url") or ""),
            support_url=str(data.get("support_url") or ""),
        )


@dataclass(slots=True)
class Subscription:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    url: str = ""
    user_agent: str = ""
    client_profile: str = "zapret"
    send_hwid: bool = False
    hwid: str = ""
    auto_update: bool = True
    update_interval_hours: int | None = None
    provider_interval_hours: int | None = None
    include_pattern: str = ""
    exclude_pattern: str = ""
    etag: str = ""
    last_modified: str = ""
    last_checked_at: str | None = None
    last_success_at: str | None = None
    last_error: str = ""
    failure_count: int = 0
    backoff_until: str | None = None
    info: SubscriptionInfo = field(default_factory=SubscriptionInfo)
    pending_url: str = ""
    hidden_source_keys: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now_iso)
    sort_order: int = 0

    @property
    def effective_interval_hours(self) -> int:
        value = self.update_interval_hours or self.provider_interval_hours or 24
        return max(1, int(value))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "user_agent": self.user_agent,
            "client_profile": self.client_profile,
            "send_hwid": self.send_hwid,
            "hwid": self.hwid,
            "auto_update": self.auto_update,
            "update_interval_hours": self.update_interval_hours,
            "provider_interval_hours": self.provider_interval_hours,
            "include_pattern": self.include_pattern,
            "exclude_pattern": self.exclude_pattern,
            "etag": self.etag,
            "last_modified": self.last_modified,
            "last_checked_at": self.last_checked_at,
            "last_success_at": self.last_success_at,
            "last_error": self.last_error,
            "failure_count": self.failure_count,
            "backoff_until": self.backoff_until,
            "info": self.info.to_dict(),
            "pending_url": self.pending_url,
            "hidden_source_keys": list(self.hidden_source_keys),
            "created_at": self.created_at,
            "sort_order": self.sort_order,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Subscription":
        def _optional_positive_int(key: str) -> int | None:
            try:
                value = int(data.get(key) or 0)
            except (TypeError, ValueError):
                return None
            return value if value > 0 else None

        def _non_negative_int(key: str) -> int:
            try:
                return max(0, int(data.get(key) or 0))
            except (TypeError, ValueError):
                return 0

        return Subscription(
            id=str(data.get("id") or uuid.uuid4()),
            name=str(data.get("name") or ""),
            url=str(data.get("url") or ""),
            user_agent=str(data.get("user_agent") or ""),
            client_profile=str(data.get("client_profile") or "zapret"),
            send_hwid=bool(data.get("send_hwid", False)),
            hwid=str(data.get("hwid") or ""),
            auto_update=bool(data.get("auto_update", True)),
            update_interval_hours=_optional_positive_int("update_interval_hours"),
            provider_interval_hours=_optional_positive_int("provider_interval_hours"),
            include_pattern=str(data.get("include_pattern") or ""),
            exclude_pattern=str(data.get("exclude_pattern") or ""),
            etag=str(data.get("etag") or ""),
            last_modified=str(data.get("last_modified") or ""),
            last_checked_at=data.get("last_checked_at"),
            last_success_at=data.get("last_success_at"),
            last_error=str(data.get("last_error") or ""),
            failure_count=_non_negative_int("failure_count"),
            backoff_until=data.get("backoff_until"),
            info=SubscriptionInfo.from_dict(dict(data.get("info") or {})),
            pending_url=str(data.get("pending_url") or ""),
            hidden_source_keys=[str(item) for item in (data.get("hidden_source_keys") or [])],
            created_at=str(data.get("created_at") or utc_now_iso()),
            sort_order=_non_negative_int("sort_order"),
        )


@dataclass(slots=True)
class SubscriptionUpdateResult:
    subscription_id: str
    success: bool
    message: str = ""
    added: int = 0
    updated: int = 0
    removed: int = 0
    skipped: int = 0
    warnings: list[str] = field(default_factory=list)
    not_modified: bool = False
    reconnect_required: bool = False
    #: Проверка только читает подписку и ничего не сохраняет, поэтому счётчики
    #: изменений у неё всегда нулевые и показывать их нельзя.
    check_only: bool = False
    #: Сколько серверов отдала подписка и сколько уже сохранено локально.
    source_count: int = 0
    stored_count: int = 0


@dataclass(slots=True)
class RoutingSettings:
    mode: str = ROUTING_RULE
    bypass_lan: bool = True
    direct_domains: list[str] = field(default_factory=list)
    proxy_domains: list[str] = field(default_factory=list)
    block_domains: list[str] = field(default_factory=list)
    dns_mode: str = "system"  # system | builtin
    dns_bootstrap_server: str = "1.1.1.1"  # DNS for direct traffic
    dns_bootstrap_type: str = "udp"        # udp | tcp | tls | https
    dns_proxy_server: str = "8.8.8.8"     # DNS for proxy traffic
    dns_proxy_type: str = "tcp"            # tcp | tls | https
    process_rules: list[dict[str, str]] = field(default_factory=list)  # [{"process": "chrome.exe", "action": "direct|proxy|block"}]
    process_preset_routes: dict[str, str] = field(default_factory=dict)  # {"telegram": "proxy", "windows_system": "direct"}
    service_routes: dict[str, str] = field(default_factory=dict)  # {"youtube": "proxy", "steam": "direct", ...}
    tun_default_outbound: str = "direct"  # "proxy" | "direct"

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "bypass_lan": self.bypass_lan,
            "direct_domains": list(self.direct_domains),
            "proxy_domains": list(self.proxy_domains),
            "block_domains": list(self.block_domains),
            "dns_mode": self.dns_mode,
            "dns_bootstrap_server": self.dns_bootstrap_server,
            "dns_bootstrap_type": self.dns_bootstrap_type,
            "dns_proxy_server": self.dns_proxy_server,
            "dns_proxy_type": self.dns_proxy_type,
            "process_rules": list(self.process_rules),
            "process_preset_routes": dict(self.process_preset_routes),
            "service_routes": dict(self.service_routes),
            "tun_default_outbound": self.tun_default_outbound,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "RoutingSettings":
        return RoutingSettings(
            mode=str(data.get("mode") or ROUTING_RULE),
            bypass_lan=bool(data.get("bypass_lan", True)),
            direct_domains=list(data.get("direct_domains") or []),
            proxy_domains=list(data.get("proxy_domains") or []),
            block_domains=list(data.get("block_domains") or []),
            dns_mode=str(data.get("dns_mode") or "system"),
            dns_bootstrap_server=str(data.get("dns_bootstrap_server") or "1.1.1.1"),
            dns_bootstrap_type=str(data.get("dns_bootstrap_type") or "udp"),
            dns_proxy_server=str(data.get("dns_proxy_server") or "8.8.8.8"),
            dns_proxy_type=str(data.get("dns_proxy_type") or "tcp"),
            process_rules=list(data.get("process_rules") or []),
            process_preset_routes=dict(data.get("process_preset_routes") or {}),
            service_routes=dict(data.get("service_routes") or {}),
            tun_default_outbound=str(data.get("tun_default_outbound") or "direct"),
        )


@dataclass(slots=True)
class SecuritySettings:
    enabled: bool = False
    password_hash: str = ""
    salt: str = ""
    auto_lock_minutes: int = 15

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "password_hash": self.password_hash,
            "salt": self.salt,
            "auto_lock_minutes": self.auto_lock_minutes,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "SecuritySettings":
        return SecuritySettings(
            enabled=bool(data.get("enabled", False)),
            password_hash=str(data.get("password_hash") or ""),
            salt=str(data.get("salt") or ""),
            auto_lock_minutes=int(data.get("auto_lock_minutes") or 15),
        )


# --- Subscription auto-update globals (startup-subscription-settings) ---
SUBSCRIPTIONS_CHECK_INTERVAL_MIN = 5
SUBSCRIPTIONS_CHECK_INTERVAL_MAX = 1440
SUBSCRIPTIONS_CHECK_INTERVAL_DEFAULT = 15
STARTUP_CONNECT_ORDERS = ("immediate", "after_subscriptions")


def clamp_subscriptions_check_interval(value: Any) -> int:
    """Clamp the global subscription check interval (minutes) to [5, 1440].

    Garbage values (None, non-numeric strings) fall back to the default
    without raising, so corrupted state files never break loading.
    """
    try:
        minutes = int(value)
    except (TypeError, ValueError):
        return SUBSCRIPTIONS_CHECK_INTERVAL_DEFAULT
    return max(
        SUBSCRIPTIONS_CHECK_INTERVAL_MIN,
        min(SUBSCRIPTIONS_CHECK_INTERVAL_MAX, minutes),
    )


def normalize_startup_connect_order(value: Any) -> str:
    """Unknown/legacy values read as \"immediate\" (current behaviour)."""
    text = str(value or "immediate")
    return text if text in STARTUP_CONNECT_ORDERS else "immediate"


@dataclass(slots=True)
class AppSettings:
    theme: str = "system"  # system | light | dark
    accent_color: str = DEFAULT_ACCENT_COLOR
    auto_connect_last: bool = True
    start_minimized: bool = False
    enable_system_proxy: bool = True
    system_proxy_bypass_lan: bool = True
    launch_on_startup: bool = False
    reconnect_on_network_change: bool = True
    xray_path: str = ""
    log_level: str = "warning"
    check_updates: bool = True
    allow_updates: bool = True
    release_channel: str = "stable"  # stable | beta | nightly
    update_feed_url: str = ""
    xray_release_channel: str = "stable"  # stable | beta | nightly
    xray_update_feed_url: str = ""
    xray_auto_update: bool = False
    tun_mode: bool = False
    proxy_engine: str = "singbox"  # "singbox" | "xray"
    tun_engine: str = "singbox"  # "singbox" | "xray" | "tun2socks"
    xray_config_file: str = ""
    xray_template_file: str = ""
    singbox_path: str = ""
    singbox_config_file: str = ""
    singbox_template_file: str = ""
    window_width: int = 1000
    window_height: int = 720
    window_x: int = -1
    window_y: int = -1
    zapret_preset: str = ""
    zapret_autostart: bool = False
    auto_switch_enabled: bool = True
    auto_switch_threshold_kbps: int = 50
    auto_switch_delay_sec: int = 30
    auto_switch_cooldown_sec: int = 60
    # Rotation: periodic exit-node switching inside a pool (xray balancer override)
    rotation_enabled: bool = False
    rotation_mode: str = "random"  # random | sequential
    rotation_interval_sec: int = 600
    rotation_jitter_pct: int = 20
    rotation_pool: str = "all"  # all | group | tag | subscription
    rotation_pool_value: str = ""
    rotation_only_alive: bool = True
    rotation_max_nodes: int = 20
    # Server list view preferences (stable english keys; empty = defaults)
    nodes_sort_key: str = "manual"  # manual | name | group | type | ping | speed | last_used
    nodes_sort_desc: bool = False
    nodes_group_filter: str = ""
    nodes_tag_filter: str = ""
    nodes_source_filter: str = ""
    nodes_visible_columns: list[str] = field(default_factory=list)  # empty = default set
    nodes_column_widths: dict[str, int] = field(default_factory=dict)
    nodes_column_order: list[str] = field(default_factory=list)
    nodes_column_layout_version: int = 1
    # Subscription auto-update globals (additive, defaults keep current behaviour)
    subscriptions_auto_update: bool = True
    subscriptions_check_on_startup: bool = True
    subscriptions_check_interval_min: int = SUBSCRIPTIONS_CHECK_INTERVAL_DEFAULT  # clamp 5..1440
    startup_connect_order: str = "immediate"  # immediate | after_subscriptions

    def to_dict(self) -> dict[str, Any]:
        return {
            "theme": self.theme,
            "accent_color": self.accent_color,
            "auto_connect_last": self.auto_connect_last,
            "start_minimized": self.start_minimized,
            "enable_system_proxy": self.enable_system_proxy,
            "system_proxy_bypass_lan": self.system_proxy_bypass_lan,
            "launch_on_startup": self.launch_on_startup,
            "reconnect_on_network_change": self.reconnect_on_network_change,
            "xray_path": self.xray_path,
            "log_level": self.log_level,
            "check_updates": self.check_updates,
            "allow_updates": self.allow_updates,
            "release_channel": self.release_channel,
            "update_feed_url": self.update_feed_url,
            "xray_release_channel": self.xray_release_channel,
            "xray_update_feed_url": self.xray_update_feed_url,
            "xray_auto_update": self.xray_auto_update,
            "tun_mode": self.tun_mode,
            "proxy_engine": self.proxy_engine,
            "tun_engine": self.tun_engine,
            "xray_config_file": self.xray_config_file,
            "xray_template_file": self.xray_template_file,
            "singbox_path": self.singbox_path,
            "singbox_config_file": self.singbox_config_file,
            "singbox_template_file": self.singbox_template_file,
            "window_width": self.window_width,
            "window_height": self.window_height,
            "window_x": self.window_x,
            "window_y": self.window_y,
            "zapret_preset": self.zapret_preset,
            "zapret_autostart": self.zapret_autostart,
            "auto_switch_enabled": self.auto_switch_enabled,
            "auto_switch_threshold_kbps": self.auto_switch_threshold_kbps,
            "auto_switch_delay_sec": self.auto_switch_delay_sec,
            "auto_switch_cooldown_sec": self.auto_switch_cooldown_sec,
            "rotation_enabled": self.rotation_enabled,
            "rotation_mode": self.rotation_mode,
            "rotation_interval_sec": self.rotation_interval_sec,
            "rotation_jitter_pct": self.rotation_jitter_pct,
            "rotation_pool": self.rotation_pool,
            "rotation_pool_value": self.rotation_pool_value,
            "rotation_only_alive": self.rotation_only_alive,
            "rotation_max_nodes": self.rotation_max_nodes,
            "nodes_sort_key": self.nodes_sort_key,
            "nodes_sort_desc": self.nodes_sort_desc,
            "nodes_group_filter": self.nodes_group_filter,
            "nodes_tag_filter": self.nodes_tag_filter,
            "nodes_source_filter": self.nodes_source_filter,
            "nodes_visible_columns": list(self.nodes_visible_columns),
            "nodes_column_widths": dict(self.nodes_column_widths),
            "nodes_column_order": list(self.nodes_column_order),
            "nodes_column_layout_version": self.nodes_column_layout_version,
            "subscriptions_auto_update": self.subscriptions_auto_update,
            "subscriptions_check_on_startup": self.subscriptions_check_on_startup,
            "subscriptions_check_interval_min": self.subscriptions_check_interval_min,
            "startup_connect_order": self.startup_connect_order,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "AppSettings":
        return AppSettings(
            theme=str(data.get("theme") or "system"),
            accent_color=normalize_accent_color(data.get("accent_color")),
            auto_connect_last=bool(data.get("auto_connect_last", True)),
            start_minimized=bool(data.get("start_minimized", False)),
            enable_system_proxy=bool(data.get("enable_system_proxy", True)),
            system_proxy_bypass_lan=bool(data.get("system_proxy_bypass_lan", True)),
            launch_on_startup=bool(data.get("launch_on_startup", False)),
            reconnect_on_network_change=bool(data.get("reconnect_on_network_change", True)),
            xray_path=str(data.get("xray_path") or ""),
            log_level=str(data.get("log_level") or "warning"),
            check_updates=bool(data.get("check_updates", True)),
            allow_updates=bool(data.get("allow_updates", True)),
            release_channel=str(data.get("release_channel") or "stable"),
            update_feed_url=str(data.get("update_feed_url") or ""),
            xray_release_channel=str(data.get("xray_release_channel") or "stable"),
            xray_update_feed_url=str(data.get("xray_update_feed_url") or ""),
            xray_auto_update=bool(data.get("xray_auto_update", False)),
            tun_mode=bool(data.get("tun_mode", False)),
            proxy_engine=str(data.get("proxy_engine") or "singbox"),
            tun_engine=str(data.get("tun_engine") or "singbox"),
            xray_config_file=str(data.get("xray_config_file") or ""),
            xray_template_file=str(data.get("xray_template_file") or ""),
            singbox_path=str(data.get("singbox_path") or ""),
            singbox_config_file=str(data.get("singbox_config_file") or ""),
            singbox_template_file=str(data.get("singbox_template_file") or ""),
            window_width=int(data.get("window_width") or 1000),
            window_height=int(data.get("window_height") or 720),
            window_x=int(data.get("window_x", -1)),
            window_y=int(data.get("window_y", -1)),
            zapret_preset=str(data.get("zapret_preset") or ""),
            zapret_autostart=bool(data.get("zapret_autostart", False)),
            auto_switch_enabled=bool(data.get("auto_switch_enabled", True)),
            auto_switch_threshold_kbps=int(data.get("auto_switch_threshold_kbps") or 50),
            auto_switch_delay_sec=int(data.get("auto_switch_delay_sec") or 30),
            auto_switch_cooldown_sec=int(data.get("auto_switch_cooldown_sec") or 60),
            rotation_enabled=bool(data.get("rotation_enabled", False)),
            rotation_mode=str(data.get("rotation_mode") or "random"),
            rotation_interval_sec=int(data.get("rotation_interval_sec") or 600),
            rotation_jitter_pct=int(data.get("rotation_jitter_pct", 20)),
            rotation_pool=str(data.get("rotation_pool") or "all"),
            rotation_pool_value=str(data.get("rotation_pool_value") or ""),
            rotation_only_alive=bool(data.get("rotation_only_alive", True)),
            rotation_max_nodes=int(data.get("rotation_max_nodes") or 20),
            nodes_sort_key=str(data.get("nodes_sort_key") or "manual"),
            nodes_sort_desc=bool(data.get("nodes_sort_desc", False)),
            nodes_group_filter=str(data.get("nodes_group_filter") or ""),
            nodes_tag_filter=str(data.get("nodes_tag_filter") or ""),
            nodes_source_filter=str(data.get("nodes_source_filter") or ""),
            nodes_visible_columns=[str(item) for item in (data.get("nodes_visible_columns") or [])],
            nodes_column_widths=_int_mapping(data.get("nodes_column_widths")),
            nodes_column_order=[str(item) for item in (data.get("nodes_column_order") or [])],
            nodes_column_layout_version=int(data.get("nodes_column_layout_version", 0) or 0),
            subscriptions_auto_update=bool(data.get("subscriptions_auto_update", True)),
            subscriptions_check_on_startup=bool(data.get("subscriptions_check_on_startup", True)),
            subscriptions_check_interval_min=clamp_subscriptions_check_interval(
                data.get("subscriptions_check_interval_min", SUBSCRIPTIONS_CHECK_INTERVAL_DEFAULT)
            ),
            startup_connect_order=normalize_startup_connect_order(data.get("startup_connect_order")),
        )


@dataclass(slots=True)
class AppState:
    schema_version: int = STATE_SCHEMA_VERSION
    selected_node_id: str | None = None
    subscription_device_id: str = field(default_factory=lambda: str(uuid.uuid4()).upper())
    nodes: list[Node] = field(default_factory=list)
    subscriptions: list[Subscription] = field(default_factory=list)
    routing: RoutingSettings = field(default_factory=RoutingSettings)
    settings: AppSettings = field(default_factory=AppSettings)
    security: SecuritySettings = field(default_factory=SecuritySettings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "selected_node_id": self.selected_node_id,
            "subscription_device_id": self.subscription_device_id,
            "nodes": [node.to_dict() for node in self.nodes],
            "subscriptions": [subscription.to_dict() for subscription in self.subscriptions],
            "routing": self.routing.to_dict(),
            "settings": self.settings.to_dict(),
            "security": self.security.to_dict(),
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "AppState":
        nodes_raw = data.get("nodes") or []
        nodes = [Node.from_dict(item) for item in nodes_raw if isinstance(item, dict)]
        subscriptions_raw = data.get("subscriptions") or []
        subscriptions = [
            Subscription.from_dict(item) for item in subscriptions_raw if isinstance(item, dict)
        ]
        return AppState(
            schema_version=int(data.get("schema_version") or STATE_SCHEMA_VERSION),
            selected_node_id=data.get("selected_node_id"),
            subscription_device_id=str(
                data.get("subscription_device_id") or uuid.uuid4()
            ).upper(),
            nodes=nodes,
            subscriptions=subscriptions,
            routing=RoutingSettings.from_dict(dict(data.get("routing") or {})),
            settings=AppSettings.from_dict(dict(data.get("settings") or {})),
            security=SecuritySettings.from_dict(dict(data.get("security") or {})),
        )
