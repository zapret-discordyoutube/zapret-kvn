"""Presentation catalog for the structured sing-box editor.

Only wording and emphasis live here: Russian labels, which fields are shown
up front, and one-line summaries for list rows. Which fields exist, their
types and allowed values always come from the core schema, so a field that is
missing from this catalog is still editable under its native key.
"""

from __future__ import annotations

from typing import Any

from .document import as_list


FIELD_LABELS: dict[str, str] = {
    # rule matching
    "domain": "Домены (точно)",
    "domain_suffix": "Домены и поддомены",
    "domain_keyword": "Домены по слову",
    "domain_regex": "Домены (regex)",
    "ip_cidr": "IP-адреса и подсети",
    "ip_is_private": "Локальные адреса",
    "source_ip_cidr": "IP источника",
    "source_ip_is_private": "Источник — локальный адрес",
    "port": "Порты",
    "port_range": "Диапазоны портов",
    "source_port": "Порты источника",
    "source_port_range": "Диапазоны портов источника",
    "process_name": "Процессы (имя файла)",
    "process_path": "Процессы (полный путь)",
    "process_path_regex": "Процессы (путь, regex)",
    "rule_set": "Наборы правил",
    "rule_set_ip_cidr_match_source": "Наборы: IP источника",
    "network": "Сеть",
    "protocol": "Протокол (sniff)",
    "client": "Клиент TLS/QUIC",
    "inbound": "Входящие",
    "ip_version": "Версия IP",
    "auth_user": "Пользователь прокси",
    "query_type": "Тип DNS-запроса",
    "clash_mode": "Режим Clash",
    "invert": "Инвертировать условие",
    "mode": "Логика",
    "rules": "Правила",
    # rule actions
    "action": "Действие",
    "outbound": "Выход",
    "method": "Способ",
    "no_drop": "Не отбрасывать при частых срабатываниях",
    "sniffer": "Анализаторы",
    "timeout": "Тайм-аут",
    "server": "Сервер",
    "strategy": "Стратегия IP",
    "override_address": "Подменить адрес",
    "override_port": "Подменить порт",
    "tls_fragment": "Фрагментировать TLS",
    "tls_record_fragment": "Фрагментировать TLS-записи",
    "tls_fragment_fallback_delay": "Задержка отката фрагментации",
    "udp_timeout": "Тайм-аут UDP",
    "udp_connect": "UDP connect",
    "disable_cache": "Без кэша",
    "rewrite_ttl": "Переписать TTL",
    "client_subnet": "Client subnet (ECS)",
    # common object keys
    "type": "Тип",
    "tag": "Тег",
    "final": "Если ничего не подошло",
    "detour": "Через выход",
    "domain_resolver": "DNS для адреса сервера",
    "server_port": "Порт сервера",
    "path": "Путь",
    "url": "URL",
    "format": "Формат",
    "update_interval": "Интервал обновления",
    "outbounds": "Выходы",
    "default": "По умолчанию",
    "interval": "Интервал",
    "tolerance": "Допуск, мс",
    # route options
    "auto_detect_interface": "Определять сетевой интерфейс",
    "default_interface": "Сетевой интерфейс",
    "default_domain_resolver": "DNS для доменов по умолчанию",
    "find_process": "Определять процесс-владелец",
    "default_mark": "Routing mark",
    # dns
    "servers": "Серверы",
    "reverse_mapping": "Обратное сопоставление",
    "disable_expire": "Не устаревать кэш",
    "cache_capacity": "Размер кэша",
    "independent_cache": "Отдельный кэш",
    "optimistic": "Оптимистичный кэш",
    # inbound tun
    "interface_name": "Имя интерфейса",
    "address": "Адреса интерфейса",
    "mtu": "MTU",
    "auto_route": "Автомаршрутизация",
    "strict_route": "Строгая маршрутизация",
    "stack": "Сетевой стек",
    "route_address": "Только эти адреса",
    "route_exclude_address": "Кроме этих адресов",
    "route_address_set": "Только наборы",
    "route_exclude_address_set": "Кроме наборов",
    "include_interface": "Только интерфейсы",
    "exclude_interface": "Кроме интерфейсов",
    "listen": "Адрес прослушивания",
    "listen_port": "Порт прослушивания",
    # log / experimental
    "level": "Уровень",
    "timestamp": "Время в строках",
    "disabled": "Отключить журнал",
    "output": "Файл журнала",
    "cache_file": "Файл кэша",
    "clash_api": "Clash API",
    "enabled": "Включено",
    "store_rdrc": "Кэшировать отказы DNS",
    "external_controller": "Адрес контроллера",
    "secret": "Секрет",
    "default_mode": "Режим по умолчанию",
}

ENUM_LABELS: dict[str, dict[Any, str]] = {
    "action": {
        "route": "Направить в выход",
        "route-options": "Задать параметры (не завершает)",
        "direct": "Напрямую с параметрами",
        "bypass": "Обойти",
        "reject": "Заблокировать",
        "hijack-dns": "Перехватить DNS",
        "sniff": "Определить протокол (sniff)",
        "resolve": "Разрешить домен в IP",
        "evaluate": "Вычислить ответ",
        "respond": "Ответить",
        "predefined": "Готовый ответ",
    },
    "method": {"default": "Отклонить (RST / ICMP)", "drop": "Молча отбросить", "reply": "Ответить (ICMP echo)"},
    "mode": {"and": "Все условия (И)", "or": "Любое условие (ИЛИ)"},
    "format": {"binary": "Бинарный (.srs)", "source": "Исходный (.json)"},
    "level": {
        "trace": "trace",
        "debug": "debug",
        "info": "info",
        "warn": "warn",
        "warning": "warning",
        "error": "error",
        "fatal": "fatal",
        "panic": "panic",
    },
    "strategy": {
        "as_is": "Как есть",
        "prefer_ipv4": "Предпочитать IPv4",
        "prefer_ipv6": "Предпочитать IPv6",
        "ipv4_only": "Только IPv4",
        "ipv6_only": "Только IPv6",
    },
}

TYPE_LABELS: dict[str, str] = {
    "default": "Обычное",
    "logical": "Логическое (И / ИЛИ)",
    "inline": "Встроенный",
    "local": "Локальный файл",
    "remote": "Загружаемый по URL",
}

OUTBOUND_TAG_LABELS: dict[str, str] = {
    "proxy": "Прокси (выбранный сервер)",
    "direct": "Напрямую",
    "block": "Блокировать",
}

SECTION_LABELS: dict[str, str] = {
    "log": "Журнал",
    "dns": "DNS",
    "ntp": "NTP",
    "inbounds": "Входящие",
    "outbounds": "Исходящие",
    "endpoints": "Endpoints",
    "route": "Маршрутизация",
    "experimental": "Experimental",
    "certificate": "Сертификаты",
    "services": "Сервисы",
    "providers": "Провайдеры",
    "http_clients": "HTTP-клиенты",
}

# Fields shown up front (in this order) even while empty; the rest is added
# through «Добавить параметр». Keys are editor contexts.
PINNED_FIELDS: dict[str, tuple[str, ...]] = {
    "rule.action:route": ("outbound",),
    "rule.action:reject": ("method",),
    "rule.action:resolve": ("server", "strategy"),
    "rule.action:sniff": ("sniffer",),
    "rule.type:logical": ("mode", "rules"),
    "dns_rule.action:route": ("server",),
    "dns_rule.type:logical": ("mode", "rules"),
    "rule_set.type:local": ("tag", "format", "path"),
    "rule_set.type:remote": ("tag", "format", "url", "update_interval"),
    "rule_set.type:inline": ("tag", "rules"),
    "outbound": ("tag",),
    "outbound.type:selector": ("tag", "outbounds", "default"),
    "outbound.type:urltest": ("tag", "outbounds", "url", "interval"),
    "outbound.type:direct": ("tag", "domain_resolver"),
    "dns_server": ("tag", "server", "detour"),
    "inbound": ("tag",),
    "inbound.type:tun": ("tag", "address", "auto_route", "strict_route", "stack"),
    "inbound.type:mixed": ("tag", "listen", "listen_port"),
    "route": ("final", "auto_detect_interface", "default_domain_resolver"),
    "dns": ("final", "strategy"),
    "log": ("level", "timestamp"),
    "experimental": ("cache_file",),
    "cache_file": ("enabled",),
}

# Matching fields that sing-box only evaluates on other platforms. They stay
# available (the JSON may be shared with Android) but are listed last.
FOREIGN_PLATFORM_FIELDS = frozenset(
    {
        "user",
        "user_id",
        "package_name",
        "package_name_regex",
        "wifi_ssid",
        "wifi_bssid",
        "network_type",
        "network_is_expensive",
        "network_is_constrained",
        "source_mac_address",
        "source_hostname",
        "override_android_vpn",
        "find_neighbor",
        "dhcp_lease_files",
    }
)

# Rule fields rendered first in «Добавить условие».
COMMON_MATCH_FIELDS = (
    "domain_suffix",
    "domain",
    "domain_keyword",
    "domain_regex",
    "rule_set",
    "ip_cidr",
    "ip_is_private",
    "process_name",
    "process_path",
    "process_path_regex",
    "port",
    "port_range",
    "network",
    "protocol",
)

_SUMMARY_FIELDS = (
    "domain_suffix",
    "domain",
    "domain_keyword",
    "domain_regex",
    "rule_set",
    "ip_cidr",
    "process_name",
    "process_path",
    "process_path_regex",
    "port",
    "port_range",
    "protocol",
    "network",
    "inbound",
    "query_type",
    "source_ip_cidr",
)

_SUMMARY_SHORT: dict[str, str] = {
    "domain_suffix": "домены",
    "domain": "домены",
    "domain_keyword": "слова",
    "domain_regex": "regex",
    "rule_set": "наборы",
    "ip_cidr": "IP",
    "process_name": "процессы",
    "process_path": "пути",
    "process_path_regex": "пути",
    "port": "порт",
    "port_range": "порты",
    "protocol": "протокол",
    "network": "сеть",
    "inbound": "вход",
    "query_type": "запрос",
    "source_ip_cidr": "источник",
}


def field_label(name: str) -> str:
    return FIELD_LABELS.get(name, name)


def enum_label(field: str, value: Any) -> str:
    if field in ("type",) and isinstance(value, str):
        return TYPE_LABELS.get(value, value)
    return ENUM_LABELS.get(field, {}).get(value, str(value))


def outbound_label(tag: str) -> str:
    label = OUTBOUND_TAG_LABELS.get(tag)
    return f"{label} · {tag}" if label else tag


def pinned_fields(context: str, discriminators: dict[str, str] | None = None) -> tuple[str, ...]:
    result: list[str] = list(PINNED_FIELDS.get(context, ()))
    for key, value in (discriminators or {}).items():
        for name in PINNED_FIELDS.get(f"{context}.{key}:{value}", ()):
            if name not in result:
                result.append(name)
    return tuple(result)


def _values_text(values: list, limit: int = 2) -> str:
    shown = ", ".join(str(value) for value in values[:limit])
    rest = len(values) - limit
    return f"{shown} +{rest}" if rest > 0 else shown


def match_summary(rule: dict) -> str:
    """Short description of what a (route or DNS) rule matches."""

    if not isinstance(rule, dict):
        return "?"
    if rule.get("type") == "logical":
        nested = [item for item in rule.get("rules") or () if isinstance(item, dict)]
        joiner = " И " if rule.get("mode") == "and" else " ИЛИ "
        text = joiner.join(f"({match_summary(item)})" for item in nested) or "пусто"
        return f"НЕ {text}" if rule.get("invert") else text
    parts: list[str] = []
    for key in _SUMMARY_FIELDS:
        values = as_list(rule.get(key))
        if values:
            parts.append(f"{_SUMMARY_SHORT[key]}: {_values_text(values)}")
    if rule.get("ip_is_private"):
        parts.append("локальные адреса")
    if rule.get("source_ip_is_private"):
        parts.append("источник локальный")
    if not parts:
        known = {"type", "invert", "action", "outbound", "server"}
        others = [key for key in rule if key not in known and key not in ACTION_KEYS]
        parts.append(", ".join(field_label(key) for key in others[:2]) if others else "любой трафик")
    text = " · ".join(parts[:3]) + (" · …" if len(parts) > 3 else "")
    return f"НЕ ({text})" if rule.get("invert") else text


# Keys that belong to an action rather than to matching. Used only to keep
# action options out of the one-line match summary.
ACTION_KEYS = frozenset(
    {
        "action",
        "outbound",
        "method",
        "no_drop",
        "sniffer",
        "timeout",
        "server",
        "strategy",
        "disable_cache",
        "disable_optimistic_cache",
        "rewrite_ttl",
        "client_subnet",
        "override_address",
        "override_port",
        "override_gateway",
        "network_strategy",
        "fallback_delay",
        "udp_disable_domain_unmapping",
        "udp_connect",
        "udp_timeout",
        "tls_fragment",
        "tls_fragment_fallback_delay",
        "tls_record_fragment",
        "tls_spoof",
        "tls_spoof_method",
        "race",
        "speculative",
        "remove_client_subnet",
        "rcode",
        "answer",
        "ns",
        "extra",
    }
)


def action_summary(rule: dict, *, dns: bool = False) -> str:
    if not isinstance(rule, dict):
        return ""
    action = rule.get("action") or "route"
    if action == "route":
        if dns:
            return f"→ {rule.get('server', '?')}"
        return f"→ {outbound_label(str(rule.get('outbound', '?')))}"
    if action == "reject":
        return "✕ " + ("отбросить" if rule.get("method") == "drop" else "заблокировать")
    return enum_label("action", action)
