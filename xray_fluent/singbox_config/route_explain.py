"""«Проверить сайт»: какое правило ``route.rules`` сработает для сайта и куда пойдёт трафик.

Повторяет порядок ядра sing-box без запуска ядра: правила сверху вниз до
первого совпадения, ``sniff``/``resolve``/``route-options`` не останавливают
перебор, ``hijack-dns`` ловит только DNS, иначе — ``route.final``.

Запрос — обычный заход браузера на сайт: TCP, порт 443, протокол TLS,
программа неизвестна. Условие, которое от запроса не зависит (программа,
входящий, источник…), даёт «может сработать» — такое правило отмечается и
перебор идёт дальше, как и ядро пошло бы для других программ.

IP-условия (``ip_cidr``, ``ip_is_private``, IP-часть наборов) ядро проверяет по
адресу назначения. В TUN он есть в самом пакете, в режиме прокси браузер
передаёт только имя сайта — IP появится лишь после правила ``resolve``.

Наборы правил проверяет вызывающий через ``match_set`` (на практике —
``sing-box rule-set match``); ``None`` значит «не узнать» (например, набор по URL).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
from typing import Callable

from . import catalog
from .document import as_list
from .simple_rule import normalize_domain

#: ``(определение набора, домен или IP) -> совпал / нет / не узнать``.
SetMatcher = Callable[[dict, str], "bool | None"]
Resolver = Callable[[str], list[str]]

_ADDRESS_KEYS = ("domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "ip_is_private", "rule_set")
_KNOWN_KEYS = set(_ADDRESS_KEYS) | {"port", "port_range", "network", "protocol"}
#: Ключи действия и служебные ключи — не условия.
_ACTION_KEYS = {
    "action", "outbound", "method", "no_drop", "invert", "type", "mode", "rules", "sniffer", "timeout",
    "server", "strategy", "disable_cache", "rewrite_ttl", "client_subnet", "override_address",
    "override_port", "network_strategy", "network_type", "fallback_network_type", "fallback_delay",
    "udp_disable_domain_unmapping", "udp_connect", "udp_timeout", "tls_fragment", "tls_record_fragment",
    "tls_fragment_fallback_delay", "rule_set_ip_cidr_match_source", "rule_set_ip_cidr_accept_empty",
}
_NON_FINAL = {"sniff", "resolve", "route-options", "hijack-dns"}
_WEB = {"network": "tcp", "port": 443, "protocol": "tls"}


@dataclass
class MaybeRule:
    index: int
    reason: str


@dataclass
class RouteVerdict:
    host: str
    #: Тег выхода, ``reject`` для блокировки.
    target: str
    #: Номер сработавшего правила (с нуля); ``None`` — ни одно, ушло в «final».
    rule_index: int | None
    maybe: list[MaybeRule] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class _Query:
    def __init__(self, host: str, *, tun: bool, resolve: Resolver | None):
        self.resolve = resolve
        self.tun = tun
        try:
            self.ip_literal = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            self.ip_literal = None
        self.domain = "" if self.ip_literal else normalize_domain(host)
        self.host = str(self.ip_literal) if self.ip_literal else self.domain
        self.ips: list[str] | None = [self.host] if self.ip_literal else None
        # В TUN адрес назначения — в самом пакете; в режиме прокси есть только имя.
        self.ip_known = bool(self.ip_literal)
        self.domain_known = not tun or bool(self.ip_literal)
        if tun and not self.ip_literal:
            self._resolve()

    def _resolve(self) -> None:
        self.ip_known = True
        if self.ips is None:
            try:
                self.ips = list(dict.fromkeys(self.resolve(self.domain))) if self.resolve else []
            except OSError:
                self.ips = []

    def after_resolve_action(self) -> None:
        if not self.ip_known:
            self._resolve()


def _tri_any(values) -> bool | None:
    seen_unknown = False
    for value in values:
        if value is True:
            return True
        if value is None:
            seen_unknown = True
    return None if seen_unknown else False


def _tri_all(values) -> bool | None:
    seen_unknown = False
    for value in values:
        if value is False:
            return False
        if value is None:
            seen_unknown = True
    return None if seen_unknown else True


def _suffix_match(domain: str, suffix: str) -> bool:
    suffix = suffix.lower()
    if suffix.startswith("."):
        return domain.endswith(suffix)
    return domain == suffix or domain.endswith("." + suffix)


def _is_private(ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    return address.is_private or address.is_loopback or address.is_link_local


def _in_cidrs(ip: str, cidrs: list) -> bool:
    address = ipaddress.ip_address(ip)
    for cidr in cidrs:
        try:
            if address in ipaddress.ip_network(str(cidr), strict=False):
                return True
        except ValueError:
            continue
    return False


class _Evaluator:
    def __init__(self, document: dict, query: _Query, match_set: SetMatcher):
        route = document.get("route") if isinstance(document.get("route"), dict) else {}
        self.sets = {item.get("tag"): item for item in route.get("rule_set") or [] if isinstance(item, dict)}
        self.query = query
        self.match_set = match_set

    def _ip_values(self) -> list[str] | None:
        """Известные IP назначения; ``None`` — ядро знало бы, но мы не смогли узнать."""
        if not self.query.ip_known:
            return []
        if not self.query.ips and not self.query.ip_literal:
            return None
        return self.query.ips or []

    def _set(self, tag: str) -> bool | None:
        definition = self.sets.get(tag)
        if definition is None:
            return False
        results = []
        if self.query.domain and self.query.domain_known:
            results.append(self.match_set(definition, self.query.domain))
        ips = self._ip_values()
        if ips is None:
            results.append(None)
        else:
            results.extend(self.match_set(definition, ip) for ip in ips)
        return _tri_any(results)

    def _address(self, rule: dict) -> bool | None:
        domain = self.query.domain if self.query.domain_known else ""
        results: list[bool | None] = []
        for value in as_list(rule.get("domain")):
            results.append(bool(domain) and domain == str(value).lower())
        for value in as_list(rule.get("domain_suffix")):
            results.append(bool(domain) and _suffix_match(domain, str(value)))
        for value in as_list(rule.get("domain_keyword")):
            results.append(bool(domain) and str(value).lower() in domain)
        for value in as_list(rule.get("domain_regex")):
            try:
                results.append(bool(domain) and re.search(str(value), domain) is not None)
            except re.error:
                results.append(None)
        ips = self._ip_values()
        if "ip_cidr" in rule:
            results.append(None if ips is None else any(_in_cidrs(ip, as_list(rule["ip_cidr"])) for ip in ips))
        if rule.get("ip_is_private"):
            results.append(None if ips is None else any(_is_private(ip) for ip in ips))
        for tag in as_list(rule.get("rule_set")):
            results.append(self._set(str(tag)))
        return _tri_any(results)

    @staticmethod
    def _port(rule: dict) -> bool | None:
        port = _WEB["port"]
        results: list[bool | None] = [port == int(value) for value in as_list(rule.get("port"))
                                      if str(value).isdigit()]
        for value in as_list(rule.get("port_range")):
            low, _sep, high = str(value).partition(":")
            try:
                results.append((int(low) if low else 0) <= port <= (int(high) if high else 65535))
            except ValueError:
                results.append(None)
        return _tri_any(results)

    def default(self, rule: dict) -> tuple[bool | None, str]:
        groups: list[bool | None] = []
        if any(key in rule for key in _ADDRESS_KEYS):
            groups.append(self._address(rule))
        if "port" in rule or "port_range" in rule:
            groups.append(self._port(rule))
        if "network" in rule:
            groups.append(_WEB["network"] in [str(v) for v in as_list(rule["network"])])
        if "protocol" in rule:
            groups.append(_WEB["protocol"] in [str(v) for v in as_list(rule["protocol"])])
        unknown = [key for key in rule if key not in _KNOWN_KEYS and key not in _ACTION_KEYS]
        result = _tri_all(groups)
        reason = ""
        if unknown and result is not False:
            result = None
            reason = "зависит от: " + ", ".join(catalog.field_label(key).lower() for key in unknown)
        elif result is None:
            reason = "зависит от IP-адреса сайта или набора, который нельзя проверить"
        if rule.get("invert") and result is not None:
            result = not result
        return result, reason

    def evaluate(self, rule: dict) -> tuple[bool | None, str]:
        if rule.get("type") == "logical":
            parts = [self.evaluate(item) for item in rule.get("rules") or [] if isinstance(item, dict)]
            values = [value for value, _reason in parts]
            result = _tri_all(values) if rule.get("mode") == "and" else _tri_any(values)
            reason = next((why for value, why in parts if value is None and why), "")
            if rule.get("invert") and result is not None:
                result = not result
            return result, reason
        return self.default(rule)


def _action(rule: dict) -> str:
    return str(rule.get("action") or "route")


def _final(document: dict) -> str:
    route = document.get("route") if isinstance(document.get("route"), dict) else {}
    if route.get("final"):
        return str(route["final"])
    for item in document.get("outbounds") or []:
        if isinstance(item, dict) and item.get("tag"):
            return str(item["tag"])
    return "direct"


def explain_route(
    document: dict,
    host: str,
    *,
    tun: bool,
    match_set: SetMatcher,
    resolve: Resolver | None = None,
) -> RouteVerdict:
    """Первое сработавшее правило для захода на ``host`` и куда уйдёт трафик."""
    query = _Query(host, tun=tun, resolve=resolve)
    evaluator = _Evaluator(document, query, match_set)
    route = document.get("route") if isinstance(document.get("route"), dict) else {}
    rules = [rule for rule in route.get("rules") or []]
    maybe: list[MaybeRule] = []
    notes: list[str] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        action = _action(rule)
        if action == "hijack-dns":
            continue
        matched, reason = evaluator.evaluate(rule)
        if action == "sniff":
            if matched is not False:
                query.domain_known = True
            continue
        if action == "resolve":
            if matched is not False:
                query.after_resolve_action()
            continue
        if action in _NON_FINAL:
            continue
        if matched is None:
            maybe.append(MaybeRule(index, reason))
            continue
        if matched:
            target = "reject" if action == "reject" else str(rule.get("outbound") or _final(document))
            return RouteVerdict(query.host, target, index, maybe, list(query.ips or []), notes)
    if tun and query.domain and not query.domain_known:
        notes.append("В начале правил нет «Определить протокол (sniff)» — в TUN ядро не узнает имя сайта.")
    return RouteVerdict(query.host, _final(document), None, maybe, list(query.ips or []), notes)
