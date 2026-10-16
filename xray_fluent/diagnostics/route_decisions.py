"""Решения маршрута для диагностики: куда ядро отправило соединения и каким правилом.

Без этого по диагностике нельзя было понять, почему VK и Яндекс ушли в туннель:
в журнале сайдкара видны только IP назначения, а конфиг — лишь последний, уже
исправленный пользователем. Источник — тот же опрос Clash API ``/connections``,
что делает ``LiveMetricsWorker`` для метрик: ни одного нового запроса.

Хранится сводка, а не поток: ключ (процесс, сайт, правило, маршрут) и счётчик
разных соединений. Сайт — последние две метки имени (``sun9-1.userapi.com`` →
``userapi.com``) или IP: в архив поддержки не уходят полные адреса страниц.
Последние сессии хранятся отдельно, чтобы переподключение не стирало ту, где
была проблема. Пометка «российский сайт» — только подпись для поддержки, на
маршрутизацию она не влияет.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from datetime import datetime, timezone
import ipaddress
import ntpath
import threading
from typing import Any, Iterable

from .proxy_demand import is_proxied_chain

#: Окончания российских сайтов и российские сервисы на чужих доменах (для подписи).
_RUSSIAN_SUFFIXES = (".ru", ".xn--p1ai", ".su")
_RUSSIAN_SERVICE_SITES = frozenset({
    "vk.com", "vk.me", "userapi.com", "vkuser.net", "vk-cdn.net", "mycdn.me",
    "yandex.net", "yandex.com", "yastatic.net", "yastat.net", "ya.cc",
})
_MAX_RULE_CHARS = 200


def site_of(host: str) -> str:
    """Сайт для сводки: IP как есть, имя — последними двумя метками."""
    value = str(host or "").strip().strip("[]").rstrip(".").lower()
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    labels = [label for label in value.split(".") if label]
    return ".".join(labels[-2:])


def is_russian_site(site: str) -> bool:
    value = f".{site}"
    return value.endswith(_RUSSIAN_SUFFIXES) or site in _RUSSIAN_SERVICE_SITES


def route_of(chains: Any) -> str:
    """``proxy`` — через туннель (вся цепочка Clash API), иначе последний выход."""
    if is_proxied_chain(chains):
        return "proxy"
    if isinstance(chains, list) and chains:
        return str(chains[0]).strip().lower() or "unknown"
    return "unknown"


def _process_of(metadata: dict) -> str:
    path = str(metadata.get("processPath") or "").strip()
    return ntpath.basename(path).lower() if path else ""


def _rule_of(connection: dict) -> str:
    rule = str(connection.get("rule") or "").strip()
    payload = str(connection.get("rulePayload") or "").strip()
    text = f"{rule} {payload}".strip() if payload else rule
    return text if len(text) <= _MAX_RULE_CHARS else text[: _MAX_RULE_CHARS - 1] + "…"


class _Session:
    def __init__(self, label: str, max_keys: int):
        self.label = label
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.max_keys = max_keys
        self.counts: OrderedDict[tuple[str, str, str, str], int] = OrderedDict()
        self.connections = 0
        self.dropped = 0

    def add(self, key: tuple[str, str, str, str]) -> None:
        self.connections += 1
        if key in self.counts:
            self.counts[key] += 1
            return
        if len(self.counts) >= self.max_keys:
            self.dropped += 1
            return
        self.counts[key] = 1

    def snapshot(self, limit: int) -> dict:
        entries = [
            {"process": process, "site": site, "rule": rule, "route": route, "count": count}
            for (process, site, rule, route), count in self.counts.items()
        ]
        entries.sort(key=lambda item: item["count"], reverse=True)
        russian = [item for item in entries if item["route"] == "proxy" and is_russian_site(item["site"])]
        return {
            "label": self.label,
            "started_at": self.started_at,
            "connections": self.connections,
            "distinct": len(entries),
            "dropped_distinct": self.dropped,
            "russian_sites_via_tunnel": sum(item["count"] for item in russian),
            "russian_via_tunnel": russian[:limit],
            "entries": entries[:limit],
        }


class RouteDecisionLog:
    """Потокобезопасная сводка решений маршрута по последним сессиям."""

    def __init__(self, *, sessions: int = 4, max_keys: int = 400, max_seen_ids: int = 8192):
        self._lock = threading.Lock()
        self._sessions: deque[_Session] = deque(maxlen=max(1, sessions))
        self._max_keys = max_keys
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._max_seen = max_seen_ids

    def begin_session(self, label: str) -> None:
        with self._lock:
            self._sessions.append(_Session(str(label), self._max_keys))
            self._seen.clear()

    def observe(self, connections: Iterable[Any]) -> None:
        """Новые соединения из ответа ``/connections``; уже учтённые id пропускаются."""
        with self._lock:
            if not self._sessions:
                self._sessions.append(_Session("session", self._max_keys))
            session = self._sessions[-1]
            for connection in connections or ():
                if not isinstance(connection, dict):
                    continue
                connection_id = str(connection.get("id") or "")
                if not connection_id or connection_id in self._seen:
                    continue
                self._seen[connection_id] = None
                if len(self._seen) > self._max_seen:
                    self._seen.popitem(last=False)
                metadata = connection.get("metadata") if isinstance(connection.get("metadata"), dict) else {}
                host = metadata.get("host") or metadata.get("destinationIP") or ""
                session.add((
                    _process_of(metadata),
                    site_of(host),
                    _rule_of(connection),
                    route_of(connection.get("chains")),
                ))

    def snapshot(self, *, limit: int = 80) -> dict:
        with self._lock:
            return {
                "schema": 1,
                "sessions": [session.snapshot(limit) for session in self._sessions],
            }
