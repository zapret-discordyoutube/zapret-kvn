"""Мёртвый кеш-кластер YouTube: плеер раз за разом открывает соединения к одному кластеру googlevideo,
отправляет запрос и не получает ничего.

Поле (Android 0.5.43, архив 2026-11-13): кластер ``sn-8ph2xajvh`` за пять дней дал 146 потоков, из них 137
без единого байта ответа, ни одного здорового, на любом сервере. Видео стояло в «буферизации» минутами.
«Умная проверка» (``application/smart_switch_service.py``) этого не видит: она начинается со спроса (растущие
счётчики байт), а соединение без единого байта спроса не создаёт; контрольный замер скорости к тому же прошёл бы
(другие адреса быстрые). Помогает смена сервера: YouTube выбирает кластер по адресу, с которого пришёл запрос
плеера, и другой сервер обычно получает другой кластер.

Чистая логика без I/O и Qt. Вызывается из потока ``LiveMetricsWorker`` на списке соединений Clash API sing-box
(активные соединения; закрытые из списка исчезают, поэтому «молчаливым» соединение считается, пока оно ещё живо).

Соединение «молчаливое», если оно проксируется, идёт к имени ``*---sn-XXXX[-YYYY].googlevideo.com``, отправило хоть
что-то (запрос ушёл), получило не больше ``max_down_bytes`` и наблюдается не меньше ``min_age_sec`` (мгновенный
сброс — отказ, а не молчание узла). Возраст считается по первому наблюдению соединения, а не по часам его запуска:
часы ядра и приложения могут расходиться, а ошибка здесь лишь задерживает приговор.

Кластер мёртв, когда за ``window_sec`` набралось не меньше ``min_dead_flows`` РАЗНЫХ молчаливых соединений к нему и
между ними не было здорового (получившего от ``healthy_down_bytes``). Здоровое соединение, ``reset()`` (смена
сервера или подключения) снимают приговор. Кластер «активен», пока от последнего молчаливого соединения прошло не
больше ``window_sec``: если плеер перестал повторять запросы, вердикт гаснет сам.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from typing import Any, Iterable

from .proxy_demand import is_proxied_chain

_CLUSTER = re.compile(r"---(sn-[a-z0-9]+)(?:-[a-z0-9]+)?\.googlevideo\.com$")


def cluster_of(host: str | None) -> str | None:
    """Кластер из имени кеш-узла: ``rr2---sn-8ph2xajvh-3a4l.googlevideo.com`` -> ``sn-8ph2xajvh``.

    Имена без метки ``sn-`` (``redirector.googlevideo.com`` и другие) кластеру не принадлежат: ``None``.
    """

    if not host:
        return None
    match = _CLUSTER.search(str(host).strip().rstrip(".").lower())
    return match.group(1) if match else None


@dataclass(frozen=True)
class ClusterEvent:
    """Событие для журнала: ``dead`` (признан мёртвым) или ``recovered`` (здоровое соединение снова пошло)."""

    kind: str
    cluster: str
    flows: int = 0
    span_sec: float = 0.0


class _State:
    __slots__ = ("times", "ids", "dead", "dead_since", "last_silent_at")

    def __init__(self) -> None:
        self.times: deque[float] = deque()
        self.ids: set[str] = set()
        self.dead = False
        self.dead_since = 0.0
        self.last_silent_at = 0.0


class DeadVideoClusterTracker:
    def __init__(
        self,
        *,
        min_dead_flows: int = 3,
        window_sec: float = 90.0,
        max_down_bytes: int = 4096,
        min_age_sec: float = 8.0,
        healthy_down_bytes: int = 64 * 1024,
        max_clusters: int = 64,
        max_seen: int = 4096,
    ) -> None:
        self._min_dead_flows = min_dead_flows
        self._window_sec = window_sec
        self._max_down_bytes = max_down_bytes
        self._min_age_sec = min_age_sec
        self._healthy_down_bytes = healthy_down_bytes
        self._max_clusters = max_clusters
        self._max_seen = max_seen
        self._clusters: dict[str, _State] = {}
        self._first_seen: dict[str, float] = {}

    def reset(self) -> None:
        self._clusters.clear()
        self._first_seen.clear()

    def active_dead(self, now: float) -> list[str]:
        """Мёртвые кластеры, к которым плеер ещё повторяет запросы."""

        return [
            name
            for name, state in self._clusters.items()
            if state.dead and now - state.last_silent_at <= self._window_sec
        ]

    def observe(self, now: float, connections: Iterable[Any]) -> list[ClusterEvent]:
        """Очередной опрос Clash API. Возвращает события для журнала."""

        events: list[ClusterEvent] = []
        alive: set[str] = set()
        for conn in connections or ():
            if not isinstance(conn, dict):
                continue
            conn_id = str(conn.get("id") or "")
            meta = conn.get("metadata")
            if not conn_id or not isinstance(meta, dict):
                continue
            cluster = cluster_of(meta.get("host") or meta.get("sniffHost"))
            if cluster is None:
                continue
            if str(meta.get("network") or "tcp").lower() != "tcp" or not is_proxied_chain(conn.get("chains")):
                continue
            alive.add(conn_id)
            first = self._first_seen.setdefault(conn_id, now)
            down = _as_int(conn.get("download"))
            up = _as_int(conn.get("upload"))
            if down >= self._healthy_down_bytes:
                event = self._recover(now, cluster)
                if event is not None:
                    events.append(event)
                continue
            if up <= 0 or down > self._max_down_bytes or now - first < self._min_age_sec:
                continue
            state = self._clusters.setdefault(cluster, _State())
            if conn_id in state.ids:
                continue
            state.ids.add(conn_id)
            state.times.append(now)
            state.last_silent_at = now
            while state.times and now - state.times[0] > self._window_sec:
                state.times.popleft()
            if not state.dead and len(state.times) >= self._min_dead_flows:
                state.dead = True
                state.dead_since = now
                events.append(ClusterEvent("dead", cluster, len(state.times), now - state.times[0]))
        # Закрытые соединения из списка исчезли: память о них не нужна.
        for conn_id in [key for key in self._first_seen if key not in alive]:
            del self._first_seen[conn_id]
        if len(self._first_seen) > self._max_seen:
            self._first_seen.clear()
        for state in self._clusters.values():
            if len(state.ids) > 512:
                state.ids.clear()
        while len(self._clusters) > self._max_clusters:
            del self._clusters[next(iter(self._clusters))]
        return events

    def _recover(self, now: float, cluster: str) -> ClusterEvent | None:
        state = self._clusters.pop(cluster, None)
        if state is not None and state.dead:
            return ClusterEvent("recovered", cluster, span_sec=max(0.0, now - state.dead_since))
        return None


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0
