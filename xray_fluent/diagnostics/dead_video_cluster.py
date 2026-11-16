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

Пауза после видео (Windows 0.8.x вслед за Android 0.6.24, поле 2026-11-15 21:06 UTC): кластер только что отдал 78 МБ,
а плеер с полным буфером открывал короткие соединения с ответом 2-3 КБ; три таких дали ложный вердикт, и сервер
сменился при идущем видео. Кластер, который за последние ``healthy_grace_sec`` отдал здоровое соединение, тихими
соединениями не судится (событие ``excused`` один раз на паузу). Свежим доказательством считается только соединение,
чей входящий счётчик вырос с прошлого опроса на ``healthy_down_bytes`` (подвисшее старое паузу не продлевает).
``healthy_grace_sec=0`` выключает правило.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from typing import Any, Iterable

from .proxy_demand import is_proxied_chain

_CLUSTER = re.compile(r"(?:---|\.)(sn-[a-z0-9]+)(?:-[a-z0-9]+)?\.googlevideo\.com$")


SAME_SNAPSHOT_SEC = 1.0


def excuse_reason(since_healthy_sec: float) -> str:
    """Why an excused connection is not a dead cluster, for the log line.

    Field 2026-11-16 (Android, Rusina, sn-ojnpo5): all three excuses came 0-2 ms after the
    healthy connection, i.e. the connections were closed together by a server switch or a
    stall reset, while the line claimed a full-buffer player pause.
    """
    if since_healthy_sec < SAME_SNAPSHOT_SEC:
        return "закрыто вместе со здоровым соединением того же кластера, кластер отдаёт видео"
    return "пауза плеера с полным буфером, не мёртвый кластер"


def cluster_of(host: str | None) -> str | None:
    """Кластер из имени кеш-узла: ``rr2---sn-8ph2xajvh-3a4l.googlevideo.com`` -> ``sn-8ph2xajvh``.

    Форма с точкой (``rr2.sn-8ph2xajvh-3a4l.googlevideo.com``, имя по ответу DNS через CNAME) равноправна: поле, архив
    Android 0.5.47, детектор молчал, пока знал только форму с ``---``.
    Имена без метки ``sn-`` (``redirector.googlevideo.com`` и другие) кластеру не принадлежат: ``None``.
    """

    if not host:
        return None
    match = _CLUSTER.search(str(host).strip().rstrip(".").lower())
    return match.group(1) if match else None


@dataclass(frozen=True)
class ClusterEvent:
    """Событие для журнала: ``dead`` (признан мёртвым), ``recovered`` (здоровое соединение снова пошло) или
    ``excused`` (тихое соединение через ``span_sec`` после здорового не засчитано: пауза плеера)."""

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
        silent_min_age_sec: float = 3.0,
        healthy_down_bytes: int = 64 * 1024,
        max_clusters: int = 64,
        max_seen: int = 4096,
        healthy_grace_sec: float = 90.0,
    ) -> None:
        self._min_dead_flows = min_dead_flows
        self._window_sec = window_sec
        self._max_down_bytes = max_down_bytes
        self._min_age_sec = min_age_sec
        # Соединение без единого байта ответа молчит уже через 3 с: здоровое получает ServerHello за 0.1-0.3 с
        # (замер узла и архив Android 0.5.48, 2026-11-14).
        self._silent_min_age_sec = silent_min_age_sec
        self._healthy_down_bytes = healthy_down_bytes
        self._max_clusters = max_clusters
        self._max_seen = max_seen
        self._healthy_grace_sec = healthy_grace_sec
        self._clusters: dict[str, _State] = {}
        self._first_seen: dict[str, float] = {}
        self._last_down: dict[str, int] = {}
        self._last_healthy_at: dict[str, float] = {}
        self._excused_for: dict[str, float] = {}

    def reset(self) -> None:
        self._clusters.clear()
        self._first_seen.clear()
        self._last_down.clear()
        self._last_healthy_at.clear()
        self._excused_for.clear()

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
            grew = down - self._last_down.get(conn_id, 0)
            self._last_down[conn_id] = down
            if down >= self._healthy_down_bytes:
                # Доказательство здоровья только от растущего соединения: подвисшее старое не снимает приговор.
                if grew >= self._healthy_down_bytes:
                    event = self._recover(now, cluster)
                    if event is not None:
                        events.append(event)
                    if self._healthy_grace_sec > 0:
                        self._last_healthy_at[cluster] = now
                continue
            required_age = self._silent_min_age_sec if down == 0 else self._min_age_sec
            if up <= 0 or down > self._max_down_bytes or now - first < required_age:
                continue
            healthy_at = self._last_healthy_at.get(cluster)
            if healthy_at is not None and now - healthy_at <= self._healthy_grace_sec:
                if self._excused_for.get(cluster) != healthy_at:
                    self._excused_for[cluster] = healthy_at
                    events.append(ClusterEvent("excused", cluster, span_sec=max(0.0, now - healthy_at)))
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
        for conn_id in [key for key in self._last_down if key not in alive]:
            del self._last_down[conn_id]
        if len(self._first_seen) > self._max_seen:
            self._first_seen.clear()
        for state in self._clusters.values():
            if len(state.ids) > 512:
                state.ids.clear()
        while len(self._clusters) > self._max_clusters:
            del self._clusters[next(iter(self._clusters))]
        while len(self._last_healthy_at) > self._max_clusters:
            oldest = next(iter(self._last_healthy_at))
            del self._last_healthy_at[oldest]
            self._excused_for.pop(oldest, None)
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
