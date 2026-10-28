"""Пинг серверов: одна долгоживущая служба вместо QThread на каждый клик.

Сам замер — настоящее подключение через ядро (``latency_probe``): тёплый
запрос через сервер даёт его RTT, а не время пустого TCP-соединения.

Раньше каждый запрос создавал свой ``PingWorker(QThread)``, а ссылку на него
обнуляли в слоте его же сигнала ``completed``. Этот сигнал испускается ещё
внутри ``run()``, поэтому при частых кликах Python удалял объект потока,
который ещё не вышел из ``run()``, — Qt завершал процесс через
``qFatal("QThread: Destroyed while thread is still running")``.

Здесь потоков Qt нет совсем, а значит, нечего и уничтожить вовремя:

* замеры идут в обычных daemon-потоках, число которых ограничено; без работы
  потоки сами завершаются, а на выходе приложения не держат процесс
  (зависший ``getaddrinfo`` не ограничен таймаутом сокета);
* результат переходит в GUI-поток через внутренний сигнал объекта, живущего в
  GUI-потоке, — Qt ставит такой вызов в очередь сам;
* повторный запрос уже измеряемого сервера ничего не запускает, а новые
  серверы вливаются в текущий раунд: растёт его ``total``, и раунд кончается,
  когда не осталось ни одного замера в работе;
* GUI-поток никогда ничего не ждёт.

Заметность на линии.  Веер подключений на весь список за секунду выдаёт сам
список серверов.  Поэтому:

* одинаковые серверы (тот же адрес, порт и настройки подключения) меряются
  одним подключением, результат получают все (в подписках сервер часто
  повторяется под разными именами);
* порядок замеров случайный, а не порядок списка;
* соединение одно за раз, а между серверами одного прохода — пауза шлюза
  проверок (``probe_gate.SWEEP_PAUSE_SEC``, 10–20 с со случайным разбросом):
  на проводе это отдельные подключения, а не веер;
* раунд можно отменить — оставшиеся в очереди серверы не трогаются.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import json
import random
import threading
import time
from typing import Callable, Iterable

from PyQt6.QtCore import QObject, pyqtSignal

from ..profiles.geoip import endpoint_hosts
from ..profiles.models import Node
from . import latency_probe, probe_gate


MAX_PARALLEL_PINGS = 1
# Не используется замером через ядро (у него свои сроки запуска и запроса);
# оставлен как параметр подменяемых в тестах проб.
PING_TIMEOUT_SEC = 2.0
IDLE_THREAD_EXIT_SEC = 20.0
# Случайная задержка перед каждым соединением: размывает ровный «залп».
PING_START_JITTER_SEC = 0.12


@dataclass(frozen=True)
class PingTarget:
    """Неизменяемый снимок сервера на момент запроса."""

    node_id: str
    server: str
    port: int
    hosts: tuple[str, ...]
    # Настройки подключения: одинаковые серверы под разными именами — один замер.
    settings: str = ""
    # Копия сервера на момент запроса — её и меряет ядро.
    node: Node | None = field(default=None, compare=False, hash=False, repr=False)
    # Сервер сейчас подключён: HTTP-порт его сессии (0 — нет).
    session_port: int = field(default=0, compare=False, hash=False)

    @classmethod
    def of(cls, node: Node, session_port: int = 0) -> "PingTarget":
        return cls(
            node_id=node.id,
            server=str(node.server or ""),
            port=int(node.port or 0),
            hosts=endpoint_hosts(node),
            settings=_settings_key(node),
            node=Node.from_dict(node.to_dict()),
            session_port=int(session_port or 0),
        )

    @property
    def endpoint(self) -> tuple[str, int, str]:
        """Куда и как реально идёт подключение: одинаковое — один замер."""
        return self.server.strip().lower(), self.port, self.settings

    def matches(self, node: Node) -> bool:
        """Сервер не сменил адрес, пока шёл замер."""
        return (
            str(node.server or "") == self.server
            and int(node.port or 0) == self.port
            and endpoint_hosts(node) == self.hosts
        )


def _settings_key(node: Node) -> str:
    outbound = node.outbound if isinstance(node.outbound, dict) else {}
    meaningful = {key: value for key, value in outbound.items() if key not in ("tag", "remarks")}
    return json.dumps([node.link or "", meaningful], sort_keys=True, ensure_ascii=True, default=str)


@dataclass(frozen=True)
class PingOutcome:
    target: PingTarget
    ping_ms: int | None
    peers: tuple[str, ...] = ()  # адрес, с которым реально установлено соединение
    # False — проверить было нечем (нет ядра, адреса без открытого DNS…):
    # такой сервер не «мёртвый», прежний вывод о нём остаётся.
    measured: bool = True
    reason: str = ""


Probe = Callable[[PingTarget, float], "latency_probe.ProbeResult"]


def probe_target(target: PingTarget, timeout: float) -> latency_probe.ProbeResult:
    if target.node is None:
        return latency_probe.ProbeResult(latency_probe.UNMEASURED, reason="нет данных сервера")
    if target.session_port:
        result = latency_probe.probe_session(target.session_port)
        if result.state == latency_probe.OK:
            return result
    return latency_probe.probe_node(target.node, cancelled=_closing.is_set)


# Выход приложения: идущий замер бросает ожидание ядра.
_closing = threading.Event()


class PingService(QObject):
    """Очередь замеров с дедупликацией; все сигналы — в GUI-потоке."""

    measured = pyqtSignal(object)          # PingOutcome
    progress = pyqtSignal(int, int, bool)  # done, total, finished

    _arrived = pyqtSignal(object)  # мост: поток замера → GUI-поток

    def __init__(
        self,
        parent: QObject | None = None,
        *,
        probe: Probe = probe_target,
        timeout: float = PING_TIMEOUT_SEC,
        max_parallel: int = MAX_PARALLEL_PINGS,
        idle_exit_sec: float = IDLE_THREAD_EXIT_SEC,
        start_jitter_sec: float = PING_START_JITTER_SEC,
        pause: Callable[[], float] = probe_gate.sweep_pause,
        gate: probe_gate.ProbeGate = probe_gate.GATE,
    ) -> None:
        super().__init__(parent)
        self._probe = probe
        self._timeout = timeout
        self._max_parallel = max(1, int(max_parallel))
        self._idle_exit_sec = idle_exit_sec
        self._start_jitter_sec = max(0.0, float(start_jitter_sec))
        self._pause = pause
        self._gate = gate
        # (id подключённого сервера, HTTP-порт его сессии) или None.
        self._current_route: Callable[[], tuple[str, int] | None] = lambda: None

        # Общее с потоками замеров — только под замком.
        self._lock = threading.Lock()
        self._wakeup = threading.Condition(self._lock)
        self._queue: deque[PingTarget] = deque()
        self._threads = 0
        self._idle = 0
        self._closed = False
        # Когда можно брать следующий сервер прохода (0 — сразу).
        self._resume_at = 0.0

        # Состояние раунда — только в GUI-потоке.
        self._pending: set[str] = set()
        # endpoint → все серверы, ждущие результата одного соединения.
        self._waiters: dict[tuple[str, int, str], list[PingTarget]] = {}
        self._done = 0
        self._total = 0

        self._arrived.connect(self._on_arrived)

    # ── GUI-поток ──

    @property
    def busy(self) -> bool:
        return bool(self._pending)

    def pending_ids(self) -> frozenset[str]:
        return frozenset(self._pending)

    def set_current_route(self, route: Callable[[], tuple[str, int] | None]) -> None:
        """Откуда узнать подключённый сервер: его меряют через его же подключение."""
        self._current_route = route

    def request(self, nodes: Iterable[Node]) -> int:
        """Поставить серверы в очередь; вернуть, сколько из них новых."""
        fresh: list[PingTarget] = []
        current = self._current_route()
        for node in nodes:
            if node.id in self._pending:
                continue
            self._pending.add(node.id)
            port = current[1] if current is not None and current[0] == node.id else 0
            fresh.append(PingTarget.of(node, port))
        if not fresh:
            return 0
        with self._lock:
            closed = self._closed
        if closed:
            self._pending.difference_update(target.node_id for target in fresh)
            return 0
        leaders: list[PingTarget] = []
        for target in fresh:
            waiting = self._waiters.get(target.endpoint)
            if waiting is None:
                self._waiters[target.endpoint] = [target]
                leaders.append(target)
            else:
                waiting.append(target)
        random.shuffle(leaders)
        with self._lock:
            self._queue.extend(leaders)
            spawn = min(self._max_parallel - self._threads, max(0, len(self._queue) - self._idle))
            spawn = max(0, spawn)
            self._threads += spawn
            self._wakeup.notify_all()
        for _ in range(spawn):
            threading.Thread(target=self._run, name="ping", daemon=True).start()
        self._total += len(fresh)
        self.progress.emit(self._done, self._total, False)
        return len(fresh)

    def cancel(self) -> int:
        """Остановить раунд: серверы из очереди не измеряются.

        Соединения, которые уже идут, дойдут до конца (не дольше таймаута) и
        отдадут результат как обычно.  Возвращает число снятых серверов.
        """
        with self._lock:
            dropped = list(self._queue)
            self._queue.clear()
            self._resume_at = 0.0
            self._wakeup.notify_all()
        removed = 0
        for leader in dropped:
            for target in self._waiters.pop(leader.endpoint, ()):
                self._pending.discard(target.node_id)
                removed += 1
        if not removed:
            return 0
        self._total -= removed
        finished = not self._pending
        self.progress.emit(self._done, max(self._total, self._done), finished)
        if finished:
            self._done = self._total = 0
        return removed

    def close(self) -> None:
        """Выход из приложения: снять очередь; замеры в работе дойдут в никуда."""
        with self._lock:
            self._closed = True
            self._queue.clear()
            self._wakeup.notify_all()
        if self._probe is probe_target:
            _closing.set()
            latency_probe.terminate_all()
        self._pending.clear()
        self._waiters.clear()
        self._done = self._total = 0

    def _on_arrived(self, outcome: PingOutcome) -> None:
        for target in self._waiters.pop(outcome.target.endpoint, ()):
            if target.node_id not in self._pending:
                continue
            self._pending.discard(target.node_id)
            self._done += 1
            self.measured.emit(
                PingOutcome(target, outcome.ping_ms, outcome.peers, outcome.measured, outcome.reason)
            )
            finished = not self._pending
            self.progress.emit(self._done, self._total, finished)
            if finished:
                self._done = self._total = 0

    # ── потоки замеров ──

    def _run(self) -> None:
        while True:
            with self._lock:
                self._idle += 1
                self._wakeup.wait_for(lambda: self._queue or self._closed, timeout=self._idle_exit_sec)
                self._idle -= 1
                if self._closed or not self._queue:
                    self._threads -= 1
                    return
                # Следующий сервер прохода — только после паузы; отмена или
                # выход будят поток раньше.
                while not self._closed and self._queue:
                    delay = self._resume_at - time.monotonic()
                    if delay <= 0:
                        break
                    self._wakeup.wait(delay)
                if self._closed or not self._queue:
                    continue
                sweeping = self._resume_at > 0 or len(self._queue) > 1
                target = self._queue.popleft()
            self._gate.record(probe_gate.SWEEP if sweeping else probe_gate.USER, target.server)
            if self._start_jitter_sec:
                time.sleep(random.uniform(0.0, self._start_jitter_sec))
            try:
                result = self._probe(target, self._timeout)
            except Exception as exc:
                result = latency_probe.ProbeResult(latency_probe.UNMEASURED, reason=f"сбой замера: {exc}")
            with self._lock:
                self._resume_at = time.monotonic() + max(0.0, self._pause()) if self._queue else 0.0
                if self._closed:
                    continue
            try:
                self._arrived.emit(PingOutcome(
                    target,
                    result.ping_ms if result.state == latency_probe.OK else None,
                    measured=result.measured,
                    reason=result.reason,
                ))
            except RuntimeError:
                return  # объект службы уже разрушен (выход приложения)
