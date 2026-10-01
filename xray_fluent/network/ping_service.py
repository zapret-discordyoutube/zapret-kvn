"""Пинг серверов: одна долгоживущая служба вместо QThread на каждый клик.

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

Заметность на линии.  TCP-замер — пустое соединение без данных, и веер таких
соединений на весь список за секунду выдаёт сам список серверов.  Поэтому:

* серверы с одним адресом и портом меряются одним соединением, результат
  получают все (в подписках один endpoint часто повторяется десятки раз);
* порядок замеров случайный, а не порядок списка;
* одновременных соединений немного, и каждое стартует со случайной задержкой;
* раунд можно отменить — оставшиеся в очереди серверы не трогаются.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import random
import threading
import time
from typing import Callable, Iterable

from PyQt6.QtCore import QObject, pyqtSignal

from ..engines.singbox.config_builder import is_singbox_endpoint_node
from ..profiles.geoip import endpoint_hosts
from ..profiles.models import Node
from .ping_worker import tcp_observation


MAX_PARALLEL_PINGS = 8
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
    measurable: bool  # False у endpoint-нод (UDP-only): TCP их не мерит

    @classmethod
    def of(cls, node: Node) -> "PingTarget":
        return cls(
            node_id=node.id,
            server=str(node.server or ""),
            port=int(node.port or 0),
            hosts=endpoint_hosts(node),
            measurable=not is_singbox_endpoint_node(node),
        )

    @property
    def endpoint(self) -> tuple[str, int, bool]:
        """Куда реально идёт соединение: одинаковый endpoint — один замер."""
        return self.server.strip().lower(), self.port, self.measurable

    def matches(self, node: Node) -> bool:
        """Сервер не сменил адрес, пока шёл замер."""
        return (
            str(node.server or "") == self.server
            and int(node.port or 0) == self.port
            and endpoint_hosts(node) == self.hosts
        )


@dataclass(frozen=True)
class PingOutcome:
    target: PingTarget
    ping_ms: int | None
    peers: tuple[str, ...]  # адрес, с которым реально установлено соединение


Probe = Callable[[PingTarget, float], tuple[int | None, tuple[str, ...]]]


def probe_target(target: PingTarget, timeout: float) -> tuple[int | None, tuple[str, ...]]:
    if not target.measurable:
        return None, ()
    return tcp_observation(target.server, target.port, timeout)


class PingService(QObject):
    """Очередь TCP-замеров с дедупликацией; все сигналы — в GUI-потоке."""

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
    ) -> None:
        super().__init__(parent)
        self._probe = probe
        self._timeout = timeout
        self._max_parallel = max(1, int(max_parallel))
        self._idle_exit_sec = idle_exit_sec
        self._start_jitter_sec = max(0.0, float(start_jitter_sec))

        # Общее с потоками замеров — только под замком.
        self._lock = threading.Lock()
        self._wakeup = threading.Condition(self._lock)
        self._queue: deque[PingTarget] = deque()
        self._threads = 0
        self._idle = 0
        self._closed = False

        # Состояние раунда — только в GUI-потоке.
        self._pending: set[str] = set()
        # endpoint → все серверы, ждущие результата одного соединения.
        self._waiters: dict[tuple[str, int, bool], list[PingTarget]] = {}
        self._done = 0
        self._total = 0

        self._arrived.connect(self._on_arrived)

    # ── GUI-поток ──

    @property
    def busy(self) -> bool:
        return bool(self._pending)

    def pending_ids(self) -> frozenset[str]:
        return frozenset(self._pending)

    def request(self, nodes: Iterable[Node]) -> int:
        """Поставить серверы в очередь; вернуть, сколько из них новых."""
        fresh: list[PingTarget] = []
        for node in nodes:
            if node.id in self._pending:
                continue
            self._pending.add(node.id)
            fresh.append(PingTarget.of(node))
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
        self._pending.clear()
        self._waiters.clear()
        self._done = self._total = 0

    def _on_arrived(self, outcome: PingOutcome) -> None:
        for target in self._waiters.pop(outcome.target.endpoint, ()):
            if target.node_id not in self._pending:
                continue
            self._pending.discard(target.node_id)
            self._done += 1
            self.measured.emit(PingOutcome(target, outcome.ping_ms, outcome.peers))
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
                target = self._queue.popleft()
            if self._start_jitter_sec:
                time.sleep(random.uniform(0.0, self._start_jitter_sec))
            try:
                ping_ms, peers = self._probe(target, self._timeout)
            except Exception:
                ping_ms, peers = None, ()
            with self._lock:
                if self._closed:
                    continue
            try:
                self._arrived.emit(PingOutcome(target, ping_ms, tuple(peers)))
            except RuntimeError:
                return  # объект службы уже разрушен (выход приложения)
