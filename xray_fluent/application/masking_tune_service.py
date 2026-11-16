"""«Подобрать» маскировки: the runner over the pure ``xray_fluent.masking.tester`` (same as
Android ``MaskingTuner``).

For each candidate the runner sets the in-memory trial for the selected server
(``masking_runtime.begin_trial``), asks the transition coordinator to reconnect, waits until the
session is up, runs the planned transfers through the tunnel in a worker thread, and hands the
numbers back; the tester decides the order, the pauses and the verdicts. At the end the trial is
dropped and the session is rebuilt with the saved settings. Nothing is stored until the user keeps
a result (``keep``).

GUI thread only: every wait is a QTimer or a worker signal, never a blocking call. Started only by
the user and only while connected; one run at a time. Never switches a VPN back on that the user
switched off.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Callable

from PyQt6.QtCore import QObject, QThread, QTimer, pyqtSignal

from ..constants import PROXY_HOST, SPEED_TEST_DEFAULT_URL
from ..masking import tester
from ..masking.apply import shape_of
from ..masking.merge import effective
from . import masking_runtime

if TYPE_CHECKING:
    from .controller import AppController

TUNE_REASON = "masking tune"
TUNE_END_REASON = "masking tune end"
POLL_MS = 500
RECONNECT_TIMEOUT_SEC = 45.0


@dataclass(frozen=True, slots=True)
class TuneIdle:
    pass


@dataclass(frozen=True, slots=True)
class TuneRunning:
    server_name: str
    candidate: int  # 1-based
    candidates: int
    title: str


@dataclass(frozen=True, slots=True)
class TuneDone:
    server_name: str
    node_id: str
    ranked: tuple[tester.Ranked, ...]
    kept: str | None = None


@dataclass(frozen=True, slots=True)
class TuneFailed:
    message: str


class TransferWorker(QThread):
    """One transfer through the running session: its HTTP inbound, or plainly in TUN mode."""

    measured = pyqtSignal(object)  # (Transfer, first_byte_ms | None)

    def __init__(self, http_port: int | None, url: str = SPEED_TEST_DEFAULT_URL):
        super().__init__()
        self._http_port = http_port
        self._url = url
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        from urllib.request import ProxyHandler

        from ..network.http_utils import build_opener
        from ..network.masking_transfer import run_transfer

        if self._http_port:
            proxy_url = f"http://{PROXY_HOST}:{int(self._http_port)}"
            opener = build_opener(ProxyHandler({"http": proxy_url, "https": proxy_url}))
        else:
            opener = build_opener()
        self.measured.emit(run_transfer(opener, self._url, cancelled=lambda: self._cancelled))


class MaskingTuneRunner(QObject):
    state_changed = pyqtSignal(object)

    def __init__(
        self,
        controller: AppController,
        parent: QObject | None = None,
        *,
        rng: random.Random | None = None,
        transfer_factory: Callable[[int | None], Any] | None = None,
        schedule: Callable[[int, Callable[[], None]], None] | None = None,
        poll_ms: int = POLL_MS,
        clock: Callable[[], float] = time.monotonic,
    ):
        super().__init__(parent)
        self._controller = controller
        self._rng = rng or random.Random()
        self._transfer_factory = transfer_factory or TransferWorker
        self._schedule = schedule or (lambda ms, callback: QTimer.singleShot(ms, callback))
        self._clock = clock
        self._poll = QTimer(self)
        self._poll.setInterval(poll_ms)
        self._poll.timeout.connect(self._on_poll)
        self.state: object = TuneIdle()
        self._generation = 0
        self._running = False
        self._workers: list[Any] = []
        self._node: Any = None
        self._groups: list[tuple[tester.Candidate, list[tester.Step]]] = []
        self._index = -1
        self._measurements: list[tester.Measurement] = []
        self._transfers: list[tester.Transfer] = []
        self._first_bytes: list[int] = []
        self._step = 0
        self._disconnects = 0
        self._deadline = 0.0
        self._then: Callable[[bool], None] | None = None

    @property
    def running(self) -> bool:
        return self._running

    # -- actions of the UI -------------------------------------------------------------------

    def start(self) -> None:
        if self._running:
            return
        controller = self._controller
        if not controller.connected:
            self._set(TuneFailed("Подключите VPN: подбор идёт через выбранный сервер."))
            return
        node = controller.selected_node
        if node is None:
            self._set(TuneFailed("Нет выбранного сервера."))
            return
        shape = shape_of(node.outbound) if isinstance(node.outbound, dict) else None
        if shape is None:
            self._set(TuneFailed("Для этого сервера подбирать нечего."))
            return
        stored = masking_runtime.stored_settings_of(controller.state.settings)
        chosen = tester.candidates(shape, effective(stored, node.id, shape).masking)
        if not chosen:
            self._set(TuneFailed("Для этого сервера подбирать нечего: у Hysteria2 маскировка задаётся в самой ссылке."))
            return
        steps = tester.plan(chosen, self._rng)
        self._groups = [(candidate, [step for step in steps if step.candidate == candidate]) for candidate in chosen]
        self._node = node
        self._measurements = []
        self._index = -1
        self._disconnects = int(getattr(controller, "user_disconnects", 0))
        self._running = True
        self._generation += 1
        self._next_candidate()

    def cancel(self) -> None:
        if not self._running:
            return
        self._end(TuneIdle(), restore=True)

    def keep(self, candidate: tester.Candidate) -> None:
        if not isinstance(self.state, TuneDone):
            return
        self._controller.keep_masking_override(self.state.node_id, candidate.override)
        self._set(replace(self.state, kept=candidate.id))

    def dismiss(self) -> None:
        if not self._running:
            self._set(TuneIdle())

    # -- the run -------------------------------------------------------------------------------

    def _next_candidate(self) -> None:
        if self._user_stopped():
            self._end(TuneFailed("VPN выключен: подбор остановлен."), restore=False)
            return
        self._index += 1
        if self._index >= len(self._groups):
            self._end(TuneDone(self._node.name, self._node.id, tuple(tester.judge(self._measurements))), restore=True)
            return
        candidate, _ = self._groups[self._index]
        self._set(TuneRunning(self._node.name, self._index + 1, len(self._groups), candidate.title))
        masking_runtime.begin_trial(self._node.id, candidate.override, candidate.title)
        self._reconnect(self._on_connected)

    def _reconnect(self, then: Callable[[bool], None]) -> None:
        controller = self._controller
        controller._desired_connected = True
        controller._request_transition(TUNE_REASON)
        self._then = then
        self._deadline = self._clock() + RECONNECT_TIMEOUT_SEC
        self._poll.start()

    def _on_poll(self) -> None:
        controller = self._controller
        if self._user_stopped():
            self._poll.stop()
            self._end(TuneFailed("VPN выключен: подбор остановлен."), restore=False)
            return
        busy = bool(
            controller._transition_active or controller._transition_pending
            or getattr(controller, "_transition_scheduled", False)
        )
        timed_out = self._clock() > self._deadline
        if busy and not timed_out:
            return
        self._poll.stop()
        then, self._then = self._then, None
        if then is not None:
            then(bool(controller.connected) and not busy)

    def _on_connected(self, ok: bool) -> None:
        candidate, _ = self._groups[self._index]
        if not ok:
            self._measurements.append(tester.Measurement(candidate, (), connected=False))
            self._next_candidate()
            return
        if self._controller.state.selected_node_id != self._node.id:
            self._end(
                TuneFailed(f"Во время подбора VPN перешёл на другой сервер: результаты были бы не про «{self._node.name}»."),
                restore=True,
            )
            return
        self._transfers = []
        self._first_bytes = []
        self._step = 0
        self._next_transfer()

    def _next_transfer(self) -> None:
        candidate, steps = self._groups[self._index]
        if self._step >= len(steps):
            first = min(self._first_bytes) if self._first_bytes else None
            self._measurements.append(tester.Measurement(candidate, tuple(self._transfers), first))
            self._next_candidate()
            return
        generation = self._generation
        self._schedule(steps[self._step].pause_before_ms, lambda: self._run_transfer(generation))

    def _run_transfer(self, generation: int) -> None:
        if generation != self._generation or not self._running:
            return
        session = getattr(self._controller, "_active_session", None)
        tun_mode = bool(getattr(session, "tun_mode", False))
        http_port = int(getattr(session, "http_port", 0) or 0)
        worker = self._transfer_factory(None if tun_mode or http_port <= 0 else http_port)
        worker.measured.connect(lambda result, generation=generation: self._on_transfer(generation, result))
        self._workers.append(worker)
        finished = getattr(worker, "finished", None)
        if finished is not None:
            finished.connect(lambda worker=worker: self._workers.remove(worker) if worker in self._workers else None)
        worker.start()

    def _on_transfer(self, generation: int, result: tuple[tester.Transfer, int | None]) -> None:
        if generation != self._generation or not self._running:
            return
        transfer, first_byte = result
        self._transfers.append(transfer)
        if first_byte is not None:
            self._first_bytes.append(first_byte)
        self._step += 1
        self._next_transfer()

    # -- helpers -------------------------------------------------------------------------------

    def _user_stopped(self) -> bool:
        return int(getattr(self._controller, "user_disconnects", 0)) != self._disconnects

    def _end(self, state: object, *, restore: bool) -> None:
        self._generation += 1
        self._running = False
        self._poll.stop()
        self._then = None
        for worker in list(self._workers):
            cancel = getattr(worker, "cancel", None)
            if callable(cancel):
                cancel()
        masking_runtime.end_trial()
        if restore and not self._user_stopped():
            self._controller._desired_connected = True
            self._controller._request_transition(TUNE_END_REASON)
        self._set(state)

    def _set(self, state: object) -> None:
        self.state = state
        self.state_changed.emit(state)
