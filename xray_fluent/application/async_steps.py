"""Generator-based transition steps (AC21).

A transition is written as a plain Python generator that yields
:class:`TransitionStep` objects.  Two drivers execute such generators:

- :class:`TransitionRunner` — the asynchronous driver.  It subscribes to the
  completion of each yielded step and resumes the generator in the GUI thread
  through a queued Qt signal, so the Qt event loop keeps running between steps
  (no ``processEvents``/``waitForFinished`` re-entrancy).  Before every resume
  the runner re-checks an ``is_current`` predicate (the controller's
  ``_transition_generation``); a stale transition is cancelled by closing the
  generator, which runs its ``finally`` blocks and keeps state consistent.
- :func:`run_steps_blocking` — the legacy synchronous driver used by the cold
  compatibility wrappers (shutdown, non-migrated connect paths).  It executes
  each step with the historical pumped-wait primitives so old call sites keep
  their exact behaviour.

Steps deliver worker exceptions into the generator via ``throw()`` so the
existing ``try/except/finally`` blocks of migrated operations (rollback,
cleanup, ``connection_changed`` in ``finally``) keep working unchanged.

QProcess objects never leave the GUI thread: only pure callables (subprocess
runs, socket probes, file reads) are shipped to the worker pool.
"""

from __future__ import annotations

import inspect
import time
from concurrent.futures import Executor, Future, TimeoutError as FutureTimeoutError
from typing import Any, Callable, Generator

from PyQt6.QtCore import QObject, QProcess, Qt, QTimer, pyqtSignal

from ..platform.windows.subprocess_utils import (
    _SUBPROCESS_EXECUTOR,
    pump_qt_events,
    sleep_with_events,
    wait_for_qprocess_finished,
    wait_for_qprocess_started,
)


# Type produced by transition generators.
TransitionSteps = Generator["TransitionStep", Any, Any]

# report(value, error) — exactly one call, may come from any thread.
StepReport = Callable[[Any, BaseException | None], None]

#: Upper bound for one worker step.  Every blocking callable shipped to a
#: worker has its own, much shorter timeout (subprocess 3-15 s, sockets < 7 s,
#: WinAPI); this deadline only guarantees that a wedged call can never keep a
#: transition (or the synchronous shutdown driver) waiting forever.
WORKER_STEP_DEADLINE_MS = 60_000


class StepDeadlineExceeded(TimeoutError):
    """A step did not complete before its hard deadline."""


class TransitionStep:
    """One awaitable unit yielded by a transition generator."""

    def start(self, report: StepReport) -> None:
        """Begin the step; ``report`` must be invoked exactly once when done."""
        raise NotImplementedError

    def cancel(self) -> None:
        """Best-effort cancellation; late ``report`` calls are ignored by the runner."""

    def run_blocking(self) -> Any:
        """Execute synchronously (legacy pumped path for cold call sites)."""
        raise NotImplementedError


class RunInWorkerStep(TransitionStep):
    """Run ``fn`` in a worker pool; the result returns to the GUI thread.

    The default pool is the shared ``_SUBPROCESS_EXECUTOR``.  Work that must
    keep a strict order (system proxy writes) passes its own single-thread
    executor.  ``fn`` must be a pure callable: it must not touch QObjects or
    controller state and must not use the pumped helpers of
    ``subprocess_utils`` (they would submit a nested job into the same pool).
    """

    def __init__(
        self,
        fn: Callable[[], Any],
        executor: Executor | None = None,
        *,
        deadline_ms: int = WORKER_STEP_DEADLINE_MS,
    ):
        self._fn = fn
        self._executor = executor
        self._deadline_ms = max(1, int(deadline_ms))
        self._future: Future[Any] | None = None
        self._timer: QTimer | None = None
        self._cancelled = False
        self._reported = False

    def _pool(self) -> Executor:
        return self._executor if self._executor is not None else _SUBPROCESS_EXECUTOR

    def start(self, report: StepReport) -> None:
        future = self._pool().submit(self._fn)
        self._future = future

        def _on_done(done: Future[Any]) -> None:
            if self._cancelled or self._reported or done.cancelled():
                return
            self._reported = True
            error = done.exception()
            if error is not None:
                report(None, error)
            else:
                report(done.result(), None)

        # Hard deadline: a wedged worker call fails the step instead of
        # parking the transition forever (the late result is ignored).
        timer = QTimer()
        timer.setSingleShot(True)

        def _on_deadline() -> None:
            if self._cancelled or self._reported:
                return
            self._reported = True
            future.cancel()
            report(None, StepDeadlineExceeded(f"worker step exceeded {self._deadline_ms} ms"))

        timer.timeout.connect(_on_deadline)
        self._timer = timer
        timer.start(self._deadline_ms)
        future.add_done_callback(_on_done)

    def cancel(self) -> None:
        self._cancelled = True
        if self._timer is not None:
            self._timer.stop()
        if self._future is not None:
            self._future.cancel()

    def run_blocking(self) -> Any:
        # Cold-path compatibility only (shutdown, tests): preserves the
        # historical run_text_pumped behaviour (worker thread + event pumping),
        # bounded by the same hard deadline as the asynchronous path.
        future = self._pool().submit(self._fn)
        deadline = time.monotonic() + self._deadline_ms / 1000.0
        while True:
            try:
                return future.result(timeout=0.05)
            except FutureTimeoutError:
                if time.monotonic() >= deadline:
                    future.cancel()
                    raise StepDeadlineExceeded(f"worker step exceeded {self._deadline_ms} ms") from None
                pump_qt_events()


class SleepStep(TransitionStep):
    """QTimer-based pause; never blocks the GUI thread in async mode."""

    def __init__(self, ms: int):
        self.ms = max(0, int(ms))
        self._timer: QTimer | None = None

    def start(self, report: StepReport) -> None:
        timer = QTimer()
        timer.setSingleShot(True)
        timer.timeout.connect(lambda: report(None, None))
        self._timer = timer
        timer.start(self.ms)

    def cancel(self) -> None:
        if self._timer is not None:
            self._timer.stop()

    def run_blocking(self) -> Any:
        sleep_with_events(self.ms / 1000.0)
        return None


class WaitProcessFinishedStep(TransitionStep):
    """Race the QProcess ``finished`` signal against a QTimer.

    Resolves to ``True`` when the process finished, ``False`` on timeout —
    the same contract as ``wait_for_qprocess_finished`` but without
    ``waitForFinished``/``processEvents``.
    """

    def __init__(self, process: Any, timeout_ms: int):
        self._process = process
        self._timeout_ms = max(0, int(timeout_ms))
        self._timer: QTimer | None = None
        self._reported = False
        self._signal_handler: Callable[..., None] | None = None

    def _already_done(self) -> bool:
        return self._process.state() == QProcess.ProcessState.NotRunning

    def _watched_signals(self) -> list[tuple[Any, Any]]:
        """(signal, value-on-fire) pairs to race against the timer."""
        return [(self._process.finished, True)]

    def _timeout_value(self) -> Any:
        return self._already_done()

    def start(self, report: StepReport) -> None:
        if self._already_done():
            report(True, None)
            return
        self._start_race(report)

    def _start_race(self, report: StepReport) -> None:
        connections: list[tuple[Any, Callable[..., None]]] = []

        def _finish(value: Any) -> None:
            if self._reported:
                return
            self._reported = True
            for signal, handler in connections:
                try:
                    signal.disconnect(handler)
                except (TypeError, RuntimeError):
                    pass
            if self._timer is not None:
                self._timer.stop()
            report(value, None)

        for signal, value in self._watched_signals():
            handler = (lambda *args, _value=value: _finish(_value))
            connections.append((signal, handler))
            signal.connect(handler)
        self._connections = connections

        timer = QTimer()
        timer.setSingleShot(True)
        timer.timeout.connect(lambda: _finish(self._timeout_value()))
        self._timer = timer
        timer.start(self._timeout_ms)

    def cancel(self) -> None:
        self._reported = True
        for signal, handler in getattr(self, "_connections", []):
            try:
                signal.disconnect(handler)
            except (TypeError, RuntimeError):
                pass
        if self._timer is not None:
            self._timer.stop()

    def run_blocking(self) -> Any:
        return wait_for_qprocess_finished(self._process, self._timeout_ms)


class WaitProcessStartedStep(WaitProcessFinishedStep):
    """Race ``started``/``errorOccurred`` against a QTimer.

    Resolves to ``True`` when the process reached Running, ``False`` on
    startup error or timeout.
    """

    def _already_done(self) -> bool:
        return self._process.state() == QProcess.ProcessState.Running

    def _watched_signals(self) -> list[tuple[Any, Any]]:
        return [
            (self._process.started, True),
            (self._process.errorOccurred, False),
        ]

    def _timeout_value(self) -> Any:
        return self._process.state() == QProcess.ProcessState.Running

    def run_blocking(self) -> Any:
        return wait_for_qprocess_started(self._process, self._timeout_ms)


def run_in_worker(
    fn: Callable[[], Any],
    *,
    executor: Executor | None = None,
    deadline_ms: int = WORKER_STEP_DEADLINE_MS,
) -> RunInWorkerStep:
    """Awaitable step: execute ``fn`` in a worker pool (shared by default)."""
    return RunInWorkerStep(fn, executor, deadline_ms=deadline_ms)


def sleep_ms(ms: int) -> SleepStep:
    """Awaitable step: resume the generator after ``ms`` milliseconds."""
    return SleepStep(ms)


def wait_process_finished(process: Any, timeout_ms: int) -> WaitProcessFinishedStep:
    """Awaitable step: wait until the QProcess finishes (or timeout)."""
    return WaitProcessFinishedStep(process, timeout_ms)


def wait_process_started(process: Any, timeout_ms: int) -> WaitProcessStartedStep:
    """Awaitable step: wait until the QProcess reaches Running (or fails/timeout)."""
    return WaitProcessStartedStep(process, timeout_ms)


class TransitionRunner(QObject):
    """Drives a transition generator on the GUI thread.

    - Each yielded :class:`TransitionStep` is started; its completion resumes
      the generator through a queued signal (always in the runner's thread).
    - Before every resume the ``is_current`` predicate is checked; when it
      turns false (a newer transition request arrived) the generator is closed
      (``GeneratorExit`` runs its ``finally`` blocks) and the run finishes
      with ``cancelled=True``, without executing the remaining steps.
    - A step error is delivered into the generator via ``throw()``; an
      exception escaping the generator finishes the run with ``error`` set.
    """

    # (seq, value, error) — queued so resumes never re-enter the caller.
    _step_completed = pyqtSignal(int, object, object)

    def __init__(
        self,
        generator: TransitionSteps,
        *,
        is_current: Callable[[], bool] | None = None,
        on_finished: Callable[["TransitionRunner"], None] | None = None,
        parent: QObject | None = None,
    ):
        super().__init__(parent)
        self._gen = generator
        self._is_current = is_current if is_current is not None else (lambda: True)
        self._on_finished = on_finished
        self._seq = 0
        self._current_step: TransitionStep | None = None
        self._done = False
        self.result: Any = None
        self.error: BaseException | None = None
        self.cancelled = False
        self._step_completed.connect(self._handle_step_completed, Qt.ConnectionType.QueuedConnection)

    @property
    def done(self) -> bool:
        return self._done

    def start(self) -> None:
        self._advance(None, None)

    def cancel(self) -> None:
        """Cancel immediately (used by shutdown paths)."""
        if not self._done:
            self._cancel_run()

    # ── internals ──

    def _handle_step_completed(self, seq: int, value: Any, error: BaseException | None) -> None:
        if self._done or seq != self._seq:
            return  # stale report from a cancelled/superseded step
        self._advance(value, error)

    def _advance(self, value: Any, error: BaseException | None) -> None:
        if self._done:
            return
        self._current_step = None
        if not self._is_current():
            self._cancel_run()
            return
        try:
            if error is not None:
                step = self._gen.throw(error)
            else:
                step = self._gen.send(value)
        except StopIteration as stop:
            # Synchronous steps can pump Qt events internally, including Stop
            # or a newer selection, without yielding back to this runner.
            self._finish(result=stop.value, cancelled=not self._is_current())
            return
        except BaseException as exc:  # noqa: BLE001 — transition errors surface via .error
            self._finish(error=exc)
            return
        if not isinstance(step, TransitionStep):
            bad = TypeError(f"Transition generator must yield TransitionStep, got {type(step)!r}")
            try:
                self._gen.close()
            except BaseException:  # noqa: BLE001
                pass
            self._finish(error=bad)
            return
        self._seq += 1
        seq = self._seq
        self._current_step = step

        def _report(step_value: Any, step_error: BaseException | None) -> None:
            # May be invoked from a worker thread: the queued signal marshals
            # the resume back to the runner's (GUI) thread.
            try:
                self._step_completed.emit(seq, step_value, step_error)
            except RuntimeError:
                # Runner already deleted (cancelled run torn down) — stale report.
                pass

        try:
            step.start(_report)
        except BaseException as exc:  # noqa: BLE001 — deliver into the generator
            self._step_completed.emit(seq, None, exc)

    def _cancel_run(self) -> None:
        step = self._current_step
        self._current_step = None
        if step is not None:
            try:
                step.cancel()
            except Exception:
                pass
        try:
            self._gen.close()
        except BaseException as exc:  # noqa: BLE001 — a broken finally block
            self.cancelled = True
            self._finish(error=exc, cancelled=True)
            return
        self._finish(cancelled=True)

    def _finish(
        self,
        *,
        result: Any = None,
        error: BaseException | None = None,
        cancelled: bool = False,
    ) -> None:
        if self._done:
            return
        self._done = True
        self.result = result
        self.error = error
        self.cancelled = cancelled
        self._current_step = None
        callback = self._on_finished
        self._on_finished = None
        if callback is not None:
            callback(self)


def run_steps_blocking(generator: TransitionSteps, *, max_steps: int = 100_000) -> Any:
    """Synchronous driver for cold compatibility wrappers.

    Executes each yielded step with the historical pumped-wait behaviour.
    Only application shutdown and tests may use it: hot transition paths go
    through :class:`TransitionRunner`.

    Guards (a wrong argument must fail fast, never spin): ``generator`` must be
    a real generator, every yielded object must be a :class:`TransitionStep`,
    and the number of steps is bounded.  Each step has its own deadline.
    """
    if not inspect.isgenerator(generator):
        raise TypeError(f"run_steps_blocking needs a generator, got {type(generator)!r}")
    value: Any = None
    error: BaseException | None = None
    for _ in range(max(1, int(max_steps))):
        try:
            if error is not None:
                step = generator.throw(error)
            else:
                step = generator.send(value)
        except StopIteration as stop:
            return stop.value
        if not isinstance(step, TransitionStep):
            generator.close()
            raise TypeError(f"Transition generator must yield TransitionStep, got {type(step)!r}")
        value, error = None, None
        try:
            value = step.run_blocking()
        except BaseException as exc:  # noqa: BLE001 — delivered via generator.throw
            error = exc
    generator.close()
    raise RuntimeError(f"run_steps_blocking exceeded {max_steps} steps")
