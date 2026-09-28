"""winws2 process: run exactly the requested plan, prove it, never block the GUI.

The whole API is declarative: :meth:`ZapretManager.apply` asks for a plan
(preset + optional VPN-server rule), :meth:`ZapretManager.stop` asks for no
process.  Every request gets a revision number; ``plan_applied(revision)`` fires
only when the winws2 process built from *that* request reports
``QProcess.started``, so a late signal of an older restart can never satisfy a
newer wait.  ``plan_failed(revision, reason)`` covers everything else, including
a 5 s timeout.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from PyQt6.QtCore import QObject, QProcess, QTimer, pyqtSignal

from ...application.async_steps import (
    TransitionRunner,
    TransitionSteps,
    run_in_worker,
    sleep_ms,
    wait_process_finished,
)
from ...platform.windows.subprocess_utils import decode_output, kill_processes_by_path
from . import presets
from .command import ServerRule, build_arguments
from .presets import ZAPRET_DIR

log = logging.getLogger(__name__)

WINWS2_EXE = ZAPRET_DIR / "exe" / "winws2.exe"
WINWS_EXE = ZAPRET_DIR / "exe" / "winws.exe"

#: How long a requested plan may take to reach ``QProcess.started``.  WinDivert
#: can hold the previous process's driver handles for a while; a transition must
#: not wait on that forever.
APPLY_TIMEOUT_MS = 5_000

_EXIT_HINTS = {
    1: "общая ошибка (другой экземпляр / не удалось открыть WinDivert)",
    2: "ошибка аргументов командной строки",
    3: "не удалось загрузить WinDivert драйвер (нужны права администратора)",
}


def _kill_orphaned_blocking() -> list[str]:
    """Worker-only: kill winws.exe / winws2.exe left over by this installation."""

    killed: list[str] = []
    if os.name != "nt":
        return killed
    for exe_name, exe_path in (("winws2.exe", WINWS2_EXE), ("winws.exe", WINWS_EXE)):
        try:
            if kill_processes_by_path(exe_name, exe_path, timeout=5, pump=False):
                killed.append(exe_name)
        except Exception:
            pass
    return killed


@dataclass(frozen=True, slots=True)
class ZapretPlan:
    """What winws2 should run: a preset and, maybe, the VPN-server rule."""

    preset: str
    rule: ServerRule | None = None


class ZapretManager(QObject):
    started = pyqtSignal()  # the process of the current plan is running
    stopped = pyqtSignal()  # no process and nothing starting
    error = pyqtSignal(str)
    log_line = pyqtSignal(str)
    plan_changed = pyqtSignal(object)  # ZapretPlan | None — the new request
    plan_applied = pyqtSignal(int)
    plan_failed = pyqtSignal(int, str)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._plan: ZapretPlan | None = None
        self._revision = 0
        self._pending = 0  # revision still waiting for its process to start
        self._runner: TransitionRunner | None = None
        self._process: QProcess | None = None
        self._process_plan: ZapretPlan | None = None
        self._process_args: list[str] = []
        # Killed processes whose exit (WinDivert handle release) is still due.
        self._exiting: list[QProcess] = []

    # ── state ────────────────────────────────────────────────────────────

    @property
    def plan(self) -> ZapretPlan | None:
        """The last requested plan (None after stop)."""
        return self._plan

    @property
    def rule(self) -> ServerRule | None:
        return self._plan.rule if self._plan is not None else None

    @property
    def revision(self) -> int:
        return self._revision

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.state() == QProcess.ProcessState.Running

    @property
    def starting(self) -> bool:
        return self._runner is not None or (
            self._process is not None and self._process.state() == QProcess.ProcessState.Starting
        )

    @property
    def active(self) -> bool:
        """Running or about to: winws2 is (or will be) filtering traffic."""
        return self._plan is not None and (self.running or self.starting or bool(self._pending))

    @property
    def pending(self) -> bool:
        return bool(self._pending)

    def is_applied(self, plan: ZapretPlan | None = None) -> bool:
        """The running process was built from ``plan`` (default: the current one)."""

        plan = self._plan if plan is None else plan
        return (
            plan is not None
            and not self._pending
            and self.running
            and self._process_plan == plan
        )

    # ── requests ─────────────────────────────────────────────────────────

    def apply(self, plan: ZapretPlan) -> int:
        """Run ``plan``; returns the revision whose ``plan_applied`` proves it.

        Re-requesting the plan that is already running or starting is free and
        returns the same revision — no restart, no signal.
        """

        if plan == self._plan and (self._pending or self.is_applied(plan)):
            return self._revision
        # A waiter of an older revision is not failed here: it re-checks the
        # facts when this revision is applied (or fails).
        self._plan = plan
        self._revision += 1
        revision = self._revision
        self._pending = revision
        if plan.rule is not None:
            self.log_line.emit(f"[zapret] Правило для VPN-сервера: {plan.rule.describe()}")
        elif self._process_plan is not None and self._process_plan.rule is not None:
            self.log_line.emit("[zapret] Правило для VPN-сервера снято")
        self.plan_changed.emit(plan)
        QTimer.singleShot(APPLY_TIMEOUT_MS, lambda: self._on_apply_timeout(revision))
        self._start_runner(plan, revision)
        return revision

    def stop(self, *, wait: bool = False) -> None:
        """No winws2 at all; a waiting request fails with ``stopped``.

        The process is killed without waiting and detached at once, so its late
        signals cannot be mistaken for a newer process.  ``wait=True`` blocks
        until it exits — for application shutdown only.
        """

        had_something = self._plan is not None or self._process is not None
        self._cancel_runner()
        self._plan = None
        self._revision += 1
        self._fail_pending("stopped")
        process = self._detach_process()
        if process is not None:
            log.info("zapret stop")
            if wait:
                process.waitForFinished(5000)
        if had_something:
            self.plan_changed.emit(None)
            self.stopped.emit()

    # ── launch ───────────────────────────────────────────────────────────

    def _start_runner(self, plan: ZapretPlan, revision: int) -> None:
        self._cancel_runner()
        self._detach_process()
        runner = TransitionRunner(
            self._launch_steps(plan, revision),
            on_finished=self._on_runner_finished,
            parent=self,
        )
        self._runner = runner
        runner.start()

    def _cancel_runner(self) -> None:
        runner, self._runner = self._runner, None
        if runner is not None:
            runner.cancel()

    def _on_runner_finished(self, runner: TransitionRunner) -> None:
        if self._runner is runner:
            self._runner = None
        runner.deleteLater()
        if runner.error is not None:
            log.exception("zapret start failed", exc_info=runner.error)
            self._fail(f"Не удалось запустить winws2.exe: {runner.error}", "start_failed")

    def _launch_steps(self, plan: ZapretPlan, revision: int) -> TransitionSteps:
        for process in list(self._exiting):
            # WinDivert releases its handles only when the old process exits.
            yield wait_process_finished(process, 5000)
        killed = yield run_in_worker(_kill_orphaned_blocking)
        for name in killed:
            self.log_line.emit(f"[zapret] Завершён сторонний процесс: {name}")
        if killed:
            yield sleep_ms(1000)  # driver grace period — a timer, not a GUI sleep

        if not WINWS2_EXE.exists():
            self._fail(f"winws2.exe не найден: {WINWS2_EXE}", "missing_executable")
            return False
        if not presets.preset_path(plan.preset).is_file():
            self._fail(f"Пресет не найден: {plan.preset}", "missing_preset")
            return False
        args = build_arguments(presets.preset_arguments(plan.preset), plan.rule)
        if not args:
            self._fail(f"Пресет пустой: {plan.preset}", "empty_preset")
            return False

        process = QProcess(self)
        process.setProgram(str(WINWS2_EXE))
        process.setArguments(args)
        process.setWorkingDirectory(str(ZAPRET_DIR))
        process.readyReadStandardOutput.connect(self._on_output)
        process.readyReadStandardError.connect(self._on_output)
        process.started.connect(lambda: self._on_started(revision))
        process.errorOccurred.connect(self._on_process_error)
        process.finished.connect(self._on_finished)
        self._process = process
        self._process_plan = plan
        self._process_args = args
        log.info("zapret start: %s [%s] (%d args)", WINWS2_EXE.name, plan.preset, len(args))
        self.log_line.emit(f"[zapret] Запуск: {plan.preset} ({len(args)} аргументов)")
        process.start()
        return True

    def _detach_process(self) -> QProcess | None:
        """Kill the current process and forget it; its exit is tracked apart."""

        process, self._process = self._process, None
        self._process_plan = None
        self._process_args = []
        if process is None:
            return None
        for signal in (
            process.readyReadStandardOutput, process.readyReadStandardError,
            process.started, process.errorOccurred, process.finished,
        ):
            try:
                signal.disconnect()
            except (TypeError, RuntimeError):
                pass
        if process.state() == QProcess.ProcessState.NotRunning:
            process.deleteLater()
            return None
        self._exiting.append(process)
        process.finished.connect(lambda *_: self._forget_exited(process))
        process.kill()
        return process

    def _forget_exited(self, process: QProcess) -> None:
        if process in self._exiting:
            self._exiting.remove(process)
        process.deleteLater()

    # ── process signals ──────────────────────────────────────────────────

    def _on_started(self, revision: int) -> None:
        if revision == self._pending:
            self._pending = 0
            self.plan_applied.emit(revision)
        self.started.emit()

    def _on_output(self) -> None:
        if self._process is None:
            return
        for line in self._read_output(self._process):
            self.log_line.emit(f"[zapret] {line}")

    @staticmethod
    def _read_output(process: QProcess) -> list[str]:
        lines: list[str] = []
        for reader in (process.readAllStandardOutput, process.readAllStandardError):
            data = reader().data()
            if data:
                lines.extend(
                    stripped for stripped in (
                        line.strip() for line in decode_output(bytes(data)).splitlines()
                    ) if stripped
                )
        return lines

    def _on_process_error(self, process_error: QProcess.ProcessError) -> None:
        if process_error != QProcess.ProcessError.FailedToStart:
            return
        process = self._process
        if process is not None and process.state() == QProcess.ProcessState.NotRunning:
            self._process = None
            self._process_plan = None
            self._process_args = []
            process.deleteLater()
        self._fail(f"Не удалось запустить winws2.exe: {process_error.name}", "start_failed")

    def _on_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        """The process died by itself (a requested stop detaches it first)."""

        process = self._process
        if process is None:
            return
        remaining = self._read_output(process)
        for line in remaining:
            self.log_line.emit(f"[zapret] {line}")
        preset = self._process_plan.preset if self._process_plan else "?"
        args = self._process_args
        log.info("zapret finished: code=%d status=%s preset=%s", exit_code, exit_status.name, preset)
        self._process = None
        self._process_plan = None
        self._process_args = []
        process.deleteLater()

        hint = _EXIT_HINTS.get(exit_code, "")
        if exit_code != 0 or exit_status == QProcess.ExitStatus.CrashExit:
            if hint:
                self.log_line.emit(f"[zapret] Код {exit_code}: {hint}")
            self.log_line.emit(f"[zapret] Пресет: {preset}")
            if args:
                preview = " ".join(args[:6])
                if len(args) > 6:
                    preview += f" ... (+{len(args) - 6} аргументов)"
                self.log_line.emit(f"[zapret] Команда: winws2.exe {preview}")
            if not remaining:
                self.log_line.emit("[zapret] Процесс не вывел ничего в stdout/stderr")
        if exit_status == QProcess.ExitStatus.CrashExit:
            message = "winws2 аварийно завершился"
        elif exit_code != 0:
            message = f"winws2 завершился с кодом {exit_code}"
        else:
            message = ""  # exited cleanly by itself: a stop, not an error
        self._fail(f"{message} — {hint}" if message and hint else message, "exited")

    # ── failure bookkeeping ──────────────────────────────────────────────

    def _fail(self, message: str, reason: str) -> None:
        """The plan cannot run: report it, drop the request, announce the stop."""

        self._plan = None
        self._fail_pending(reason)
        if message:
            self.error.emit(message)
        self.plan_changed.emit(None)
        self.stopped.emit()

    def _fail_pending(self, reason: str) -> None:
        revision, self._pending = self._pending, 0
        if revision:
            self.plan_failed.emit(revision, reason)

    def _on_apply_timeout(self, revision: int) -> None:
        if revision != self._pending:
            return
        self.log_line.emit(
            f"[zapret] winws2 не запустился за {APPLY_TIMEOUT_MS} мс — правило не подтверждено"
        )
        self._fail_pending("timeout")
