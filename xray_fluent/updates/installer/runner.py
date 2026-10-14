"""Установка Zapret KVN — общим ядром обновления ``zapret_update.apply``.

Порядок шагов, замена файлов с журналом и откат — те же, что у Zapret 2 GUI
(ядро одно на обе программы). Здесь только то, что своё у Zapret KVN: план
прежнего вида (его пишет ещё прежняя версия), журнал ``data/logs/update.log``,
хвост ``startup.log`` упавшего запуска и сообщение об ошибке.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

from zapret_update import apply, processes
from zapret_update.apply import Stage, failure_code

from .plan import InstallPlan

_log = logging.getLogger("xray_fluent.update_installer")

# Файл с короткой причиной неудачи для сервера обновлений (``why``). Его
# читает версия, которая работает после отката (``auto_update.resolve_startup``).
FAILURE_CODE_NAME = "app_update_failure.txt"
# Подготовленные и вынесенные файлы замены лежат рядом с программой.
STAGE_ROOT_NAME = "app_update"
# Столько последних строк startup.log упавшего запуска попадает в update.log.
STARTUP_LOG_TAIL_LINES = 40

Report = apply.Report


def stage_root_for(app_dir: Path) -> Path:
    return app_dir / "data" / "runtime" / STAGE_ROOT_NAME


def setup_logging(app_dir: Path) -> None:
    log_dir = app_dir / "data" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(log_dir / "update.log", maxBytes=512 * 1024, backupCount=1, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s  %(levelname)s  %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    for logger in (_log, logging.getLogger("zapret_update")):
        if logger.handlers:
            continue
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False


def core_plan(plan: InstallPlan) -> apply.ApplyPlan:
    """План ядра из плана Zapret KVN."""
    app_dir = Path(plan.app_dir)
    return apply.ApplyPlan(
        product="Zapret KVN",
        version=plan.version,
        from_version="",
        app_dir=str(app_dir),
        tree_dir=str(plan.source_dir),
        work_dir=str(stage_root_for(app_dir) / plan.work_dir.name),
        app_pid=plan.app_pid,
        app_exe=plan.exe_name,
        restart_args=list(plan.restart_args),
        # data/ — настройки и подписки человека; всё остальное в папке —
        # поставка, и лишнее в ней убирается (как и прежде).
        preserve=["data"],
        remove=None,
        failure_file=str(app_dir / "data" / "runtime" / FAILURE_CODE_NAME),
        error_log=str(app_dir / "data" / "logs" / "update_error.log"),
        hold_file=str(plan.hold_marker),
    )


class KvnHooks(apply.Hooks):
    def before_start(self, plan: apply.ApplyPlan):
        return _startup_log_size(plan)

    def failed_start(self, plan: apply.ApplyPlan, mark, exit_code) -> None:
        _log_startup_tail(plan, int(mark or 0))

    def show_fatal(self, plan: apply.ApplyPlan, details: list[str]) -> None:
        if not processes.IS_WINDOWS:
            return
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(
                None,
                "Не удалось завершить обновление и запустить прежнюю версию.\n\n"
                f"Подробности: {Path(plan.app_dir) / 'data' / 'logs' / 'update.log'}",
                "Zapret KVN",
                0x10,
            )
        except Exception:
            _log.exception("Не удалось показать сообщение об ошибке")


def run_install(plan: InstallPlan, report: Report | None = None) -> bool:
    """Установить обновление; при любой ошибке вернуть прежнюю версию."""
    return apply.run_apply(core_plan(plan), KvnHooks(), report)


def _startup_log(plan: apply.ApplyPlan) -> Path:
    return Path(plan.app_dir) / "data" / "logs" / "startup.log"


def _startup_log_size(plan: apply.ApplyPlan) -> int:
    try:
        return _startup_log(plan).stat().st_size
    except OSError:
        return 0


def _log_startup_tail(plan: apply.ApplyPlan, offset: int) -> None:
    """Переписать в update.log то, что упавший запуск успел сказать о себе."""
    try:
        with _startup_log(plan).open("rb") as stream:
            size = stream.seek(0, os.SEEK_END)
            # Журнал короче отметки — значит, его сменила ротация: он весь новый.
            start = offset if offset <= size else 0
            stream.seek(max(start, size - 64 * 1024))
            text = stream.read().decode("utf-8", "replace")
    except OSError:
        text = ""
    lines = [line for line in text.splitlines() if line.strip()][-STARTUP_LOG_TAIL_LINES:]
    if not lines:
        _log.error("В startup.log этот запуск не оставил ни строки: процесс не дошёл до журнала")
        return
    _log.error("Последние строки startup.log этого запуска:\n%s", "\n".join(lines))


__all__ = ["FAILURE_CODE_NAME", "Stage", "core_plan", "failure_code", "run_install", "setup_logging", "stage_root_for"]
