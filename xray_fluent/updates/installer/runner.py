"""Порядок шагов установки. Интерфейса здесь нет: окно лишь слушает ``report``."""

from __future__ import annotations

import logging
import time
import traceback
from enum import Enum
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Callable

from . import processes
from .file_swap import FileSwap, InstallError
from .plan import InstallPlan

_log = logging.getLogger("xray_fluent.update_installer")

APP_EXIT_WAIT_S = 60.0
CORE_STOP_WAIT_S = 20.0
# Сборка, которая не может запуститься, падает в первые секунды: импорт
# модулей и создание окна. Столько установщик ждёт, прежде чем убрать
# резервную копию прежней версии.
HEALTH_CHECK_S = 5.0


class Stage(Enum):
    PREPARE = "prepare"
    WAIT_APP = "wait_app"
    SWAP = "swap"
    START = "start"
    DONE = "done"
    ROLLBACK = "rollback"
    FAILED = "failed"


Report = Callable[[Stage, float], None]


def setup_logging(app_dir: Path) -> None:
    if _log.handlers:
        return
    log_dir = app_dir / "data" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        log_dir / "update.log", maxBytes=512 * 1024, backupCount=1, encoding="utf-8"
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s  %(levelname)s  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    )
    _log.addHandler(handler)
    _log.setLevel(logging.INFO)
    _log.propagate = False


def run_install(plan: InstallPlan, report: Report | None = None) -> bool:
    """Установить обновление; при любой ошибке вернуть прежнюю версию."""

    report = report or (lambda stage, fraction: None)
    swap = FileSwap(
        plan.source_dir,
        plan.app_dir,
        plan.work_dir.name,
        # Занятый файл чаще всего держит ядро, которое успело запуститься
        # заново или ещё не завершилось.
        on_locked=lambda path: processes.stop_processes_under(plan.app_dir, 5.0),
    )
    _log.info("Установка v%s в %s", plan.version, plan.app_dir)
    try:
        report(Stage.PREPARE, 0.0)
        swap.prepare(lambda fraction: report(Stage.PREPARE, fraction))
        _log.info(
            "Файлы: без изменений %d, заменить %d, добавить %d, убрать %d",
            swap.unchanged, swap.replaced, swap.added, swap.removed,
        )
        report(Stage.WAIT_APP, 0.0)
        _close_application(plan)
        report(Stage.SWAP, 0.0)
        swap.commit()
        for path in swap.left_behind:
            _log.warning("Лишний файл занят и оставлен на месте: %s", path)
        report(Stage.START, 0.0)
        _start_and_verify(plan, lambda fraction: report(Stage.START, fraction))
    except Exception as error:
        _log.exception("Установка не удалась")
        details = _describe_failure(plan, error)
        report(Stage.ROLLBACK, 0.0)
        try:
            _recover(plan, swap, details)
        except Exception:
            _log.exception("Сбой при возврате прежней версии")
        report(Stage.FAILED, 1.0)
        return False
    swap.discard()
    _log.info("Установка v%s завершена", plan.version)
    report(Stage.DONE, 1.0)
    return True


def _close_application(plan: InstallPlan) -> None:
    if not processes.wait_for_exit(plan.app_pid, APP_EXIT_WAIT_S):
        _log.warning("Приложение не закрылось за %.0f с — завершаем", APP_EXIT_WAIT_S)
        processes.terminate(plan.app_pid)
        processes.wait_for_exit(plan.app_pid, 10.0)
    for survivor in processes.stop_processes_under(plan.app_dir, CORE_STOP_WAIT_S):
        _log.warning("Процесс не завершился: %s", survivor)


def _start_and_verify(plan: InstallPlan, progress: Callable[[float], None]) -> None:
    process = _start_application(plan)
    started = time.monotonic()
    while (elapsed := time.monotonic() - started) < HEALTH_CHECK_S:
        if process.poll() is not None:
            raise InstallError(
                f"Новая версия завершилась сразу после запуска (код {process.returncode})"
            )
        progress(elapsed / HEALTH_CHECK_S)
        time.sleep(0.2)


def _start_application(plan: InstallPlan):
    return processes.start_detached(
        [str(plan.app_exe), *plan.restart_args], cwd=plan.app_dir, console=True
    )


def _describe_failure(plan: InstallPlan, error: Exception) -> list[str]:
    lines = [f"Обновление до v{plan.version} не установлено: {error}"]
    path = getattr(error, "path", None)
    if path is not None:
        # Спрашиваем до отката: после него файл уже может быть свободен.
        holders = processes.lock_holders(path)
        if holders:
            lines.append("Файл удерживают: " + "; ".join(holders))
    if not isinstance(error, InstallError):
        lines.append(traceback.format_exc().strip())
    return lines


def _recover(plan: InstallPlan, swap: FileSwap, details: list[str]) -> None:
    # Прежняя версия могла ещё не выйти (сбой на подготовке), а новая —
    # успеть запустить ядро: до отката не должно остаться ни той, ни другой.
    _close_application(plan)
    rollback_errors = swap.rollback()
    if rollback_errors:
        details.append("Прежнюю версию не удалось вернуть полностью:")
        details.extend(rollback_errors)
        details.append(f"Её файлы сохранены в {swap.stage_dir}")
    else:
        details.append("Прежняя версия возвращена.")
        swap.discard()
    for line in details:
        _log.error(line)
    _write_error_log(plan, details)

    restarted = False
    if plan.app_exe.is_file():
        try:
            process = _start_application(plan)
            time.sleep(HEALTH_CHECK_S)
            restarted = process.poll() is None
        except OSError:
            _log.exception("Не удалось запустить прежнюю версию")
    if not restarted:
        _show_fatal_message(plan)


def _write_error_log(plan: InstallPlan, details: list[str]) -> None:
    # Этот файл читает приложение на следующем старте и показывает причину.
    try:
        log_dir = plan.app_dir / "data" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / "update_error.log").write_text("\n".join(details) + "\n", encoding="utf-8")
    except OSError:
        _log.exception("Не удалось записать update_error.log")


def _show_fatal_message(plan: InstallPlan) -> None:
    if not processes.IS_WINDOWS:
        return
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(
            None,
            "Не удалось завершить обновление и запустить прежнюю версию.\n\n"
            f"Подробности: {plan.app_dir / 'data' / 'logs' / 'update.log'}",
            "Zapret KVN",
            0x10,
        )
    except Exception:
        _log.exception("Не удалось показать сообщение об ошибке")
