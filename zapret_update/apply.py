"""Новая версия ставит себя сама: порядок шагов, проверка здоровья, откат.

Основа — установщик Zapret KVN. Новая версия запускается из пробного дерева
с ``--apply-update <план>`` и делает всё сама — поэтому порядок установки
всегда тот, что знает самая новая версия:

1. подготовка: изменившиеся файлы копируются рядом с программой;
2. прежняя программа закрывается (её процессы внутри папки программы тоже);
3. «до замены» (``Hooks.before_swap``): у Zapret GUI — остановить драйверы
   WinDivert и Monkey, запущенные из этой папки;
4. замена файлов с журналом на диске (``swap``);
5. «после замены» (``Hooks.after_swap``): у Zapret GUI — номер версии в
   «Программах и компонентах», задача автозапуска;
6. пробный запуск новой версии «за кулисами» (``handoff``): она должна
   отметиться «готова» за ``ready_wait_s``; молчащий, но живой процесс тоже
   считается запустившимся — медленный диск не повод откатывать;
7. любой сбой — откат по журналу, запуск прежней версии, код причины для
   сервера очереди в ``failure_file``.

Окно обновления у каждой программы своё: шаги приходят в ``report``.
"""

from __future__ import annotations

import json
import logging
import time
import traceback
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable

from . import handoff, processes
from .swap import FileSwap, InstallError

_log = logging.getLogger("zapret_update.apply")

APP_EXIT_WAIT_S = 60.0
CORE_STOP_WAIT_S = 20.0
NEW_VERSION_READY_WAIT_S = 20.0
OLD_VERSION_READY_WAIT_S = 5.0


class Stage(Enum):
    PREPARE = "prepare"
    WAIT_APP = "wait_app"
    SWAP = "swap"
    START = "start"
    DONE = "done"
    ROLLBACK = "rollback"
    FAILED = "failed"


Report = Callable[[Stage, float], None]


@dataclass
class ApplyPlan:
    """Всё, что новой версии нужно знать, чтобы поставить себя."""

    product: str
    version: str
    from_version: str
    app_dir: str
    tree_dir: str  # пробное дерево новой версии
    work_dir: str  # рабочая папка замены (подготовленные и вынесенные файлы, журнал)
    app_pid: int
    app_exe: str  # путь к exe внутри программы, через «/»
    restart_args: list[str] = field(default_factory=list)
    preserve: list[str] = field(default_factory=list)  # папки данных человека
    remove: list[str] | None = None  # файлы прежней версии, которых нет в новой
    failure_file: str = ""  # сюда пишется код причины неудачи
    blocker_file: str = ""  # при «lock» — код программы, державшей файл (msmpeng, explorer…)
    error_log: str = ""  # сюда — подробности для человека
    hold_file: str = ""  # замок окна обновления (пусто — в рабочей папке)
    extra: dict = field(default_factory=dict)  # для окна обновления программы

    @property
    def app_path(self) -> Path:
        return Path(self.app_dir)

    @property
    def exe_path(self) -> Path:
        return self.app_path.joinpath(*self.app_exe.split("/"))

    @property
    def hold_marker(self) -> Path:
        return Path(self.hold_file) if self.hold_file else Path(self.work_dir) / "hold"

    def save(self, path: Path) -> None:
        Path(path).write_text(json.dumps(asdict(self), ensure_ascii=False, indent=1), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "ApplyPlan":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        known = {name for name in cls.__dataclass_fields__}
        return cls(**{key: value for key, value in payload.items() if key in known})


class Hooks:
    """Особые шаги программы; по умолчанию — как у Zapret KVN (ничего сверх)."""

    def close_application(self, plan: ApplyPlan) -> None:
        if not processes.wait_for_exit(plan.app_pid, APP_EXIT_WAIT_S):
            _log.warning("Программа не закрылась за %.0f с — завершаем", APP_EXIT_WAIT_S)
            processes.terminate(plan.app_pid)
            processes.wait_for_exit(plan.app_pid, 10.0)
        for survivor in processes.stop_processes_under(plan.app_path, CORE_STOP_WAIT_S):
            _log.warning("Процесс не завершился: %s", survivor)

    def on_locked(self, plan: ApplyPlan, path: Path) -> None:
        processes.stop_processes_under(plan.app_path, 5.0)

    def before_swap(self, plan: ApplyPlan) -> None:
        pass

    def after_swap(self, plan: ApplyPlan) -> None:
        pass

    def after_rollback(self, plan: ApplyPlan) -> None:
        pass

    def start_command(self, plan: ApplyPlan) -> list[str]:
        return [str(plan.exe_path), *plan.restart_args]

    def before_start(self, plan: ApplyPlan):
        """Отметка перед запуском (например, длина журнала запуска программы)."""
        return None

    def failed_start(self, plan: ApplyPlan, mark, exit_code: int | None) -> None:
        """Программа завершилась сразу после запуска: записать, что она успела сказать."""

    def show_fatal(self, plan: ApplyPlan, details: list[str]) -> None:
        if not processes.IS_WINDOWS:
            return
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(
                None,
                "Не удалось завершить обновление и запустить прежнюю версию.\n\n"
                + (f"Подробности: {plan.error_log}" if plan.error_log else "\n".join(details[:3])),
                plan.product,
                0x10,
            )
        except Exception:
            _log.exception("Не удалось показать сообщение об ошибке")


def failure_code(stage: Stage, error: Exception) -> str:
    """Короткая причина для сервера очереди: на каком шаге и почему."""
    if stage is Stage.START:
        return "crash"  # новая версия завершилась сразу после запуска
    if stage is Stage.SWAP:
        return "lock" if getattr(error, "path", None) is not None else "swap"
    if stage is Stage.PREPARE:
        return "prep"
    if stage is Stage.WAIT_APP:
        return "close"
    return "other"


def run_apply(plan: ApplyPlan, hooks: Hooks | None = None, report: Report | None = None) -> bool:
    """Поставить новую версию; при любой ошибке вернуть прежнюю."""
    hooks = hooks or Hooks()
    report = report or (lambda stage, fraction: None)
    files = FileSwap(
        Path(plan.tree_dir),
        plan.app_path,
        Path(plan.work_dir) / "swap",
        preserve=plan.preserve,
        remove=plan.remove,
        on_locked=lambda path: hooks.on_locked(plan, path),
    )
    _log.info("Установка %s %s → %s в %s", plan.product, plan.from_version, plan.version, plan.app_dir)
    stage = Stage.PREPARE
    try:
        report(Stage.PREPARE, 0.0)
        files.prepare(lambda fraction: report(Stage.PREPARE, fraction))
        _log.info(
            "Файлы: без изменений %d, заменить %d, добавить %d, убрать %d",
            files.unchanged, files.replaced, files.added, files.removed,
        )
        stage = Stage.WAIT_APP
        report(Stage.WAIT_APP, 0.0)
        hooks.close_application(plan)
        hooks.before_swap(plan)
        stage = Stage.SWAP
        report(Stage.SWAP, 0.0)
        files.commit()
        for path in files.left_behind:
            _log.warning("Лишний файл занят и оставлен на месте: %s", path)
        hooks.after_swap(plan)
        stage = Stage.START
        report(Stage.START, 0.0)
        _start_and_verify(plan, hooks, lambda fraction: report(Stage.START, fraction))
    except Exception as error:
        _log.exception("Установка не удалась")
        details = [f"Обновление до {plan.version} не установлено: {error}"]
        path = getattr(error, "path", None)
        if path is not None:
            holders = processes.lock_holders(path)
            if holders:
                details.append("Файл удерживают: " + "; ".join(holders))
            codes = processes.lock_holder_codes(path)
            if codes:
                _write(plan.blocker_file, codes[0])
        if not isinstance(error, InstallError):
            details.append(traceback.format_exc().strip())
        _write(plan.failure_file, failure_code(stage, error))
        report(Stage.ROLLBACK, 0.0)
        try:
            _recover(plan, hooks, files, details)
        except Exception:
            _log.exception("Сбой при возврате прежней версии")
        report(Stage.FAILED, 1.0)
        return False
    files.discard()
    _log.info("Установка %s завершена", plan.version)
    report(Stage.DONE, 1.0)
    return True


_STATUS_CONTROL_C_EXIT = 0xC000013A


def exit_code_text(code: int | None) -> str:
    """Код выхода для человека: обычные — числом, аварийные Windows — 0x…"""
    if code is None:
        return "код неизвестен"
    code &= 0xFFFFFFFF
    text = f"код {code}" if code < 0x10000 else f"код 0x{code:08X}"
    if code == _STATUS_CONTROL_C_EXIT:
        text += ", прерван Ctrl+C"
    return text


def _start_and_verify(plan: ApplyPlan, hooks: Hooks, progress: Callable[[float], None]) -> None:
    mark = hooks.before_start(plan)
    process = processes.start_detached(
        hooks.start_command(plan), cwd=plan.exe_path.parent, env=handoff.arm(plan.hold_marker)
    )
    if not _wait_until_started(plan, process, NEW_VERSION_READY_WAIT_S, progress):
        hooks.failed_start(plan, mark, process.returncode)
        raise InstallError(f"Новая версия завершилась сразу после запуска ({exit_code_text(process.returncode)})")


def _wait_until_started(plan: ApplyPlan, process, wait_s: float, progress=lambda fraction: None) -> bool:
    """True — программа готова показаться или хотя бы пережила ожидание."""
    started = time.monotonic()
    while (elapsed := time.monotonic() - started) < wait_s:
        if process.poll() is not None:
            return False
        if handoff.is_ready(plan.hold_marker):
            return True
        progress(elapsed / wait_s)
        time.sleep(0.1)
    return process.poll() is None


def _recover(plan: ApplyPlan, hooks: Hooks, files: FileSwap, details: list[str]) -> None:
    # Прежняя версия могла ещё не выйти (сбой на подготовке), а новая — успеть
    # запустить свои процессы: до отката не должно остаться ни той, ни другой.
    hooks.close_application(plan)
    errors = files.rollback()
    if errors:
        details.append("Прежнюю версию не удалось вернуть полностью:")
        details.extend(errors)
        details.append(f"Её файлы сохранены в {files.work_dir}")
    else:
        details.append("Прежняя версия возвращена.")
        files.discard()
    try:
        hooks.after_rollback(plan)
    except Exception:
        _log.exception("Шаг после отката не выполнен")
    for line in details:
        _log.error(line)
    _write(plan.error_log, "\n".join(details) + "\n")

    restarted = False
    if plan.exe_path.is_file():
        try:
            mark = hooks.before_start(plan)
            # С замком: прежняя версия, которая его понимает, не покажет окно
            # поверх окна обновления; не понимает — просто стартует как обычно.
            process = processes.start_detached(
                hooks.start_command(plan), cwd=plan.exe_path.parent, env=handoff.arm(plan.hold_marker)
            )
            restarted = _wait_until_started(plan, process, OLD_VERSION_READY_WAIT_S)
        except OSError:
            _log.exception("Не удалось запустить прежнюю версию")
        else:
            if not restarted:
                _log.error("Прежняя версия завершилась сразу после запуска (%s)", exit_code_text(process.returncode))
                hooks.failed_start(plan, mark, process.returncode)
    if restarted:
        _log.info("Прежняя версия запущена")
    else:
        hooks.show_fatal(plan, details)


def _write(path: str, text: str) -> None:
    if not path:
        return
    try:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    except OSError:
        _log.exception("Не удалось записать %s", path)


__all__ = ["ApplyPlan", "Hooks", "Stage", "exit_code_text", "failure_code", "run_apply"]
