"""Режим ``ZapretKVN.exe --apply-update <план>``: установить и выйти."""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path

from . import handoff, processes
from .plan import WORK_DIR_PREFIX, InstallPlan
from .runner import Stage, run_install, setup_logging

_log = logging.getLogger("xray_fluent.update_installer")


def main(plan_path: str) -> int:
    plan = InstallPlan.load(Path(plan_path))
    setup_logging(plan.app_dir)
    try:
        ok = _install(plan)
    except Exception:
        _log.exception("Установщик завершился с ошибкой")
        ok = False
    finally:
        # Окно обновления закрыто: приложение может показать своё.
        handoff.release(plan.hold_marker)
    _remove_work_dir_later(plan)
    return 0 if ok else 1


def _install(plan: InstallPlan) -> bool:
    try:
        session = _WindowSession(plan)
    except Exception:
        # Окно — удобство, а не условие: без него установка идёт так же.
        _log.exception("Окно обновления недоступно, установка продолжается без него")
        _confirm_ready(plan)
        return run_install(plan)
    _confirm_ready(plan)
    return session.run()


def _confirm_ready(plan: InstallPlan) -> None:
    # Приложение ждёт этот файл и только после него закрывается: окно
    # обновления к этому моменту уже на экране.
    plan.ready_marker.write_text("ready", encoding="utf-8")


class _WindowSession:
    """Окно в главном потоке, установка — в рабочем."""

    def __init__(self, plan: InstallPlan):
        from PyQt6.QtCore import QThread, pyqtSignal
        from PyQt6.QtGui import QIcon
        from PyQt6.QtWidgets import QApplication

        from ...constants import APP_ICON_PATH, APP_NAME
        from ...ui.theme import apply_theme
        from .window import UpdateWindow

        class Worker(QThread):
            progress = pyqtSignal(object, float)

            def __init__(self) -> None:
                super().__init__()
                self.ok = False

            def run(self) -> None:
                try:
                    self.ok = run_install(plan, self.progress.emit)
                except Exception:
                    _log.exception("Установка прервана")
                    self.progress.emit(Stage.FAILED, 1.0)

        self._app = QApplication.instance() or QApplication([sys.argv[0]])
        self._app.setApplicationName(APP_NAME)
        self._app.setWindowIcon(QIcon(str(APP_ICON_PATH)))
        self._app.setQuitOnLastWindowClosed(True)
        apply_theme(plan.theme, plan.accent, force=True)
        self._window = UpdateWindow(plan)
        self._worker = Worker()
        self._worker.progress.connect(self._window.on_progress)
        self._window.show()

    def run(self) -> bool:
        self._worker.start()
        try:
            self._app.exec()
        finally:
            # Что бы ни случилось с окном, установка доводится до конца:
            # выход посреди замены оставил бы приложение разобранным.
            self._worker.wait()
        return self._worker.ok


def _remove_work_dir_later(plan: InstallPlan) -> None:
    """Удалить временный каталог загрузки после выхода установщика.

    Установщик запущен из этого каталога и удалить его сам не может; без
    уборки каждое обновление оставляло бы на диске сотни мегабайт до
    следующего запуска приложения.
    """

    work_dir = plan.work_dir
    if not processes.IS_WINDOWS:
        return
    if not work_dir.name.startswith(WORK_DIR_PREFIX) or any(c in str(work_dir) for c in '"%'):
        return
    try:
        subprocess.Popen(
            f'cmd.exe /d /c "ping -n 4 127.0.0.1 >nul & rmdir /s /q "{work_dir}""',
            cwd=str(work_dir.parent),
            creationflags=processes.CREATE_NO_WINDOW,
            close_fds=True,
        )
    except OSError:
        _log.warning("Не удалось запланировать удаление %s", work_dir, exc_info=True)
