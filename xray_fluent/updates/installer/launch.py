"""Запуск установщика из работающего приложения."""

from __future__ import annotations

import subprocess

from . import APPLY_UPDATE_FLAG, processes
from .plan import PLAN_FILE_NAME, InstallPlan


def launch_installer(plan: InstallPlan) -> subprocess.Popen:
    """Запустить новую сборку в режиме установки.

    Приложение выходит не сразу, а когда установщик создаст
    ``plan.ready_marker``: если он не поднялся, закрываться незачем.
    """

    plan_path = plan.work_dir / PLAN_FILE_NAME
    plan.ready_marker.unlink(missing_ok=True)
    plan.save(plan_path)
    return processes.start_detached(
        [str(plan.installer_exe), APPLY_UPDATE_FLAG, str(plan_path)],
        cwd=plan.source_dir,
        console=False,
    )
