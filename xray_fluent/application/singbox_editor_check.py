"""Check the edited sing-box config with the bundled core, off the GUI thread.

«Проверить» on the routing pages asks the core itself (``sing-box check``) about
the source document the user is editing. App-owned launch mutations (selected
server in ``proxy``, proxy inbounds, Clash API port) are applied only at
launch, so this validates the user's native JSON, not the runtime copy.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from PyQt6.QtCore import QObject, pyqtSignal

from ..constants import RUNTIME_DIR, SINGBOX_PATH_DEFAULT
from ..engines.singbox.config_check import check_config
from ..profiles.path_utils import resolve_configured_path

CHECK_FILE_NAME = "singbox_editor_check.json"
_NOT_RUN_PREFIX = "Проверка конфигурации не выполнена"


class SingboxEditorCheck(QObject):
    #: ``(generation, level, message)``; level is ``success``/``error``/``warning``.
    finished = pyqtSignal(int, str, str)

    def __init__(self, parent: QObject | None = None, *, runtime_dir: Path = RUNTIME_DIR):
        super().__init__(parent)
        self._runtime_dir = runtime_dir
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="singbox_editor_check")
        self._generation = 0

    def start(self, singbox_path: str, text: str) -> int:
        self._generation += 1
        generation = self._generation
        exe = resolve_configured_path(
            singbox_path,
            default_path=SINGBOX_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        self._executor.submit(self._run, generation, exe, text)
        return generation

    def _run(self, generation: int, exe: Path | None, text: str) -> None:
        # Worker thread: the signal is delivered queued to the GUI thread.
        try:
            level, message = self.check_blocking(exe, text)
        except Exception as exc:  # never let a worker error vanish silently
            level, message = "warning", f"{_NOT_RUN_PREFIX}: {type(exc).__name__}: {exc}"
        self.finished.emit(generation, level, message)

    def check_blocking(self, exe: Path | None, text: str) -> tuple[str, str]:
        if exe is None or not exe.is_file():
            return "warning", f"{_NOT_RUN_PREFIX}: не найден sing-box.exe."
        self._runtime_dir.mkdir(parents=True, exist_ok=True)
        path = self._runtime_dir / CHECK_FILE_NAME
        path.write_text(text, encoding="utf-8")
        try:
            ok, message = check_config(exe, path)
        finally:
            path.unlink(missing_ok=True)
        if ok and message.startswith(_NOT_RUN_PREFIX):
            return "warning", message
        if ok:
            return "success", "Ядро sing-box приняло конфиг (sing-box check)."
        return "error", message

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
