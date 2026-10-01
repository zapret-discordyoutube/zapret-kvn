"""План установки: всё, что установщику нужно знать о предстоящей замене."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

PLAN_FILE_NAME = "install_plan.json"
# Префикс временного каталога загрузки в %TEMP%.
WORK_DIR_PREFIX = "zapretkvn_update_"
READY_FILE_NAME = "installer_ready"
APP_EXE_NAME = "ZapretKVN.exe"


@dataclass(slots=True)
class InstallPlan:
    version: str
    app_pid: int
    app_dir: Path
    # Распакованная сборка новой версии; из неё же запущен установщик.
    source_dir: Path
    # Временный каталог загрузки целиком (архив + распакованная сборка).
    work_dir: Path
    exe_name: str = APP_EXE_NAME
    # Приложение было свёрнуто в трей: после установки оно возвращается туда
    # же, а окно обновления не забирает фокус у чужих программ.
    start_in_tray: bool = False
    theme: str = "system"
    accent: str = ""
    # Геометрия главного окна (x, y, ширина, высота): окно обновления
    # появляется на его месте.
    anchor: tuple[int, int, int, int] | None = None

    @property
    def app_exe(self) -> Path:
        return self.app_dir / self.exe_name

    @property
    def installer_exe(self) -> Path:
        return self.source_dir / self.exe_name

    @property
    def ready_marker(self) -> Path:
        """Файл, которым установщик подтверждает приложению, что он работает."""
        return self.work_dir / READY_FILE_NAME

    @property
    def hold_marker(self) -> Path:
        """Замок, под которым приложение стартует, не показывая окна (см. handoff)."""
        return self.app_dir / "data" / "runtime" / "update_hold"

    @property
    def restart_args(self) -> list[str]:
        return ["--tray"] if self.start_in_tray else []

    def save(self, path: Path) -> None:
        payload = {
            "version": self.version,
            "app_pid": self.app_pid,
            "app_dir": str(self.app_dir),
            "source_dir": str(self.source_dir),
            "work_dir": str(self.work_dir),
            "exe_name": self.exe_name,
            "start_in_tray": self.start_in_tray,
            "theme": self.theme,
            "accent": self.accent,
            "anchor": list(self.anchor) if self.anchor else None,
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "InstallPlan":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        anchor = data.get("anchor")
        return cls(
            version=str(data["version"]),
            app_pid=int(data["app_pid"]),
            app_dir=Path(data["app_dir"]),
            source_dir=Path(data["source_dir"]),
            work_dir=Path(data["work_dir"]),
            exe_name=str(data.get("exe_name") or APP_EXE_NAME),
            start_in_tray=bool(data.get("start_in_tray", False)),
            theme=str(data.get("theme") or "system"),
            accent=str(data.get("accent") or ""),
            anchor=tuple(int(value) for value in anchor) if anchor and len(anchor) == 4 else None,
        )
