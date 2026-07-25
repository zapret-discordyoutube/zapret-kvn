from __future__ import annotations

from dataclasses import dataclass, replace
import json
import os
from pathlib import Path
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class SingboxConfigRepair:
    repaired_text: str
    description: str
    backup_path: Path | None = None

    def notice(self, source_name: str) -> str:
        message = f"{source_name}: конфиг sing-box восстановлен автоматически — {self.description}."
        if self.backup_path is not None:
            message += f" Исходный текст сохранён в {self.backup_path.name}."
        return message


def try_repair_singbox_config_text(text: str) -> SingboxConfigRepair | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None

    changes: list[str] = []
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            return None
        changes.append("убраны внешние кавычки и экранирование")

    if isinstance(payload, list):
        if len(payload) != 1 or not isinstance(payload[0], dict):
            return None
        payload = payload[0]
        changes.append("убраны внешние квадратные скобки")

    if not isinstance(payload, dict) or not changes:
        return None

    return SingboxConfigRepair(
        repaired_text=json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        description="; ".join(changes),
    )


def repair_singbox_config_file(path: Path, text: str) -> SingboxConfigRepair | None:
    repair = try_repair_singbox_config_text(text)
    if repair is None:
        return None

    backup_path = _write_recovery_backup(path, text)
    temporary_path = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        temporary_path.write_text(repair.repaired_text, encoding="utf-8")
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)
    return replace(repair, backup_path=backup_path)


def _write_recovery_backup(path: Path, text: str) -> Path:
    for index in range(1000):
        suffix = ".invalid.bak" if index == 0 else f".invalid.{index}.bak"
        backup_path = path.with_name(f"{path.name}{suffix}")
        try:
            with backup_path.open("x", encoding="utf-8") as handle:
                handle.write(text)
        except FileExistsError:
            continue
        return backup_path
    raise OSError(f"Не удалось подобрать имя резервной копии для {path.name}")
