"""Что скачать для новой версии: сравнение подписанного списка с диском.

Для каждого файла новой версии:

- на диске уже лежит файл с той же контрольной суммой — он остаётся;
- на диске прежняя версия файла и в хранилище есть заплатка от неё — качается
  самая маленькая из заплаток (если она меньше файла целиком);
- иначе качается файл целиком.

Контрольные суммы файлов на диске считаются один раз и запоминаются по
размеру и времени изменения (``HashCache``): повторная проверка после
сорвавшегося скачивания не перечитывает сотни мегабайт.

Файлы прежней версии, которых в новой нет, убираются, только если известно,
что их поставила программа (``installed`` — список установленной версии).
Без него лишнее остаётся на месте: чужого не трогаем.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .manifest import FileEntry, Manifest, PatchEntry, file_sha256, safe_relative_path
from . import store


class PlanError(ValueError):
    """По списку нельзя обновиться по файлам: нужен установщик целиком."""

    code = "plan"


@dataclass(frozen=True, slots=True)
class Want:
    entry: FileEntry
    patch: PatchEntry | None = None

    @property
    def name(self) -> str:
        if self.patch is not None:
            return store.patch_file_name(self.patch)
        return store.blob_name(self.entry.sha256)

    @property
    def download_size(self) -> int:
        return self.patch.size if self.patch is not None else self.entry.zsize


@dataclass
class UpdatePlan:
    version: str
    keep: list[FileEntry] = field(default_factory=list)
    want: list[Want] = field(default_factory=list)
    # Файлы прежней версии, которых нет в новой (пути внутри программы).
    remove: list[str] = field(default_factory=list)

    @property
    def download_size(self) -> int:
        return sum(item.download_size for item in self.want)


class HashCache:
    """Контрольные суммы файлов по пути, размеру и времени изменения."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path is not None else None
        self._items: dict[str, list] = {}
        if self._path is not None:
            try:
                loaded = json.loads(self._path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self._items = {str(k): v for k, v in loaded.items() if isinstance(v, list) and len(v) == 3}
            except (OSError, ValueError):
                self._items = {}

    def sha256(self, path: Path) -> str | None:
        try:
            info = path.stat()
        except OSError:
            return None
        if not path.is_file():
            return None
        key = str(path)
        known = self._items.get(key)
        if known and known[0] == info.st_size and known[1] == info.st_mtime_ns:
            return str(known[2])
        value = file_sha256(path)
        self._items[key] = [info.st_size, info.st_mtime_ns, value]
        return value

    def save(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_name(self._path.name + ".tmp")
        temporary.write_text(json.dumps(self._items), encoding="utf-8")
        os.replace(temporary, self._path)


def make_plan(
    new: Manifest,
    root: Path,
    *,
    installed: Manifest | None = None,
    hashes: HashCache | None = None,
) -> UpdatePlan:
    """План обновления папки ``root`` до версии ``new``."""
    if not new.files:
        raise PlanError("в списке выпуска нет файлов программы")
    missing_store = [entry.path for entry in new.files if not entry.zsize]
    if missing_store:
        raise PlanError(f"файлов выпуска нет в хранилище: {missing_store[0]}")
    cache = hashes or HashCache()
    base = Path(root)
    result = UpdatePlan(version=new.version)
    for entry in new.files:
        local = cache.sha256(base.joinpath(*safe_relative_path(entry.path).split("/")))
        if local == entry.sha256:
            result.keep.append(entry)
            continue
        patch = new.patch_for(local, entry.sha256) if local else None
        if patch is not None and patch.size < entry.zsize:
            result.want.append(Want(entry, patch))
        else:
            result.want.append(Want(entry))
    if installed is not None:
        wanted = {entry.path.casefold() for entry in new.files}
        result.remove = sorted(entry.path for entry in installed.files if entry.path.casefold() not in wanted)
    cache.save()
    return result


__all__ = ["HashCache", "PlanError", "UpdatePlan", "Want", "make_plan"]
