"""Замена файлов установленной копии: сравнение, подготовка, коммит, откат.

Каталоги целиком не переименовываются никогда. Windows отказывает в
переименовании каталога, пока внутри открыт хотя бы один файл, и одного
антивируса или не выгруженного драйвера хватало, чтобы сорвать всё
обновление. Отдельный файл переименовывается почти всегда, поэтому замена
идёт пофайлово и только для того, что действительно изменилось:

1. ``prepare`` сравнивает новую сборку с установленной и копирует изменённые
   файлы в ``data/runtime/app_update/<id>/new`` — на тот же том, рядом с
   приложением. Установленная копия при этом не затрагивается.
2. ``commit`` выносит заменяемые и лишние файлы в ``…/old`` и ставит на их
   место подготовленные. Это одни переименования; каждое записано в журнал.
3. ``rollback`` проходит журнал в обратном порядке и возвращает всё как было.
"""

from __future__ import annotations

import errno
import hashlib
import os
import shutil
import time
from pathlib import Path
from typing import Callable

# Пользовательские данные: обновление их не читает и не меняет.
PRESERVED_NAMES = frozenset({"data"})
STAGE_ROOT_NAME = "app_update"

_CHUNK = 1024 * 1024
_FREE_SPACE_MARGIN = 32 * 1024 * 1024
_RETRY_PAUSE_S = 0.25


class InstallError(Exception):
    """Установка невозможна; ``path`` — файл, на котором она остановилась."""

    def __init__(self, message: str, *, path: Path | None = None):
        super().__init__(message)
        self.path = path


def stage_root_for(app_dir: Path) -> Path:
    return app_dir / "data" / "runtime" / STAGE_ROOT_NAME


def _scan(root: Path) -> dict[str, Path]:
    """Файлы дерева по относительному пути (регистр — как принято в ОС)."""

    files: dict[str, Path] = {}
    for current, dir_names, file_names in os.walk(root):
        if Path(current) == root:
            dir_names[:] = [name for name in dir_names if name.lower() not in PRESERVED_NAMES]
        for name in file_names:
            path = Path(current) / name
            files[os.path.normcase(str(path.relative_to(root)))] = path
    return files


def _sha256(path: Path) -> bytes:
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        while chunk := file.read(_CHUNK):
            digest.update(chunk)
    return digest.digest()


def _same_content(left: Path, right: Path) -> bool:
    try:
        if left.stat().st_size != right.stat().st_size:
            return False
        return _sha256(left) == _sha256(right)
    except OSError:
        # Нечитаемый установленный файл считается изменённым: его заменят.
        return False


class FileSwap:
    def __init__(
        self,
        source_dir: Path,
        app_dir: Path,
        stage_id: str,
        *,
        lock_wait_s: float = 30.0,
        on_locked: Callable[[Path], None] | None = None,
    ):
        self._source_dir = source_dir
        self._app_dir = app_dir
        self._stage_dir = stage_root_for(app_dir) / stage_id
        self._new_dir = self._stage_dir / "new"
        self._old_dir = self._stage_dir / "old"
        self._lock_wait_s = lock_wait_s
        self._on_locked = on_locked
        self._wait_left = 0.0
        # Установленные файлы на вынос; True — файл заменяется новой версией
        # (без его выноса установка невозможна), False — он просто лишний.
        self._outgoing: list[tuple[Path, bool]] = []
        # Относительные пути подготовленных файлов.
        self._incoming: list[Path] = []
        # Выполненные переименования: (где файл сейчас, откуда он взят).
        self._journal: list[tuple[Path, Path]] = []
        self._created_dirs: list[Path] = []
        self.unchanged = 0
        self.replaced = 0
        self.added = 0
        self.removed = 0
        # Лишние файлы, которые не удалось убрать: на работу новой версии они
        # не влияют, поэтому установку не останавливают.
        self.left_behind: list[Path] = []

    @property
    def stage_dir(self) -> Path:
        return self._stage_dir

    # ── подготовка ──────────────────────────────────────────────

    def prepare(self, progress: Callable[[float], None] | None = None) -> None:
        report = progress or (lambda fraction: None)
        source = _scan(self._source_dir)
        if not source:
            raise InstallError("В архиве обновления нет файлов")
        installed = _scan(self._app_dir)

        total = sum(path.stat().st_size for path in source.values()) or 1
        done = 0
        to_stage: list[tuple[Path, Path]] = []
        replaced_keys: set[str] = set()
        for key, new_file in source.items():
            current = installed.get(key)
            if current is not None and _same_content(new_file, current):
                self.unchanged += 1
            else:
                to_stage.append((new_file, new_file.relative_to(self._source_dir)))
                if current is not None:
                    replaced_keys.add(key)
            done += new_file.stat().st_size
            report(0.5 * done / total)

        for key, current in installed.items():
            if key in replaced_keys:
                self._outgoing.append((current, True))
            elif key not in source:
                self._outgoing.append((current, False))
        self.replaced = len(replaced_keys)
        self.added = len(to_stage) - self.replaced
        self.removed = len(self._outgoing) - self.replaced

        stage_bytes = sum(path.stat().st_size for path, _ in to_stage)
        self._require_free_space(stage_bytes)
        shutil.rmtree(self._stage_dir, ignore_errors=True)
        self._new_dir.mkdir(parents=True, exist_ok=True)
        self._old_dir.mkdir(parents=True, exist_ok=True)
        done = 0
        for new_file, relative in to_stage:
            staged = self._new_dir / relative
            staged.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(new_file, staged)
            self._incoming.append(relative)
            done += new_file.stat().st_size
            report(0.5 + 0.5 * done / (stage_bytes or 1))
        report(1.0)

    def _require_free_space(self, needed: int) -> None:
        try:
            free = shutil.disk_usage(self._app_dir).free
        except OSError:
            return
        if free < needed + _FREE_SPACE_MARGIN:
            raise InstallError(
                "Недостаточно места на диске: нужно "
                f"{(needed + _FREE_SPACE_MARGIN) // (1024 * 1024)} МБ, "
                f"свободно {free // (1024 * 1024)} МБ"
            )

    # ── замена ──────────────────────────────────────────────────

    def commit(self) -> None:
        self._wait_left = self._lock_wait_s
        for current, required in self._outgoing:
            relative = current.relative_to(self._app_dir)
            try:
                self._move(current, self._old_dir / relative)
            except FileNotFoundError:
                continue
            except OSError as error:
                if required:
                    raise InstallError(
                        f"Файл занят другой программой: {relative}", path=current
                    ) from error
                self.left_behind.append(current)
                continue
            self._journal.append((self._old_dir / relative, current))

        for relative in self._incoming:
            target = self._app_dir / relative
            try:
                self._make_room(target)
                self._move(self._new_dir / relative, target)
            except OSError as error:
                raise InstallError(
                    f"Не удалось записать файл: {relative} ({error})", path=target
                ) from error
            self._journal.append((target, self._new_dir / relative))

        self._prune_emptied_dirs()

    def _make_room(self, target: Path) -> None:
        missing = [parent for parent in target.parents if not parent.exists()]
        target.parent.mkdir(parents=True, exist_ok=True)
        self._created_dirs.extend(reversed(missing))
        self._remove_empty_tree(target)

    @staticmethod
    def _remove_empty_tree(target: Path) -> None:
        """Убрать каталог, занявший место файла; файлы из него уже вынесены."""

        if not target.is_dir():
            return
        for current, dir_names, _ in os.walk(target, topdown=False):
            for name in dir_names:
                os.rmdir(Path(current) / name)
        os.rmdir(target)

    def _move(self, source: Path, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        announced = False
        while True:
            try:
                os.replace(source, destination)
                return
            except FileNotFoundError:
                raise
            except OSError as error:
                if error.errno == errno.EXDEV:
                    # data/ вынесен на другой том: переименование невозможно.
                    shutil.copy2(source, destination)
                    os.unlink(source)
                    return
                if not announced and self._on_locked is not None:
                    announced = True
                    self._on_locked(source)
                if self._wait_left <= 0:
                    raise
                time.sleep(_RETRY_PAUSE_S)
                self._wait_left -= _RETRY_PAUSE_S

    def _prune_emptied_dirs(self) -> None:
        parents = {
            parent
            for current, _ in self._outgoing
            for parent in current.parents
            if parent != self._app_dir and self._app_dir in parent.parents
        }
        for parent in sorted(parents, key=lambda item: len(item.parts), reverse=True):
            try:
                os.rmdir(parent)
            except OSError:
                pass

    # ── откат и уборка ──────────────────────────────────────────

    def rollback(self) -> list[str]:
        """Вернуть установленную копию к исходному виду; вернуть список сбоев."""

        self._wait_left = self._lock_wait_s
        errors: list[str] = []
        for current, origin in reversed(self._journal):
            try:
                self._remove_empty_tree(origin)
                self._move(current, origin)
            except OSError as error:
                errors.append(f"{origin}: {error}")
        self._journal.clear()
        for created in reversed(self._created_dirs):
            try:
                os.rmdir(created)
            except OSError:
                pass
        self._created_dirs.clear()
        return errors

    def discard(self) -> None:
        """Удалить подготовленные и вынесенные файлы этой попытки."""

        shutil.rmtree(self._stage_dir, ignore_errors=True)
        try:
            os.rmdir(self._stage_dir.parent)
        except OSError:
            pass
