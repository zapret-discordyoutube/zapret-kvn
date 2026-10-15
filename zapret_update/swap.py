"""Замена файлов программы: подготовка, замена, откат — с журналом на диске.

Основа — замена из Zapret KVN, проверенная на живых обновлениях. Каталоги
целиком не переименовываются никогда: Windows не даёт переименовать каталог,
пока внутри открыт хоть один файл, и одного антивируса хватало, чтобы сорвать
всё обновление. Отдельный файл переименовывается почти всегда, поэтому
замена идёт пофайлово и только для изменившегося:

1. ``prepare`` сравнивает пробное дерево новой версии с программой и копирует
   изменённые файлы в ``<рабочая папка>/new`` — на тот же диск. Программа при
   этом не затрагивается.
2. ``commit`` выносит лишние файлы в ``<рабочая папка>/old``, а каждый
   заменяемый — парой «прежний в ``old`` → сразу новый на его место»: без
   exe программа остаётся на одно переименование, а не на всю замену. Это
   одни переименования; каждое сразу пишется в журнал ``journal.json`` вместе
   с размером и временем файла.
3. ``rollback`` проходит журнал в обратном порядке. Что вернуть не вышло
   (файл держит антивирус), остаётся в журнале — откат можно повторить, и
   уборка не сотрёт последнюю копию прежней версии. Журнал на диске: если
   питание пропало посреди замены, ``recover`` вернёт всё при следующем
   запуске; файл, который с тех пор заменили (переустановка), не трогается.

Чужого замена не трогает: убираются только файлы прежней версии, которые
поставила сама программа (``remove``), а папки из ``preserve`` (настройки и
данные человека) не читаются и не меняются.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import time
from collections.abc import Callable, Iterable
from pathlib import Path

JOURNAL_NAME = "journal.json"
_CHUNK = 1024 * 1024
_FREE_SPACE_MARGIN = 32 * 1024 * 1024
_RETRY_PAUSE_S = 0.25


# Запись журнала: где файл сейчас, где был, его размер и время изменения
# (None — журнал прежнего вида, без них).
Entry = tuple[Path, Path, "tuple[int, int] | None"]


class InstallError(Exception):
    """Установка невозможна; ``path`` — файл, на котором она остановилась."""

    def __init__(self, message: str, *, path: Path | None = None) -> None:
        super().__init__(message)
        self.path = path


def _scan(root: Path, preserve: frozenset[str]) -> dict[str, Path]:
    """Файлы дерева по относительному пути (регистр — как принято в ОС)."""
    files: dict[str, Path] = {}
    for current, dir_names, file_names in os.walk(root):
        if Path(current) == root:
            dir_names[:] = [name for name in dir_names if name.casefold() not in preserve]
        for name in file_names:
            path = Path(current) / name
            files[os.path.normcase(str(path.relative_to(root)))] = path
    return files


def _sha256(path: Path) -> bytes:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
    return digest.digest()


def _same_content(left: Path, right: Path) -> bool:
    try:
        if left.stat().st_size != right.stat().st_size:
            return False
        if os.path.samefile(left, right):
            return True  # жёсткая ссылка пробного дерева на этот же файл
        return _sha256(left) == _sha256(right)
    except OSError:
        # Нечитаемый файл программы считается изменённым: его заменят.
        return False


class FileSwap:
    def __init__(
        self,
        source_dir: Path,
        app_dir: Path,
        work_dir: Path,
        *,
        preserve: Iterable[str] = (),
        remove: Iterable[str] | None = None,
        keep: Iterable[str] = (),
        lock_wait_s: float = 30.0,
        on_locked: Callable[[Path], None] | None = None,
    ) -> None:
        """``remove`` — пути прежней версии, которых нет в новой (``None`` —
        считать лишним всё в папке программы, чего нет в новой, кроме
        ``preserve``). ``keep`` — папки поставки (через «/»), куда человек
        кладёт свои файлы рядом с её файлами (пресеты): поставку в них новая
        версия меняет, но чужого не убирает."""
        self._source_dir = Path(source_dir)
        self._app_dir = Path(app_dir)
        self._work_dir = Path(work_dir)
        self._new_dir = self._work_dir / "new"
        self._old_dir = self._work_dir / "old"
        self._preserve = frozenset(name.casefold() for name in preserve)
        self._remove = None if remove is None else [str(item) for item in remove]
        self._keep = tuple(os.path.normcase(str(Path(*str(item).split("/")))) + os.sep for item in keep)
        self._lock_wait_s = lock_wait_s
        self._on_locked = on_locked
        self._wait_left = 0.0
        self._outgoing: list[tuple[Path, bool]] = []
        self._incoming: list[Path] = []
        self._journal: list[Entry] = []
        self._created_dirs: list[Path] = []
        self.unchanged = 0
        self.replaced = 0
        self.added = 0
        self.removed = 0
        self.left_behind: list[Path] = []

    @property
    def work_dir(self) -> Path:
        return self._work_dir

    # ── подготовка ──────────────────────────────────────────────

    def prepare(self, progress: Callable[[float], None] | None = None) -> None:
        report = progress or (lambda fraction: None)
        # Прошлая попытка в этой же папке могла не вернуть всё: тогда в ``old``
        # лежит единственная копия прежней версии — вернуть её до сравнения.
        leftover = recover(self._work_dir)
        if leftover:
            raise InstallError("Прошлое обновление не откачено до конца: " + "; ".join(leftover))
        # Папки данных человека новая версия не несёт, а если несёт (Zapret KVN
        # кладёт в архив data/ с шаблонами), то не трогает: шаблоны программа
        # переносит сама при запуске.
        source = _scan(self._source_dir, self._preserve)
        if not source:
            raise InstallError("В новой версии нет файлов")
        skipped = set(self._preserve)
        try:
            # Рабочая папка обновления внутри программы — не часть программы.
            skipped.add(self._work_dir.resolve().relative_to(self._app_dir.resolve()).parts[0].casefold())
        except (ValueError, IndexError):
            pass
        installed = _scan(self._app_dir, frozenset(skipped))

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

        if self._remove is None:
            extra = [key for key in installed if key not in source]
        else:
            extra = [os.path.normcase(str(Path(*item.split("/")))) for item in self._remove]
            extra = [key for key in extra if key in installed and key not in source]
        extra = [key for key in extra if not key.startswith(self._keep)]
        for key in replaced_keys:
            self._outgoing.append((installed[key], True))
        for key in extra:
            self._outgoing.append((installed[key], False))
        self.replaced = len(replaced_keys)
        self.added = len(to_stage) - self.replaced
        self.removed = len(extra)

        stage_bytes = sum(path.stat().st_size for path, _ in to_stage)
        self._require_free_space(stage_bytes)
        shutil.rmtree(self._new_dir, ignore_errors=True)
        shutil.rmtree(self._old_dir, ignore_errors=True)
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
        self._save_journal()
        # Сначала лишние файлы: среди них и содержимое каталога, на месте
        # которого в новой версии файл. Потом каждый заменяемый — парой.
        for current, required in self._outgoing:
            if not required:
                self._take_out(current, required)
        replacing = {current.relative_to(self._app_dir) for current, required in self._outgoing if required}
        for relative in self._incoming:
            if relative in replacing:
                self._take_out(self._app_dir / relative, True)
            target = self._app_dir / relative
            try:
                self._make_room(target)
                self._move(self._new_dir / relative, target)
            except OSError as error:
                raise InstallError(f"Не удалось записать файл: {relative} ({error})", path=target) from error
            self._record(target, self._new_dir / relative)

        self._prune_emptied_dirs()

    def _take_out(self, current: Path, required: bool) -> None:
        relative = current.relative_to(self._app_dir)
        try:
            self._move(current, self._old_dir / relative)
        except FileNotFoundError:
            return
        except OSError as error:
            if required:
                raise InstallError(f"Файл занят другой программой: {relative}", path=current) from error
            self.left_behind.append(current)
            return
        self._record(self._old_dir / relative, current)

    def _record(self, current: Path, origin: Path) -> None:
        self._journal.append((current, origin, _signature(current)))
        self._save_journal()

    def _save_journal(self) -> None:
        payload = {
            "app_dir": str(self._app_dir),
            "moves": [
                [str(current), str(origin), *(signature or ())] for current, origin, signature in self._journal
            ],
            "created_dirs": [str(path) for path in self._created_dirs],
        }
        self._work_dir.mkdir(parents=True, exist_ok=True)
        target = self._work_dir / JOURNAL_NAME
        temporary = target.with_name(target.name + ".tmp")
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)

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
        """Вернуть программу к исходному виду; вернуть список сбоев.

        Что вернуть не вышло, остаётся в журнале: повторный ``rollback`` или
        ``recover`` доделает именно это, а уборка не сотрёт ``old``.
        """
        self._wait_left = self._lock_wait_s
        errors, remaining = _undo(self._journal, self._created_dirs, self._move, self._remove_empty_tree)
        self._journal = remaining
        if not remaining:
            self._created_dirs.clear()
        self._save_journal()
        return errors

    def discard(self) -> None:
        """Удалить подготовленные и вынесенные файлы этой попытки вместе с журналом."""
        shutil.rmtree(self._work_dir, ignore_errors=True)


def _signature(path: Path) -> tuple[int, int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return stat.st_size, stat.st_mtime_ns


def _undo(journal, created_dirs, move, remove_empty_tree) -> tuple[list[str], list[Entry]]:
    """Пройти журнал назад. Вернуть сбои и записи, которые стоит повторить."""
    errors: list[str] = []
    remaining: list[Entry] = []
    stuck: set[Path] = set()  # где остался файл, который не удалось вынести
    for current, origin, signature in reversed(list(journal)):
        current, origin = Path(current), Path(origin)
        if not current.exists():
            continue  # шаг сделан прошлым откатом (или файла нет — повтор не поможет)
        if signature is not None and _signature(current) != signature:
            continue  # файл с тех пор заменили (переустановка) — не наш
        if origin.is_file():
            if origin in stuck:
                remaining.append((current, origin, signature))
                errors.append(f"{origin}: место занято файлом, который не удалось вынести")
            continue  # место занял чужой файл (переустановка) — не трогаем
        try:
            remove_empty_tree(origin)
            move(current, origin)
        except OSError as error:
            remaining.append((current, origin, signature))
            stuck.add(current)
            errors.append(f"{origin}: {error}")
    remaining.reverse()
    for created in reversed(list(created_dirs)):
        try:
            os.rmdir(created)
        except OSError:
            pass
    return errors, remaining


def _load_journal(journal_path: Path) -> tuple[Path, list[Entry], list[Path]] | None:
    try:
        payload = json.loads(journal_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    moves: list[Entry] = []
    for item in payload.get("moves") or ():
        signature = (int(item[2]), int(item[3])) if len(item) >= 4 else None
        moves.append((Path(item[0]), Path(item[1]), signature))
    app_dir = Path(payload.get("app_dir") or journal_path.parent)
    return app_dir, moves, [Path(item) for item in payload.get("created_dirs") or ()]


def pending(work_dir: Path) -> bool:
    """В журнале замены остались невозвращённые файлы: папку убирать нельзя."""
    loaded = _load_journal(Path(work_dir) / JOURNAL_NAME)
    return bool(loaded and loaded[1])


def recover(work_dir: Path) -> list[str] | None:
    """Откатить замену, оборванную на полпути (выключение, сбой).

    ``None`` — оборванной замены нет. Иначе — список сбоев отката (пустой —
    всё возвращено); журнал после этого убирается.
    """
    journal_path = Path(work_dir) / JOURNAL_NAME
    loaded = _load_journal(journal_path)
    if loaded is None:
        return None
    app_dir, moves, created_dirs = loaded
    if not moves:
        journal_path.unlink(missing_ok=True)
        return None
    swap = FileSwap(Path(work_dir), app_dir, Path(work_dir))
    swap._wait_left = 30.0
    errors, remaining = _undo(moves, created_dirs, swap._move, swap._remove_empty_tree)
    if remaining:
        # Повторять только то, что не вышло: сделанные шаги второй раз не идут.
        swap._journal, swap._created_dirs = remaining, created_dirs
        swap._save_journal()
    else:
        journal_path.unlink(missing_ok=True)
    return errors


__all__ = ["FileSwap", "InstallError", "JOURNAL_NAME", "pending", "recover"]
