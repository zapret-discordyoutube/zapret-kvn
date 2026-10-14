"""Сборка хранилища выпуска на машине сборки (Python 3.14).

Берёт раскладку установленной программы (путь в программе → файл сборки),
сжимает каждый новый файл один раз и делает заплатки для больших файлов,
изменившихся с прежних версий. Всё складывается в ``cache_dir`` под именами
хранилища (``store``); кэш живёт между выпусками, поэтому не изменившиеся
файлы второй раз не сжимаются.

Прежний файл для заплатки берётся из кэша, а если его там нет — через
``read_old(sha256, size)`` (сборка качает его из хранилища и проверяет).
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from . import store
from .manifest import Manifest, file_sha256, safe_relative_path

# Заплатка нужна, только если она заметно меньше файла целиком.
PATCH_WORTH_SHARE = 0.8


@dataclass
class StoreBuild:
    files: list[dict] = field(default_factory=list)
    patches: list[dict] = field(default_factory=list)
    # Имена файлов хранилища, на которые ссылается выпуск (все лежат в кэше).
    names: set[str] = field(default_factory=set)
    # Сколько файлов сжато и заплаток сделано заново в этот раз.
    compressed: int = 0
    patched: int = 0


def _write_atomic(path: Path, data: bytes) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def _cached_blob(cache_dir: Path, sha256: str) -> Path:
    return cache_dir / store.blob_name(sha256)


def _old_bytes(cache_dir: Path, sha256: str, size: int, read_old) -> bytes | None:
    cached = _cached_blob(cache_dir, sha256)
    if cached.is_file():
        try:
            return store.unpack_blob(cached.read_bytes(), sha256=sha256, size=size)
        except store.StoreError:
            cached.unlink(missing_ok=True)
    return read_old(sha256, size) if read_old is not None else None


def build_store(
    *,
    layout: Mapping[str, Path],
    cache_dir: Path,
    previous: Iterable[Manifest] = (),
    read_old: Callable[[str, int], bytes | None] | None = None,
    log: Callable[[str], None] = lambda _message: None,
) -> StoreBuild:
    """Файлы выпуска с ``zsize`` и заплатки; файлы хранилища — в ``cache_dir``."""
    cache = Path(cache_dir)
    cache.mkdir(parents=True, exist_ok=True)
    result = StoreBuild()
    earlier = list(previous)[: store.PATCH_FROM_VERSIONS]

    for relative in sorted(layout):
        source = Path(layout[relative])
        path = safe_relative_path(relative)
        size = source.stat().st_size
        sha256 = file_sha256(source)
        blob = _cached_blob(cache, sha256)
        if not blob.is_file():
            _write_atomic(blob, store.compress(source.read_bytes()))
            result.compressed += 1
        zsize = blob.stat().st_size
        result.files.append({"path": path, "size": size, "sha256": sha256, "zsize": zsize})
        result.names.add(blob.name)

        if size < store.PATCH_MIN_SIZE:
            continue
        bases = []
        for manifest in earlier:
            old = next((entry for entry in manifest.files if entry.path == path), None)
            if old is not None and old.sha256 != sha256 and old.sha256 not in {base.sha256 for base in bases}:
                bases.append(old)
        new_bytes: bytes | None = None
        for base in bases:
            name = store.patch_name(base.sha256, sha256)
            patch_path = cache / name
            if not patch_path.is_file():
                old_bytes = _old_bytes(cache, base.sha256, base.size, read_old)
                if old_bytes is None:
                    log(f"заплатка для {path} от {base.sha256[:12]} не сделана: прежнего файла нет")
                    continue
                if new_bytes is None:
                    new_bytes = source.read_bytes()
                _write_atomic(patch_path, store.make_patch(old_bytes, new_bytes))
                result.patched += 1
            patch_size = patch_path.stat().st_size
            if patch_size < zsize * PATCH_WORTH_SHARE:
                result.patches.append({"from": base.sha256, "to": sha256, "size": patch_size})
                result.names.add(name)
    return result


def prune_cache(cache_dir: Path, keep: Iterable[str]) -> int:
    """Убирает из кэша файлы, на которые не ссылаются последние выпуски."""
    wanted = set(keep)
    removed = 0
    for path in Path(cache_dir).glob("*.zst"):
        if path.name not in wanted:
            path.unlink(missing_ok=True)
            removed += 1
    return removed


__all__ = ["StoreBuild", "build_store", "prune_cache"]
