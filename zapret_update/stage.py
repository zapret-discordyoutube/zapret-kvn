"""Пробное дерево новой версии рядом с программой.

Дерево — полная копия поставки новой версии: неизменившиеся файлы ставятся
жёсткими ссылками на файлы программы (мгновенно и без лишнего места на
диске; если ссылку сделать нельзя — копией), скачанные — переносятся из
рабочей папки. Из этого дерева запускается новая версия, которая сама ставит
себя (замена по файлам с откатом). Дерево лежит на том же диске, что и
программа, поэтому перенос — это переименование.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from .manifest import file_sha256, safe_relative_path
from .plan import UpdatePlan


class StageError(OSError):
    code = "stage"


def _place(source: Path, target: Path, *, move: bool) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.unlink()
    if move:
        os.replace(source, target)
        return
    try:
        os.link(source, target)
    except OSError:
        shutil.copy2(source, target)


def build_stage(plan: UpdatePlan, *, root: Path, ready: dict[str, Path], stage_dir: Path) -> Path:
    """Собирает дерево версии ``plan.version`` в ``stage_dir`` и проверяет его."""
    tree = Path(stage_dir)
    if tree.exists():
        shutil.rmtree(tree)
    tree.mkdir(parents=True)
    base = Path(root)
    for entry in plan.keep:
        relative = safe_relative_path(entry.path).split("/")
        _place(base.joinpath(*relative), tree.joinpath(*relative), move=False)
    for want in plan.want:
        source = ready.get(want.entry.sha256)
        if source is None:
            raise StageError(f"не скачан {want.entry.path}")
        target = tree.joinpath(*safe_relative_path(want.entry.path).split("/"))
        # Один и тот же файл может стоять в выпуске по нескольким путям.
        shared = sum(1 for other in plan.want if other.entry.sha256 == want.entry.sha256) > 1
        _place(source, target, move=not shared)
    for entry in [*plan.keep, *(item.entry for item in plan.want)]:
        path = tree.joinpath(*safe_relative_path(entry.path).split("/"))
        if not path.is_file() or path.stat().st_size != entry.size:
            raise StageError(f"в пробном дереве не тот файл: {entry.path}")
    # Скачанные файлы уже проверены при распаковке; ссылки — проверяем, файл
    # программы мог измениться, пока шло скачивание.
    for entry in plan.keep:
        path = tree.joinpath(*safe_relative_path(entry.path).split("/"))
        if file_sha256(path) != entry.sha256:
            raise StageError(f"файл программы изменился во время обновления: {entry.path}")
    return tree


__all__ = ["StageError", "build_stage"]
