"""Preset files: the user's own winws2 command lines under ``zapret/presets``.

A preset is a text file of winws2 arguments, one per line, with a ``# Key:``
comment header (name, description, dates).  It configures site bypass and runs
on its own; the selected-server rule is added on top at launch time and never
written into the file.
"""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ...constants import BASE_DIR

log = logging.getLogger(__name__)

ZAPRET_DIR = BASE_DIR / "zapret"
PRESETS_DIR = ZAPRET_DIR / "presets"

#: Preset used when the user never picked one; falls back to any preset on disk.
DEFAULT_PRESET_NAME = "Default"

_HEADER_KEYS = ("Preset", "Description", "Created", "Modified", "BuiltinVersion")
_REWRITTEN_KEYS = ("Preset", "Description", "Created", "Modified")


@dataclass(frozen=True, slots=True)
class PresetInfo:
    name: str
    description: str
    created: str
    modified: str
    arg_count: int
    file_path: Path


def preset_path(name: str) -> Path:
    return PRESETS_DIR / f"{name}.txt"


def _is_preset_file(path: Path) -> bool:
    return path.suffix == ".txt" and not path.name.startswith("_")


def _argument_lines(text: str) -> list[str]:
    return [
        stripped for stripped in (line.strip() for line in text.splitlines())
        if stripped and not stripped.startswith("#")
    ]


def _header(text: str) -> dict[str, str]:
    """``# Key: value`` lines before the first argument."""

    meta: dict[str, str] = {}
    for line in text.splitlines()[:15]:
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith("#"):
            break
        for key in _HEADER_KEYS:
            prefix = f"# {key}:"
            if stripped.startswith(prefix):
                meta[key] = stripped[len(prefix):].strip()
                break
    return meta


def _info(path: Path, text: str) -> PresetInfo:
    meta = _header(text)
    return PresetInfo(
        name=path.stem,
        description=meta.get("Description", ""),
        created=meta.get("Created", ""),
        modified=meta.get("Modified", ""),
        arg_count=len(_argument_lines(text)),
        file_path=path,
    )


def list_presets() -> list[str]:
    if not PRESETS_DIR.is_dir():
        return []
    return sorted(path.stem for path in PRESETS_DIR.iterdir() if _is_preset_file(path))


def list_preset_infos() -> list[PresetInfo]:
    if not PRESETS_DIR.is_dir():
        return []
    result: list[PresetInfo] = []
    for path in sorted(PRESETS_DIR.iterdir()):
        if not _is_preset_file(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            # This runs while the window is built; one unreadable file must not
            # take the whole page down with it.
            log.warning("Не удалось прочитать пресет %s: %s", path.name, exc)
            continue
        result.append(_info(path, text))
    return result


def default_preset() -> str:
    """Preset a fresh install can connect with (``Default``, else any)."""

    if preset_path(DEFAULT_PRESET_NAME).is_file():
        return DEFAULT_PRESET_NAME
    available = list_presets()
    return available[0] if available else ""


def read_preset(name: str) -> str:
    path = preset_path(name)
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def preset_arguments(name: str) -> list[str]:
    """winws2 arguments of a preset (``@file`` can't take spaces in the path)."""

    return _argument_lines(preset_path(name).read_text(encoding="utf-8", errors="replace"))


def save_preset(name: str, content: str, description: str = "") -> PresetInfo:
    """Write a preset, refreshing its header and keeping the creation date."""

    path = preset_path(name)
    PRESETS_DIR.mkdir(parents=True, exist_ok=True)
    created = _header(path.read_text(encoding="utf-8", errors="replace")).get("Created", "") \
        if path.is_file() else ""
    now = datetime.now().isoformat(timespec="seconds")
    body = [
        line for line in content.splitlines()
        if not any(line.strip().startswith(f"# {key}:") for key in _REWRITTEN_KEYS)
    ]
    while body and not body[0].strip():
        body.pop(0)
    text = (
        f"# Preset: {name}\n# Description: {description}\n"
        f"# Created: {created or now}\n# Modified: {now}\n\n"
        + "\n".join(body) + "\n"
    )
    path.write_text(text, encoding="utf-8")
    return _info(path, text)


def rename_preset(old_name: str, new_name: str) -> PresetInfo | None:
    old_path, new_path = preset_path(old_name), preset_path(new_name)
    if not old_path.is_file() or new_path.exists():
        return None
    text = old_path.read_text(encoding="utf-8", errors="replace")
    text = text.replace(f"# Preset: {old_name}", f"# Preset: {new_name}", 1)
    new_path.write_text(text, encoding="utf-8")
    old_path.unlink()
    return _info(new_path, text)


def delete_preset(name: str) -> bool:
    path = preset_path(name)
    if not path.is_file():
        return False
    path.unlink()
    return True


def import_preset(source_path: Path) -> PresetInfo | None:
    """Copy a preset file in, numbering the name on conflicts."""

    if not source_path.is_file():
        return None
    PRESETS_DIR.mkdir(parents=True, exist_ok=True)
    target = preset_path(source_path.stem)
    counter = 1
    while target.exists():
        target = preset_path(f"{source_path.stem} ({counter})")
        counter += 1
    shutil.copy2(source_path, target)
    return _info(target, target.read_text(encoding="utf-8", errors="replace"))
