"""Журналы для поддержки: что берётся, как редактируется, как кладётся в архив."""

from __future__ import annotations

import json
import platform
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..constants import APP_VERSION
from ..diagnostics.export import _redact_log_line

# Только эти файлы журналов попадают в архив: остальное в data/logs (например,
# дампы с чужими данными) без явного решения не берём.
SUPPORT_LOG_FILES = ("update.log", "update_error.log", "update_stall.log", "startup.log")
# С каждого файла берётся хвост: свежее важнее, а архив должен остаться маленьким.
MAX_TAIL_BYTES = 256 * 1024
SUPPORT_FORMAT = 1

_USER_PROFILE = re.compile(r"(?i)([A-Z]:[\\/]+Users[\\/]+)[^\\/\s\"']+")
_HOME_PROFILE = re.compile(r"(/(?:home|Users)/)[^/\s\"']+")
_LONG_SECRET = re.compile(r"(?i)\b(token|password|passwd|secret|key|uuid)\b(\s*[=:]\s*)[^\s\"',;]+")


def redact_support_text(text: str) -> str:
    """Журнал без ссылок, секретов и имени учётной записи Windows."""

    cleaned = _redact_log_line(text)
    cleaned = _USER_PROFILE.sub(r"\1<user>", cleaned)
    cleaned = _HOME_PROFILE.sub(r"\1<user>", cleaned)
    return _LONG_SECRET.sub(r"\1\2***", cleaned)


def _tail_text(path: Path) -> str | None:
    try:
        with path.open("rb") as stream:
            size = stream.seek(0, 2)
            stream.seek(max(0, size - MAX_TAIL_BYTES))
            data = stream.read()
    except OSError:
        return None
    text = data.decode("utf-8", "replace")
    if size > MAX_TAIL_BYTES:
        # Первая строка хвоста обрезана посередине: не выдавать её за целую.
        text = text.split("\n", 1)[-1]
    return text


@dataclass(slots=True)
class SupportBundle:
    path: Path
    included: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)


def append_support_files(
    zip_path: Path,
    log_dir: Path,
    *,
    mirror_tag: str = "",
    now: datetime | None = None,
) -> SupportBundle:
    """Дописать в архив ``diagnostics`` журналы установки/запуска и ``support.json``."""

    bundle = SupportBundle(Path(zip_path))
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    with zipfile.ZipFile(zip_path, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        existing = set(archive.namelist())
        for name in SUPPORT_LOG_FILES:
            text = _tail_text(Path(log_dir) / name)
            arcname = f"logs/{name}"
            if text is None or arcname in existing:
                bundle.missing.append(name)
                continue
            archive.writestr(arcname, "\n".join(redact_support_text(line) for line in text.splitlines()))
            bundle.included.append(name)
        archive.writestr(
            "support.json",
            json.dumps(
                {
                    "support_format": SUPPORT_FORMAT,
                    "app_version": APP_VERSION,
                    "created": stamp,
                    "platform": platform.platform(),
                    "python": platform.python_version(),
                    "mirror": mirror_tag,
                    "log_files": bundle.included,
                    "log_files_missing": bundle.missing,
                },
                ensure_ascii=False,
                indent=2,
            ),
        )
    return bundle
