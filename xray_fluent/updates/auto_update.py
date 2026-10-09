"""Фоновая автоустановка: учёт попыток, возврат подключения и уборка мусора.

Обновление ставится без участия пользователя, поэтому единственное, что
отделяет неудачную сборку от бесконечного цикла «скачать → перезапуск →
откат → снова скачать», — запись о попытке в ``data/runtime``. Каталог
``data/`` переживает замену файлов, поэтому новая (или откатившаяся старая)
версия на старте видит, чем закончилась попытка, и решает, пробовать ли снова.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from ..constants import RUNTIME_DIR
from .app_updater import _is_newer_version, _parse_semver
from .installer.file_swap import STAGE_ROOT_NAME
from .installer.plan import WORK_DIR_PREFIX

_log = logging.getLogger(__name__)

ATTEMPT_FILE = RUNTIME_DIR / "app_update_attempt.json"
# Одна и та же версия ставится автоматически не больше трёх раз; дальше —
# только кнопкой на странице «Обновления» (новый релиз сбрасывает счётчик).
MAX_AUTO_ATTEMPTS = 3
# Пауза после неудачной попытки растёт: 1 ч, 2 ч.
RETRY_BACKOFF_S = 60 * 60
# Возврат подключения относится только к перезапуску самого обновления, а не
# к ручному запуску приложения через день после сорвавшейся попытки.
RESUME_WINDOW_S = 15 * 60
# Из каталога загрузки работает установщик, поэтому свежие каталоги не трогаем.
TEMP_LEFTOVER_MIN_AGE_S = 10 * 60
# Вынесенные файлы, оставшиеся после отката с ошибками, — последняя копия
# прежней версии; держим её сутки на случай ручного восстановления.
BACKUP_LEFTOVER_MIN_AGE_S = 24 * 60 * 60
TEMP_PREFIX = WORK_DIR_PREFIX
# Каталоги резервных копий, которые создавали прежние версии установщика.
_LEGACY_BACKUP_DIRS = ("update_backups",)


@dataclass(slots=True)
class UpdateAttempt:
    version: str
    attempts: int
    last_attempt: float
    reconnect: bool
    resume_pending: bool = True
    # С какой версии шло обновление и когда сервер его разрешил: по ним новая
    # версия сообщит серверу, что обновление дошло и сколько оно заняло.
    from_version: str = ""
    granted_at: float = 0.0

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "attempts": self.attempts,
            "last_attempt": self.last_attempt,
            "reconnect": self.reconnect,
            "resume_pending": self.resume_pending,
            "from_version": self.from_version,
            "granted_at": self.granted_at,
        }


@dataclass(slots=True)
class StartupOutcome:
    """Итог предыдущей попытки, увиденный на старте.

    ``resume`` — было ли подключение до перезапуска (``None``: решать как
    обычно, по настройке автоподключения).
    """

    updated: bool
    version: str
    attempts: int
    resume: bool | None
    # Что сказать серверу, который раздаёт версию по ступеням: «дошла, с
    # такой-то версии, за столько-то секунд» либо «не вышло». Пусто — нечего.
    report: dict | None = None


def load_attempt(path: Path = ATTEMPT_FILE) -> UpdateAttempt | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return UpdateAttempt(
            version=str(data["version"]),
            attempts=max(1, int(data.get("attempts", 1))),
            last_attempt=float(data.get("last_attempt", 0.0)),
            reconnect=bool(data.get("reconnect", False)),
            resume_pending=bool(data.get("resume_pending", False)),
            from_version=str(data.get("from_version") or ""),
            granted_at=max(float(data.get("granted_at") or 0.0), 0.0),
        )
    except FileNotFoundError:
        return None
    except (OSError, ValueError, KeyError, TypeError):
        _log.warning("Unreadable update attempt record, discarding", exc_info=True)
        _remove(path)
        return None


def _write_attempt(record: UpdateAttempt, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(record.to_dict()), encoding="utf-8")
    os.replace(tmp, path)


def _remove(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        _log.warning("Failed to remove %s", path, exc_info=True)


def record_attempt(
    version: str,
    *,
    reconnect: bool,
    restarting: bool = True,
    now: float | None = None,
    path: Path = ATTEMPT_FILE,
    from_version: str = "",
    granted_at: float = 0.0,
) -> UpdateAttempt:
    """Записать попытку установки.

    ``restarting=True`` — непосредственно перед запуском установщика: следующий
    старт вернёт подключение. ``False`` — архив отвергнут ещё до установки
    (битая сумма или содержимое): попытка засчитывается, чтобы неисправный
    релиз не скачивался каждые полчаса, но перезапуска не было.
    """

    previous = load_attempt(path)
    attempts = previous.attempts + 1 if previous and previous.version == version else 1
    record = UpdateAttempt(
        version=version,
        attempts=attempts,
        last_attempt=time.time() if now is None else now,
        reconnect=reconnect,
        resume_pending=restarting,
        from_version=str(from_version or ""),
        granted_at=max(float(granted_at or 0.0), 0.0),
    )
    _write_attempt(record, path)
    return record


def resolve_startup(
    current_version: str,
    *,
    now: float | None = None,
    path: Path = ATTEMPT_FILE,
) -> StartupOutcome | None:
    """Разобрать запись о попытке после перезапуска.

    Успех определяется только версией запущенной сборки: наличие или
    отсутствие ``update_error.log`` ничего не доказывает (установщик мог
    «успешно» поставить сборку, которая всё ещё сообщает старую версию).
    """

    record = load_attempt(path)
    if record is None:
        return None
    if _parse_semver(record.version) is None or _parse_semver(current_version) is None:
        _remove(path)
        return None

    moment = time.time() if now is None else now
    resume: bool | None = None
    if record.resume_pending and 0 <= moment - record.last_attempt <= RESUME_WINDOW_S:
        resume = record.reconnect

    if not _is_newer_version(record.version, current_version):
        _remove(path)
        return StartupOutcome(True, record.version, record.attempts, resume, _success_report(record, current_version, moment))

    # Откат: счётчик остаётся, а возврат подключения и сообщение серверу о
    # неудаче расходуются один раз — на первом запуске после попытки.
    report = None
    if record.resume_pending:
        report = {"fail": record.version}
        record.resume_pending = False
        try:
            _write_attempt(record, path)
        except OSError:
            _log.warning("Failed to update update attempt record", exc_info=True)
    return StartupOutcome(False, record.version, record.attempts, resume, report)


# Дольше недели от разрешения до запуска — это уже не «время обновления».
_MAX_TOOK_S = 7 * 24 * 60 * 60


def _success_report(record: UpdateAttempt, current_version: str, moment: float) -> dict | None:
    """«Дошла»: с какой версии и за сколько секунд от разрешения сервера."""
    previous = record.from_version
    if not previous or _parse_semver(previous) is None or not _is_newer_version(current_version, previous):
        return None
    report = {"prev": previous}
    took = moment - record.granted_at
    if record.granted_at > 0 and 0 <= took <= _MAX_TOOK_S:
        report["took"] = str(int(took))
    return report


def auto_install_block_reason(
    version: str,
    current_version: str,
    *,
    now: float | None = None,
    path: Path = ATTEMPT_FILE,
) -> str:
    """Пустая строка — можно ставить без участия пользователя."""

    # _is_newer_version при нераспознанной версии сравнивает строки на
    # неравенство, то есть считает её «всегда новее» — для тихой установки
    # это вечный цикл перезапусков.
    if _parse_semver(version) is None or _parse_semver(current_version) is None:
        return "нераспознанная версия"
    if not _is_newer_version(version, current_version):
        return "версия не новее установленной"
    record = load_attempt(path)
    if record is None or record.version != version:
        return ""
    if record.attempts >= MAX_AUTO_ATTEMPTS:
        return f"установка не удалась уже {record.attempts} раза"
    moment = time.time() if now is None else now
    wait = RETRY_BACKOFF_S * (2 ** (record.attempts - 1)) - (moment - record.last_attempt)
    if wait > 0:
        return f"повтор после неудачной попытки через {max(1, int(wait // 60))} мин"
    return ""


def purge_update_leftovers(
    *,
    runtime_dir: Path = RUNTIME_DIR,
    temp_dir: Path | None = None,
    now: float | None = None,
) -> int:
    """Удалить брошенные каталоги прошлых обновлений. Вызывать не из GUI-потока."""

    moment = time.time() if now is None else now
    temp_root = Path(tempfile.gettempdir()) if temp_dir is None else temp_dir
    candidates: list[tuple[Path, float]] = []
    try:
        candidates += [
            (item, TEMP_LEFTOVER_MIN_AGE_S)
            for item in temp_root.glob(f"{TEMP_PREFIX}*")
            if item.is_dir()
        ]
    except OSError:
        pass
    for name in (STAGE_ROOT_NAME, *_LEGACY_BACKUP_DIRS):
        attempts = runtime_dir / name
        try:
            if attempts.is_dir():
                candidates += [(item, BACKUP_LEFTOVER_MIN_AGE_S) for item in attempts.iterdir()]
        except OSError:
            pass
    # Фиксированный каталог самых ранних версий установщика.
    legacy = runtime_dir / "update_backup"
    if legacy.exists():
        candidates.append((legacy, BACKUP_LEFTOVER_MIN_AGE_S))

    removed = 0
    for item, min_age in candidates:
        try:
            age = moment - item.stat().st_mtime
        except OSError:
            continue
        if age < min_age:
            continue
        if item.is_dir():
            shutil.rmtree(item, ignore_errors=True)
        else:
            _remove(item)
        if not item.exists():
            removed += 1
    return removed
