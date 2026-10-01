"""Передача экрана от окна обновления главному окну приложения.

Установщик запускает приложение раньше, чем закрывает своё окно: иначе не
узнать, что новая версия вообще способна стартовать. Чтобы два окна не
оказались на экране одновременно, приложение стартует «за кулисами»:

* установщик создаёт файл-замок и передаёт его путь в переменной окружения;
* приложение, собрав оболочку, создаёт рядом файл готовности и не показывает
  окно, пока замок существует;
* установщик закрывает окно обновления и удаляет замок.

Переменная окружения, а не аргумент командной строки: при откате запускается
прежняя сборка, и незнакомый аргумент она бы не пережила.
"""

from __future__ import annotations

import os
from pathlib import Path

HOLD_ENV = "ZAPRETKVN_UPDATE_HOLD"
# Если установщик исчез, не сняв замок, приложение показывается само.
MAX_HOLD_S = 20.0


def ready_marker(hold: Path) -> Path:
    return hold.with_name(hold.name + ".ready")


# ── сторона установщика ─────────────────────────────────────────


def arm(hold: Path) -> dict[str, str]:
    """Поставить замок; вернуть окружение для запускаемого приложения."""

    hold.parent.mkdir(parents=True, exist_ok=True)
    ready_marker(hold).unlink(missing_ok=True)
    hold.write_text("hold", encoding="utf-8")
    return {HOLD_ENV: str(hold)}


def is_ready(hold: Path) -> bool:
    return ready_marker(hold).exists()


def release(hold: Path) -> None:
    for path in (hold, ready_marker(hold)):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


# ── сторона приложения ──────────────────────────────────────────


def claim() -> Path | None:
    """Замок, под которым запущено приложение (None — обычный запуск)."""

    return claim_from(os.environ)


def claim_from(environment) -> Path | None:
    # pop: переменная не должна достаться ядрам и другим дочерним процессам.
    value = environment.pop(HOLD_ENV, "")
    if not value:
        return None
    hold = Path(value)
    return hold if hold.exists() else None


def confirm_ready(hold: Path) -> None:
    try:
        ready_marker(hold).write_text("ready", encoding="utf-8")
    except OSError:
        pass
