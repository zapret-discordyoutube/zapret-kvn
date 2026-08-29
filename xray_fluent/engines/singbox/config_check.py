"""Проверка конфигурации ядром до запуска процесса.

Без этой проверки единственным признаком негодного конфига был вывод самого
ядра: строка с ANSI-кодами вида ``[31mFATAL[0m[0000] decode config at ...``,
после которой процесс просто останавливался. Пользователь видел «не
запускается», а какое поле не понравилось ядру — приходилось вычитывать из лога.
"""

from __future__ import annotations

from pathlib import Path
import re


ANSI_ESCAPE = re.compile(r"\x1b?\[[0-9;]*m")

#: `outbounds[0].Tag: json: unknown field "Tag"` — путь к полю и его имя.
UNKNOWN_FIELD = re.compile(
    r"(?P<path>[\w\[\]\.]*?):?\s*json: unknown field \"(?P<field>[^\"]+)\""
)
DECODE_PREFIX = re.compile(r"^.*?decode config at [^:]*:\s*", re.S)


def strip_ansi(text: str) -> str:
    """Убрать управляющие последовательности, которыми ядро красит вывод."""

    return ANSI_ESCAPE.sub("", text).replace("\x1b", "")


def describe_config_failure(output: str) -> str:
    """Превратить вывод ядра в объяснение для пользователя."""

    text = strip_ansi(str(output or "")).strip()
    if not text:
        return "Ядро не приняло конфигурацию и не объяснило причину."
    first_line = text.splitlines()[0].strip()
    body = DECODE_PREFIX.sub("", first_line).strip() or first_line

    unknown = UNKNOWN_FIELD.search(body)
    if unknown:
        field = unknown.group("field")
        path = unknown.group("path").strip(". ")
        location = _location(path, field)
        return (
            f"Ядро не знает поле «{field}» {location}. "
            "Оно не входит в схему sing-box: уберите его из конфигурации "
            "или исправьте написание."
        )
    return f"Ядро не приняло конфигурацию: {body}"


def _location(path: str, field: str) -> str:
    """Описать, где именно лежит поле, по пути из сообщения ядра."""

    trimmed = path
    if trimmed.endswith(field):
        trimmed = trimmed[: -len(field)].strip(". ")
    if not trimmed:
        return "в корне конфигурации"
    return f"в «{trimmed}»"


def check_config(exe: Path, config_path: Path, *, timeout: float = 15.0) -> tuple[bool, str]:
    """Спросить ядро, годится ли конфигурация. Возвращает (ок, объяснение)."""

    from ...subprocess_utils import result_output_text, run_text_pumped

    try:
        result = run_text_pumped(
            [str(exe), "check", "-D", str(exe.parent), "-c", str(config_path)],
            timeout=timeout,
        )
    except Exception as exc:  # ядро может отсутствовать или не запуститься
        return True, f"Проверка конфигурации не выполнена: {type(exc).__name__}: {exc}"
    if result.returncode == 0:
        return True, ""
    return False, describe_config_failure(result_output_text(result))
