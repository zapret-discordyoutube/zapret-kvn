"""Core error evidence. Classification never replaces the original message.

runtime-errors.json is shared byte-for-byte with Android. Unknown core errors
remain visible and terminal; a parser must never invent a server diagnosis.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import time
from threading import RLock

from .runtime_logging import redact_runtime_log


_CATALOG = json.loads(Path(__file__).with_name("runtime-errors.json").read_text(encoding="utf-8"))

# One relayed connection failed because the authenticated server could not
# reach its destination (node network policy, dead site). The catalog marks it
# record_only for every engine on both platforms: it proves the tunnel is
# alive, so it must never start a transport failure episode or a failover.
DESTINATION_UNREACHABLE_CODE = "TARGET_DESTINATION_UNREACHABLE"
_RULES = tuple(
    (rule["code"], rule["action"], re.compile(rule["pattern"], re.IGNORECASE))
    for rule in _CATALOG["rules"]
)


@dataclass(frozen=True, slots=True)
class RuntimeFailure:
    component: str
    stage: str
    message: str
    code: str = "CORE_UNCLASSIFIED"
    action: str = "stop"
    session_generation: int = 0
    target_generation: int = 0
    target_id: str = ""


def classify_core_error(message: str) -> tuple[str, str]:
    for code, action, pattern in _RULES:
        if pattern.search(message):
            return code, action
    return _CATALOG["unknown_code"], "stop"


def core_failure(component: str, stage: str, message: str, **identity) -> RuntimeFailure:
    """Retain the core/OS message, removing only credentials and terminal escapes."""
    code, action = classify_core_error(message)
    return RuntimeFailure(component, stage, redact_runtime_log(message), code, action, **identity)


@dataclass(frozen=True, slots=True)
class RecordedRuntimeFailure:
    failure: RuntimeFailure
    first_seen: float
    last_seen: float
    occurrences: int = 1


# Журнал живёт всю сессию. Без предела каждая строка лога с новым временем,
# id соединения или портом становилась отдельной записью: у пользователей с
# «шумным» ядром журнал рос без конца, а весь снимок уходил в GUI на каждую
# строку — CPU и память росли с аптаймом.
MAX_JOURNAL_RECORDS = 300
_VOLATILE_DIGITS = re.compile(r"\d+")


def _grouping_key(failure: RuntimeFailure) -> tuple:
    """Одна запись на «ту же» ошибку: числа (время, id, порты) не различают."""
    return (
        failure.component, failure.stage, failure.code, failure.action,
        failure.session_generation, failure.target_generation, failure.target_id,
        _VOLATILE_DIGITS.sub("#", failure.message),
    )


class RuntimeErrorJournal:
    """Error evidence is independent of the bounded traffic/UI log.

    Записи группируются по ``_grouping_key`` (последний исходный текст
    сохраняется) и ограничены ``MAX_JOURNAL_RECORDS``: при переполнении
    вытесняется запись, которую дольше всех не видели. Порядок снимка —
    порядок первого появления.
    """

    def __init__(self, max_records: int = MAX_JOURNAL_RECORDS):
        self._records: dict[tuple, RecordedRuntimeFailure] = {}
        self._max_records = max(1, int(max_records))
        self._lock = RLock()

    def record(self, failure: RuntimeFailure) -> None:
        now = time.time()
        key = _grouping_key(failure)
        with self._lock:
            previous = self._records.get(key)
            self._records[key] = RecordedRuntimeFailure(
                failure, previous.first_seen if previous else now, now,
                previous.occurrences + 1 if previous else 1,
            )
            if len(self._records) > self._max_records:
                stale = min(self._records, key=lambda k: self._records[k].last_seen)
                del self._records[stale]

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def snapshot(self) -> tuple[RecordedRuntimeFailure, ...]:
        with self._lock:
            return tuple(self._records.values())


def is_core_error_line(message: str) -> bool:
    return bool(re.search(r"\b(?:error|fatal|panic|warn(?:ing)?|rejected)\b", message, re.IGNORECASE))


# Xray на каждый outbound пула печатает «The feature … is deprecated» (WebSocket,
# gRPC): при сотне узлов это сотни одинаковых строк за запуск. Это не сбой —
# ядро работает, — поэтому они не идут в журнал ошибок, а в логе остаётся одна
# строка на текст плюс счётчик повторов.
_DEPRECATION_NOTICE_RE = re.compile(r"\[Warning\]\s+\S+:\s+The feature\b.+\bis deprecated\b", re.IGNORECASE)


_LEADING_TIMESTAMP = re.compile(r"^\d{4}/\d{2}/\d{2} [\d:.]+ ")


def is_deprecation_notice(message: str) -> bool:
    return bool(_DEPRECATION_NOTICE_RE.search(message))


class RepeatedNoticeFilter:
    """Пропускает первое появление текста, повторы только считает."""

    def __init__(self) -> None:
        self._counts: dict[tuple[str, str], int] = {}
        self._samples: dict[tuple[str, str], str] = {}

    def first_time(self, engine: str, line: str) -> bool:
        key = (engine, _VOLATILE_DIGITS.sub("#", line))
        count = self._counts.get(key, 0) + 1
        self._counts[key] = count
        if count == 1:
            self._samples[key] = line
        return count == 1

    def drain_summary(self, engine: str) -> list[str]:
        """Строки «скрыто N повторов» для движка; счётчики сбрасываются."""

        lines: list[str] = []
        for key in [key for key in self._counts if key[0] == engine]:
            hidden = self._counts.pop(key) - 1
            sample = self._samples.pop(key, "")
            if hidden > 0:
                lines.append(f"[{engine}] скрыто повторов: {hidden} — {_LEADING_TIMESTAMP.sub('', sample)[:160]}")
        return lines
