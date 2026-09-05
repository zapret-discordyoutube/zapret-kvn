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


class RuntimeErrorJournal:
    """Error evidence is independent of the bounded traffic/UI log."""

    def __init__(self):
        self._records: dict[RuntimeFailure, RecordedRuntimeFailure] = {}
        self._lock = RLock()

    def record(self, failure: RuntimeFailure) -> None:
        now = time.time()
        with self._lock:
            previous = self._records.get(failure)
            self._records[failure] = RecordedRuntimeFailure(
                failure, previous.first_seen if previous else now, now,
                previous.occurrences + 1 if previous else 1,
            )

    def snapshot(self) -> tuple[RecordedRuntimeFailure, ...]:
        with self._lock:
            return tuple(self._records.values())


def is_core_error_line(message: str) -> bool:
    return bool(re.search(r"\b(?:error|fatal|panic|warn(?:ing)?|rejected)\b", message, re.IGNORECASE))
