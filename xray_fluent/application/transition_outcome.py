"""The outcome of one coordinated transition, published once by its owner.

Transition steps never write a failure into the connection status
themselves. They report a cause here; the transition runner publishes exactly
one status when the transition ends, and only when it was not superseded by a
newer request. This makes three earlier bugs structurally impossible:

- a start cancelled by the user's own newer click showed «Не удалось
  запустить sing-box…» (a superseded transition publishes nothing);
- a specific cause (the server did not answer over UDP) was overwritten by a
  later generic step message (the higher-ranked cause wins, ties keep the
  first one);
- a failed switch with the previous runtime still serving showed «Ошибка
  подключения» (the phase is derived from what is actually running).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class FailureRank(IntEnum):
    # Generic message of the step that noticed the failure.
    STEP = 0
    # Raw core error text (shortened for the UI by connection_message).
    CORE = 1
    # Cause derived from the failed component's own evidence.
    CAUSE = 2
    # Rejected certificate/password/obfs: always the reason shown.
    SECURITY = 3


GENERIC_FAILURE = "Переход не завершился. Подробности — в логах."


@dataclass(frozen=True, slots=True)
class TransitionFailure:
    message: str
    rank: FailureRank


class TransitionOutcome:
    """Collects the most specific cause of the running transition."""

    __slots__ = ("_failure",)

    def __init__(self) -> None:
        self._failure: TransitionFailure | None = None

    @property
    def failure(self) -> TransitionFailure | None:
        return self._failure

    def reset(self) -> None:
        self._failure = None

    def fail(self, message: str, rank: FailureRank = FailureRank.STEP) -> None:
        text = str(message or "").strip()
        if not text:
            return
        current = self._failure
        if current is None or rank > current.rank:
            self._failure = TransitionFailure(text, FailureRank(rank))

    def take(self) -> TransitionFailure | None:
        failure, self._failure = self._failure, None
        return failure


def failure_status(
    failure: TransitionFailure | None,
    *,
    connected: bool,
    serving_name: str = "",
) -> tuple[str, str, str]:
    """``(phase, message, level)`` for a failed, non-superseded transition."""

    message = failure.message if failure is not None else GENERIC_FAILURE
    if not connected:
        return "error", message, "error"
    # The previous runtime still carries traffic: say so instead of
    # «Ошибка подключения».
    tail = f"Соединение осталось на «{serving_name}»." if serving_name else "Прежнее подключение сохранено."
    return "running", f"{message} {tail}", "warning-long"
