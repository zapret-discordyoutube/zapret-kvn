"""Намерение пользователя поверх наблюдаемого состояния.

Элемент управления (переключатель системного прокси и т. п.) показывает то,
что пользователь только что выбрал, пока изменение применяется в фоне, — а
не откатывается к старому фактическому состоянию. Ожидание снимается, когда
факт догнал намерение, или по таймауту (тогда показывается правда).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Generic, TypeVar

T = TypeVar("T")

DEFAULT_TIMEOUT_S = 15.0


class PendingValue(Generic[T]):
    def __init__(self, timeout_s: float = DEFAULT_TIMEOUT_S, clock: Callable[[], float] = time.monotonic):
        self._timeout_s = float(timeout_s)
        self._clock = clock
        self._value: T | None = None
        self._deadline = 0.0
        self._active = False

    @property
    def pending(self) -> bool:
        return self._active and self._clock() < self._deadline

    @property
    def timeout_s(self) -> float:
        return self._timeout_s

    def request(self, value: T) -> None:
        """Пользователь выбрал ``value``; факт ещё не догнал."""
        self._value = value
        self._deadline = self._clock() + self._timeout_s
        self._active = True

    def resolve(self, observed: T) -> None:
        """Сверить с фактом: совпало или истёк таймаут — ожидание снято."""
        if self._active and (observed == self._value or self._clock() >= self._deadline):
            self.clear()

    def clear(self) -> None:
        self._active = False
        self._value = None

    def display(self, observed: T) -> T:
        """Что показать: намерение, пока оно ожидает, иначе факт."""
        self.resolve(observed)
        return self._value if self.pending else observed  # type: ignore[return-value]
