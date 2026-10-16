"""Шлюз проверок: когда и куда приложению можно стучаться самому.

Требование незаметности: проверки не должны выдавать VPN-серверы оборудованию
провайдера (ТСПУ). Обычный пользователь работает с одним сервером; пачка
одновременных рукопожатий к разным адресам или ровный ритм фоновых запросов
выдают весь список подписки. Правила здесь, а не в каждом месте, которое
что-то проверяет:

* текущий сервер — только по сигналу беды;
* другой сервер — только во время замены (кандидат) и в пределах бюджета;
* по кнопке — по одному серверу; между серверами одного прохода «все» —
  пауза со случайным разбросом, проход можно отменить;
* каждая проверка записывается в журнал — по нему тесты проверяют, что без
  сигнала к нетекущим серверам не ушло ни одного соединения.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import random
import threading
import time
from typing import Callable

# Пауза между серверами прохода «Пинг всех» / «Скорость всех»: на проводе это
# отдельные подключения, а не веер.
SWEEP_PAUSE_SEC: tuple[float, float] = (10.0, 20.0)
# Автоматических проверок других серверов (умная замена) — не больше стольких
# за скользящий час, сверх кулдаунов самой замены.
CANDIDATE_PROBES_PER_HOUR = 3
_HOUR_SEC = 3600.0
_JOURNAL_LIMIT = 512

# Виды проверок.
SWEEP = "sweep"            # по кнопке, проход по списку
USER = "user"              # по кнопке, один сервер
CURRENT = "current"        # текущий сервер по сигналу
CANDIDATE = "candidate"    # другой сервер во время замены


def sweep_pause(rng: random.Random | None = None) -> float:
    low, high = SWEEP_PAUSE_SEC
    return (rng or random).uniform(low, high)


@dataclass(frozen=True)
class ProbeRecord:
    kind: str
    target: str
    at: float


class ProbeGate:
    """Бюджет автоматических проверок и журнал всех проверок; потокобезопасен."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._journal: deque[ProbeRecord] = deque(maxlen=_JOURNAL_LIMIT)
        self._candidates: deque[float] = deque()

    def record(self, kind: str, target: str) -> None:
        with self._lock:
            self._journal.append(ProbeRecord(kind, str(target or ""), self._clock()))

    def try_candidate(self, target: str) -> bool:
        """Можно ли сейчас автоматически проверить другой сервер; да — записано."""

        with self._lock:
            now = self._clock()
            while self._candidates and now - self._candidates[0] >= _HOUR_SEC:
                self._candidates.popleft()
            if len(self._candidates) >= CANDIDATE_PROBES_PER_HOUR:
                return False
            self._candidates.append(now)
            self._journal.append(ProbeRecord(CANDIDATE, str(target or ""), now))
            return True

    def journal(self) -> tuple[ProbeRecord, ...]:
        with self._lock:
            return tuple(self._journal)

    def reset(self) -> None:
        with self._lock:
            self._journal.clear()
            self._candidates.clear()


GATE = ProbeGate()
