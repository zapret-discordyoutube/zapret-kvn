"""Список изменений выпуска: одно правило для Zapret 2 GUI и Zapret KVN.

Пасхалка в духе «Removed Herobrine» из списков изменений Minecraft: иногда
последней строкой выпуска идёт «Удалена буква «О»» (просьба владельца
2026-10-15). Правило:

- только в маленьком выпуске — в списке один пункт. В большом списке шутка
  лишняя: настоящие изменения важнее;
- примерно в трёх таких выпусках из десяти, решение зависит только от канала
  и версии — повторная публикация того же выпуска его не меняет;
- после шутки — не меньше ``GAP`` выпусков канала без неё. Без перерыва
  случайность давала серии: 21.1.7.155–158 вышли с шуткой все четыре подряд.

Здесь только решение «нужна ли шутка». Как её вписать (знак списка, пределы
Telegram) решает сценарий выпуска своей программы.
"""

from __future__ import annotations

import random

LINE = "Удалена буква «О»"
CHANCE = 0.30
GAP = 3
MAX_ITEMS = 1


# Посчитанные ответы по (канал, версия без последнего числа): ответ версии
# зависит от всех прежних, считать их заново на каждый вызов незачем.
_HISTORY: dict[tuple[str, str], list[bool]] = {}


def _roll(channel: str, version: str) -> bool:
    return random.Random(f"zapret-easter-egg:{channel}:{version}").random() < CHANCE


def lucky(channel: str, version: str) -> bool:
    """Выпала ли шутка этой версии с учётом перерыва (без учёта размера списка).

    Выпуски канала идут подряд по последнему числу версии: перерыв считается
    с нуля, поэтому ответ одинаков при любом запуске.
    """
    head, _, last = str(version).rpartition(".")
    if not last.isdigit():
        return _roll(channel, version)
    history = _HISTORY.setdefault((channel, head), [])
    while len(history) <= int(last):
        number = len(history)
        # Сколько выпусков прошло с последней шутки; до первой — перерыв не мешает.
        since_joke = next((number - i - 1 for i in range(number - 1, -1, -1) if history[i]), GAP + number)
        history.append(since_joke >= GAP and _roll(channel, f"{head}.{number}" if head else str(number)))
    return history[int(last)]


def wants_joke(channel: str, version: str, items: int) -> bool:
    """Нужна ли шутка выпуску, в списке изменений которого ``items`` пунктов."""
    return 0 < items <= MAX_ITEMS and lucky(channel, version)


__all__ = ["CHANCE", "GAP", "LINE", "MAX_ITEMS", "lucky", "wants_joke"]
