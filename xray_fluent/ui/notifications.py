"""Уведомления окна: одно место, где решается, как и сколько их показывать.

Раньше каждое место звало ``InfoBar`` со своим сроком (от 2,2 до 30 с), и
уведомление гасло по таймеру библиотеки, даже если его читали с мышью над ним
или окно было свёрнуто. Теперь:

* срок зависит от уровня и длины текста — на чтение есть время;
* отсчёт стоит, пока над уведомлением мышь, и пока окно не активно или
  свёрнуто: уведомление не исчезает, пока его не увидели;
* увёл мышь — после неё есть ещё несколько секунд;
* одинаковое уведомление не складывается стопкой — висящее продлевается;
* на экране одновременно не больше ``MAX_VISIBLE``, старые уходят первыми;
* «липкие» уведомления (прогресс пинга, теста скорости) живут, пока их не
  закроют или не переведут в обычный отсчёт (:meth:`Notification.expire_in`).

Показывать уведомления только через :func:`notify` / :class:`Notifier`;
``InfoBar`` напрямую в окнах не создаётся.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from PyQt6.QtCore import QElapsedTimer, QObject, Qt, QTimer
from PyQt6.QtWidgets import QWidget
from qfluentwidgets import InfoBar, InfoBarIcon, InfoBarPosition

LEVELS = ("info", "success", "warning", "error")

# Минимальный срок по уровню: ошибку и предупреждение надо успеть прочесть и
# понять, что делать, успех — только заметить.
_MIN_MS = {"success": 3_000, "info": 4_000, "warning": 6_000, "error": 8_000}
# Уведомления с пометкой «-long» несут то, что надо дочитать (итог проверки
# подписки с предупреждениями, ссылка): не меньше этого.
LONG_MIN_MS = 12_000
# Время чтения: секунда на то, чтобы заметить, и ~15 знаков в секунду.
_NOTICE_MS = 1_000
_PER_CHAR_MS = 65
MAX_MS = 30_000
# После того как мышь ушла с уведомления, оно ещё столько живёт.
LEAVE_GRACE_MS = 2_500
MAX_VISIBLE = 4
_TICK_MS = 200

_TITLES = {"info": "Инфо", "success": "Готово", "warning": "Внимание", "error": "Ошибка"}
_ICONS = {
    "info": InfoBarIcon.INFORMATION,
    "success": InfoBarIcon.SUCCESS,
    "warning": InfoBarIcon.WARNING,
    "error": InfoBarIcon.ERROR,
}


@dataclass(frozen=True)
class Level:
    """Разобранный уровень: ``"warning-long"`` → ``Level("warning", True)``."""

    name: str
    long: bool = False

    @classmethod
    def parse(cls, raw: str) -> "Level":
        text = str(raw or "").strip().lower()
        long = text.endswith("-long")
        if long:
            text = text[: -len("-long")]
        return cls(text if text in LEVELS else "info", long)


def display_duration_ms(level: str, title: str, message: str, *, min_ms: int = 0) -> int:
    """Сколько уведомление видно при отсчёте (паузы под мышью не входят)."""

    parsed = Level.parse(level)
    chars = len(str(title or "")) + len(str(message or ""))
    reading = _NOTICE_MS + chars * _PER_CHAR_MS
    floor = max(_MIN_MS[parsed.name], LONG_MIN_MS if parsed.long else 0, int(min_ms or 0))
    return min(max(reading, floor), max(MAX_MS, int(min_ms or 0)))


class Notification(InfoBar):
    """``InfoBar`` со своим отсчётом: пауза под мышью и в неактивном окне.

    Таймер библиотеки выключен (``duration=-1``); вместо него тикает свой
    таймер и вычитает время только тогда, когда уведомление действительно
    можно прочесть.
    """

    def __init__(self, level: str, title: str, content: str, *, duration_ms: int | None, parent: QWidget):
        parsed = Level.parse(level)
        super().__init__(
            icon=_ICONS[parsed.name],
            title=title,
            content=content,
            isClosable=True,
            duration=-1,
            position=InfoBarPosition.TOP_RIGHT,
            parent=parent,
        )
        self.level = parsed.name
        self._remaining: int | None = duration_ms
        self._closing = False
        self._clock = QElapsedTimer()
        self._ticker = QTimer(self)
        self._ticker.setInterval(_TICK_MS)
        self._ticker.timeout.connect(self._tick)
        self.setMouseTracking(True)

    # --- публичное -------------------------------------------------------

    @property
    def sticky(self) -> bool:
        return self._remaining is None

    @property
    def closing(self) -> bool:
        return self._closing

    @property
    def remaining_ms(self) -> int | None:
        return self._remaining

    def set_content(self, content: str) -> None:
        self.content = str(content or "")
        self._adjustText()

    def expire_in(self, duration_ms: int) -> None:
        """Начать (или заново начать) отсчёт; липкое становится обычным."""

        self._remaining = max(0, int(duration_ms))
        self._closing = False
        if self.isVisible():
            self._start_ticking()

    def extend(self, duration_ms: int) -> None:
        """Продлить до ``duration_ms``, если осталось меньше (повтор того же)."""

        if self._remaining is None:
            return
        self.expire_in(max(self._remaining, int(duration_ms)))

    def dismiss(self) -> None:
        """Плавно убрать (как по истечении срока)."""

        if self._closing:
            return
        self._closing = True
        self._ticker.stop()
        try:
            self.opacityAni.stop()
            self.opacityAni.setDuration(200)
            self.opacityAni.setStartValue(self.opacityEffect.opacity())
            self.opacityAni.setEndValue(0)
            self.opacityAni.finished.connect(self.close)
            self.opacityAni.start()
        except RuntimeError:
            # Окно уже разрушается вместе с уведомлением.
            pass

    def counting(self) -> bool:
        """Идёт ли сейчас отсчёт: видно, мышь не над ним, окно активно."""

        if self._remaining is None or self._closing or not self.isVisible():
            return False
        if self.underMouse():
            return False
        window = self.window()
        if window is None or window.isMinimized() or not window.isActiveWindow():
            return False
        return True

    # --- события ---------------------------------------------------------

    def showEvent(self, e) -> None:
        super().showEvent(e)
        if self._remaining is not None:
            self._start_ticking()

    def enterEvent(self, e) -> None:
        super().enterEvent(e)
        self._restore_opacity()

    def leaveEvent(self, e) -> None:
        super().leaveEvent(e)
        if self._remaining is not None and not self._closing:
            self._remaining = max(self._remaining, LEAVE_GRACE_MS)

    def _restore_opacity(self) -> None:
        # Мышь поймала уже гаснущее уведомление — вернуть его.
        if not self._closing or self._remaining is None:
            return
        try:
            self.opacityAni.stop()
            self.opacityAni.finished.disconnect(self.close)
        except (RuntimeError, TypeError):
            pass
        self.opacityEffect.setOpacity(1)
        self._closing = False
        self._remaining = max(self._remaining, LEAVE_GRACE_MS)
        self._start_ticking()

    def _start_ticking(self) -> None:
        self._clock.start()
        if not self._ticker.isActive():
            self._ticker.start()

    def _tick(self) -> None:
        elapsed = self._clock.restart()
        if self._remaining is None:
            self._ticker.stop()
            return
        if not self.counting():
            return
        self._remaining -= elapsed
        if self._remaining <= 0:
            self._remaining = 0
            self.dismiss()


class Notifier(QObject):
    """Очередь уведомлений одного окна: дубли, лимит, сроки."""

    def __init__(self, window: QWidget):
        super().__init__(window)
        self._window = window
        self._live: list[tuple[tuple[str, str, str], Notification]] = []

    def show(
        self,
        level: str,
        message: str,
        *,
        title: str | None = None,
        min_ms: int = 0,
        sticky: bool = False,
        on_closed: Callable[[], None] | None = None,
    ) -> Notification:
        parsed = Level.parse(level)
        title = _TITLES[parsed.name] if title is None else str(title)
        message = str(message or "")
        duration = None if sticky else display_duration_ms(level, title, message, min_ms=min_ms)
        key = (parsed.name, title, message)

        if not sticky:
            existing = self._find(key)
            if existing is not None:
                existing.extend(duration)
                return existing

        self._trim(MAX_VISIBLE - 1)
        bar = Notification(level, title, message, duration_ms=duration, parent=self._window)
        self._live.append((key, bar))
        bar.closedSignal.connect(lambda bar=bar: self._forget(bar))
        if on_closed is not None:
            bar.closedSignal.connect(on_closed)
        bar.show()
        return bar

    def visible(self) -> list[Notification]:
        return [bar for _key, bar in self._live]

    def _find(self, key: tuple[str, str, str]) -> Notification | None:
        for live_key, bar in self._live:
            if live_key == key and not bar.closing:
                return bar
        return None

    def _trim(self, keep: int) -> None:
        # Липкие (прогресс) не вытесняются: их закрывает владелец.
        active = [bar for _key, bar in self._live if not bar.closing]
        removable = [bar for bar in active if not bar.sticky]
        while len(active) > keep and removable:
            oldest = removable.pop(0)
            active.remove(oldest)
            oldest.dismiss()

    def _forget(self, bar: Notification) -> None:
        self._live = [(key, live) for key, live in self._live if live is not bar]


def notifier_for(widget: QWidget) -> Notifier:
    """Очередь окна, которому принадлежит ``widget`` (создаётся при первом зове)."""

    window = widget.window() if widget is not None else None
    if window is None:
        raise ValueError("notification needs a widget")
    notifier = window.findChild(Notifier, options=Qt.FindChildOption.FindDirectChildrenOnly)
    if notifier is None:
        notifier = Notifier(window)
    return notifier


def notify(widget: QWidget, level: str, message: str, **kwargs) -> Notification:
    """Показать уведомление в окне ``widget``; см. :meth:`Notifier.show`."""

    return notifier_for(widget).show(level, message, **kwargs)


__all__ = [
    "LEAVE_GRACE_MS",
    "LONG_MIN_MS",
    "MAX_MS",
    "MAX_VISIBLE",
    "Level",
    "Notification",
    "Notifier",
    "display_duration_ms",
    "notifier_for",
    "notify",
]
