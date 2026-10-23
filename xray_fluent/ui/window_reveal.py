"""Окно появляется на экране уже нарисованным — при запуске и из трея.

Между ``show()`` и отрисовкой проходит время: Qt сначала разбирает очередь
событий и только потом рисует окно. Всё это время Windows выводит окно таким,
какое оно есть, — пустым и белым. Скрытое в трей окно Qt при возврате рисует
заново целиком, поэтому белый кадр был при каждом щелчке по значку (замер на
win10: белое через 4–79 мс, готовое через 30–226 мс; на обычном компьютере
в разы дольше).

У Windows для этого есть штатное средство — скрытие окна от экрана (cloak):
окно считается показанным, получает события и рисуется, но на экран не
выводится. Перед показом окно скрывается, после отрисовки — открывается, и
пользователь сразу видит готовый кадр.
"""

from __future__ import annotations

import sys
from collections.abc import Callable

from PyQt6.QtCore import QEvent, QObject, QTimer


# DwmSetWindowAttribute: «скрыть окно от экрана, продолжая его рисовать».
DWMWA_CLOAK = 13
# Дольше этого окно скрытым не остаётся, даже если отрисовка так и не пришла:
# белое окно лучше невидимой программы.
FRAME_WAIT_MAX_MS = 1_500


def wait_for_composition() -> None:
    """Ждёт, пока Windows соберёт уже нарисованный кадр окна для экрана.

    Без этого шторка снималась раньше, чем кадр доходил до экрана: на стенде
    win10 окно после снятия шторки ещё ~20 мс было белым в 4 случаях из 6, с
    ожиданием — ни разу из 5. Ждать приходится не дольше одного кадра экрана.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.dwmapi.DwmFlush()
    except Exception:
        pass


def set_window_cloaked(hwnd: int, cloaked: bool) -> bool:
    """Скрывает окно от экрана или открывает его. True — Windows приняла запрос."""
    if sys.platform != "win32" or not hwnd:
        return False
    try:
        import ctypes
        from ctypes import wintypes

        value = ctypes.c_int(1 if cloaked else 0)
        result = ctypes.windll.dwmapi.DwmSetWindowAttribute(
            wintypes.HWND(int(hwnd)),
            DWMWA_CLOAK,
            ctypes.byref(value),
            ctypes.sizeof(value),
        )
        return int(result) == 0
    except Exception:
        return False


class FrameReveal(QObject):
    """Держит окно скрытым от экрана от ``show()`` до его отрисовки; годится на каждый показ."""

    def __init__(
        self,
        window,
        *,
        cloak: Callable[[int, bool], bool] = set_window_cloaked,
        wait_composed: Callable[[], None] = wait_for_composition,
        wait_max_ms: int = FRAME_WAIT_MAX_MS,
    ) -> None:
        super().__init__(window)
        self._window = window
        self._cloak = cloak
        self._wait_composed = wait_composed
        self._hwnd = 0
        self._cloaked = False
        self._deadline = QTimer(self)
        self._deadline.setSingleShot(True)
        self._deadline.setInterval(max(0, int(wait_max_ms)))
        self._deadline.timeout.connect(self._deadline_reached)

    def start(self) -> bool:
        """Вызывается из showEvent: окно ещё не выведено на экран."""
        if self._cloaked:
            return True
        try:
            hwnd = int(self._window.winId())
        except Exception:
            return False
        if not self._cloak(hwnd, True):
            return False
        self._hwnd = hwnd
        self._cloaked = True
        self._window.installEventFilter(self)
        self._deadline.start()
        return True

    def is_cloaked(self) -> bool:
        return self._cloaked

    def eventFilter(self, watched, event):  # noqa: N802 (Qt API)
        if self._cloaked and watched is self._window and event.type() == QEvent.Type.Paint:
            watched.removeEventFilter(self)
            # Событие приходит до самой отрисовки. Открываем окно следующим
            # проходом цикла событий — когда кадр уже нарисован и отдан системе —
            # и после того, как Windows соберёт его для экрана.
            QTimer.singleShot(0, self.reveal)
        return False

    def _deadline_reached(self) -> None:
        # Срок идёт по тому же циклу событий, что и отрисовка: если запуск
        # занял поток интерфейса дольше срока, таймер срабатывает раньше первой
        # отрисовки, и окно открылось бы пустым и белым. Рисуем его сами, сразу,
        # а уже потом открываем.
        if self._cloaked:
            try:
                self._window.repaint()
            except Exception:
                pass
        self.reveal()

    def reveal(self) -> None:
        if not self._cloaked:
            return
        self._cloaked = False
        self._deadline.stop()
        try:
            self._window.removeEventFilter(self)
        except Exception:
            pass
        self._wait_composed()
        self._cloak(self._hwnd, False)


def is_system_show_event(event) -> bool:
    """Показ по команде Windows (окно развернули из панели задач), а не наш ``show()``.

    Такое окно Windows выводит сама, с его прежней картинкой; прятать его
    нельзя — Qt может не перерисовать окно, и оно пропало бы до запасного срока.
    """
    try:
        return bool(event.spontaneous())
    except Exception:
        return False


def cloak_until_painted(window) -> FrameReveal:
    """Прячет окно от экрана до отрисовки. Вызывается из showEvent при каждом ``show()``."""
    reveal = getattr(window, "_frame_reveal", None)
    if not isinstance(reveal, FrameReveal):
        reveal = FrameReveal(window)
        window._frame_reveal = reveal
    reveal.start()
    return reveal


__all__ = [
    "DWMWA_CLOAK",
    "FRAME_WAIT_MAX_MS",
    "FrameReveal",
    "cloak_until_painted",
    "is_system_show_event",
    "set_window_cloaked",
    "wait_for_composition",
]
