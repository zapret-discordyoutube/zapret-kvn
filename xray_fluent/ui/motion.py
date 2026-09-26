"""Единый «гейт кадров» для анимированных виджетов.

``FrameGate`` — таймер кадров, который тикает только когда анимация реально
видна: виджет показан, окно не свёрнуто и в Windows не выключена анимация
интерфейса. Виджет лишь сообщает желаемый интервал (``set_interval``) и
перерисовывается по сигналу ``frame``.

Инвариант жизненного цикла: гейт — дочерний QObject виджета и **не хранит
сильных ссылок на предков**. Окно вычисляется на лету (``parent().window()``),
а для снятия фильтра событий запоминается только ``weakref``. Сильная ссылка
ребёнка на Python-обёртку окна (``self._watched_window = window``) образует
цикл «C++-владение родителем ↔ ``__dict__`` ребёнка», который сборщик мусора
не разрывает. Тогда окно доживает до финализации интерпретатора и может
разрушиться уже после ``QApplication``, а это плавающий segfault при выходе.
"""

from __future__ import annotations

import sys
import weakref

from PyQt6.QtCore import QEvent, QObject, Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import QWidget

_WINDOW_EVENTS = (QEvent.Type.WindowStateChange, QEvent.Type.Show, QEvent.Type.Hide)


def reduced_motion() -> bool:
    """Выключена ли в Windows анимация интерфейса (Параметры → Специальные возможности).

    Читается при каждом вызове: это один системный вызов, а пользователь может
    переключить настройку на ходу. Вне Windows возвращает ``False``.
    """
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        enabled = wintypes.BOOL(True)
        # SPI_GETCLIENTAREAANIMATION
        if ctypes.windll.user32.SystemParametersInfoW(0x1042, 0, ctypes.byref(enabled), 0):
            return not bool(enabled.value)
    except Exception:
        pass
    return False


class FrameGate(QObject):
    """Таймер кадров виджета, работающий только пока анимацию видно."""

    frame = pyqtSignal()

    def __init__(self, widget: QWidget, *, respect_reduced_motion: bool = True):
        super().__init__(widget)
        self._interval: int | None = None
        self._respect_reduced_motion = respect_reduced_motion
        # Системная настройка читается при sync(), а не на каждом кадре.
        self._motion_ok = True
        self._window_ref: weakref.ref | None = None
        self._timer = QTimer(self)
        self._timer.setTimerType(Qt.TimerType.CoarseTimer)
        self._timer.timeout.connect(self._on_timeout)
        widget.installEventFilter(self)

    # ── API ─────────────────────────────────────────────

    def set_interval(self, interval_ms: int | None) -> None:
        """Желаемый интервал кадров; ``None`` — анимация не нужна."""
        self._interval = interval_ms
        self.sync()

    def is_running(self) -> bool:
        return self._timer.isActive()

    def motion_allowed(self) -> bool:
        return not (self._respect_reduced_motion and reduced_motion())

    def sync(self) -> None:
        self._motion_ok = self.motion_allowed()
        if self._should_run():
            if not self._timer.isActive() or self._timer.interval() != self._interval:
                self._timer.start(self._interval)
        else:
            self._timer.stop()

    # ── Внутреннее ──────────────────────────────────────

    def _widget(self) -> QWidget | None:
        widget = self.parent()
        return widget if isinstance(widget, QWidget) else None

    def _should_run(self) -> bool:
        widget = self._widget()
        if self._interval is None or widget is None or not widget.isVisible():
            return False
        window = widget.window()
        if window is not None and window.isMinimized():
            return False
        return self._motion_ok

    def _on_timeout(self) -> None:
        if not self._should_run():
            self._timer.stop()
            return
        self.frame.emit()

    def _watch_window(self) -> None:
        widget = self._widget()
        if widget is None:
            return
        window = widget.window()
        current = self._window_ref() if self._window_ref is not None else None
        if window is current or window is widget:
            return
        if current is not None:
            current.removeEventFilter(self)
        window.installEventFilter(self)
        self._window_ref = weakref.ref(window)

    def eventFilter(self, obj, event) -> bool:
        kind = event.type()
        if obj is self.parent():
            if kind == QEvent.Type.Show:
                self._watch_window()
                self.sync()
            elif kind == QEvent.Type.Hide:
                self._timer.stop()
        elif kind in _WINDOW_EVENTS:
            QTimer.singleShot(0, self.sync)
        return False
