"""Ряд кнопок, который сворачивает подписи в значки, когда не хватает места.

Кнопка со значком, которой нет места в ряду, показывает только значок, а
её текст уходит в подсказку; появится место — текст вернётся. Сворачиваются
с конца ряда (последние кнопки — наименее важные).

Ширину нельзя брать только у самого ряда: на прокручиваемой странице ряд не
бывает уже своего минимума — вместо этого появляется горизонтальная
прокрутка. Поэтому доступная ширина = ширина ряда минус переполнение
ближайшей области прокрутки.
"""

from __future__ import annotations

from collections.abc import Sequence

from PyQt6.QtCore import QEvent, QObject, QTimer
from PyQt6.QtWidgets import QAbstractScrollArea, QLayout, QPushButton, QScrollArea, QWidget

_MAX_WIDTH = 16777215  # QWIDGETSIZE_MAX
_HYSTERESIS = 8        # запас при разворачивании, чтобы ряд не «дрожал» на границе


def set_icon_only(button: QPushButton, icon_only: bool, full_text: str, tooltip: str, square: int) -> None:
    """Переключить кнопку между «значок + текст» и «только значок»."""
    button._zk_icon_only = icon_only
    if icon_only:
        button.setText("")
        button.setToolTip(tooltip or full_text)
        button.setFixedWidth(square)
    else:
        button.setText(full_text)
        button.setToolTip(tooltip)
        button.setMinimumWidth(0)
        button.setMaximumWidth(_MAX_WIDTH)
    button.update()


class AdaptiveButtonRow(QObject):
    def __init__(self, layout: QLayout, buttons: Sequence[QPushButton], *, square: int = 36):
        host = layout.parentWidget()
        super().__init__(host)
        self._layout = layout
        self._buttons = [b for b in buttons if not b.icon().isNull()]
        self._square = square
        self._full: dict[int, tuple[str, str]] = {}
        self._widths: dict[int, int] = {}
        self._collapsed: list[QPushButton] = []
        self._pending = False
        host.installEventFilter(self)
        self._scroll = self._find_scroll_area(host)
        if self._scroll is not None:
            self._scroll.viewport().installEventFilter(self)
        self.schedule()

    @staticmethod
    def _find_scroll_area(widget: QWidget | None) -> QAbstractScrollArea | None:
        while widget is not None:
            if isinstance(widget, QScrollArea):
                return widget
            widget = widget.parentWidget()
        return None

    def collapsed_buttons(self) -> list[QPushButton]:
        return list(self._collapsed)

    def eventFilter(self, obj, event) -> bool:
        if event.type() in (QEvent.Type.Resize, QEvent.Type.Show):
            self.schedule()
        return False

    def schedule(self) -> None:
        if not self._pending:
            self._pending = True
            QTimer.singleShot(0, self.update_now)

    def _overflow(self) -> int:
        scroll = self._scroll
        if scroll is None or scroll.widget() is None:
            return 0
        return max(0, scroll.widget().width() - scroll.viewport().width())

    def update_now(self) -> None:
        self._pending = False
        available = self._layout.geometry().width() - self._overflow()
        if available <= 0:
            return
        needed = self._layout.minimumSize().width()
        for button in reversed(self._buttons):
            if needed <= available:
                break
            if button in self._collapsed or button.isHidden():
                continue
            key = id(button)
            self._full[key] = (button.text(), button.toolTip())
            self._widths[key] = button.minimumSizeHint().width()
            set_icon_only(button, True, button.text(), button.toolTip(), self._square)
            self._collapsed.append(button)
            needed -= max(0, self._widths[key] - self._square)
        while self._collapsed:
            button = self._collapsed[-1]
            key = id(button)
            gain = max(0, self._widths[key] - self._square)
            if needed + gain > available - _HYSTERESIS:
                break
            text, tooltip = self._full[key]
            set_icon_only(button, False, text, tooltip, self._square)
            self._collapsed.pop()
            needed += gain
