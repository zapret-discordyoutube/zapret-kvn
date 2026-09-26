"""Точечные исправления дефектов qfluentwidgets.

Патчи ставятся при импорте пакета ``xray_fluent.ui`` — раньше, чем создаётся
любой виджет, поэтому они действуют и на виджеты, которые библиотека создаёт
сама внутри себя (например ``SwitchSettingCard.switchButton``).
"""

from __future__ import annotations

_installed = False

_SLIDER_OFF_X = 5.0
_SLIDER_ON_X = 25.0


def _toggle_slider(self) -> None:
    """Сдвинуть кружок переключателя к позиции, соответствующей состоянию.

    Оригинал только меняет ``endValue`` и зовёт ``start()``: на бегущей
    анимации ``start()`` ничего не делает, а неявный ``startValue`` Qt
    запоминает с прошлого запуска. Серия вкл→выкл→вкл быстрее 120 мс
    (например, повторный ``_sync_switches``) оставляла кружок слева при
    включённом состоянии. Здесь анимация всегда перезапускается с текущей
    точки, а у невидимого виджета позиция ставится сразу.
    """
    target = _SLIDER_ON_X if self.isChecked() else _SLIDER_OFF_X
    animation = self.slideAni
    animation.stop()
    if not self.isVisible():
        self.setSliderX(target)
        return
    animation.setStartValue(float(self.getSliderX()))
    animation.setEndValue(target)
    animation.start()


def install() -> None:
    global _installed
    if _installed:
        return
    from qfluentwidgets.components.widgets.switch_button import Indicator

    Indicator._toggleSlider = _toggle_slider
    _installed = True
