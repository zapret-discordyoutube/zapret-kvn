"""Точечные исправления дефектов qfluentwidgets.

Патчи ставятся при импорте пакета ``xray_fluent.ui`` — раньше, чем создаётся
любой виджет, поэтому они действуют и на виджеты, которые библиотека создаёт
сама внутри себя (например ``SwitchSettingCard.switchButton``).
"""

from __future__ import annotations

from PyQt6.QtCore import QCoreApplication, QTranslator

_installed = False
_translator: QTranslator | None = None

# qfluentwidgets подписывает переключатели через self.tr('On'/'Off') — без
# перевода в настройках и подписках стояло английское «On/Off», а на панели
# русское «Вкл/Выкл».
_SWITCH_TEXTS = {"On": "Вкл", "Off": "Выкл"}
_SWITCH_CONTEXTS = frozenset({"SwitchButton", "SwitchSettingCard"})


class _FluentRussianTranslator(QTranslator):
    def translate(self, context, source_text, disambiguation=None, n=-1):
        if context in _SWITCH_CONTEXTS:
            text = _SWITCH_TEXTS.get(source_text)
            if text is not None:
                return text
        return ""  # пустая строка — «перевода нет», Qt оставит исходный текст


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


def install_translations(app: QCoreApplication) -> None:
    """Русские подписи стандартных виджетов qfluentwidgets (до создания окон)."""
    global _translator
    if _translator is None:
        _translator = _FluentRussianTranslator(app)
        app.installTranslator(_translator)


def _icon_only_paint(original):
    """``PushButton`` в режиме «только значок»: значок строго по центру.

    Оригинал сдвигает значок влево под подпись (x = 12 + ...), поэтому у
    кнопки без текста он съезжал и обрезался. Режим включает
    ``adaptive_buttons`` атрибутом ``_zk_icon_only``.
    """
    from PyQt6.QtCore import QRectF
    from PyQt6.QtGui import QPainter
    from PyQt6.QtWidgets import QPushButton

    def paintEvent(self, event):
        if not getattr(self, "_zk_icon_only", False):
            return original(self, event)
        QPushButton.paintEvent(self, event)
        if self.icon().isNull():
            return
        painter = QPainter(self)
        painter.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.SmoothPixmapTransform)
        if not self.isEnabled():
            painter.setOpacity(0.3628)
        elif self.isPressed:
            painter.setOpacity(0.786)
        w, h = self.iconSize().width(), self.iconSize().height()
        self._drawIcon(self._icon, painter, QRectF((self.width() - w) / 2, (self.height() - h) / 2, w, h))

    return paintEvent


def install() -> None:
    global _installed
    if _installed:
        return
    from qfluentwidgets import PushButton
    from qfluentwidgets.components.widgets.switch_button import Indicator

    Indicator._toggleSlider = _toggle_slider
    PushButton.paintEvent = _icon_only_paint(PushButton.paintEvent)
    _installed = True
