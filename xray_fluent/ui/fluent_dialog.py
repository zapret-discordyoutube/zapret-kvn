"""Base dialog that participates in the qfluentwidgets theme mechanism.

Plain ``QDialog`` subclasses get the OS default backdrop, which breaks the
half-transparent fluent QSS in dark mode and leaves ``QPalette`` roles
(``PlaceholderText``/``Text``) out of sync with the theme.  ``FluentDialog``
paints its surface from the :mod:`theme` tokens and re-applies everything on
``qconfig.themeChanged``.
"""

from __future__ import annotations

from PyQt6.QtGui import QPalette
from PyQt6.QtWidgets import QDialog, QWidget
from qfluentwidgets import qconfig

from .theme import placeholder_text_color, surface_color, text_color


class FluentDialog(QDialog):
    """QDialog with a fluent surface that follows theme changes."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._apply_dialog_theme()
        # Bound-method connection: Qt disconnects automatically on destroy.
        qconfig.themeChanged.connect(self._on_fluent_theme_changed)

    def _on_fluent_theme_changed(self) -> None:
        self._apply_dialog_theme()

    def _apply_dialog_theme(self) -> None:
        surface = surface_color()
        # The leaf class name matches the QSS class selector, keeping the
        # background scoped to this dialog (children keep fluent styling).
        selector = type(self).__name__
        self.setStyleSheet(f"{selector} {{ background-color: {surface.name()}; }}")

        palette = self.palette()
        text = text_color()
        palette.setColor(QPalette.ColorRole.Window, surface)
        palette.setColor(QPalette.ColorRole.WindowText, text)
        palette.setColor(QPalette.ColorRole.Text, text)
        palette.setColor(QPalette.ColorRole.PlaceholderText, placeholder_text_color())
        self.setPalette(palette)
