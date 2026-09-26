"""Подпись в одну строку: не хватает места — многоточие, полный текст в подсказке."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QSizePolicy
from qfluentwidgets import CaptionLabel


class ElidedCaptionLabel(CaptionLabel):
    """``CaptionLabel``, который не переносится, а сокращается по ширине.

    ``text()`` возвращает полный текст (его читают логика и тесты), на экране
    — сокращённый; полный показывается подсказкой, когда не влез.
    """

    def __init__(self, text: str = "", parent=None):
        super().__init__(parent)
        self._full_text = ""
        self.setWordWrap(False)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.setMinimumWidth(40)
        self.setText(text)

    def text(self) -> str:  # noqa: D401 — полный текст, не сокращённый
        return self._full_text

    def setText(self, text: str) -> None:
        self._full_text = text or ""
        self._update_elided()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._update_elided()

    def _update_elided(self) -> None:
        width = max(0, self.width() - 2)
        shown = self.fontMetrics().elidedText(self._full_text, Qt.TextElideMode.ElideMiddle, width) if width else self._full_text
        super().setText(shown)
        self.setToolTip(self._full_text if shown != self._full_text else "")
