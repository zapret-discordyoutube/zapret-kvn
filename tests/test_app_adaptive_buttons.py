"""Кнопки со значком сворачиваются в значок, когда ряду не хватает места.

Keep the ``test_app_*`` prefix (QApplication before tests/test_engine_process_stop.py).
"""

from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QEventLoop, QTimer
from PyQt6.QtWidgets import QApplication, QHBoxLayout, QWidget

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError("widget tests need a QApplication")
app = _existing or QApplication([])

import xray_fluent.ui  # noqa: F401  (fluent_fixes: центрированный значок)
from qfluentwidgets import FluentIcon as FIF, PushButton

from xray_fluent.ui.adaptive_buttons import AdaptiveButtonRow


def _spin(ms: int = 30) -> None:
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


class AdaptiveButtonRowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.host = QWidget()
        cls.row = QHBoxLayout(cls.host)
        cls.first = PushButton(FIF.SYNC, "Проверить обновления подписок", cls.host)
        cls.second = PushButton(FIF.DOWNLOAD, "Полностью обновить без кэша", cls.host)
        cls.second.setToolTip("Своя подсказка")
        cls.plain = PushButton("Без значка", cls.host)
        for widget in (cls.first, cls.second, cls.plain):
            cls.row.addWidget(widget)
        cls.row.addStretch(1)
        cls.fit = AdaptiveButtonRow(cls.row, [cls.first, cls.second, cls.plain])
        cls.host.show()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.host.hide()

    def _resize(self, width: int) -> None:
        self.host.setMinimumWidth(0)
        self.host.resize(width, 60)
        _spin()
        self.fit.update_now()
        _spin()

    def test_wide_row_keeps_texts(self) -> None:
        self._resize(1200)
        self.assertEqual(self.first.text(), "Проверить обновления подписок")
        self.assertEqual(self.second.text(), "Полностью обновить без кэша")
        self.assertFalse(getattr(self.first, "_zk_icon_only", False))

    def test_narrow_row_collapses_from_the_end_with_text_in_tooltip(self) -> None:
        self._resize(1200)
        needed = self.row.minimumSize().width()
        self._resize(needed - 40)  # не хватает немного — сворачивается последняя кнопка со значком
        self.assertEqual(self.second.text(), "")
        self.assertTrue(self.second._zk_icon_only)
        self.assertEqual(self.second.toolTip(), "Своя подсказка")
        self.assertEqual(self.first.text(), "Проверить обновления подписок")
        self.assertEqual(self.plain.text(), "Без значка")  # без значка не сворачивается
        self._resize(200)
        self.assertEqual(self.first.text(), "")
        self.assertEqual(self.first.toolTip(), "Проверить обновления подписок")
        self.assertEqual(self.first.width(), 36)

    def test_widening_restores_texts(self) -> None:
        self._resize(200)
        self._resize(1400)
        self.assertEqual(self.first.text(), "Проверить обновления подписок")
        self.assertEqual(self.second.text(), "Полностью обновить без кэша")
        self.assertEqual(self.second.toolTip(), "Своя подсказка")
        self.assertFalse(self.second._zk_icon_only)

    def test_icon_only_paints(self) -> None:
        self._resize(200)
        self.assertFalse(self.first.grab().isNull())


if __name__ == "__main__":
    unittest.main()
