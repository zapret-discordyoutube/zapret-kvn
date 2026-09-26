"""Подпись в одну строку: сокращается по ширине, полный текст в подсказке.

Keep the ``test_app_*`` prefix (QApplication before tests/test_engine_process_stop.py).
"""

from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError("widget tests need a QApplication")
app = _existing or QApplication([])

from xray_fluent.ui.elided_label import ElidedCaptionLabel

TEXT = "Открыта активная копия: default.json"


class ElidedCaptionLabelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.label = ElidedCaptionLabel(TEXT)
        cls.label.show()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.label.hide()

    def test_wide_label_shows_full_text_without_tooltip(self) -> None:
        self.label.setText(TEXT)
        self.label.resize(600, 20)
        app.processEvents()
        self.assertEqual(self.label.text(), TEXT)
        self.assertEqual(self.label.toolTip(), "")
        self.assertFalse(self.label.wordWrap())

    def test_narrow_label_elides_and_keeps_full_text(self) -> None:
        self.label.setText(TEXT)
        self.label.resize(120, 20)
        app.processEvents()
        self.assertEqual(self.label.text(), TEXT)  # логика видит полный текст
        self.assertEqual(self.label.toolTip(), TEXT)
        self.assertLessEqual(self.label.sizeHint().height(), self.label.fontMetrics().height() + 8)

    def test_new_text_is_elided_for_current_width(self) -> None:
        self.label.resize(120, 20)
        self.label.setText("Есть несохранённые изменения в очень длинном конфиге")
        self.assertEqual(self.label.text(), "Есть несохранённые изменения в очень длинном конфиге")
        self.assertTrue(self.label.toolTip())


if __name__ == "__main__":
    unittest.main()
