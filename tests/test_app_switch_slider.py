"""Кружок SwitchButton всегда совпадает с состоянием (xray_fluent/ui/fluent_fixes.py).

Keep the ``test_app_*`` prefix: widget test modules must sort before
``tests/test_engine_process_stop.py`` which creates a bare QCoreApplication
at import time (see tests/test_app_nodes_page_view.py).
"""

from __future__ import annotations

import os
import time
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QEventLoop, QTimer
from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError(
        "A bare QCoreApplication was created before test_app_switch_slider "
        "was imported; widget tests need a QApplication."
    )
app = _existing or QApplication([])

import xray_fluent.ui  # noqa: F401  (ставит fluent_fixes)
from qfluentwidgets import SwitchButton, SwitchSettingCard
from qfluentwidgets import FluentIcon as FIF


def _spin(ms: int) -> None:
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


class SwitchSliderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.switch = SwitchButton()
        self.switch.show()
        _spin(20)

    def tearDown(self) -> None:
        self.switch.hide()
        self.switch.deleteLater()

    def _assert_settled(self) -> None:
        _spin(250)
        expected = 25.0 if self.switch.isChecked() else 5.0
        self.assertAlmostEqual(self.switch.indicator.sliderX, expected, delta=0.5)

    def test_rapid_on_off_on_ends_on_the_right(self) -> None:
        # До фикса: checked=True, а кружок оставался на x=5 («выкл»).
        self.switch.setChecked(True)
        self.switch.setChecked(False)
        self.switch.setChecked(True)
        self.assertTrue(self.switch.isChecked())
        self._assert_settled()

    def test_resync_while_gui_thread_blocked(self) -> None:
        self.switch.setChecked(True)
        time.sleep(0.2)
        self.switch.setChecked(False)
        self.switch.setChecked(True)
        self._assert_settled()

    def test_reverse_mid_animation(self) -> None:
        self.switch.setChecked(True)
        _spin(60)
        self.switch.setChecked(False)
        _spin(20)
        self.switch.setChecked(True)
        self._assert_settled()
        self.switch.setChecked(False)
        _spin(30)
        self.switch.setChecked(True)
        self.switch.setChecked(False)
        self._assert_settled()

    def test_hidden_switch_snaps_immediately(self) -> None:
        self.switch.hide()
        self.switch.setChecked(True)
        self.assertEqual(self.switch.indicator.sliderX, 25.0)

    def test_setting_card_switch_is_patched(self) -> None:
        card = SwitchSettingCard(FIF.GLOBE, "VPN (TUN)")
        card.show()
        try:
            button = card.switchButton
            button.setChecked(True)
            button.setChecked(False)
            button.setChecked(True)
            _spin(250)
            self.assertAlmostEqual(button.indicator.sliderX, 25.0, delta=0.5)
        finally:
            card.hide()
            card.deleteLater()


class SwitchTranslationTests(unittest.TestCase):
    def test_setting_card_switch_is_russian(self) -> None:
        from xray_fluent.ui.fluent_fixes import install_translations

        install_translations(app)
        card = SwitchSettingCard(FIF.GLOBE, "Тест")
        try:
            self.assertEqual(card.switchButton.text, "Выкл")
            card.setChecked(True)
            self.assertEqual(card.switchButton.text, "Вкл")
        finally:
            card.deleteLater()


if __name__ == "__main__":
    unittest.main()
