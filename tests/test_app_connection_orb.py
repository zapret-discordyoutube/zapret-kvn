"""Сфера подключения: анимация только когда нужна и видна.

Keep the ``test_app_*`` prefix: widget test modules must sort before
``tests/test_engine_process_stop.py`` (see tests/test_app_nodes_page_view.py).
"""

from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QEventLoop, QPointF, Qt, QTimer
from PyQt6.QtGui import QMouseEvent
from PyQt6.QtWidgets import QApplication, QWidget

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError("widget tests need a QApplication")
app = _existing or QApplication([])

from xray_fluent.ui.connection_orb import CONNECTED, CONNECTING, ERROR, IDLE, ConnectionOrb


def _spin(ms: int) -> None:
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


class ConnectionOrbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.window = QWidget()
        cls.orb = ConnectionOrb(cls.window)
        cls.window.show()
        _spin(20)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.window.hide()
        cls.window.deleteLater()

    def setUp(self) -> None:
        self.window.showNormal()
        self.orb.show()
        self.orb.set_state(IDLE)
        _spin(10)

    def test_static_states_do_not_run_a_timer(self) -> None:
        for state in (IDLE, ERROR):
            self.orb.set_state(state)
            self.assertFalse(self.orb.is_animating(), state)

    def test_animated_states_run_only_while_visible(self) -> None:
        for state in (CONNECTING, CONNECTED):
            self.orb.set_state(state)
            self.assertTrue(self.orb.is_animating(), state)
        self.orb.hide()
        self.assertFalse(self.orb.is_animating())
        self.orb.show()
        _spin(10)
        self.assertTrue(self.orb.is_animating())

    def test_minimized_window_pauses_animation(self) -> None:
        self.orb.set_state(CONNECTED)
        self.window.showMinimized()
        _spin(30)
        self.orb._frames._on_timeout()  # кадр на свёрнутом окне сам гасит таймер
        self.assertFalse(self.orb.is_animating())

    def test_every_state_paints(self) -> None:
        for state in (IDLE, CONNECTING, CONNECTED, ERROR):
            self.orb.set_state(state)
            self.assertFalse(self.orb.grab().isNull(), state)

    def test_click_on_center_emits_and_ring_does_not(self) -> None:
        clicks = []
        self.orb.clicked.connect(lambda: clicks.append(1))
        center = QPointF(self.orb.width() / 2, self.orb.height() / 2)
        edge = QPointF(2, self.orb.height() / 2)
        for pos in (center, edge):
            for kind in (QMouseEvent.Type.MouseButtonPress, QMouseEvent.Type.MouseButtonRelease):
                app.sendEvent(self.orb, QMouseEvent(kind, pos, self.orb.mapToGlobal(pos), Qt.MouseButton.LeftButton,
                                                    Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier))
        self.assertEqual(clicks, [1])


if __name__ == "__main__":
    unittest.main()
