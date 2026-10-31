from __future__ import annotations

import os
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QWidget

from xray_fluent.ui import notifications as n

_app = QApplication.instance() or QApplication([])


class _Clock:
    """Подменный QElapsedTimer: каждый тик «прошло» столько мс."""

    def __init__(self, step: int) -> None:
        self.step = step

    def start(self) -> None:
        pass

    def restart(self) -> int:
        return self.step


class DurationTests(unittest.TestCase):
    def test_longer_text_stays_longer_and_levels_have_floors(self):
        short = n.display_duration_ms("success", "Готово", "ок")
        self.assertEqual(short, 3000)
        self.assertGreaterEqual(n.display_duration_ms("error", "Ошибка", "x"), 8000)
        dns = "Зашифрованный DNS сейчас не отвечает. " * 3
        self.assertGreater(n.display_duration_ms("warning", "Внимание", dns), 8000)
        self.assertLessEqual(n.display_duration_ms("warning", "", "x" * 5000), n.MAX_MS)

    def test_long_flag_and_explicit_minimum(self):
        self.assertEqual(n.Level.parse("warning-long"), n.Level("warning", True))
        self.assertEqual(n.Level.parse("bogus"), n.Level("info", False))
        self.assertGreaterEqual(n.display_duration_ms("info-long", "", "x"), n.LONG_MIN_MS)
        self.assertEqual(n.display_duration_ms("info", "", "x", min_ms=45_000), 45_000)


class NotificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.window = QWidget()
        self.window.resize(900, 600)
        self.window.show()
        self.notifier = n.Notifier(self.window)
        active = patch.object(QWidget, "isActiveWindow", return_value=True)
        active.start()
        self.addCleanup(active.stop)

    def tearDown(self) -> None:
        self.window.close()
        self.window.deleteLater()
        QApplication.processEvents()

    def tick(self, bar: n.Notification, ms: int) -> None:
        bar._clock = _Clock(ms)
        bar._tick()

    def test_counts_down_and_fades_out(self):
        bar = self.notifier.show("success", "ок")
        self.assertEqual(bar.remaining_ms, 3000)
        self.tick(bar, 1000)
        self.assertEqual(bar.remaining_ms, 2000)
        self.tick(bar, 2500)
        self.assertTrue(bar.closing)

    def test_hover_pauses_and_leaving_gives_grace(self):
        bar = self.notifier.show("success", "ок")
        self.tick(bar, 2900)
        with patch.object(n.Notification, "underMouse", return_value=True):
            for _ in range(50):
                self.tick(bar, 1000)
            self.assertFalse(bar.closing)
            self.assertEqual(bar.remaining_ms, 100)
        bar.leaveEvent(None)
        self.assertEqual(bar.remaining_ms, n.LEAVE_GRACE_MS)

    def test_inactive_or_minimized_window_pauses(self):
        bar = self.notifier.show("info", "текст")
        before = bar.remaining_ms
        with patch.object(QWidget, "isActiveWindow", return_value=False):
            self.tick(bar, 5000)
        with patch.object(QWidget, "isMinimized", return_value=True):
            self.tick(bar, 5000)
        self.assertEqual(bar.remaining_ms, before)

    def test_mouse_rescues_fading_notification(self):
        bar = self.notifier.show("success", "ок")
        self.tick(bar, 5000)
        self.assertTrue(bar.closing)
        bar.enterEvent(None)
        self.assertFalse(bar.closing)
        self.assertEqual(bar.opacityEffect.opacity(), 1)
        self.assertGreaterEqual(bar.remaining_ms, n.LEAVE_GRACE_MS)

    def test_same_message_extends_instead_of_stacking(self):
        first = self.notifier.show("warning", "Буфер обмена пуст")
        self.tick(first, 4000)
        again = self.notifier.show("warning", "Буфер обмена пуст")
        self.assertIs(again, first)
        self.assertEqual(len(self.notifier.visible()), 1)
        self.assertEqual(first.remaining_ms, n.display_duration_ms("warning", "Внимание", "Буфер обмена пуст"))

    def test_limit_drops_oldest_but_keeps_sticky_progress(self):
        progress = self.notifier.show("info", "1/10", title="Пинг серверов", sticky=True)
        bars = [self.notifier.show("info", f"сообщение {i}") for i in range(n.MAX_VISIBLE + 2)]
        self.assertFalse(progress.closing)
        live = [bar for bar in self.notifier.visible() if not bar.closing]
        self.assertEqual(len(live), n.MAX_VISIBLE)
        self.assertTrue(bars[0].closing)
        self.assertFalse(bars[-1].closing)

    def test_sticky_waits_until_owner_starts_countdown(self):
        bar = self.notifier.show("info", "1/10", title="Тест скорости", sticky=True)
        self.tick(bar, 600_000)
        self.assertFalse(bar.closing)
        bar.set_content("Завершено 10/10")
        self.assertEqual(bar.content, "Завершено 10/10")
        bar.expire_in(4000)
        self.assertFalse(bar.sticky)
        self.tick(bar, 4000)
        self.assertTrue(bar.closing)

    def test_notify_reuses_window_queue(self):
        child = QWidget(self.window)
        self.assertIs(n.notifier_for(child), self.notifier)
        bar = n.notify(child, "error", "нет сети")
        self.assertIn(bar, self.notifier.visible())
        self.assertEqual(bar.title, "Ошибка")


if __name__ == "__main__":
    unittest.main()
