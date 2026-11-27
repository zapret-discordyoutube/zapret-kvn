"""The background update waits while the person is at the computer with the connection on (owner investigation 2026-11-27).

Why: the busy check of the update core protects only full-screen games (``zapret_update.screen.is_fullscreen``), and the
default «Устанавливать автоматически» restarts the program, which cuts the connection and the game with it. Releases came out
every one to two hours on 2026-11-26/27.
"""

from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from xray_fluent.updates import update_signal, user_activity
from xray_fluent.updates.update_signal import UpdateSignal
from zapret_update import screen


class UserIsActiveTests(unittest.TestCase):
    def test_recent_input_is_active_and_a_long_pause_is_not(self) -> None:
        threshold = user_activity.ACTIVE_USER_SECONDS
        for idle, expected in ((0.0, True), (12.0, True), (threshold - 1, True), (threshold, False), (3600.0, False)):
            with self.subTest(idle=idle):
                self.assertEqual(expected, user_activity.user_is_active(idle))

    def test_an_unknown_idle_time_never_blocks_the_update(self) -> None:
        self.assertFalse(user_activity.user_is_active(None))

    @unittest.skipUnless(sys.platform == "win32", "GetLastInputInfo exists on Windows only")
    def test_windows_reports_a_plausible_idle_time(self) -> None:
        idle = user_activity.idle_seconds()
        self.assertIsNotNone(idle)
        self.assertGreaterEqual(idle, 0.0)
        self.assertLess(idle, 60 * 60 * 24 * 49, "the tick counter wraps every 49 days: the value must stay unsigned")

    @unittest.skipIf(sys.platform == "win32", "off Windows there is nothing to ask")
    def test_off_windows_the_answer_is_unknown(self) -> None:
        self.assertIsNone(user_activity.idle_seconds())


class WindowedGameIsNotInvisibleTests(unittest.TestCase):
    """The case that cut a windowed WoW: Windows says «can show notifications» (5) and the game has a title bar."""

    def test_the_old_rule_alone_lets_a_windowed_game_be_updated_over(self) -> None:
        for label, state, foreground in (
            ("windowed", 5, screen.FOREGROUND_PART),
            ("maximized with a title bar", 5, screen.FOREGROUND_FULL),
        ):
            with self.subTest(label=label):
                self.assertFalse(screen.is_fullscreen(state, foreground), "the update core does not see this game: that is the gap")

    def _signal(self, *, connected: bool) -> UpdateSignal:
        return UpdateSignal(
            is_enabled=lambda: True,
            window_shown=lambda: False,
            connected=lambda: connected,
            watcher_factory=lambda **kwargs: SimpleNamespace(reachable=None, start=Mock(), stop=Mock()),
        )

    def test_connected_and_typing_waits(self) -> None:
        signal = self._signal(connected=True)
        with patch.object(update_signal, "fullscreen_app_active", return_value=False), patch.object(
            update_signal, "idle_seconds", return_value=4.0
        ):
            self.assertIn("за компьютером", signal.busy_reason())

    def test_connected_and_away_installs(self) -> None:
        signal = self._signal(connected=True)
        with patch.object(update_signal, "fullscreen_app_active", return_value=False), patch.object(
            update_signal, "idle_seconds", return_value=user_activity.ACTIVE_USER_SECONDS + 60
        ):
            self.assertEqual("", signal.busy_reason())

    def test_not_connected_installs_even_while_typing(self) -> None:
        signal = self._signal(connected=False)
        with patch.object(update_signal, "fullscreen_app_active", return_value=False), patch.object(
            update_signal, "idle_seconds", return_value=1.0
        ):
            self.assertEqual("", signal.busy_reason(), "a restart cuts nothing when there is no connection")

    def test_a_full_screen_game_still_waits_first(self) -> None:
        signal = self._signal(connected=False)
        with patch.object(update_signal, "fullscreen_app_active", return_value=True):
            self.assertIn("на весь экран", signal.busy_reason())

    def test_a_broken_connection_probe_does_not_block_forever(self) -> None:
        def boom() -> bool:
            raise RuntimeError("controller is gone")

        signal = UpdateSignal(
            is_enabled=lambda: True,
            window_shown=lambda: False,
            connected=boom,
            watcher_factory=lambda **kwargs: SimpleNamespace(reachable=None, start=Mock(), stop=Mock()),
        )
        with patch.object(update_signal, "fullscreen_app_active", return_value=False), patch.object(
            update_signal, "idle_seconds", return_value=1.0
        ):
            self.assertEqual("", signal.busy_reason())


if __name__ == "__main__":
    unittest.main()
