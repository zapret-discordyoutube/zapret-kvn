"""WinDivert after «Пакеты-обманки»: unloaded once the spoofing core exited, never under winws2.

Owner 2026-11-16: when spoofing is turned off, the session stops or the app exits, WinDivert
is unloaded and available again.
"""
from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from PyQt6.QtCore import QCoreApplication, QProcess

from xray_fluent.engines import windivert_release
from xray_fluent.engines.singbox.manager import SingBoxManager

_APP = QCoreApplication.instance() or QCoreApplication([])

_SPOOF_CONFIG = {"route": {"rules": [
    {"inbound": ["__app_hybrid_protect_in"], "domain": ["srv.example"], "action": "route-options",
     "tls_spoof": "vk.com", "tls_spoof_method": "wrong-sequence"},
]}}


class DecisionTests(unittest.TestCase):
    def test_running_driver_without_other_users_is_released(self) -> None:
        self.assertTrue(windivert_release.decide(state="running", users=[]).release)

    def test_winws2_keeps_the_shared_driver(self) -> None:
        decision = windivert_release.decide(state="running", users=["winws2.exe"])
        self.assertFalse(decision.release)
        self.assertIn("winws2.exe", decision.message)

    def test_nothing_to_do_when_not_loaded(self) -> None:
        for state in (None, "stopped"):
            self.assertFalse(windivert_release.decide(state=state, users=[]).release)
        self.assertFalse(windivert_release.decide(state="stop_pending", users=[]).release)

    def test_release_stops_and_waits_until_the_service_is_gone(self) -> None:
        states = iter(["running", "stop_pending", None])
        stop = Mock(return_value=True)
        outcome = windivert_release.release_if_unused(query=lambda: next(states), stop=stop, users=list)
        stop.assert_called_once_with()
        self.assertEqual("WinDivert выгружен, драйвер свободен", outcome)

    def test_release_never_stops_under_another_user(self) -> None:
        stop = Mock(return_value=True)
        outcome = windivert_release.release_if_unused(
            query=lambda: "running", stop=stop, users=lambda: ["winws2.exe"])
        stop.assert_not_called()
        self.assertIn("оставлен", outcome)


class ManagerTests(unittest.TestCase):
    def _manager(self, *, pending: bool) -> tuple[SingBoxManager, list[str]]:
        manager = SingBoxManager()
        fake = Mock()
        fake.state.return_value = QProcess.ProcessState.NotRunning
        manager._process = fake
        manager._windivert_pending = pending
        notices: list[str] = []
        manager.notice.connect(notices.append)
        return manager, notices

    def test_stop_after_a_spoofing_core_releases_the_driver_once(self) -> None:
        manager, notices = self._manager(pending=True)
        with patch.object(windivert_release, "release_if_unused", return_value="WinDivert выгружен, драйвер свободен") as release:
            self.assertTrue(manager.stop())
            self.assertTrue(manager.stop())
        release.assert_called_once_with()
        self.assertEqual(["WinDivert выгружен, драйвер свободен"], notices)

    def test_core_without_spoof_never_touches_the_driver(self) -> None:
        manager, notices = self._manager(pending=False)
        with patch.object(windivert_release, "release_if_unused") as release:
            self.assertTrue(manager.stop())
        release.assert_not_called()
        self.assertEqual([], notices)

    def test_config_with_tls_spoof_marks_the_driver_for_release(self) -> None:
        from xray_fluent.masking import desync

        self.assertTrue(desync.uses_windivert(_SPOOF_CONFIG))
        self.assertFalse(desync.uses_windivert({"route": {"rules": [{"action": "route-options", "kvn_desync": "disorder:sni"}]}}))


if __name__ == "__main__":
    unittest.main()
