"""«Автоматическое переподключение» (owner request 2026-11-27): off means nothing reconnects or switches by itself."""

import unittest
from types import SimpleNamespace

from xray_fluent.application.smart_switch_service import gate_reason
from xray_fluent.application.subscription_service import reconnect_after_update
from xray_fluent.profiles.models import AppSettings, SubscriptionUpdateResult


def _result(required: bool) -> SubscriptionUpdateResult:
    return SubscriptionUpdateResult(subscription_id="s", success=True, message="", reconnect_required=required)


class MasterSwitchTests(unittest.TestCase):
    def test_the_setting_is_on_by_default_and_roundtrips(self) -> None:
        self.assertTrue(AppSettings().auto_reconnect_enabled)
        settings = AppSettings()
        settings.auto_reconnect_enabled = False
        self.assertFalse(AppSettings.from_dict(settings.to_dict()).auto_reconnect_enabled)
        # a state saved before the setting existed keeps the old behaviour
        self.assertTrue(AppSettings.from_dict({}).auto_reconnect_enabled)

    def test_a_subscription_refresh_restarts_only_with_the_switch_on(self) -> None:
        on, off = AppSettings(), AppSettings()
        off.auto_reconnect_enabled = False
        self.assertTrue(reconnect_after_update(on, _result(True), active=True))
        self.assertFalse(reconnect_after_update(off, _result(True), active=True))
        self.assertFalse(reconnect_after_update(on, _result(False), active=True))
        self.assertFalse(reconnect_after_update(on, _result(True), active=False))

    def test_the_smart_switch_is_refused_when_the_master_switch_is_off(self) -> None:
        settings = AppSettings()
        settings.auto_switch_enabled = True
        settings.auto_reconnect_enabled = False
        controller = SimpleNamespace(state=SimpleNamespace(settings=settings), connected=True, _switching=False,
                                     _reconnecting=False)
        self.assertEqual("авто-переключение выключено", gate_reason(controller, 0.0))


if __name__ == "__main__":
    unittest.main()
