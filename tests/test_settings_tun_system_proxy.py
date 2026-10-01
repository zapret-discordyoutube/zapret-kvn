"""Возврат из «VPN (TUN)» в «Прокси» возвращает прежний системный прокси."""

from __future__ import annotations

import unittest
from pathlib import Path

from xray_fluent.profiles.models import AppSettings

MAIN_WINDOW = Path(__file__).resolve().parents[1] / "xray_fluent" / "ui" / "main_window.py"


class TunSystemProxyTests(unittest.TestCase):
    def test_round_trip_restores_enabled_system_proxy(self) -> None:
        settings = AppSettings()
        self.assertTrue(settings.enable_system_proxy)
        settings.set_tun_mode(True)
        self.assertTrue(settings.tun_mode)
        self.assertFalse(settings.enable_system_proxy)
        settings.set_tun_mode(False)
        self.assertFalse(settings.tun_mode)
        self.assertTrue(settings.enable_system_proxy)

    def test_round_trip_keeps_system_proxy_the_user_turned_off(self) -> None:
        settings = AppSettings(enable_system_proxy=False)
        settings.set_tun_mode(True)
        settings.set_tun_mode(False)
        self.assertFalse(settings.enable_system_proxy)

    def test_choice_survives_restart_in_tun_mode(self) -> None:
        settings = AppSettings()
        settings.set_tun_mode(True)
        restored = AppSettings.from_dict(settings.to_dict())
        restored.set_tun_mode(False)
        self.assertTrue(restored.enable_system_proxy)

    def test_repeated_switch_to_same_mode_changes_nothing(self) -> None:
        settings = AppSettings()
        settings.set_tun_mode(True)
        settings.set_tun_mode(True)  # не должен запомнить «выключен» поверх выбора
        settings.set_tun_mode(False)
        self.assertTrue(settings.enable_system_proxy)
        settings.enable_system_proxy = False
        settings.set_tun_mode(False)
        self.assertFalse(settings.enable_system_proxy)

    def test_state_saved_before_this_field_existed_gets_system_proxy_back(self) -> None:
        """Кто обновился, сидя в VPN (TUN), при возврате получает умолчание — включён."""
        data = AppSettings(tun_mode=True, enable_system_proxy=False).to_dict()
        del data["system_proxy_before_tun"]
        settings = AppSettings.from_dict(data)
        settings.set_tun_mode(False)
        self.assertTrue(settings.enable_system_proxy)

    def test_dashboard_switch_goes_through_set_tun_mode(self) -> None:
        source = MAIN_WINDOW.read_text(encoding="utf-8")
        handler = source[source.index("def _on_dashboard_tun_toggled"):source.index("def _on_dashboard_proxy_toggled")]
        self.assertIn("settings.set_tun_mode(checked)", handler)
        self.assertNotIn("enable_system_proxy", handler)
        owned = source[source.index("_WINDOW_OWNED_SETTINGS = tuple("):]
        self.assertIn('"system_proxy_before_tun"', owned[: owned.index(")\n\n")])


if __name__ == "__main__":
    unittest.main()
