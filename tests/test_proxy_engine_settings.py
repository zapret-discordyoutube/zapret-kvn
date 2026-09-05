import unittest

from xray_fluent.profiles.models import AppSettings


class ProxyEngineSettingsTests(unittest.TestCase):
    def test_new_and_legacy_states_default_to_singbox_proxy(self) -> None:
        self.assertEqual(AppSettings().proxy_engine, "singbox")
        self.assertEqual(AppSettings.from_dict({}).proxy_engine, "singbox")

    def test_legacy_engines_migrate_without_auto_connecting_different_rules(self) -> None:
        for settings in (AppSettings(proxy_engine="xray"), AppSettings(tun_engine="xray"),
                         AppSettings(tun_engine="tun2socks")):
            with self.subTest(settings=settings):
                settings.xray_config_file = "custom-rules.json"
                restored = AppSettings.from_dict(settings.to_dict())
                self.assertEqual(restored.proxy_engine, "singbox")
                self.assertEqual(restored.tun_engine, "singbox")
                self.assertFalse(restored.auto_connect_last)
                self.assertEqual(restored.xray_config_file, "custom-rules.json")

    def test_singbox_auto_connect_is_preserved(self) -> None:
        self.assertTrue(AppSettings.from_dict(AppSettings().to_dict()).auto_connect_last)


if __name__ == "__main__":
    unittest.main()
