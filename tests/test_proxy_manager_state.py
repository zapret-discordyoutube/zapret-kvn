from __future__ import annotations

import inspect
import tempfile
import unittest
from pathlib import Path

from xray_fluent.platform.windows import proxy_manager
from xray_fluent.constants import PROXY_HOST
from xray_fluent.platform.windows.proxy_manager import (
    INTERNET_POLICY_KEY,
    INTERNET_SETTINGS_KEY,
    ProxyManager,
    SystemProxyState,
)


OUR_PROXY_SERVER = (
    f"http={PROXY_HOST}:10809;https={PROXY_HOST}:10809;socks={PROXY_HOST}:10808"
)
FOREIGN_PROXY_SERVER = "http=proxy.corp.example:8080;https=proxy.corp.example:8080"


class _FakeKeyHandle:
    def __init__(self, values: dict[str, tuple[object, int]]) -> None:
        self.values = values

    def __enter__(self) -> "_FakeKeyHandle":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


class FakeWinreg:
    """Минимальный in-memory winreg: только то, что использует ProxyManager."""

    HKEY_CURRENT_USER = "HKCU"
    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_READ = 0x20019
    KEY_SET_VALUE = 0x0002
    REG_SZ = 1
    REG_DWORD = 4

    def __init__(self) -> None:
        self.hives: dict[tuple[str, str], dict[str, tuple[object, int]]] = {}

    @staticmethod
    def _key_id(hive: str, subkey: str) -> tuple[str, str]:
        return (hive, subkey.lower())

    def create_key(self, hive: str, subkey: str) -> dict[str, tuple[object, int]]:
        return self.hives.setdefault(self._key_id(hive, subkey), {})

    def set_value(self, hive: str, subkey: str, name: str, value: object, value_type: int = REG_SZ) -> None:
        self.create_key(hive, subkey)[name] = (value, value_type)

    def get_value(self, hive: str, subkey: str, name: str) -> object:
        return self.hives[self._key_id(hive, subkey)][name][0]

    def has_value(self, hive: str, subkey: str, name: str) -> bool:
        return name in self.hives.get(self._key_id(hive, subkey), {})

    # winreg API surface used by ProxyManager
    def OpenKey(self, hive: str, subkey: str, reserved: int, access: int) -> _FakeKeyHandle:
        key_id = self._key_id(hive, subkey)
        if key_id not in self.hives:
            raise FileNotFoundError(f"registry key not found: {hive}\\{subkey}")
        return _FakeKeyHandle(self.hives[key_id])

    def QueryValueEx(self, key: _FakeKeyHandle, name: str) -> tuple[object, int]:
        if name not in key.values:
            raise FileNotFoundError(f"registry value not found: {name}")
        return key.values[name]

    def SetValueEx(self, key: _FakeKeyHandle, name: str, reserved: int, value_type: int, value: object) -> None:
        key.values[name] = (value, value_type)


class ProxyManagerFakeRegistryTestCase(unittest.TestCase):
    """Тесты ProxyManager на фейковом реестре (запускаются на Linux)."""

    def setUp(self) -> None:
        self.fake = FakeWinreg()
        self.fake.create_key(FakeWinreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY)
        self._original_winreg = proxy_manager.winreg
        proxy_manager.winreg = self.fake
        self.addCleanup(self._restore_winreg)

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.manager = ProxyManager()
        self.manager._backup_file = Path(self._tmp.name) / "system_proxy_backup.json"

    def _restore_winreg(self) -> None:
        proxy_manager.winreg = self._original_winreg

    def _set_hkcu(self, name: str, value: object, value_type: int = FakeWinreg.REG_SZ) -> None:
        self.fake.set_value(FakeWinreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, name, value, value_type)

    def _hkcu_value(self, name: str) -> object:
        return self.fake.get_value(FakeWinreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, name)

    # --- AC1: policy redirect / PAC / is_ours ---

    def test_query_state_reads_hkcu_by_default(self) -> None:
        self._set_hkcu("ProxyEnable", 1, FakeWinreg.REG_DWORD)
        self._set_hkcu("ProxyServer", OUR_PROXY_SERVER)
        state = self.manager.query_state()
        self.assertIsInstance(state, SystemProxyState)
        self.assertTrue(state.supported)
        self.assertTrue(state.enabled)
        self.assertEqual(state.source, "hkcu")
        self.assertEqual(state.server, OUR_PROXY_SERVER)

    def test_policy_per_user_zero_redirects_to_hklm(self) -> None:
        self.fake.set_value(
            FakeWinreg.HKEY_LOCAL_MACHINE, INTERNET_POLICY_KEY,
            "ProxySettingsPerUser", 0, FakeWinreg.REG_DWORD,
        )
        self.fake.set_value(
            FakeWinreg.HKEY_LOCAL_MACHINE, INTERNET_SETTINGS_KEY,
            "ProxyEnable", 1, FakeWinreg.REG_DWORD,
        )
        self.fake.set_value(
            FakeWinreg.HKEY_LOCAL_MACHINE, INTERNET_SETTINGS_KEY,
            "ProxyServer", FOREIGN_PROXY_SERVER,
        )
        # В HKCU лежат другие значения — они должны быть проигнорированы.
        self._set_hkcu("ProxyEnable", 0, FakeWinreg.REG_DWORD)
        self._set_hkcu("ProxyServer", OUR_PROXY_SERVER)

        state = self.manager.query_state()
        self.assertEqual(state.source, "hklm-policy")
        self.assertTrue(state.enabled)
        self.assertEqual(state.server, FOREIGN_PROXY_SERVER)
        self.assertFalse(state.is_ours)

    def test_policy_per_user_one_keeps_hkcu(self) -> None:
        self.fake.set_value(
            FakeWinreg.HKEY_LOCAL_MACHINE, INTERNET_POLICY_KEY,
            "ProxySettingsPerUser", 1, FakeWinreg.REG_DWORD,
        )
        self._set_hkcu("ProxyEnable", 1, FakeWinreg.REG_DWORD)
        self._set_hkcu("ProxyServer", OUR_PROXY_SERVER)
        state = self.manager.query_state()
        self.assertEqual(state.source, "hkcu")
        self.assertTrue(state.is_ours)

    def test_autoconfig_url_detected(self) -> None:
        self._set_hkcu("AutoConfigURL", "http://corp.example/proxy.pac")
        state = self.manager.query_state()
        self.assertEqual(state.autoconfig_url, "http://corp.example/proxy.pac")
        self.assertFalse(state.enabled)

    def test_is_ours_positive(self) -> None:
        self._set_hkcu("ProxyEnable", 1, FakeWinreg.REG_DWORD)
        self._set_hkcu("ProxyServer", OUR_PROXY_SERVER)
        state = self.manager.query_state()
        self.assertTrue(state.is_ours)
        self.assertTrue(self.manager.is_enabled())

    def test_is_ours_negative_foreign_server(self) -> None:
        self._set_hkcu("ProxyEnable", 1, FakeWinreg.REG_DWORD)
        self._set_hkcu("ProxyServer", FOREIGN_PROXY_SERVER)
        state = self.manager.query_state()
        self.assertTrue(state.enabled)
        self.assertFalse(state.is_ours)

    def test_is_ours_false_when_disabled(self) -> None:
        self._set_hkcu("ProxyEnable", 0, FakeWinreg.REG_DWORD)
        self._set_hkcu("ProxyServer", OUR_PROXY_SERVER)
        state = self.manager.query_state()
        self.assertFalse(state.enabled)
        self.assertFalse(state.is_ours)

    def test_is_our_proxy_server_string_matching(self) -> None:
        self.assertTrue(ProxyManager.is_our_proxy_server(OUR_PROXY_SERVER))
        self.assertTrue(
            ProxyManager.is_our_proxy_server(
                f"http={PROXY_HOST}:1; https={PROXY_HOST}:2; socks={PROXY_HOST}:3"
            )
        )
        self.assertFalse(ProxyManager.is_our_proxy_server(""))
        self.assertFalse(ProxyManager.is_our_proxy_server("192.168.1.10:3128"))
        self.assertFalse(ProxyManager.is_our_proxy_server(FOREIGN_PROXY_SERVER))
        # Одна лишь http-запись на 127.0.0.1 не считается нашей связкой.
        self.assertFalse(ProxyManager.is_our_proxy_server(f"http={PROXY_HOST}:8080"))

    # --- AC2/AC3: enable/disable через фейковый реестр ---

    def test_enable_writes_our_proxy_and_backup(self) -> None:
        self._set_hkcu("ProxyEnable", 0, FakeWinreg.REG_DWORD)
        self.manager.enable(http_port=10809, socks_port=10808)
        self.assertEqual(int(self._hkcu_value("ProxyEnable")), 1)
        self.assertTrue(ProxyManager.is_our_proxy_server(str(self._hkcu_value("ProxyServer"))))
        self.assertTrue(self.manager.has_backup())
        self.assertTrue(self.manager.query_state().is_ours)

    def test_disable_without_backup_clears_residue(self) -> None:
        self._set_hkcu("ProxyEnable", 1, FakeWinreg.REG_DWORD)
        self._set_hkcu("ProxyServer", OUR_PROXY_SERVER)
        self.assertFalse(self.manager.has_backup())

        self.manager.disable(restore_previous=True)

        self.assertEqual(int(self._hkcu_value("ProxyEnable")), 0)
        self.assertEqual(str(self._hkcu_value("ProxyServer")), "")

    def test_disable_restores_backup(self) -> None:
        self._set_hkcu("ProxyEnable", 1, FakeWinreg.REG_DWORD)
        self._set_hkcu("ProxyServer", FOREIGN_PROXY_SERVER)
        self._set_hkcu("ProxyOverride", "<local>")
        self.manager.enable(http_port=10809, socks_port=10808)
        self.assertTrue(self.manager.query_state().is_ours)

        self.manager.disable(restore_previous=True)

        self.assertEqual(int(self._hkcu_value("ProxyEnable")), 1)
        self.assertEqual(str(self._hkcu_value("ProxyServer")), FOREIGN_PROXY_SERVER)
        self.assertFalse(self.manager.has_backup())

    # --- AC3: ownership-гейт ---

    def test_should_auto_disable_true_for_our_proxy(self) -> None:
        self._set_hkcu("ProxyEnable", 1, FakeWinreg.REG_DWORD)
        self._set_hkcu("ProxyServer", OUR_PROXY_SERVER)
        self.assertTrue(self.manager.should_auto_disable())

    def test_should_auto_disable_false_for_foreign_proxy(self) -> None:
        self._set_hkcu("ProxyEnable", 1, FakeWinreg.REG_DWORD)
        self._set_hkcu("ProxyServer", FOREIGN_PROXY_SERVER)
        self.assertFalse(self.manager.should_auto_disable())

    def test_should_auto_disable_true_when_backup_exists(self) -> None:
        self.manager._backup_file.write_text('{"ProxyEnable": 0, "ProxyServer": ""}', encoding="utf-8")
        self.assertTrue(self.manager.should_auto_disable())

    def test_release_if_owned_skips_foreign_proxy(self) -> None:
        self._set_hkcu("ProxyEnable", 1, FakeWinreg.REG_DWORD)
        self._set_hkcu("ProxyServer", FOREIGN_PROXY_SERVER)

        released = self.manager.release_if_owned(restore_previous=True)

        self.assertFalse(released)
        # Чужой прокси остался нетронутым.
        self.assertEqual(int(self._hkcu_value("ProxyEnable")), 1)
        self.assertEqual(str(self._hkcu_value("ProxyServer")), FOREIGN_PROXY_SERVER)

    def test_release_if_owned_disables_our_proxy(self) -> None:
        self._set_hkcu("ProxyEnable", 1, FakeWinreg.REG_DWORD)
        self._set_hkcu("ProxyServer", OUR_PROXY_SERVER)

        released = self.manager.release_if_owned(restore_previous=True)

        self.assertTrue(released)
        self.assertEqual(int(self._hkcu_value("ProxyEnable")), 0)
        self.assertEqual(str(self._hkcu_value("ProxyServer")), "")


class OwnershipGateWiringTestCase(unittest.TestCase):
    """Пути runtime_services/connection_service/main.py используют гейт."""

    def test_shutdown_path_uses_ownership_gate(self) -> None:
        from xray_fluent.application import runtime_services

        source = inspect.getsource(runtime_services)
        self.assertIn("proxy.release_if_owned(", source)
        self.assertNotIn("if controller.proxy.is_enabled():\n        controller.proxy.disable", source)

    def test_tun_start_path_uses_ownership_gate(self) -> None:
        from xray_fluent.application import connection_service

        source = inspect.getsource(connection_service)
        self.assertIn("proxy.release_if_owned(", source)

    def test_main_exit_safety_net_uses_ownership_gate(self) -> None:
        import main

        source = inspect.getsource(main)
        self.assertIn("release_if_owned(", source)
        self.assertNotIn("_looks_like_app_proxy", source)
        self.assertNotIn("import winreg", source)


class NonWindowsFallbackTestCase(unittest.TestCase):
    """Без winreg (Linux) все вызовы — безопасные no-op."""

    def setUp(self) -> None:
        self._original_winreg = proxy_manager.winreg
        proxy_manager.winreg = None
        self.addCleanup(self._restore_winreg)
        self.manager = ProxyManager()

    def _restore_winreg(self) -> None:
        proxy_manager.winreg = self._original_winreg

    def test_query_state_unsupported(self) -> None:
        state = self.manager.query_state()
        self.assertFalse(state.supported)
        self.assertFalse(state.enabled)
        self.assertFalse(state.is_ours)

    def test_calls_do_not_raise(self) -> None:
        self.assertFalse(self.manager.is_enabled())
        self.assertFalse(self.manager.should_auto_disable())
        self.assertFalse(self.manager.release_if_owned())
        self.manager.enable(http_port=10809, socks_port=10808)
        self.manager.disable(restore_previous=True)


if __name__ == "__main__":
    unittest.main()
