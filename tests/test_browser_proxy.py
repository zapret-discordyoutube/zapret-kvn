from __future__ import annotations

import json
import unittest
from unittest.mock import Mock, patch

from xray_fluent.platform.windows import browser_proxy as bp

PORTS = (10808, 10809)


def _prefs(ext_id: str = "abc", *, mode: str = "direct", server: str = "", enabled: bool = True,
           scope: str = "preferences", name: str = "Proxy SwitchyOmega 3 (ZeroOmega)") -> dict:
    entry: dict = {
        "manifest": {"name": name},
        scope: {"proxy": {"mode": mode, "server": server}},
    }
    if not enabled:
        entry["disable_reasons"] = [1]
    return {"extensions": {"settings": {ext_id: entry}}}


class PolicyTests(unittest.TestCase):
    def test_system_or_absent_policy_is_fine(self) -> None:
        self.assertIsNone(bp.policy_bypass("Google Chrome", {}, PORTS))
        self.assertIsNone(bp.policy_bypass("Google Chrome", {"ProxyMode": "system"}, PORTS))
        self.assertIsNone(bp.policy_bypass("Google Chrome", {"ProxyServerMode": 3}, PORTS))

    def test_direct_policy_bypasses_the_system_proxy(self) -> None:
        hit = bp.policy_bypass("Google Chrome", {"ProxyMode": "direct"}, PORTS)
        self.assertEqual((hit.source, hit.mode), ("policy", "direct"))
        self.assertEqual(bp.policy_bypass("Google Chrome", {"ProxyServerMode": 0}, PORTS).mode, "direct")

    def test_proxy_settings_json_wins_and_own_port_is_fine(self) -> None:
        values = {
            "ProxyMode": "direct",
            "ProxySettings": json.dumps({"ProxyMode": "fixed_servers", "ProxyServer": "127.0.0.1:10808"}),
        }
        self.assertIsNone(bp.policy_bypass("Google Chrome", values, PORTS))
        values["ProxySettings"] = json.dumps({"ProxyMode": "fixed_servers", "ProxyServer": "10.0.0.5:3128"})
        self.assertEqual(bp.policy_bypass("Google Chrome", values, PORTS).mode, "fixed_servers")


class ExtensionTests(unittest.TestCase):
    def test_extension_set_to_direct_is_found_with_its_name(self) -> None:
        [hit] = bp.extension_bypasses("Google Chrome", _prefs(), PORTS)
        self.assertEqual((hit.source, hit.mode), ("extension", "direct"))
        self.assertIn("ZeroOmega", hit.detail)

    def test_harmless_extensions_are_ignored(self) -> None:
        for prefs in (
            _prefs(mode="system"),
            _prefs(enabled=False),
            _prefs(mode="fixed_servers", server="socks5://127.0.0.1:10808"),
            {"extensions": {"settings": {"x": {"manifest": {"name": "uBlock"}}}}},
            {},
        ):
            with self.subTest(prefs=prefs):
                self.assertEqual(bp.extension_bypasses("Google Chrome", prefs, PORTS), [])

    def test_foreign_proxy_and_localized_name(self) -> None:
        prefs = _prefs("ext123", mode="fixed_servers", server="proxy.example:8080",
                       scope="regular_only_preferences", name="__MSG_appName__")
        [hit] = bp.extension_bypasses("Microsoft Edge", prefs, PORTS)
        self.assertEqual(hit.detail, "ext123")
        # Свой прокси расширения на чужом локальном порту — тоже мимо нас.
        self.assertEqual(
            len(bp.extension_bypasses("Google Chrome", _prefs(mode="fixed_servers", server="127.0.0.1:2080"), PORTS)),
            1,
        )


class MessageTests(unittest.TestCase):
    def test_message_names_the_browser_the_cause_and_the_fix(self) -> None:
        text = bp.message([
            bp.ProxyBypass("Google Chrome", "extension", "direct", "ZeroOmega"),
            bp.ProxyBypass("Microsoft Edge", "policy", "direct"),
        ])
        self.assertIn("Google Chrome идёт мимо VPN", text)
        self.assertIn("«ZeroOmega»", text)
        self.assertIn("Системный прокси", text)
        self.assertIn("политикой", text)
        self.assertIn("TUN", text)

    def test_not_windows_finds_nothing(self) -> None:
        with patch.object(bp.sys, "platform", "linux"):
            self.assertEqual(bp.find_bypasses(PORTS), [])


class ControllerHookTests(unittest.TestCase):
    def test_each_bypass_is_reported_once_per_run(self) -> None:
        from xray_fluent.application import controller as module

        controller = Mock()
        controller.__dict__["_browser_bypass_reported"] = set()
        hit = bp.ProxyBypass("Google Chrome", "extension", "direct", "ZeroOmega")
        runs = []
        with (
            patch.object(module.browser_proxy, "find_bypasses", return_value=[hit]),
            patch.object(module, "_BROWSER_CHECK_EXECUTOR") as executor,
        ):
            executor.submit.side_effect = lambda job: runs.append(job) or job()
            module.AppController._check_browsers_take_system_proxy(controller, (10808, 10809))
            module.AppController._check_browsers_take_system_proxy(controller, (10808, 10809))
        self.assertEqual(len(runs), 2)
        controller.status.emit.assert_called_once()
        level, text = controller.status.emit.call_args.args
        self.assertEqual(level, "warning-long")
        self.assertIn("Google Chrome", text)


class OverrideTests(unittest.TestCase):
    def test_lan_bypass_covers_only_private_172(self) -> None:
        from xray_fluent.platform.windows import proxy_manager as pm

        manager = pm.ProxyManager.__new__(pm.ProxyManager)
        manager._backup = {"ProxyEnable": 0}
        written = {}
        with (
            patch.object(pm.ProxyManager, "is_supported", new=True),
            patch.object(pm.ProxyManager, "_write_settings", lambda self, values: written.update(values)),
            patch.object(pm.ProxyManager, "_apply_per_connection", lambda *a, **k: None),
            patch.object(pm.ProxyManager, "_refresh_system_proxy", lambda self: None),
        ):
            manager.enable(10809, 10808, bypass_lan=True)
        parts = written["ProxyOverride"].split(";")
        self.assertNotIn("172.*", parts)
        self.assertIn("172.16.*", parts)
        self.assertIn("172.31.*", parts)
        self.assertNotIn("172.32.*", parts)
        self.assertIn("192.168.*", parts)


if __name__ == "__main__":
    unittest.main()
