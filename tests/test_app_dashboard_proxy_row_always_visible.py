"""The system-proxy row of the main screen never disappears (owner 2026-11-27: "the proxy option disappeared in three places,
it was always on top, fix it so that it never disappears; a separate shield icon with the status is better").

Until 0.8.138 `_refresh_mode_card` hid the «Системный прокси Windows» row in the VPN (TUN) mode, and the address row and
the «Добавить в Telegram» button whenever the proxy was not running. Real DashboardPage with real settings objects in every
mode and connection state: none of the three may be hidden, the shield shows the state, and the controls that cannot act say
why instead of vanishing. Keep the ``test_app_*`` prefix (QApplication).
"""

from __future__ import annotations

import itertools
import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
app = _existing if isinstance(_existing, QApplication) else (_existing or QApplication([]))

from xray_fluent.profiles.models import AppSettings
from xray_fluent.ui.dashboard_page import DashboardPage


class ProxyRowAlwaysVisibleTests(unittest.TestCase):
    def _page(self, *, tun: bool, connected: bool, engine: str = "singbox", system_proxy: bool = False) -> DashboardPage:
        page = DashboardPage()
        page.set_settings_snapshot(AppSettings(tun_mode=tun, proxy_engine=engine, enable_system_proxy=system_proxy))
        if connected:
            page.set_proxy_ports(1392, 1393)
        page.set_connection(connected)
        page._do_refresh_dashboard()
        return page

    def test_the_three_places_are_never_hidden_in_any_mode_or_state(self) -> None:
        for tun, connected, engine in itertools.product((False, True), (False, True), ("singbox", "xray")):
            with self.subTest(tun=tun, connected=connected, engine=engine):
                page = self._page(tun=tun, connected=connected, engine=engine)
                for name in ("proxy_options", "proxy_address_row", "connection_ports_label", "telegram_proxy_btn", "proxy_shield"):
                    self.assertFalse(getattr(page, name).isHidden(), name)
                page.deleteLater()
                QApplication.processEvents()

    def test_the_telegram_button_acts_only_with_a_live_proxy_and_says_why_otherwise(self) -> None:
        live = self._page(tun=False, connected=True)
        self.assertTrue(live.telegram_proxy_btn.isEnabled())
        self.assertIn("SOCKS5: 127.0.0.1:1392", live.connection_ports_label.text())
        idle = self._page(tun=False, connected=False)
        self.assertFalse(idle.telegram_proxy_btn.isEnabled())
        self.assertIn("после подключения", idle.telegram_proxy_btn.toolTip())
        tunnel = self._page(tun=True, connected=True)
        self.assertFalse(tunnel.telegram_proxy_btn.isEnabled())
        self.assertIn("TUN", tunnel.telegram_proxy_btn.toolTip())
        for page in (live, idle, tunnel):
            page.deleteLater()
        QApplication.processEvents()

    def test_the_shield_shows_the_state_and_names_it_in_the_tooltip(self) -> None:
        tunnel_on = self._page(tun=True, connected=True)
        self.assertEqual(tunnel_on.proxy_shield.state, "on")
        self.assertIn("весь трафик", tunnel_on.proxy_shield.toolTip())
        tunnel_off = self._page(tun=True, connected=False)
        self.assertEqual(tunnel_off.proxy_shield.state, "off")
        proxy_off = self._page(tun=False, connected=False)
        self.assertEqual(proxy_off.proxy_shield.state, "off")
        self.assertIn("выключен", proxy_off.proxy_shield.toolTip())
        proxy_set = self._page(tun=False, connected=False, system_proxy=True)
        self.assertEqual(proxy_set.proxy_shield.state, "on")
        self.assertIn("включён", proxy_set.proxy_shield.toolTip())
        proxy_on = self._page(tun=False, connected=False)
        proxy_on._proxy_intent.request(True)
        proxy_on._sync_switches()
        self.assertEqual(proxy_on.proxy_shield.state, "applying")
        for page in (tunnel_on, tunnel_off, proxy_off, proxy_set, proxy_on):
            page.deleteLater()
        QApplication.processEvents()

    def test_the_switch_is_inactive_but_present_in_vpn_mode_and_explains_it(self) -> None:
        page = self._page(tun=True, connected=False)
        self.assertFalse(page.proxy_switch.isEnabled())
        self.assertIn("TUN", page.proxy_hint_label.text())
        page.deleteLater()
        QApplication.processEvents()


if __name__ == "__main__":
    unittest.main()
