"""«Мимо TUN» on the simple-rule page: addresses go into the TUN inbound of the user's JSON (owner request 2026-11-27).

Uses the real ConfigsPage with the shipped sing-box template, like tests/test_app_singbox_routing_page.py (the shared page of
that module is reused: deleting widgets mid-run crashes on Windows).
"""

from __future__ import annotations

import json
import unittest
from unittest import mock

from tests.test_app_singbox_routing_page import _page, _pump, _section
from xray_fluent.singbox_config import tun_bypass
from xray_fluent.ui.singbox.simple_rule_page import BYPASS

WOW = "C:\\Program Files (x86)\\World of Warcraft\\"
CONNECTIONS = [
    (WOW + "_retail_\\Wow.exe", "137.221.106.5"),
    (WOW + "_retail_\\Wow.exe", "137.221.106.9"),
    (WOW + "Launcher.exe", "185.60.112.3"),
    (WOW + "_retail_\\Wow.exe", "192.168.1.1"),
    ("C:\\Program Files\\Mozilla Firefox\\firefox.exe", "142.250.74.14"),
]


def _tun_field(page) -> list[str] | None:
    document = json.loads(page.session.text())
    return tun_bypass.tun_inbounds(document)[0].get("route_exclude_address")


class TunBypassPageTests(unittest.TestCase):
    def _simple(self):
        page = _page()
        rules = _section(page, "rules")
        return page, rules, rules.open_simple_rule()

    def tearDown(self) -> None:
        page = _page()
        page.session.revert()

    def test_the_target_is_offered_when_the_config_has_a_tun_inbound(self) -> None:
        _page_, _rules, simple = self._simple()
        self.assertIn(BYPASS, [key for key, _title in simple._targets])

    def test_nothing_is_written_until_added_and_only_the_tun_field_changes(self) -> None:
        page, rules, simple = self._simple()
        before = json.loads(page.session.text())
        simple.set_target(BYPASS)
        simple.editors["ips"].setPlainText("137.221.106.0/24\n185.60.112.3")
        _pump()
        self.assertIsNone(_tun_field(page), "typing alone must not touch the config")
        simple._submit(apply=False)
        _pump()
        self.assertEqual(["137.221.106.0/24", "185.60.112.3/32"], _tun_field(page))
        after = json.loads(page.session.text())
        tun_bypass.remove_from_document(after)
        self.assertEqual(before["route"], after["route"], "it is not a route rule: the rules stay as they were")
        self.assertTrue(page.is_dirty("singbox"))

    def test_apply_asks_for_a_reconnect(self) -> None:
        page, _rules, simple = self._simple()
        applied: list[str] = []
        page.apply_requested.connect(lambda core, text: applied.append(text))
        try:
            simple.set_target(BYPASS)
            simple.editors["ips"].setPlainText("137.221.106.0/24")
            simple._submit(apply=True)
        finally:
            page.apply_requested.disconnect()
        _pump()
        self.assertEqual(1, len(applied))
        self.assertEqual(["137.221.106.0/24"], tun_bypass.tun_inbounds(json.loads(applied[0]))[0]["route_exclude_address"])

    def test_a_domain_cannot_be_excluded_and_the_page_says_why(self) -> None:
        _page_, _rules, simple = self._simple()
        simple.set_target(BYPASS)
        simple.editors["ips"].setPlainText("eu.actual.battle.net")
        simple._refresh()
        self.assertFalse(simple.add_btn.isEnabled())
        self.assertFalse(simple.apply_btn.isEnabled())
        self.assertIn("IP-адрес, а не имя сайта", simple.preview.text())
        self.assertTrue(simple.editors["sites"].isHidden(), "domains do not apply to this target")

    def test_the_other_targets_still_show_the_sites_field(self) -> None:
        _page_, _rules, simple = self._simple()
        simple.set_target(BYPASS)
        simple.set_target("direct")
        self.assertFalse(simple.editors["sites"].isHidden())
        self.assertTrue(simple.bypass_note.isHidden())
        self.assertFalse(simple.hint.isHidden())
        self.assertTrue(simple.find_addresses_btn.isHidden())

    def test_find_addresses_takes_what_the_game_is_connected_to(self) -> None:
        _page_, _rules, simple = self._simple()
        simple.set_target(BYPASS)
        simple.editors["programs"].setPlainText(WOW)
        with mock.patch("xray_fluent.ui.singbox.simple_rule_page.established_connections", return_value=CONNECTIONS):
            simple._find_addresses()
        self.assertEqual(
            ["137.221.106.5/32", "137.221.106.9/32", "185.60.112.3/32"], simple.editors["ips"].toPlainText().split(),
        )
        simple.editors["ips"].setPlainText("")
        simple.widen_check.setChecked(True)
        with mock.patch("xray_fluent.ui.singbox.simple_rule_page.established_connections", return_value=CONNECTIONS):
            simple._find_addresses()
        self.assertEqual(["137.221.106.0/24", "185.60.112.0/24"], simple.editors["ips"].toPlainText().split())

    def test_find_addresses_explains_when_the_game_is_not_connected(self) -> None:
        _page_, _rules, simple = self._simple()
        simple.set_target(BYPASS)
        with mock.patch("xray_fluent.ui.singbox.simple_rule_page.established_connections", return_value=[]):
            simple._find_addresses()
            self.assertIn("Сначала укажите программы", simple.preview.text())
            simple.editors["programs"].setPlainText(WOW)
            simple._find_addresses()
        self.assertIn("Запустите игру", simple.preview.text())
        self.assertEqual("", simple.editors["ips"].toPlainText())

    def test_the_exclusions_can_be_turned_off_again(self) -> None:
        page, rules, simple = self._simple()
        simple.set_target(BYPASS)
        simple.editors["ips"].setPlainText("137.221.106.0/24")
        simple._submit(apply=False)
        _pump()
        self.assertEqual(["137.221.106.0/24"], _tun_field(page))
        again = rules.open_simple_rule()
        again.set_target(BYPASS)
        self.assertIn("Сейчас мимо TUN: 1 адрес: 137.221.106.0/24", again.preview.text())
        self.assertTrue(again.clear_bypass_btn.isEnabled())
        again._clear_bypass()
        self.assertIsNone(_tun_field(page))


if __name__ == "__main__":
    unittest.main()
