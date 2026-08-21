from __future__ import annotations

import os
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError("Zapret widget tests require QApplication")
app = _existing or QApplication([])

from xray_fluent.models import Node, ZapretTargetSettings
from xray_fluent.ui.detail_page import DetailPage
from xray_fluent.ui.zapret_page import ZapretPage

_page = ZapretPage()


class ZapretTargetUiTests(unittest.TestCase):
    def setUp(self) -> None:
        _page.show_root()
        _page.set_target_settings(ZapretTargetSettings())

    def test_card_opens_breadcrumb_page(self) -> None:
        _page.target_open_btn.click()
        self.assertIs(_page._stack.currentWidget(), _page._target_page)
        self.assertIsInstance(_page._target_page, DetailPage)
        self.assertEqual(_page._target_page.breadcrumb.count(), 2)
        self.assertEqual(_page._target_page.breadcrumb.itemAt(0).text, "Zapret")
        self.assertEqual(_page._target_page.breadcrumb.itemAt(1).text, "Выбранный сервер")

    def test_live_summary_contains_transport_and_endpoint(self) -> None:
        node = Node(
            name="Amsterdam",
            scheme="vless",
            server="vpn.example",
            port=443,
            outbound={"protocol": "vless", "streamSettings": {"network": "tcp"}},
        )
        _page.set_target(node)
        self.assertIn("Amsterdam", _page.target_summary.text())
        self.assertIn("TCP 443", _page.target_summary.text())
        self.assertIn("alt v9", _page.target_summary.text())
        self.assertIn("vpn.example", _page._target_page.live_details.text())

    def test_udp_group_cannot_be_saved_without_udp_strategy(self) -> None:
        emitted: list[ZapretTargetSettings] = []
        _page.target_settings_changed.connect(emitted.append)
        target = _page._target_page
        target.quic_switch.setChecked(True)
        target.udp_combo.setCurrentIndex(-1)
        target.apply_btn.click()
        self.assertEqual(emitted, [])
        self.assertIn("UDP-стратегию", target.validation_label.text())

    def test_valid_tcp_settings_are_emitted_from_breadcrumb_page(self) -> None:
        emitted: list[ZapretTargetSettings] = []
        _page.target_settings_changed.connect(emitted.append)
        target = _page._target_page
        target.quic_switch.setChecked(False)
        target.wg_switch.setChecked(False)
        target.apply_btn.click()
        self.assertTrue(emitted)
        self.assertTrue(emitted[-1].tcp_proxy_enabled)
        self.assertEqual(emitted[-1].tcp_strategy_id, "alt9")

    def test_page_does_not_force_translucent_or_opaque_styles(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "xray_fluent" / "ui" / "zapret_page.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("WA_TranslucentBackground", source)
        self.assertNotIn("background-color:", source)


if __name__ == "__main__":
    unittest.main()
