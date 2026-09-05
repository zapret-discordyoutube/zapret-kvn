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

from xray_fluent.profiles.models import Node, ZapretTargetSettings
from xray_fluent.ui.detail_page import DetailPage
from xray_fluent.ui.zapret_page import DEFAULT_UDP_STRATEGY, ZapretPage

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

    def test_udp_group_falls_back_to_default_strategy(self) -> None:
        """Enabling a UDP group must not need a manual pick to be saveable."""

        emitted: list[ZapretTargetSettings] = []
        _page.target_settings_changed.connect(emitted.append)
        target = _page._target_page
        target.set_settings(ZapretTargetSettings(udp_strategy_id=""), force=True)
        target.quic_switch.setChecked(True)
        target.apply_btn.click()
        self.assertTrue(emitted)
        self.assertEqual(emitted[-1].udp_strategy_id, DEFAULT_UDP_STRATEGY)

    def test_only_the_node_transport_section_is_shown(self) -> None:
        target = _page._target_page
        tcp_node = Node(
            name="TCP", scheme="vless", server="tcp.example", port=443,
            outbound={"protocol": "vless", "streamSettings": {"network": "tcp"}},
        )
        _page.set_target(tcp_node)
        self.assertEqual(target._transport, "tcp")
        self.assertIn("TCP-стратегия", target.picker.title_label.text())
        udp_node = Node(
            name="QUIC", scheme="hysteria2", server="udp.example", port=443,
            outbound={"protocol": "hysteria2"},
        )
        _page.set_target(udp_node)
        self.assertEqual(target._transport, "udp")
        self.assertIn("UDP-стратегия", target.picker.title_label.text())

    def test_group_switch_captions_survive_being_enabled(self) -> None:
        target = _page._target_page
        target.tcp_switch.setChecked(True)
        for switch in (target.tcp_switch, target.quic_switch, target.wg_switch):
            self.assertNotIn("On", str(switch.text or ""))

    def test_search_does_not_reassign_the_selection(self) -> None:
        target = _page._target_page
        _page.set_target(Node(
            name="TCP", scheme="vless", server="tcp.example", port=443,
            outbound={"protocol": "vless", "streamSettings": {"network": "tcp"}},
        ))
        target.picker.set_selected("alt9")
        target.picker.search.setText("zzz-no-such-strategy")
        target.picker._rebuild()
        self.assertEqual(target.picker.selected_id(), "alt9")
        self.assertIn("скрыта", target.picker.hidden_hint.text())
        target.picker.search.setText("")
        target.picker._rebuild()

    def test_unapplied_edits_are_dirty_and_survive_external_settings(self) -> None:
        target = _page._target_page
        target.set_settings(ZapretTargetSettings(), force=True)
        self.assertFalse(target.is_dirty())
        target.wg_switch.setChecked(not target.wg_switch.isChecked())
        self.assertTrue(target.is_dirty())
        keep = target._snapshot()
        target.set_settings(ZapretTargetSettings())  # external push, not forced
        self.assertEqual(target._snapshot(), keep)
        target.set_settings(ZapretTargetSettings(), force=True)
        self.assertFalse(target.is_dirty())

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

    def test_selecting_a_node_does_not_look_like_an_unsaved_edit(self) -> None:
        """Rebuilding the form for another node is not a user edit (regression)."""

        target = _page._target_page
        _page.set_target_settings(ZapretTargetSettings())
        _page.set_target(Node(
            name="H2", scheme="hysteria2", server="udp.example", port=443,
            outbound={"protocol": "hysteria2"},
        ))
        self.assertFalse(target.is_dirty())
        _page.set_target_settings(ZapretTargetSettings(quic_proxy_enabled=True))
        self.assertTrue(target.quic_switch.isChecked())

    def test_udp_node_opens_with_a_runnable_default_strategy(self) -> None:
        emitted: list[ZapretTargetSettings] = []
        _page.target_settings_changed.connect(emitted.append)
        target = _page._target_page
        _page.set_target_settings(ZapretTargetSettings(udp_strategy_id=""))
        _page.set_target(Node(
            name="H2", scheme="hysteria2", server="udp.example", port=443,
            outbound={"protocol": "hysteria2"},
        ))
        self.assertEqual(target.picker.selected_id(), DEFAULT_UDP_STRATEGY)
        target.apply_btn.click()
        self.assertTrue(emitted)
        self.assertEqual(emitted[-1].udp_strategy_id, DEFAULT_UDP_STRATEGY)

    def test_apply_status_survives_the_settings_round_trip(self) -> None:
        target = _page._target_page
        _page.set_target_settings(ZapretTargetSettings())
        target.apply_btn.click()
        # main_window pushes the stored settings straight back into the page.
        _page.set_target_settings(target._settings)
        self.assertTrue(target.validation_label.text())
        target.set_runtime_state("Настройки сохранены")
        self.assertEqual(target.validation_label.text(), "Сохранено")

    def test_real_edits_survive_a_node_switch(self) -> None:
        """Re-baselining on transport change must not swallow genuine edits."""

        target = _page._target_page
        _page.set_target_settings(ZapretTargetSettings())
        _page.set_target(Node(
            name="T", scheme="vless", server="tcp.example", port=443,
            outbound={"protocol": "vless", "streamSettings": {"network": "tcp"}},
        ))
        target.wg_switch.setChecked(not target.wg_switch.isChecked())
        edited = target.wg_switch.isChecked()
        self.assertTrue(target.is_dirty())
        _page.set_target(Node(
            name="H2", scheme="hysteria2", server="udp.example", port=443,
            outbound={"protocol": "hysteria2"},
        ))
        self.assertTrue(target.is_dirty())
        _page.set_target_settings(ZapretTargetSettings())
        self.assertEqual(target.wg_switch.isChecked(), edited)
        target.set_settings(ZapretTargetSettings(), force=True)

    def test_custom_body_does_not_leak_between_transports(self) -> None:
        emitted: list[ZapretTargetSettings] = []
        _page.target_settings_changed.connect(emitted.append)
        target = _page._target_page
        target.set_settings(
            ZapretTargetSettings(tcp_strategy_id="custom", tcp_custom_args="--lua-desync=multisplit:pos=1"),
            force=True,
        )
        _page.set_target(Node(
            name="T", scheme="vless", server="tcp.example", port=443,
            outbound={"protocol": "vless", "streamSettings": {"network": "tcp"}},
        ))
        self.assertIn("multisplit", target.custom_edit.toPlainText())
        _page.set_target(Node(
            name="H2", scheme="hysteria2", server="udp.example", port=443,
            outbound={"protocol": "hysteria2"},
        ))
        self.assertEqual(target.custom_edit.toPlainText(), "")
        target.apply_btn.click()
        self.assertTrue(emitted)
        self.assertEqual(emitted[-1].udp_custom_args, "")

    def test_dirty_form_still_tracks_the_other_transport_settings(self) -> None:
        """Protecting on-screen edits must not roll back the hidden transport."""

        emitted: list[ZapretTargetSettings] = []
        _page.target_settings_changed.connect(emitted.append)
        target = _page._target_page
        _page.set_target_settings(ZapretTargetSettings(tcp_strategy_id="multisplit_pos1"))
        _page.set_target(Node(
            name="H2", scheme="hysteria2", server="udp.example", port=443,
            outbound={"protocol": "hysteria2"},
        ))
        target.wg_switch.setChecked(not target.wg_switch.isChecked())
        self.assertTrue(target.is_dirty())
        _page.set_target_settings(ZapretTargetSettings(tcp_strategy_id="tls_fake_badseq"))
        target.apply_btn.click()
        self.assertTrue(emitted)
        self.assertEqual(emitted[-1].tcp_strategy_id, "tls_fake_badseq")
        target.set_settings(ZapretTargetSettings(), force=True)

    def test_strategy_list_never_shows_a_sliced_row(self) -> None:
        """A partially drawn row at the edge reads as a rendering glitch."""

        from xray_fluent.ui.strategy_picker import _ROW_HEIGHT, _VISIBLE_ROWS

        target = _page._target_page
        _page.set_target_settings(ZapretTargetSettings(quic_proxy_enabled=True))
        _page.set_target(Node(
            name="H2", scheme="hysteria2", server="udp.example", port=443,
            outbound={"protocol": "hysteria2"},
        ))
        picker = target.picker
        picker._fit_list_height()
        viewport = picker.list.viewport().height()
        self.assertEqual(viewport % _ROW_HEIGHT, 0)
        self.assertEqual(viewport // _ROW_HEIGHT, _VISIBLE_ROWS)

    def test_lists_scroll_by_whole_rows(self) -> None:
        from PyQt6.QtWidgets import QAbstractItemView

        per_item = QAbstractItemView.ScrollMode.ScrollPerItem
        self.assertEqual(_page.preset_list.verticalScrollMode(), per_item)
        self.assertEqual(_page._target_page.picker.list.verticalScrollMode(), per_item)

    def test_catalog_is_hidden_while_the_bypass_is_off(self) -> None:
        """66 irrelevant strategies must not crowd a server with bypass disabled."""

        target = _page._target_page
        node = Node(
            name="H2", scheme="hysteria2", server="udp.example", port=443,
            outbound={"protocol": "hysteria2"},
        )
        _page.set_target_settings(ZapretTargetSettings(quic_proxy_enabled=False))
        _page.set_target(node)
        self.assertTrue(target.picker.isHidden())
        self.assertFalse(target.disabled_hint.isHidden())
        self.assertIn("QUIC", target.disabled_hint.text())
        _page.set_target_settings(ZapretTargetSettings(quic_proxy_enabled=True))
        _page.set_target(node)
        self.assertFalse(target.picker.isHidden())
        self.assertTrue(target.disabled_hint.isHidden())

    def test_summary_never_shows_the_internal_pass_id(self) -> None:
        _page.set_target_settings(ZapretTargetSettings(quic_proxy_enabled=False))
        _page.set_target(Node(
            name="H2", scheme="hysteria2", server="udp.example", port=443,
            outbound={"protocol": "hysteria2"},
        ))
        summary = _page.target_summary.text()
        self.assertNotIn("pass", summary)
        self.assertIn("обход выключен", summary)

    def test_page_does_not_force_translucent_or_opaque_styles(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "xray_fluent" / "ui" / "zapret_page.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("WA_TranslucentBackground", source)
        self.assertNotIn("background-color:", source)


if __name__ == "__main__":
    unittest.main()
