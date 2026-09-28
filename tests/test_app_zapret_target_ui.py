"""Zapret section: status card, selected server, per-kind pages, presets.

Keep the ``test_app_*`` prefix (QApplication before tests/test_engine_process_stop.py).
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QWidget

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError("Zapret widget tests require QApplication")
app = _existing or QApplication([])

from xray_fluent.engines.zapret.command import ServerRule
from xray_fluent.engines.zapret.endpoint import ResolvedEndpoint, endpoint_for_node
from xray_fluent.engines.zapret.presets import PresetInfo
from xray_fluent.engines.zapret.strategies import CUSTOM_STRATEGY_ID, load_strategy_catalog
from xray_fluent.profiles.models import Node, ZapretTargetSettings
from xray_fluent.ui.zapret_browser import ID_ROLE
from xray_fluent.ui.zapret_page import ZapretPage, ZapretStatus

_page = ZapretPage()

_TCP = Node(
    name="Tiraru", scheme="vless", server="tcp.example", port=443,
    outbound={"protocol": "vless", "streamSettings": {"network": "tcp"}},
)
_H2 = Node(name="H2", scheme="hysteria2", server="udp.example", port=443, outbound={"protocol": "hysteria2"})


def _preset(name: str) -> PresetInfo:
    return PresetInfo(name, "", "", "", 3, Path(f"{name}.txt"))


class ZapretOverviewTests(unittest.TestCase):
    def setUp(self) -> None:
        _page.show_root()
        _page.set_target_settings(ZapretTargetSettings())
        _page.set_presets([_preset("Default"), _preset("Other")], "Default")
        _page.set_status(ZapretStatus("stopped"))
        _page.set_selected_node(None)
        _page.set_rule(None)
        _page.set_server_status(False, "")

    def test_status_card_follows_the_process(self) -> None:
        _page.set_status(ZapretStatus("running", "Default"))
        self.assertEqual(_page.status_title.text(), "Zapret работает")
        self.assertEqual(_page.toggle_btn.text(), "Остановить")
        _page.set_status(ZapretStatus("error", message="winws2 завершился с кодом 3"))
        self.assertIn("ошибки", _page.status_title.text())
        self.assertEqual(_page.status_detail.text(), "winws2 завершился с кодом 3")
        self.assertEqual(_page.toggle_btn.text(), "Запустить")

    def test_toggle_starts_the_chosen_preset_and_stops(self) -> None:
        started: list[str] = []
        stopped: list[bool] = []
        _page.start_requested.connect(started.append)
        _page.stop_requested.connect(lambda: stopped.append(True))
        try:
            _page.toggle_btn.click()
            _page.set_status(ZapretStatus("running", "Default"))
            _page.toggle_btn.click()
        finally:
            _page.start_requested.disconnect(started.append)
            _page.stop_requested.disconnect()
        self.assertEqual(started, ["Default"])
        self.assertEqual(stopped, [True])

    def test_choosing_a_preset_while_running_restarts_on_it(self) -> None:
        started: list[str] = []
        chosen: list[str] = []
        _page.set_status(ZapretStatus("running", "Default"))
        _page.preset_link.click()
        self.assertIs(_page._stack.currentWidget(), _page._presets_page)
        browser = _page._presets_page.browser
        self.assertEqual(browser.highlighted(), "Default")
        _page.start_requested.connect(started.append)
        _page.preset_selected.connect(chosen.append)
        try:
            browser.highlight("Other")
            self.assertEqual(chosen, [])  # highlighting only shows the preset
            browser.choose_btn.click()
        finally:
            _page.start_requested.disconnect(started.append)
            _page.preset_selected.disconnect(chosen.append)
        self.assertEqual((chosen, started), (["Other"], ["Other"]))
        self.assertEqual(_page.preset_link.text(), "Other")
        self.assertEqual(browser.choose_btn.text(), "Выбран")
        _page.show_root()

    def test_stopped_card_says_when_zapret_will_start_by_itself(self) -> None:
        _page.set_selected_node(_TCP)
        self.assertIn("Tiraru", _page.status_detail.text())
        _page.set_target_settings(ZapretTargetSettings(tcp_proxy_enabled=False))
        self.assertEqual(_page.status_detail.text(), "")

    def test_selected_server_shows_endpoint_rule_and_live_ips(self) -> None:
        _page.set_selected_node(_TCP)
        self.assertIn("tcp.example", _page.server_endpoint.text())
        self.assertIn("TCP 443", _page.server_endpoint.text())
        self.assertIn("alt v9", _page.server_rule.text())
        rule = ServerRule(
            ResolvedEndpoint(endpoint_for_node(_TCP), ("203.0.113.5",)), load_strategy_catalog("tcp")["alt9"],
        )
        _page.set_rule(rule)
        _page.set_status(ZapretStatus("running", "Default"))
        self.assertIn("203.0.113.5", _page.server_rule.text())
        _page.set_server_status(True, "DNS выбранного VPN-сервера...")
        self.assertIn("DNS", _page.server_rule.text())

    def test_off_meaning_is_spelled_out_and_never_says_pass(self) -> None:
        _page.set_selected_node(_H2)
        self.assertIn("не трогать", _page.server_rule.text())
        self.assertNotIn("pass", _page.server_rule.text())
        _page.set_target_settings(ZapretTargetSettings(tcp_proxy_enabled=False))
        self.assertIn("по пресету", _page.kind_rows["tcp"].value.text())
        self.assertIn("не трогать", _page.kind_rows["wireguard"].value.text())

    def test_the_selected_server_kind_is_marked(self) -> None:
        _page.set_selected_node(_H2)
        self.assertFalse(_page.kind_rows["quic"].current_mark.isHidden())
        self.assertTrue(_page.kind_rows["tcp"].current_mark.isHidden())

    def test_help_link_opens_the_zapret_guide(self) -> None:
        with patch("xray_fluent.ui.zapret_page.open_guide") as open_guide:
            _page.help_link.click()
        open_guide.assert_called_once()
        self.assertEqual(open_guide.call_args.args[0], "zapret")


class KindPageTests(unittest.TestCase):
    def setUp(self) -> None:
        _page.show_root()
        _page.set_target_settings(ZapretTargetSettings())
        self.emitted: list[ZapretTargetSettings] = []
        _page.target_settings_changed.connect(self.emitted.append)

    def tearDown(self) -> None:
        _page.target_settings_changed.disconnect(self.emitted.append)
        _page.show_root()

    def _open(self, kind: str):
        _page.kind_rows[kind].clicked.emit()
        return _page._kind_page

    def test_row_opens_the_kind_page_on_the_strategy_in_use(self) -> None:
        page = self._open("tcp")
        self.assertIs(_page._stack.currentWidget(), page)
        self.assertEqual(page.title_label.text(), "TCP-серверы")
        self.assertEqual(page.browser.highlighted_id(), "alt9")
        self.assertEqual(page.browser.use_btn.text(), "Используется")
        self.assertFalse(page.browser.use_btn.isEnabled())

    def test_switch_applies_at_once_and_shows_the_catalog(self) -> None:
        page = self._open("quic")
        self.assertTrue(page.browser.isHidden())
        self.assertIn("не трогать", page.off_title.text())
        page.switch.setChecked(True)
        self.assertFalse(page.browser.isHidden())
        self.assertEqual(len(self.emitted), 1)
        self.assertTrue(self.emitted[0].quic_proxy_enabled)

    def test_use_button_changes_only_that_kind(self) -> None:
        page = self._open("wireguard")
        page.switch.setChecked(True)
        page.browser.highlight("fake_zero")
        self.assertEqual(len(self.emitted), 1)  # highlighting applies nothing
        page.browser.use_btn.click()
        latest = self.emitted[-1]
        self.assertTrue(latest.wireguard_enabled)
        self.assertEqual(latest.wireguard_strategy_id, "fake_zero")
        self.assertEqual(latest.quic_strategy_id, "general_bf_32")
        self.assertEqual(page.browser.chosen_id(), "fake_zero")
        self.assertIn("Fake 0x00", _page.kind_rows["wireguard"].value.text())

    def test_invalid_own_strategy_is_refused(self) -> None:
        page = self._open("tcp")
        page.browser.highlight(CUSTOM_STRATEGY_ID)
        self.assertFalse(page.browser.custom_edit.isHidden())
        page.browser.custom_edit.setPlainText("--new")
        page.browser.use_btn.click()
        self.assertEqual(self.emitted, [])
        self.assertTrue(page.browser.error_label.text())
        page.browser.custom_edit.setPlainText("--lua-desync=fake:repeats=2")
        page.browser.use_btn.click()
        self.assertEqual(self.emitted[-1].tcp_strategy_id, CUSTOM_STRATEGY_ID)
        self.assertEqual(self.emitted[-1].tcp_custom_args, "--lua-desync=fake:repeats=2")

    def test_filter_keeps_the_highlight(self) -> None:
        browser = self._open("tcp").browser
        browser.search.setText("zzz-no-such-strategy")
        browser._rebuild()
        self.assertEqual(browser.highlighted_id(), "alt9")
        self.assertEqual(browser.list.count(), 0)
        browser.search.setText("")
        browser._rebuild()
        self.assertEqual(browser.list.currentItem().data(ID_ROLE), "alt9")

    def test_group_filter_lists_labels_with_counts(self) -> None:
        browser = self._open("tcp").browser
        titles = [browser.group.itemText(index) for index in range(browser.group.count())]
        self.assertTrue(titles[0].startswith("Все · "))
        self.assertTrue(any(title.startswith("Рекомендуется · ") for title in titles))
        browser.group.setCurrentIndex(titles.index(next(t for t in titles if t.startswith("Осторожно"))))
        shown = [browser.list.item(row).data(ID_ROLE) for row in range(browser.list.count())]
        self.assertTrue(all(load_strategy_catalog("tcp")[i].label == "caution" for i in shown if i != CUSTOM_STRATEGY_ID))
        browser.group.setCurrentIndex(0)

    def test_arguments_are_split_into_readable_lines(self) -> None:
        from xray_fluent.ui.zapret_browser import readable_arguments

        self.assertEqual(
            readable_arguments(("--payload=tls_client_hello", "--lua-desync=fake:blob=tls_google:repeats=6")),
            "--payload=tls_client_hello\n--lua-desync=fake\n    blob=tls_google\n    repeats=6",
        )

    def test_card_moves_under_the_list_on_a_narrow_window(self) -> None:
        from xray_fluent.ui.zapret_browser import SplitView

        split = SplitView(QWidget(), QWidget())
        split.resize(1000, 600)
        split.resize(700, 600)
        split.show()
        app.processEvents()
        self.assertTrue(split.stacked)
        split.resize(1100, 600)
        app.processEvents()
        self.assertFalse(split.stacked)
        split.deleteLater()


class PresetsPageTests(unittest.TestCase):
    def test_running_preset_is_badged(self) -> None:
        _page.set_presets([_preset("Default"), _preset("Other")], "Default")
        _page.set_status(ZapretStatus("running", "Other"))
        from PyQt6.QtCore import Qt

        badge = _page._presets_page.browser.list.item(1).data(Qt.ItemDataRole.UserRole + 2)
        self.assertEqual(badge, "Работает")
        _page.set_status(ZapretStatus("stopped"))

    def test_editor_returns_to_the_preset_list(self) -> None:
        _page.show_sub_page(_page._presets_page)
        _page._on_create()
        self.assertIs(_page._stack.currentWidget(), _page._editor)
        _page._editor.request_back()
        self.assertIs(_page._stack.currentWidget(), _page._presets_page)
        _page.show_root()

    def test_rename_does_not_leave_a_copy_behind(self) -> None:
        import tempfile

        from xray_fluent.engines.zapret import presets

        with tempfile.TemporaryDirectory() as tmp, patch.object(presets, "PRESETS_DIR", Path(tmp)):
            presets.save_preset("Old", "--wf-tcp-out=443\n")
            _page._on_save_preset("Old", "New", "", "--wf-tcp-out=443\n")
            self.assertEqual(presets.list_presets(), ["New"])
            presets.save_preset("Taken", "--wf-tcp-out=443\n")
            _page._on_save_preset("New", "Taken", "", "--wf-tcp-out=443\n")
            self.assertIn("уже есть", _page._editor.error_label.text())
        _page.show_root()

    def test_saving_the_running_preset_restarts_it(self) -> None:
        import tempfile

        from xray_fluent.engines.zapret import presets

        started: list[str] = []
        with tempfile.TemporaryDirectory() as tmp, patch.object(presets, "PRESETS_DIR", Path(tmp)):
            presets.save_preset("Live", "--wf-tcp-out=443\n")
            _page.set_presets(presets.list_preset_infos(), "Live")
            _page.set_status(ZapretStatus("running", "Live"))
            _page.start_requested.connect(started.append)
            try:
                _page._on_save_preset("Live", "Live 2", "", "--wf-tcp-out=80\n")
            finally:
                _page.start_requested.disconnect(started.append)
        self.assertEqual(started, ["Live 2"])
        _page.set_status(ZapretStatus("stopped"))
        _page.show_root()

    def test_lists_scroll_by_whole_rows(self) -> None:
        from PyQt6.QtWidgets import QAbstractItemView

        per_item = QAbstractItemView.ScrollMode.ScrollPerItem
        self.assertEqual(_page._presets_page.browser.list.verticalScrollMode(), per_item)
        self.assertEqual(_page._kind_page.browser.list.verticalScrollMode(), per_item)

    def test_preset_summary_names_its_targets(self) -> None:
        from xray_fluent.engines.zapret.presets import summarize_arguments

        summary = summarize_arguments([
            "--wf-tcp-out=80,443", "--filter-tcp=443", "--hostlist=lists/youtube.txt",
            "--hostlist-domains=updates.discord.com", "--new", "--filter-udp=443",
            "--ipset=lists/ipset-cloudflare1.txt", "--new", "--filter-tcp=80,443",
            "--hostlist-exclude=lists/netrogat.txt",
        ])
        self.assertEqual(summary.profiles, 3)
        self.assertEqual(summary.targets, ("youtube", "discord", "cloudflare"))
        self.assertTrue(summary.catch_all)
        self.assertEqual(summary.tcp_ports, "80,443")
        self.assertIn("остальной трафик", summary.short())


class SourceRulesTests(unittest.TestCase):
    def test_page_does_not_force_translucent_or_opaque_styles(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "xray_fluent" / "ui" / "zapret_page.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("WA_TranslucentBackground", source)
        self.assertNotIn("background-color:", source)

    def test_overview_holds_only_data_and_the_guide_link(self) -> None:
        from xray_fluent.ui.singbox.art import ArtCanvas

        self.assertEqual(_page.findChildren(ArtCanvas), [])


if __name__ == "__main__":
    unittest.main()
