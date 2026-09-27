"""Structured sing-box routing pages edit the native JSON and nothing else."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import json
from pathlib import Path
import unittest

from PyQt6.QtCore import QCoreApplication, QEvent, Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication

_app = QApplication.instance()
if _app is None:
    _app = QApplication([])
elif not isinstance(_app, QApplication):
    raise RuntimeError("A bare QCoreApplication already exists; UI tests need QApplication")

from xray_fluent.ui.configs_page import ConfigsPage  # noqa: E402
from xray_fluent.ui.singbox.sections import ItemPage, count_references  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "data" / "templates" / "sing-box" / "default.json"
TEMPLATE_TEXT = TEMPLATE.read_text(encoding="utf-8")
LIST_SECTIONS = ("rules", "rule_sets", "dns", "outbounds", "system")

#: Shared page kept alive for the whole module (deleting widgets mid-run
#: crashes on Windows, see test_app_detail_pages).
_shared: dict[str, ConfigsPage] = {}


def _page() -> ConfigsPage:
    if "page" not in _shared:
        _shared["page"] = ConfigsPage()
    page = _shared["page"]
    page.show_section("overview")
    page.set_document("singbox", Path("data/configs/sing-box/default.json"), TEMPLATE_TEXT)
    page.set_template_source("singbox", TEMPLATE)
    return page


def _section(page: ConfigsPage, key: str):
    """Show a routing sub-page the way the navigation does and return it."""
    page.show_section(key)
    return page._sections[key]


def _guide(open_guide):
    """Open a guide the way the link does and keep it for the module.

    The dialog stays open (hidden mask) instead of being destroyed mid-run:
    deleting widgets mid-run crashes on Windows, see test_app_detail_pages.
    """
    from xray_fluent.ui.singbox.guide import GuideDialog

    before = set(map(id, _shared.setdefault("guides", [])))
    result = open_guide()
    dialog = result if isinstance(result, GuideDialog) else None
    if dialog is None:
        page = _shared["page"]
        dialog = next(d for d in page.findChildren(GuideDialog) if id(d) not in before)
    dialog.finished.disconnect()
    dialog.hide()
    _shared["guides"].append(dialog)
    return dialog


def _pump() -> None:
    for _ in range(3):
        QCoreApplication.processEvents()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


def _object_lists(section):
    from xray_fluent.ui.singbox.lists import ObjectList

    return [view for view in section.root.body.findChildren(ObjectList) if view.isVisibleTo(section.root.body)]


class RoutingPageTests(unittest.TestCase):
    def test_browsing_every_section_and_item_never_changes_the_json(self) -> None:
        page = _page()
        for key in LIST_SECTIONS + ("json", "overview"):
            page.show_section(key)
            _pump()
        for key in LIST_SECTIONS:
            section = _section(page, key)
            for view in _object_lists(section):
                for index in range(len(view._items())):
                    view.open_requested.emit(index)
                    _pump()
                    self.assertIsInstance(section.nav.currentWidget(), ItemPage)
                    section.nav.pop()
                    _pump()
        self.assertFalse(page.is_dirty("singbox"))
        self.assertEqual(page.session.text(), TEMPLATE_TEXT)

    def test_edit_marks_dirty_and_undo_restores(self) -> None:
        page = _page()
        rules = _section(page, "rules")
        rules.rules.open_requested.emit(4)
        _pump()
        item_page = rules.nav.currentWidget()
        item_page.item["domain_keyword"] = ["example"]
        item_page.form.changed.emit()
        self.assertTrue(page.is_dirty("singbox"))
        self.assertIn('"domain_keyword"', page.session.text())
        item_page._undo()
        self.assertFalse(page.is_dirty("singbox"))
        rules.nav.pop()

    def test_switching_action_drops_fields_the_new_action_rejects(self) -> None:
        page = _page()
        rules = _section(page, "rules")
        rules.rules.open_requested.emit(4)
        _pump()
        item_page = rules.nav.currentWidget()
        item_page.form._switch_variant("action", "reject")
        _pump()
        self.assertEqual(item_page.item.get("action"), "reject")
        self.assertNotIn("outbound", item_page.item)
        item_page._undo()
        rules.nav.pop()
        self.assertFalse(page.is_dirty("singbox"))

    def test_new_rule_is_native_and_reorder_moves_it(self) -> None:
        page = _page()
        rules = _section(page, "rules")
        before = len(rules.rules._items())
        rules.rules._add(_first_option(rules.rules))
        _pump()
        rules.nav.pop()
        document = json.loads(page.session.text())
        self.assertEqual(len(document["route"]["rules"]), before + 1)
        self.assertEqual(document["route"]["rules"][-1], {"action": "route", "outbound": "proxy"})
        rules.rules._move(before, -1)
        document = json.loads(page.session.text())
        self.assertEqual(document["route"]["rules"][before - 1], {"action": "route", "outbound": "proxy"})
        page.session.revert()
        self.assertFalse(page.is_dirty("singbox"))

    def test_simple_rule_writes_nothing_until_added_and_goes_on_top(self) -> None:
        from xray_fluent.ui.singbox.simple_rule_page import SimpleRulePage

        page = _page()
        rules = _section(page, "rules")
        before = page.session.text()
        simple = rules.open_simple_rule()
        self.assertIsInstance(rules.nav.currentWidget(), SimpleRulePage)
        simple.set_target("direct")
        simple.editors["sites"].setPlainText("https://www.2ip.ru/\n2ip.io")
        self.assertEqual(page.session.text(), before)
        self.assertFalse(page.is_dirty("singbox"))
        applied: list[str] = []
        checks: list[tuple[str, str]] = []
        page.apply_requested.connect(lambda core, text: applied.append(text))
        page.route_check_requested.connect(lambda host, text: checks.append((host, text)))
        try:
            simple._submit(apply=True)
        finally:
            page.apply_requested.disconnect()
            page.route_check_requested.disconnect()
        _pump()
        self.assertIs(rules.nav.currentWidget(), rules.root)
        document = json.loads(page.session.text())
        self.assertEqual(
            document["route"]["rules"][4],
            {"domain_suffix": ["2ip.ru", "2ip.io"], "action": "route", "outbound": "direct"},
        )
        self.assertEqual(len(applied), 1)
        self.assertEqual(json.loads(applied[0])["route"]["rules"][4]["outbound"], "direct")
        self.assertEqual([host for host, _text in checks], ["https://www.2ip.ru/"])

        from xray_fluent.singbox_config.route_explain import explain_route

        verdict = explain_route(document, "2ip.ru", tun=False, match_set=lambda _d, _v: False)
        page.show_route_check(verdict)
        self.assertIn("Напрямую", rules.check_row.headline.text())
        self.assertIn("Правило 5", rules.check_row.details.text())
        self.assertIn("Применить", rules.check_row.details.text())
        page.session.mark_saved(None, page.session.text())
        page.show_route_check(verdict, unapplied=True)
        self.assertIn("по прежним правилам", rules.check_row.details.text())
        page.session.revert()
        self.assertFalse(page.is_dirty("singbox"))

    def test_invalid_json_makes_structured_pages_read_only(self) -> None:
        page = _page()
        page.show_section("json")
        page.json_panel.editor.setPlainText('{"route": ')
        page.show_section("rules")
        _pump()
        self.assertFalse(page.session.editable)
        self.assertEqual(_object_lists(_section(page, "rules")), [])
        self.assertEqual(page.session.text(), '{"route": ')
        page.session.revert()
        self.assertTrue(page.session.editable)

    def test_json_panel_and_sections_share_one_document(self) -> None:
        page = _page()
        page.show_section("json")
        document = json.loads(page.json_panel.editor.toPlainText())
        document["route"]["final"] = "direct"
        page.json_panel.editor.setPlainText(json.dumps(document, ensure_ascii=False, indent=2))
        page.show_section("rules")
        _pump()
        self.assertEqual(page.session.document["route"]["final"], "direct")
        self.assertTrue(page.is_dirty("singbox"))
        page.session.revert()

    def test_reset_section_restores_stock_only_there(self) -> None:
        page = _page()
        page.session.document["dns"]["final"] = "bootstrap-dns"
        page.session.document["log"]["level"] = "debug"
        page.session.mark_edited()
        self.assertTrue(page.session.reset_section("dns"))
        stock = json.loads(TEMPLATE_TEXT)
        self.assertEqual(page.session.document["dns"], stock["dns"])
        self.assertEqual(page.session.document["log"]["level"], "debug")
        page.session.revert()

    def test_proxy_outbound_opens_locked_with_explanation(self) -> None:
        page = _page()
        outbounds = _section(page, "outbounds")
        view = _object_lists(outbounds)[0]
        index = next(i for i, item in enumerate(view._items()) if item.get("tag") == "proxy")
        view.open_requested.emit(index)
        _pump()
        item_page = outbounds.nav.currentWidget()
        self.assertTrue(item_page.form.locked)
        outbounds.nav.pop()

    def test_mark_saved_with_rewritten_text_reloads(self) -> None:
        page = _page()
        page.session.document["log"]["level"] = "info"
        page.session.mark_edited()
        saved = page.session.text()
        page.mark_saved("singbox", Path("x.json"), saved)
        self.assertFalse(page.is_dirty("singbox"))

    def _open_rule(self, page, index: int):
        rules = _section(page, "rules")
        page.show_section("rules")
        rules.rules.open_requested.emit(index)
        _pump()
        return rules, rules.nav.currentWidget()

    def test_typed_list_value_survives_immediate_done(self) -> None:
        from xray_fluent.ui.singbox.fields import ListEditor

        page = _page()
        rules, item_page = self._open_rule(page, 4)
        editor = next(e for e in item_page.form.findChildren(ListEditor) if e.name == "process_name")
        editor.edit.setFocus()
        editor.edit.moveCursor(editor.edit.textCursor().MoveOperation.End)
        QTest.keyClick(editor.edit, Qt.Key.Key_Return)
        QTest.keyClicks(editor.edit, "new.exe")
        item_page.request_back()  # before the debounce fires
        _pump()
        self.assertEqual(rules.nav.depth, 0)
        self.assertIn("new.exe", page.session.document["route"]["rules"][4]["process_name"])
        page.session.revert()

    def test_typed_list_value_reaches_save_signal(self) -> None:
        from xray_fluent.ui.singbox.fields import ListEditor

        page = _page()
        rules, item_page = self._open_rule(page, 4)
        editor = next(e for e in item_page.form.findChildren(ListEditor) if e.name == "process_name")
        editor.edit.moveCursor(editor.edit.textCursor().MoveOperation.End)
        QTest.keyClick(editor.edit, Qt.Key.Key_Return)
        QTest.keyClicks(editor.edit, "saved.exe")
        received: list[str] = []
        page.save_requested.connect(lambda _core, text: received.append(text))
        page.save_btn.click()
        self.assertTrue(received and "saved.exe" in received[-1])
        rules.nav.pop()
        page.session.revert()

    def test_switching_action_through_the_real_combo_popup(self) -> None:
        from qfluentwidgets import ComboBox

        page = _page()
        for attempt in range(4):
            rules, item_page = self._open_rule(page, 4)
            combo = next(
                c for c in item_page.form.findChildren(ComboBox)
                if c.currentData() in ("route", "reject")
            )
            target = "reject" if combo.currentData() == "route" else "route"
            index = next(i for i in range(combo.count()) if combo.itemData(i) == target)
            combo._showComboMenu()
            _pump()
            combo.dropMenu.actions()[index].trigger()
            _pump()
            _pump()
            self.assertEqual(item_page.item.get("action"), target, attempt)
            if target == "reject":
                self.assertNotIn("outbound", item_page.item)
            item_page._undo()
            item_page.request_back()
            _pump()
        self.assertFalse(page.is_dirty("singbox"))

    def test_launch_required_tags_are_explained(self) -> None:
        from xray_fluent.singbox_config.document import app_owned_note

        self.assertIn("служебные", app_owned_note("outbounds", {"type": "direct", "tag": "direct"}))
        self.assertIn("доменное имя", app_owned_note("dns.servers", {"type": "fallback", "tag": "bootstrap-dns"}))
        page = _page()
        warn = _section(page, "dns").reference_warning("сервер", "dns.servers")
        bootstrap = next(s for s in page.session.document["dns"]["servers"] if s["tag"] == "bootstrap-dns")
        self.assertIn("не запустится", warn(bootstrap))

    def test_nav_stack_stays_consistent_through_animated_slides(self) -> None:
        page = _page()
        rules = _section(page, "rules")
        for _ in range(3):
            rules.rules.open_requested.emit(1)
            self.assertEqual(rules.nav.depth, 1)
            self.assertIsInstance(rules.nav.currentWidget(), ItemPage)
            rules.nav.pop()
            self.assertEqual(rules.nav.depth, 0)
            self.assertIs(rules.nav.currentWidget(), rules.root)
        _pump()

    def test_rows_show_badges_and_guide_art_shows_the_config(self) -> None:
        from xray_fluent.ui.singbox.art import KindBadge, RouteMapArt, RuleScanArt

        page = _page()
        rules = _section(page, "rules")
        badges = [b for b in rules.rules.findChildren(KindBadge) if b.isVisibleTo(rules.rules)]
        self.assertEqual(len(badges), len(rules.rules._items()))
        scan = _guide(rules.open_guide)
        self.assertIsInstance(scan.art, RuleScanArt)
        self.assertEqual(len(scan.art._visuals), min(8, len(rules.rules._items())))
        page.show_section("overview")
        route_map = _guide(page.overview.open_guide)
        self.assertIsInstance(route_map.art, RouteMapArt)
        self.assertEqual(route_map.art._counts, (2, 5, 2))
        page.session.document["route"]["rules"].append({"domain": ["x.org"], "action": "reject"})
        page.session.mark_edited()
        self.assertEqual(_guide(page.overview.open_guide).art._counts, (2, 5, 3))
        self.assertTrue(page.dirty_dot.isVisibleTo(page))
        page.session.revert()
        self.assertFalse(page.dirty_dot.isVisibleTo(page))

    def test_every_page_has_only_a_link_and_the_guide_explains_it(self) -> None:
        from qfluentwidgets import CaptionLabel

        from xray_fluent.ui.configs_page import SECTIONS
        from xray_fluent.ui.singbox.art import ArtCanvas
        from xray_fluent.ui.singbox.guide import ART_CLASSES, GUIDES, LINK_LABEL, LINK_TEXT, GuideDialog

        page = _page()
        self.assertEqual(set(GUIDES), {key for key, _title, _icon in SECTIONS})
        self.assertEqual(set(ART_CLASSES), set(GUIDES))
        for key, _title, _icon in SECTIONS:
            _section(page, key)
            widget = page._sections[key]
            link = widget.help_link
            self.assertEqual(link.text(), LINK_LABEL)
            self.assertEqual(link.toolTip(), LINK_TEXT)
            self.assertTrue(link.isVisibleTo(widget), key)
            # Explanations and animations live only in the guide dialog.
            self.assertEqual(widget.findChildren(ArtCanvas), [], key)
            if key != "overview":  # the overview body shows file/stock captions
                header = link.parentWidget()
                captions = [c.text() for c in header.findChildren(CaptionLabel) if c.isVisibleTo(header)]
                self.assertEqual(captions, [], key)
            dialog = _guide(widget.open_guide if hasattr(widget, "open_guide") else link.click)
            self.assertIsInstance(dialog, GuideDialog)
            self.assertEqual(dialog.key, key)
            self.assertIsInstance(dialog.art, ART_CLASSES[key])
            self.assertGreater(len(dialog.text()), 300, key)
            self.assertFalse(dialog.cancelButton.isVisibleTo(dialog))
            self.assertLessEqual(dialog.widget.width(), max(360, page.window().width() - 2 * dialog.MARGIN) + 1)

    def test_guide_closes_and_is_disposed(self) -> None:
        from PyQt6 import sip

        page = _page()
        rules = _section(page, "rules")
        dialog = rules.open_guide()
        self.assertFalse(dialog.isHidden())
        dialog.yesButton.click()
        for _ in range(40):
            QTest.qWait(10)
            if sip.isdeleted(dialog):
                break
        self.assertTrue(sip.isdeleted(dialog))
        self.assertEqual(page.current_section(), "rules")

    def test_reference_counting(self) -> None:
        document = json.loads(TEMPLATE_TEXT)
        own = next(item for item in document["route"]["rule_set"] if item["tag"] == "geoip-ru")
        self.assertEqual(count_references(document, "geoip-ru", own), 1)


def _first_option(view):
    """The first add option that appends a core object (not «Простое правило»)."""
    return next(option for option in view.options if option.factory is not None)


if __name__ == "__main__":
    unittest.main()
