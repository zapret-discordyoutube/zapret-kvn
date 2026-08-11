"""ScrollablePage / layout width tests (AC7, AC9).

Keep the ``test_app_*`` prefix: widget test modules must sort before
``tests/test_engine_process_stop.py`` which creates a bare QCoreApplication
at import time (see tests/test_app_nodes_page_view.py).
"""

from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QSizePolicy

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError(
        "A bare QCoreApplication was created before test_app_scrollable_page "
        "was imported; widget tests need a QApplication."
    )
app = _existing or QApplication([])

from PyQt6.QtCore import Qt
from qfluentwidgets import FluentIcon as FIF

from xray_fluent.ui.base_page import ScrollablePage
from xray_fluent.ui.configs_page import ConfigsPage
from xray_fluent.ui.dashboard_page import DashboardPage
from xray_fluent.ui.history_page import HistoryPage
from xray_fluent.ui.routing_page import RoutingPage
from xray_fluent.ui.settings_page import SettingsPage, _BrowseCard, _LineEditCard
from xray_fluent.ui.traffic_graph import DetailTrafficGraphWidget

AS_NEEDED = Qt.ScrollBarPolicy.ScrollBarAsNeeded
MIN_WINDOW_WIDTH = 860


def _page_factories():
    return [
        ("dashboard", DashboardPage),
        ("settings", SettingsPage),
        ("routing", RoutingPage),
        ("history", HistoryPage),
        ("configs", ConfigsPage),
    ]


def _scroll_areas(page):
    """All scroll areas that AC7 covers for the given page."""
    if isinstance(page, DashboardPage):
        return [
            page._main_page.scroll_area,
            page._traffic_detail_page.scroll_area,
            page._proc_detail_page.scroll_area,
        ]
    return [page.scroll_area]


def _assert_transparent_stylesheet(test: unittest.TestCase, widget) -> None:
    sheet = widget.styleSheet()
    if "background" in sheet:
        test.assertIn("transparent", sheet, f"opaque background on {widget}: {sheet!r}")
    test.assertNotIn("#", sheet, f"hardcoded color on {widget}: {sheet!r}")


class ScrollablePageBaseTest(unittest.TestCase):
    def test_base_page_policies_and_body(self) -> None:
        page = ScrollablePage()
        self.assertEqual(page.scroll_area.horizontalScrollBarPolicy(), AS_NEEDED)
        self.assertEqual(page.scroll_area.verticalScrollBarPolicy(), AS_NEEDED)
        self.assertTrue(page.scroll_area.widgetResizable())
        self.assertIs(page.scroll_area.widget(), page.body)
        margins = page.body_layout.contentsMargins()
        self.assertEqual(
            (margins.left(), margins.top(), margins.right(), margins.bottom()),
            (24, 20, 24, 20),
        )
        _assert_transparent_stylesheet(self, page)
        _assert_transparent_stylesheet(self, page.scroll_area)
        _assert_transparent_stylesheet(self, page.body)


class PagesUseScrollablePageTest(unittest.TestCase):
    """AC7: every listed page scrolls with ScrollBarAsNeeded, Mica-transparent."""

    def test_pages_horizontal_policy_as_needed(self) -> None:
        for name, factory in _page_factories():
            with self.subTest(page=name):
                page = factory()
                for area in _scroll_areas(page):
                    self.assertEqual(area.horizontalScrollBarPolicy(), AS_NEEDED)
                    self.assertTrue(area.widgetResizable())
                page.deleteLater()
        QApplication.processEvents()

    def test_pages_have_no_opaque_background(self) -> None:
        for name, factory in _page_factories():
            with self.subTest(page=name):
                page = factory()
                _assert_transparent_stylesheet(self, page)
                for area in _scroll_areas(page):
                    _assert_transparent_stylesheet(self, area)
                    _assert_transparent_stylesheet(self, area.viewport())
                    _assert_transparent_stylesheet(self, area.widget())
                page.deleteLater()
        QApplication.processEvents()

    def test_non_dashboard_pages_subclass_scrollable_page(self) -> None:
        for name, factory in _page_factories():
            if name == "dashboard":
                continue
            with self.subTest(page=name):
                page = factory()
                self.assertIsInstance(page, ScrollablePage)
                page.deleteLater()
        QApplication.processEvents()


class MinimumWidthsTest(unittest.TestCase):
    """AC9: pages must fit the 860px minimum window width."""

    def test_page_minimum_size_hints_fit_min_window(self) -> None:
        for name, factory in _page_factories():
            with self.subTest(page=name):
                page = factory()
                self.assertLessEqual(page.minimumSizeHint().width(), MIN_WINDOW_WIDTH)
                self.assertLessEqual(page.minimumWidth(), MIN_WINDOW_WIDTH)
                page.deleteLater()
        QApplication.processEvents()

    def test_detail_traffic_graph_minimum_width(self) -> None:
        graph = DetailTrafficGraphWidget()
        self.assertEqual(graph.minimumWidth(), 240)
        graph.deleteLater()
        QApplication.processEvents()

    def test_settings_edit_cards_are_moderate_and_expanding(self) -> None:
        line_card = _LineEditCard(FIF.LINK, "t", "c")
        self.assertLessEqual(line_card.edit.minimumWidth(), 240)
        self.assertEqual(
            line_card.edit.sizePolicy().horizontalPolicy(), QSizePolicy.Policy.Expanding
        )
        browse_card = _BrowseCard(FIF.FOLDER, "t", "c")
        self.assertLessEqual(browse_card.edit.minimumWidth(), 220)
        self.assertEqual(
            browse_card.edit.sizePolicy().horizontalPolicy(), QSizePolicy.Policy.Expanding
        )

        page = SettingsPage()
        for card in (page.xray_path_card, page.singbox_path_card):
            self.assertLessEqual(card.edit.minimumWidth(), 220)
            self.assertEqual(
                card.edit.sizePolicy().horizontalPolicy(), QSizePolicy.Policy.Expanding
            )
        for widget in (line_card, browse_card, page):
            widget.deleteLater()
        QApplication.processEvents()

    def test_configs_combos_are_moderate_and_expanding(self) -> None:
        page = ConfigsPage()
        for core, editor in page._editors.items():
            for combo in (editor.config_combo, editor.template_combo):
                with self.subTest(core=core):
                    self.assertLessEqual(combo.minimumWidth(), 200)
                    self.assertEqual(
                        combo.sizePolicy().horizontalPolicy(),
                        QSizePolicy.Policy.Expanding,
                    )
        page.deleteLater()
        QApplication.processEvents()

    def test_dashboard_cards_size_policy(self) -> None:
        page = DashboardPage()
        cards = (
            page.connection_card,
            page.routing_card,
            page.traffic_card,
            page._proc_traffic_card,
        )
        for card in cards:
            policy = card.sizePolicy()
            self.assertEqual(policy.horizontalPolicy(), QSizePolicy.Policy.Expanding)
            self.assertEqual(policy.verticalPolicy(), QSizePolicy.Policy.Preferred)
        page.deleteLater()
        QApplication.processEvents()


if __name__ == "__main__":
    unittest.main()
