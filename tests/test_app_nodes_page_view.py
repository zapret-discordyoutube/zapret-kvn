"""NodesPage view tests (AC8 compact layout, AC11 apply_view_settings).

NOTE on the module name: unittest discover imports test modules in
alphabetical order, and ``tests/test_engine_process_stop.py`` (and others)
create a bare ``QCoreApplication`` at import time, which cannot host
widgets and cannot be upgraded in-process.  This module must therefore be
imported *first* among app-creating modules so it can install a full
``QApplication`` (offscreen); being a ``QCoreApplication`` subclass, it
satisfies every later ``QCoreApplication.instance() or ...`` bootstrap.
Keep the ``test_app_*`` prefix so it sorts before ``test_engine_*``.
"""

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QHeaderView

from xray_fluent.profiles.models import AppSettings, Node
from xray_fluent.ui.nodes_filter_proxy import SORT_KEYS
from xray_fluent.ui.nodes_table_model import COL_PING, COL_SPEED
from xray_fluent.ui.nodes_page import _COLUMN_WIDTHS, _FLAG_ICON_SIZE, _ROW_HEIGHT, NodesPage
from xray_fluent.ui.nodes_table_delegate import NodesActivityDelegate
from xray_fluent.ui.nodes_table_model import (
    COL_ADDRESS,
    COL_NAME,
    COL_TYPE,
    COLUMN_BY_KEY,
    COLUMN_KEYS,
    DEFAULT_VISIBLE_COLUMNS,
    NODE_ID_ROLE,
)

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError(
        "A bare QCoreApplication was created before test_app_nodes_page_view "
        "was imported; widget tests need a QApplication. Keep this module "
        "alphabetically before any QCoreApplication-creating test module."
    )
_APP = _existing or QApplication([])


def _proxy_order(page: NodesPage) -> list[str]:
    proxy = page._proxy
    return [proxy.index(row, 0).data(NODE_ID_ROLE) for row in range(proxy.rowCount())]


class NodesPageViewTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.page = NodesPage()

    def tearDown(self) -> None:
        self.page.deleteLater()
        _APP.processEvents()


class NodesPageCompactLayoutTests(NodesPageViewTestCase):
    """AC8: compact table — 30px rows, ~18x13 flag icon, default visible columns."""

    def test_row_height_constant_is_30(self) -> None:
        self.assertEqual(_ROW_HEIGHT, 36)

    def test_table_rows_are_30px(self) -> None:
        self.page.set_nodes([Node(name="A")])
        index = self.page._group_model.index(0, 0)
        self.assertEqual(index.data(Qt.ItemDataRole.SizeHintRole).height(), 36)

    def test_flag_icon_size_is_18x13(self) -> None:
        self.assertEqual((_FLAG_ICON_SIZE.width(), _FLAG_ICON_SIZE.height()), (18, 13))
        icon_size = self.page.table.iconSize()
        self.assertEqual((icon_size.width(), icon_size.height()), (18, 13))

    def test_default_visible_columns_include_type_and_masked_address(self) -> None:
        expected = ["name", "type", "ping", "speed"]
        self.assertEqual(list(DEFAULT_VISIBLE_COLUMNS), expected)
        self.assertEqual(self.page.visible_column_keys(), expected)

    def test_columns_are_movable_and_user_resizable(self) -> None:
        header = self.page.table.horizontalHeader()
        self.assertTrue(header.sectionsMovable())
        # AC1: every column, including the "name" flex column, is Interactive;
        # ResizeMode.Stretch is not used anywhere.
        for col in range(header.count()):
            self.assertEqual(
                header.sectionResizeMode(col),
                QHeaderView.ResizeMode.Interactive,
                f"column {COLUMN_KEYS[col]} must be Interactive",
            )

    def test_type_column_has_compact_default_width(self) -> None:
        self.assertEqual(_COLUMN_WIDTHS[COL_TYPE], 110)

    def test_type_column_is_clamped_to_compact_interactive_range(self) -> None:
        # AC7: the live drag is clamped only by the generous sanity bounds
        # (type: 44..200); values inside the range are never rolled back.
        header = self.page.table.horizontalHeader()
        header.resizeSection(COL_TYPE, 150)
        self.assertEqual(header.sectionSize(COL_TYPE), 150)
        header.resizeSection(COL_TYPE, 300)
        self.assertEqual(header.sectionSize(COL_TYPE), 200)
        header.resizeSection(COL_TYPE, 20)
        self.assertEqual(header.sectionSize(COL_TYPE), 90)

    def test_reveal_button_masks_again_after_mouse_and_keyboard_release(self) -> None:
        self.page.set_nodes(
            [Node(id="secret", server="secret.example", port=8443, scheme="vless")]
        )
        index = self.page._table_model.index(0, COL_ADDRESS)
        button = self.page.reveal_addresses_btn

        QTest.mousePress(button, Qt.MouseButton.LeftButton)
        self.assertEqual(index.data(), "secret.example:8443")
        QTest.mouseRelease(button, Qt.MouseButton.LeftButton)
        self.assertEqual(index.data(), "********")

        button.setFocus()
        QTest.keyPress(button, Qt.Key.Key_Space)
        self.assertEqual(index.data(), "secret.example:8443")
        QTest.keyRelease(button, Qt.Key.Key_Space)
        self.assertEqual(index.data(), "********")


class NodesPageApplyViewSettingsTests(NodesPageViewTestCase):
    """AC11: apply_view_settings round-trip and view_prefs_changed emissions."""

    def setUp(self) -> None:
        super().setUp()
        self.prefs: list[dict] = []
        self.page.view_prefs_changed.connect(self.prefs.append)
        self.nodes = [
            Node(id="a", name="Alpha", group="EU", tags=["fast"], ping_ms=50, sort_order=0),
            Node(id="b", name="Bravo", group="EU", tags=["fast"], ping_ms=200, sort_order=1),
            Node(id="c", name="Charlie", group="EU", tags=["fast"], ping_ms=None, sort_order=2),
            Node(id="d", name="Delta", group="US", tags=["slow"], ping_ms=500, sort_order=3),
        ]

    def test_apply_view_settings_round_trip_without_pref_emissions(self) -> None:
        settings = AppSettings(
            nodes_sort_key="ping",
            nodes_sort_desc=True,
            nodes_group_filter="EU",
            nodes_tag_filter="fast",
            nodes_visible_columns=["name", "address", "ping"],
            nodes_column_widths={"type": 110, "address": 240},
            nodes_column_order=["name", "address", "type", "ping", "speed"],
        )

        self.page.apply_view_settings(settings)
        self.assertEqual(self.prefs, [], "apply_view_settings must not emit view_prefs_changed")

        # Group/tag filters are deferred until set_nodes populates the combos.
        self.page.set_nodes(self.nodes)
        self.assertEqual(self.prefs, [], "applying deferred filters must not emit view_prefs_changed")

        self.assertEqual(self.page.group_filter.currentText(), "EU")
        self.assertEqual(self.page.tag_filter.currentText(), "fast")
        self.assertEqual(self.page.visible_column_keys(), ["name", "address", "ping"])
        self.assertEqual(self.page.column_widths()["type"], 110)
        self.assertEqual(self.page.column_widths()["address"], 240)
        self.assertEqual(self.page.column_order()[:3], ["name", "address", "type"])

        # Sort key "ping" descending is applied to the proxy; "d" is filtered
        # out (group US), None-ping stays last even in descending order.
        self.assertEqual(_proxy_order(self.page), ["b", "a", "c"])

        # Reading the preferences back reproduces exactly what was applied.
        self.page._emit_view_prefs()
        self.assertEqual(len(self.prefs), 1)
        self.assertEqual(
            self.prefs[0],
            {
                "nodes_sort_key": "ping",
                "nodes_sort_desc": True,
                "nodes_group_filter": "EU",
                "nodes_tag_filter": "fast",
                "nodes_source_filter": "",
                "nodes_visible_columns": ["name", "address", "ping"],
                "nodes_column_widths": self.page.column_widths(),
                "nodes_column_order": self.page.column_order(),
                "nodes_column_layout_version": 2,
                "nodes_group_by": "source",
                "nodes_collapsed_groups": [],
                "nodes_favorites_only": False,
            },
        )

    def test_legacy_visibility_is_migrated_to_type_and_address(self) -> None:
        settings = AppSettings(
            nodes_visible_columns=["name", "ping", "speed"],
            nodes_column_layout_version=0,
        )
        self.page.apply_view_settings(settings)
        self.assertEqual(
            self.page.visible_column_keys(),
            ["name", "type", "ping", "speed"],
        )

    def test_user_sort_change_emits_view_prefs(self) -> None:
        self.page.set_nodes(self.nodes)
        self.assertEqual(self.prefs, [])

        # User picks the "ping" sort key in the combo box.
        self.page.sort_combo.setCurrentIndex(SORT_KEYS.index("ping"))
        self.assertEqual(len(self.prefs), 1)
        self.assertEqual(self.prefs[0]["nodes_sort_key"], "ping")
        self.assertFalse(self.prefs[0]["nodes_sort_desc"])
        self.assertEqual(_proxy_order(self.page), ["a", "b", "d", "c"])

        # User toggles the sort direction.
        self.page.sort_order_btn.click()
        self.assertEqual(len(self.prefs), 2)
        self.assertEqual(self.prefs[1]["nodes_sort_key"], "ping")
        self.assertTrue(self.prefs[1]["nodes_sort_desc"])
        self.assertEqual(_proxy_order(self.page), ["d", "b", "a", "c"])


class NodesPageColumnLayoutTests(NodesPageViewTestCase):
    def test_resize_preserves_all_column_widths(self):
        self.page.resize(1000, 600)
        self.page.show()
        _APP.processEvents()
        before = self.page.column_widths()
        self.page.resize(1800, 800)
        _APP.processEvents()
        self.assertEqual(before, self.page.column_widths())
        self.assertEqual(self.page.table.header().sectionSize(COL_NAME), 360)

    def test_name_drag_does_not_resize_neighbors_and_is_persisted(self):
        header = self.page.table.header()
        others = [header.sectionSize(c) for c in (COL_TYPE, COL_PING, COL_SPEED)]
        header.resizeSection(COL_NAME, 500)
        self.assertEqual(self.page.column_widths()["name"], 500)
        self.assertEqual(others, [header.sectionSize(c) for c in (COL_TYPE, COL_PING, COL_SPEED)])
        header.resizeSection(COL_NAME, 5000)
        self.assertEqual(header.sectionSize(COL_NAME), 640)

    def test_programmatic_resize_does_not_save_preferences(self):
        events = []
        self.page.view_prefs_changed.connect(events.append)
        self.page.resize(1600, 900)
        self.page._relayout_flex_column()
        self.assertEqual(events, [])


class NodesActiveRowFillSeamTests(NodesPageViewTestCase):
    """The translucent active-row fill must not double up at column edges."""

    def test_fill_has_no_alpha_doubling_at_column_boundaries(self) -> None:
        nodes = [
            Node(id=f"n{i}", name=f"Node {i}", server=f"s{i}.example", port=443, scheme="vless")
            for i in range(6)
        ]
        self.page.set_nodes(nodes)
        self.page._table_model.set_active_node_id("n2")
        self.page.resize(1000, 400)
        self.page.show()
        _APP.processEvents()

        table = self.page.table
        proxy = self.page._proxy
        row = next(
            r for r in range(proxy.rowCount()) if proxy.index(r, 0).data(NODE_ID_ROLE) == "n2"
        )
        rect = table.visualRect(proxy.index(row, 0))
        image = table.viewport().grab().toImage()

        header = table.horizontalHeader()
        boundaries = [
            header.sectionPosition(col)
            for col in range(header.count())
            if not header.isSectionHidden(col)
            and 0 < header.sectionPosition(col) < image.width() - 8
        ]
        self.assertTrue(boundaries)

        # Scan just inside the fill's top edge, above flag icons and glyphs.
        y = rect.top() + 4
        reference = image.pixelColor(boundaries[0] // 2, y)
        for boundary in boundaries:
            for x in range(boundary - 6, boundary + 7):
                color = image.pixelColor(x, y)
                deviation = max(
                    abs(color.red() - reference.red()),
                    abs(color.green() - reference.green()),
                    abs(color.blue() - reference.blue()),
                )
                self.assertLessEqual(
                    deviation,
                    3,
                    f"seam at x={x} near boundary {boundary}: "
                    f"{color.getRgb()} vs {reference.getRgb()}",
                )


class NodesActivityDelegateTests(NodesPageViewTestCase):
    def test_active_server_uses_stock_tree_delegate_and_bold_font(self):
        from qfluentwidgets import TreeItemDelegate
        self.page.set_nodes([Node(id="a", name="A")])
        self.page.set_active_node("a")
        self.assertIsInstance(self.page.table.itemDelegate(), TreeItemDelegate)
        parent = self.page._group_model.index(0, 0)
        index = self.page._group_model.index(0, 0, parent)
        self.assertTrue(index.data(Qt.ItemDataRole.FontRole).bold())


if __name__ == "__main__":
    unittest.main()
