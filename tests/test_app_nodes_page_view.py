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

from xray_fluent.models import AppSettings, Node
from xray_fluent.ui.nodes_filter_proxy import SORT_KEYS
from xray_fluent.ui.nodes_page import _COLUMN_WIDTHS, _FLAG_ICON_SIZE, _ROW_HEIGHT, NodesPage
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
        self.assertEqual(_ROW_HEIGHT, 30)

    def test_table_rows_are_30px(self) -> None:
        vertical_header = self.page.table.verticalHeader()
        self.assertIsNotNone(vertical_header)
        self.assertEqual(vertical_header.defaultSectionSize(), 30)

    def test_flag_icon_size_is_18x13(self) -> None:
        self.assertEqual((_FLAG_ICON_SIZE.width(), _FLAG_ICON_SIZE.height()), (18, 13))
        icon_size = self.page.table.iconSize()
        self.assertEqual((icon_size.width(), icon_size.height()), (18, 13))

    def test_default_visible_columns_include_type_and_masked_address(self) -> None:
        expected = ["name", "type", "address", "ping", "speed"]
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
        self.assertEqual(_COLUMN_WIDTHS[COL_TYPE], 58)

    def test_type_column_is_clamped_to_compact_interactive_range(self) -> None:
        # AC7: the live drag is clamped only by the generous sanity bounds
        # (type: 44..200); values inside the range are never rolled back.
        header = self.page.table.horizontalHeader()
        header.resizeSection(COL_TYPE, 150)
        self.assertEqual(header.sectionSize(COL_TYPE), 150)
        header.resizeSection(COL_TYPE, 300)
        self.assertEqual(header.sectionSize(COL_TYPE), 200)
        header.resizeSection(COL_TYPE, 20)
        self.assertEqual(header.sectionSize(COL_TYPE), 44)

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
            nodes_column_widths={"type": 52, "address": 240},
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
        self.assertEqual(self.page.column_widths()["type"], 52)
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
                "nodes_column_layout_version": 1,
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
            ["name", "type", "address", "ping", "speed"],
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


class NodesPageFlexLayoutTests(NodesPageViewTestCase):
    """Flex-column layout: "name" absorbs the leftover viewport width (AC2-AC6, AC8)."""

    def _show_page(self, width: int = 1000, height: int = 500) -> None:
        self.page.resize(width, height)
        self.page.show()
        _APP.processEvents()

    def _header(self):
        return self.page.table.horizontalHeader()

    def _visible_total(self) -> int:
        header = self._header()
        return sum(
            header.sectionSize(col)
            for col in range(header.count())
            if not self.page.table.isColumnHidden(col)
        )

    def test_flex_layout_fills_viewport_exactly(self) -> None:
        # AC2: with enough room the visible columns fill the viewport exactly
        # and "name" sits above its minimum (no horizontal scrollbar needed).
        self._show_page(1000, 500)
        header = self._header()
        viewport_width = self.page.table.viewport().width()
        self.assertGreater(viewport_width, 0)
        self.assertEqual(self._visible_total(), viewport_width)
        self.assertGreater(
            header.sectionSize(COL_NAME), COLUMN_BY_KEY["name"].minimum_width
        )

        # A viewport resize re-runs the relayout and fills the new width too.
        self.page.resize(1200, 500)
        _APP.processEvents()
        new_viewport_width = self.page.table.viewport().width()
        self.assertGreater(new_viewport_width, viewport_width)
        self.assertEqual(self._visible_total(), new_viewport_width)

    def test_resizing_non_flex_column_is_absorbed_by_name(self) -> None:
        # AC3: a user drag of a non-flex column is compensated by "name";
        # the total width of visible columns does not change.
        self._show_page(1000, 500)
        header = self._header()
        viewport_width = self.page.table.viewport().width()
        name_before = header.sectionSize(COL_NAME)
        address_before = header.sectionSize(COL_ADDRESS)

        header.resizeSection(COL_ADDRESS, address_before + 100)

        self.assertEqual(header.sectionSize(COL_ADDRESS), address_before + 100)
        self.assertEqual(header.sectionSize(COL_NAME), name_before - 100)
        self.assertEqual(self._visible_total(), viewport_width)
        # AC8: the flex column width is derived and never persisted.
        self.assertNotIn("name", self.page.column_widths())
        self.assertEqual(self.page.column_widths()["address"], address_before + 100)

    def test_resizing_name_shifts_delta_to_right_neighbor(self) -> None:
        # AC4: growing "name" shrinks the first visible column to its right
        # in visual order ("type"), cascading further right on shortage.
        self._show_page(1000, 500)
        header = self._header()
        viewport_width = self.page.table.viewport().width()
        name_before = header.sectionSize(COL_NAME)
        type_before = header.sectionSize(COL_TYPE)  # 58, minimum 44
        address_before = header.sectionSize(COL_ADDRESS)

        header.resizeSection(COL_NAME, name_before + 10)
        self.assertEqual(header.sectionSize(COL_NAME), name_before + 10)
        self.assertEqual(header.sectionSize(COL_TYPE), type_before - 10)
        self.assertEqual(self._visible_total(), viewport_width)

        # Cascade: "type" has only 4px left above its minimum; the remaining
        # 16px of the next 20px drag are taken from "address".
        header.resizeSection(COL_NAME, name_before + 30)
        self.assertEqual(header.sectionSize(COL_NAME), name_before + 30)
        self.assertEqual(
            header.sectionSize(COL_TYPE), COLUMN_BY_KEY["type"].minimum_width
        )
        self.assertEqual(header.sectionSize(COL_ADDRESS), address_before - 16)
        self.assertEqual(self._visible_total(), viewport_width)
        self.assertNotIn("name", self.page.column_widths())

    def test_resizing_name_clamps_when_no_neighbor_can_absorb(self) -> None:
        # AC4 (clamp case): with no visible neighbor to the right able to
        # absorb the delta, the "name" drag itself is clamped.
        self._show_page(1000, 500)
        for col, key in enumerate(COLUMN_KEYS):
            if key != "name":
                self.page._set_column_visible(col, False)
        _APP.processEvents()
        header = self._header()
        name_before = header.sectionSize(COL_NAME)
        self.assertEqual(name_before, self.page.table.viewport().width())

        header.resizeSection(COL_NAME, name_before + 50)
        self.assertEqual(header.sectionSize(COL_NAME), name_before)

    def test_min_widths_overflow_enables_horizontal_scroll(self) -> None:
        # AC5: once "name" is at its minimum, further widening of other
        # columns is NOT rolled back; the sections overflow the viewport,
        # which is the horizontal-scrollbar condition.
        self._show_page(900, 500)
        header = self._header()
        viewport_width = self.page.table.viewport().width()
        name_minimum = COLUMN_BY_KEY["name"].minimum_width
        address_before = header.sectionSize(COL_ADDRESS)

        header.resizeSection(COL_ADDRESS, address_before + 800)

        self.assertEqual(header.sectionSize(COL_ADDRESS), address_before + 800)
        self.assertEqual(header.sectionSize(COL_NAME), name_minimum)
        self.assertGreater(self._visible_total(), viewport_width)

        # A further drag while "name" sits at its minimum still sticks
        # (address maximum is 1000, so +10 stays inside the sanity bound).
        wide = header.sectionSize(COL_ADDRESS)
        header.resizeSection(COL_ADDRESS, wide + 10)
        self.assertEqual(header.sectionSize(COL_ADDRESS), wide + 10)
        self.assertEqual(header.sectionSize(COL_NAME), name_minimum)

    def test_programmatic_relayout_does_not_emit_view_prefs(self) -> None:
        # AC6: apply_view_settings, viewport resizes and the relayouts they
        # trigger must not emit view_prefs_changed nor arm the save debounce.
        prefs: list[dict] = []
        self.page.view_prefs_changed.connect(prefs.append)

        settings = AppSettings(
            nodes_visible_columns=["name", "type", "address", "ping", "speed"],
            nodes_column_widths={"address": 240},
            nodes_column_layout_version=1,
        )
        self.page.apply_view_settings(settings)
        self._show_page(1000, 500)
        self.page.resize(1200, 500)
        _APP.processEvents()

        self.assertEqual(self._visible_total(), self.page.table.viewport().width())
        self.assertFalse(self.page._column_layout_timer.isActive())
        QTest.qWait(250)  # let any (wrongly) armed debounce timer fire
        self.assertEqual(prefs, [])


if __name__ == "__main__":
    unittest.main()
