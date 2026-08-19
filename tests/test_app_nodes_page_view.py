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

from PyQt6.QtWidgets import QApplication, QHeaderView

from xray_fluent.models import AppSettings, Node
from xray_fluent.ui.nodes_filter_proxy import SORT_KEYS
from xray_fluent.ui.nodes_page import _COLUMN_WIDTHS, _FLAG_ICON_SIZE, _ROW_HEIGHT, NodesPage
from xray_fluent.ui.nodes_table_model import COL_ADDRESS, COL_TYPE, DEFAULT_VISIBLE_COLUMNS, NODE_ID_ROLE

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

    def test_default_visible_columns_are_name_ping_speed(self) -> None:
        self.assertEqual(list(DEFAULT_VISIBLE_COLUMNS), ["name", "ping", "speed"])
        self.assertEqual(self.page.visible_column_keys(), ["name", "ping", "speed"])

    def test_columns_are_movable_and_user_resizable(self) -> None:
        header = self.page.table.horizontalHeader()
        self.assertTrue(header.sectionsMovable())
        self.assertEqual(header.sectionResizeMode(COL_ADDRESS), QHeaderView.ResizeMode.Interactive)

    def test_type_column_has_compact_default_width(self) -> None:
        self.assertEqual(_COLUMN_WIDTHS[COL_TYPE], 72)


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
        )

        self.page.apply_view_settings(settings)
        self.assertEqual(self.prefs, [], "apply_view_settings must not emit view_prefs_changed")

        # Group/tag filters are deferred until set_nodes populates the combos.
        self.page.set_nodes(self.nodes)
        self.assertEqual(self.prefs, [], "applying deferred filters must not emit view_prefs_changed")

        self.assertEqual(self.page.group_filter.currentText(), "EU")
        self.assertEqual(self.page.tag_filter.currentText(), "fast")
        self.assertEqual(self.page.visible_column_keys(), ["name", "address", "ping"])

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
            },
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


if __name__ == "__main__":
    unittest.main()
