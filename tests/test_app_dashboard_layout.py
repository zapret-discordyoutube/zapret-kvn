"""Dashboard layout tests: wordWrap invariant (AC8) and adaptive grid (AC10).

Keep the ``test_app_*`` prefix: widget test modules must sort before
``tests/test_engine_process_stop.py`` which creates a bare QCoreApplication
at import time (see tests/test_app_nodes_page_view.py).
"""

from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError(
        "A bare QCoreApplication was created before test_app_dashboard_layout "
        "was imported; widget tests need a QApplication."
    )
app = _existing or QApplication([])

from xray_fluent.models import AppSettings
from xray_fluent.ui.dashboard_page import DashboardPage


def _routing_card_position(page: DashboardPage) -> tuple[int, int, int, int]:
    grid = page._cards_grid
    index = grid.indexOf(page.routing_card)
    assert index >= 0, "routing_card is not in the cards grid"
    return grid.getItemPosition(index)


class DashboardWordWrapTest(unittest.TestCase):
    """AC8: variable-length labels of the connection/routing cards wrap."""

    LABELS = (
        "connection_status_label",
        "connection_target_label",
        "connection_engine_label",
        "routing_mode_label",
        "routing_dns_label",
        "routing_rules_label",
        "routing_bypass_label",
    )

    def test_labels_have_word_wrap(self) -> None:
        page = DashboardPage()
        for name in self.LABELS:
            with self.subTest(label=name):
                label = getattr(page, name)
                self.assertTrue(label.wordWrap(), f"{name} must have wordWrap")
        page.deleteLater()
        QApplication.processEvents()

    def test_minimum_size_hint_with_typical_texts(self) -> None:
        # AC9 companion: with the (long) default TUN/proxy explanation texts
        # rendered, the page minimum must still fit the 860px window minimum.
        page = DashboardPage()
        page.set_settings_snapshot(AppSettings())
        page._do_refresh_dashboard()
        self.assertLessEqual(page.minimumSizeHint().width(), 860)
        page.deleteLater()
        QApplication.processEvents()


class DashboardAdaptiveGridTest(unittest.TestCase):
    """AC10: routing card moves to row 1 below 900px, back at >= 900px."""

    def test_routing_card_reflows_on_resize(self) -> None:
        page = DashboardPage()
        try:
            page.resize(850, 600)
            page.show()
            QApplication.processEvents()
            row, col, _rspan, cspan = _routing_card_position(page)
            self.assertEqual((row, col), (1, 0), "narrow: routing card in second row")
            self.assertEqual(cspan, 2, "narrow: routing card spans both columns")

            page.resize(1200, 700)
            QApplication.processEvents()
            row, col, _rspan, cspan = _routing_card_position(page)
            self.assertEqual((row, col), (0, 1), "wide: routing card back in first row")
            self.assertEqual(cspan, 1)

            # Reflow must not recreate widgets: same connection card position.
            grid = page._cards_grid
            conn_row, conn_col, _r, _c = grid.getItemPosition(
                grid.indexOf(page.connection_card)
            )
            self.assertEqual((conn_row, conn_col), (0, 0))
        finally:
            page.hide()
            page.deleteLater()
            QApplication.processEvents()

    def test_resize_around_threshold_is_stable(self) -> None:
        page = DashboardPage()
        try:
            page.resize(1000, 700)
            page.show()
            QApplication.processEvents()
            self.assertEqual(_routing_card_position(page)[:2], (0, 1))

            for width, expected in ((899, (1, 0)), (900, (0, 1)), (850, (1, 0)), (1200, (0, 1))):
                page.resize(width, 700)
                QApplication.processEvents()
                self.assertEqual(
                    _routing_card_position(page)[:2], expected, f"width={width}"
                )
        finally:
            page.hide()
            page.deleteLater()
            QApplication.processEvents()


if __name__ == "__main__":
    unittest.main()
