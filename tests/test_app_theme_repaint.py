"""Theme repaint tests for manual-paint widgets (AC6b).

Keep the ``test_app_*`` prefix: widget test modules must sort before
``tests/test_engine_process_stop.py`` which creates a bare QCoreApplication
at import time (see tests/test_app_nodes_page_view.py).
"""

from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError(
        "A bare QCoreApplication was created before test_app_theme_repaint "
        "was imported; widget tests need a QApplication."
    )
app = _existing or QApplication([])

from qfluentwidgets import Theme, qconfig, setTheme

from xray_fluent.profiles.models import Node
from xray_fluent.ui.nodes_table_model import COL_PING, NodesTableModel


class NodesModelThemeRepaintTest(unittest.TestCase):
    def setUp(self) -> None:
        self._saved_theme = qconfig.themeMode.value
        self.model = NodesTableModel()
        self.nodes = [
            Node(name="a", server="1.1.1.1", port=443, scheme="vless", is_alive=True),
            Node(name="b", server="2.2.2.2", port=443, scheme="vless", is_alive=False),
        ]
        self.model.set_nodes(self.nodes)

    def tearDown(self) -> None:
        setTheme(self._saved_theme)
        QApplication.processEvents()

    def test_theme_change_repaints_every_row_and_column(self) -> None:
        # Цвета статуса берутся из темы в момент отрисовки; смена темы должна
        # перерисовать все строки (включая заголовки групп) и все колонки.
        # Пустой список ролей в dataChanged означает «все роли», в том числе
        # ForegroundRole.
        emissions: list[tuple[int, int, int, int, list[int]]] = []

        def on_data_changed(top_left, bottom_right, roles) -> None:
            emissions.append(
                (top_left.row(), bottom_right.row(), top_left.column(), bottom_right.column(), list(roles))
            )

        self.model.dataChanged.connect(on_data_changed)
        setTheme(Theme.DARK)
        QApplication.processEvents()
        emissions.clear()

        setTheme(Theme.LIGHT)
        QApplication.processEvents()

        self.assertEqual(self.model.rowCount(), 3)  # заголовок группы + 2 сервера
        full_spans = [
            emission
            for emission in emissions
            if emission[:4] == (0, self.model.rowCount() - 1, 0, self.model.columnCount() - 1)
            and (not emission[4] or Qt.ItemDataRole.ForegroundRole in emission[4])
        ]
        self.assertTrue(full_spans, f"no full-table dataChanged on theme change: {emissions}")

    def test_status_brushes_follow_theme(self) -> None:
        index = self.model.index(self.model.row_of_node(self.nodes[1].id), COL_PING)  # dead node -> error brush
        setTheme(Theme.DARK)
        dark_brush = self.model.data(index, Qt.ItemDataRole.ForegroundRole)
        setTheme(Theme.LIGHT)
        light_brush = self.model.data(index, Qt.ItemDataRole.ForegroundRole)
        self.assertIsNotNone(dark_brush)
        self.assertIsNotNone(light_brush)
        self.assertNotEqual(dark_brush.color().getRgb(), light_brush.color().getRgb())


if __name__ == "__main__":
    unittest.main()
