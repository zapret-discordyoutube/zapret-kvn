"""FluentDialog theming tests (AC3 of ui-theme-layout-architecture).

NOTE on the module name: unittest discover imports test modules in
alphabetical order, and ``tests/test_engine_process_stop.py`` (and others)
create a bare ``QCoreApplication`` at import time, which cannot host
widgets and cannot be upgraded in-process.  Keep the ``test_app_*`` prefix
so widget test modules sort before any ``QCoreApplication``-creating
module (see tests/test_app_nodes_page_view.py).
"""

from __future__ import annotations

import os
import unittest
from collections import deque
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtGui import QPalette
from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError(
        "A bare QCoreApplication was created before test_app_fluent_dialog "
        "was imported; widget tests need a QApplication."
    )
app = _existing or QApplication([])

from qfluentwidgets import Theme, qconfig, setTheme

from xray_fluent.models import Node
from xray_fluent.ui.bulk_edit_dialog import BulkEditDialog
from xray_fluent.ui.fluent_dialog import FluentDialog
from xray_fluent.ui.lock_dialog import PasswordDialog
from xray_fluent.ui.node_edit_dialog import NodeEditDialog
from xray_fluent.ui.subscriptions_page import SubscriptionDeleteDialog, SubscriptionDialog
from xray_fluent.ui.theme import surface_color
from xray_fluent.ui.traffic_graph import TrafficGraphDialog

UI_DIR = Path(__file__).resolve().parent.parent / "xray_fluent" / "ui"


class FluentDialogThemeTest(unittest.TestCase):
    def setUp(self) -> None:
        self._saved_theme = qconfig.themeMode.value

    def tearDown(self) -> None:
        setTheme(self._saved_theme)
        QApplication.processEvents()

    def test_all_six_dialogs_inherit_fluent_dialog(self) -> None:
        node = Node(name="n", server="example.com", port=443, scheme="vless")
        dialogs = [
            PasswordDialog(),
            NodeEditDialog(node, ["g"]),
            BulkEditDialog(2, []),
            TrafficGraphDialog(deque(), deque()),
            SubscriptionDialog(),
            SubscriptionDeleteDialog("x"),
        ]
        for dialog in dialogs:
            with self.subTest(dialog=type(dialog).__name__):
                self.assertIsInstance(dialog, FluentDialog)
            dialog.deleteLater()

    def test_dialog_surface_and_palette_follow_theme(self) -> None:
        setTheme(Theme.DARK)
        dialog = PasswordDialog()
        try:
            dark_surface = surface_color().name()
            self.assertIn(dark_surface, dialog.styleSheet())
            dark_placeholder = dialog.palette().color(
                QPalette.ColorRole.PlaceholderText
            ).getRgb()
            dark_text = dialog.palette().color(QPalette.ColorRole.Text).getRgb()

            setTheme(Theme.LIGHT)
            QApplication.processEvents()

            light_surface = surface_color().name()
            self.assertNotEqual(dark_surface, light_surface)
            self.assertIn(light_surface, dialog.styleSheet())
            self.assertNotIn(dark_surface, dialog.styleSheet())
            light_placeholder = dialog.palette().color(
                QPalette.ColorRole.PlaceholderText
            ).getRgb()
            light_text = dialog.palette().color(QPalette.ColorRole.Text).getRgb()
            self.assertNotEqual(dark_placeholder, light_placeholder)
            self.assertNotEqual(dark_text, light_text)
        finally:
            dialog.deleteLater()

    def test_no_hardcoded_dialog_backgrounds_left(self) -> None:
        offenders: list[str] = []
        for path in sorted(UI_DIR.glob("*.py")):
            if path.name == "theme.py":
                continue  # theme.py legitimately owns the surface token values
            text = path.read_text(encoding="utf-8")
            if "#2b2b2b" in text or "#f3f3f3" in text:
                offenders.append(path.name)
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
