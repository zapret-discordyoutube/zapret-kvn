"""Global accent theme tests — widget-level ACs (AC5, AC6, AC8, AC9).

Task: .agent/tasks/20260820-global-accent-theme.

Keep the ``test_app_*`` prefix: widget test modules must sort before
``tests/test_engine_process_stop.py`` which creates a bare QCoreApplication
at import time (see tests/test_app_nodes_page_view.py).
"""

from __future__ import annotations

import os
import re
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError(
        "A bare QCoreApplication was created before test_app_accent_widgets "
        "was imported; widget tests need a QApplication."
    )
app = _existing or QApplication([])

from qfluentwidgets import qconfig, setTheme, setThemeColor, themeColor

from xray_fluent.profiles.models import AppSettings, Node, SecuritySettings
from xray_fluent.ui import theme
from xray_fluent.ui.nodes_table_delegate import NodesActivityDelegate
from xray_fluent.ui.nodes_table_model import COL_NAME, NodesTableModel
from xray_fluent.ui.settings_page import SettingsPage
from xray_fluent.ui.traffic_graph import DetailTrafficGraphWidget, TrafficGraphWidget
from xray_fluent.ui.zapret_page import ZapretPage
from xray_fluent.engines.zapret.manager import PresetInfo

REPO_ROOT = Path(__file__).resolve().parent.parent
UI_DIR = REPO_ROOT / "xray_fluent" / "ui"


class _AccentRestoreMixin(unittest.TestCase):
    def setUp(self) -> None:
        self._saved_theme = qconfig.themeMode.value
        self._saved_accent = QColor(themeColor())

    def tearDown(self) -> None:
        setTheme(self._saved_theme)
        setThemeColor(self._saved_accent)
        QApplication.processEvents()


class NodesDelegateActiveFillTest(_AccentRestoreMixin):
    """AC5: soft accent fill for the active node row."""

    def setUp(self) -> None:
        super().setUp()
        self.model = NodesTableModel()
        self.nodes = [
            Node(name="a", server="1.1.1.1", port=443, scheme="vless"),
            Node(name="b", server="2.2.2.2", port=443, scheme="vless"),
        ]
        self.model.set_nodes(self.nodes)
        self.model.set_active_node_id(self.nodes[0].id)

    def test_active_row_fill_matches_accent_soft_bg(self) -> None:
        index = self.model.index(0, COL_NAME)
        fill = NodesActivityDelegate.row_fill_color(index)
        self.assertIsNotNone(fill)
        self.assertEqual(fill.getRgb(), theme.accent_soft_bg().getRgb())
        self.assertEqual(fill.alpha(), 38)

    def test_inactive_row_has_no_fill(self) -> None:
        index = self.model.index(1, COL_NAME)
        self.assertIsNone(NodesActivityDelegate.row_fill_color(index))

    def test_fill_follows_accent_change(self) -> None:
        index = self.model.index(0, COL_NAME)
        setThemeColor("#123456")
        before = NodesActivityDelegate.row_fill_color(index).getRgb()
        setThemeColor("#654321")
        after = NodesActivityDelegate.row_fill_color(index).getRgb()
        self.assertNotEqual(before, after)
        self.assertEqual(after[:3], (0x65, 0x43, 0x21))


class TrafficGraphAccentRepaintTest(_AccentRestoreMixin):
    """AC6: traffic graphs schedule a repaint when only the accent changes."""

    def test_compact_graph_updates_on_accent_change(self) -> None:
        widget = TrafficGraphWidget()
        try:
            setThemeColor("#336699")
            QApplication.processEvents()
            with mock.patch.object(widget, "update") as update:
                setThemeColor("#663399")
                QApplication.processEvents()
                update.assert_called()
        finally:
            widget.deleteLater()
            QApplication.processEvents()

    def test_detail_graph_updates_on_accent_change(self) -> None:
        widget = DetailTrafficGraphWidget()
        try:
            setThemeColor("#336699")
            QApplication.processEvents()
            with mock.patch.object(widget, "update") as update:
                setThemeColor("#663399")
                QApplication.processEvents()
                update.assert_called()
        finally:
            widget.deleteLater()
            QApplication.processEvents()


class NodesPageAccentRepaintTest(_AccentRestoreMixin):
    """AC6: the nodes table viewport repaints when only the accent changes."""

    def test_nodes_view_repaints_on_accent_change(self) -> None:
        from xray_fluent.ui.nodes_page import NodesPage

        page = NodesPage()
        try:
            setThemeColor("#336699")
            QApplication.processEvents()
            with mock.patch.object(page.table.viewport(), "update") as update:
                setThemeColor("#663399")
                QApplication.processEvents()
                update.assert_called()
        finally:
            page.deleteLater()
            QApplication.processEvents()


def _preset(name: str) -> PresetInfo:
    return PresetInfo(
        name=name,
        description=f"desc {name}",
        created="2026-08-20T00:00:00",
        modified="2026-08-20T00:00:00",
        arg_count=3,
        file_path=Path(f"{name}.txt"),
    )


class ZapretActivePresetAccentTest(_AccentRestoreMixin):
    """AC8: the active preset row is accent-styled, not success-green."""

    def setUp(self) -> None:
        super().setUp()
        self.page = ZapretPage()
        self.page.set_presets([_preset("alpha"), _preset("beta")])

    def tearDown(self) -> None:
        self.page.deleteLater()
        QApplication.processEvents()
        super().tearDown()

    def _badge(self, row: int) -> str:
        item = self.page.preset_list.item(row)
        return str(item.data(Qt.ItemDataRole.UserRole + 2) or "")

    def _row_colors(self, row: int) -> set[tuple[int, int, int]]:
        """Colors the delegate actually paints for one row."""

        from PyQt6.QtCore import QRect
        from PyQt6.QtGui import QImage, QPainter
        from PyQt6.QtWidgets import QStyleOptionViewItem

        view = self.page.preset_list
        index = view.model().index(row, 0)
        option = QStyleOptionViewItem()
        option.rect = QRect(0, 0, 420, 44)
        option.font = view.font()
        option.palette = view.palette()
        image = QImage(420, 44, QImage.Format.Format_ARGB32)
        image.fill(0)
        painter = QPainter(image)
        view.itemDelegate().paint(painter, option, index)
        painter.end()
        colors = set()
        for y in range(image.height()):
            for x in range(image.width()):
                pixel = image.pixelColor(x, y)
                if pixel.alpha():
                    colors.add((pixel.red(), pixel.green(), pixel.blue()))
        return colors

    def test_active_row_is_badged_and_painted_with_the_accent(self) -> None:
        self.page.set_running(True, "alpha")
        self.assertEqual(self._badge(0), "Активен")
        accent = theme.accent_color()
        success = theme.success_color()
        colors = self._row_colors(0)
        self.assertIn((accent.red(), accent.green(), accent.blue()), colors)
        self.assertNotIn((success.red(), success.green(), success.blue()), colors)

    def test_inactive_rows_carry_no_active_badge(self) -> None:
        self.page.set_running(True, "alpha")
        self.assertEqual(self._badge(1), "")

    def test_stopped_state_has_no_row_highlight(self) -> None:
        self.page.set_running(True, "alpha")
        self.page.set_running(False)
        self.assertEqual(self._badge(0), "")

    def test_accent_change_recolors_active_row(self) -> None:
        setThemeColor("#123456")
        self.page.set_running(True, "alpha")
        self.assertIn((0x12, 0x34, 0x56), self._row_colors(0))
        setThemeColor("#654321")
        QApplication.processEvents()
        self.assertIn((0x65, 0x43, 0x21), self._row_colors(0))


class SettingsAccentPresetsTest(_AccentRestoreMixin):
    """AC9: preset swatches in the settings page."""

    def setUp(self) -> None:
        super().setUp()
        self.page = SettingsPage()
        self.page.set_values(AppSettings(), SecuritySettings())

    def tearDown(self) -> None:
        self.page.deleteLater()
        QApplication.processEvents()
        super().tearDown()

    def test_accent_presets_contract(self) -> None:
        self.assertEqual(len(theme.ACCENT_PRESETS), 8)
        self.assertEqual(theme.ACCENT_PRESETS[0][0], theme.DEFAULT_ACCENT)
        hexes = [value for value, _name in theme.ACCENT_PRESETS]
        self.assertEqual(len(set(hexes)), 8)
        for value, name in theme.ACCENT_PRESETS:
            self.assertRegex(value, r"^#[0-9A-F]{6}$")
            self.assertTrue(name)

    def test_swatch_click_emits_normalized_save(self) -> None:
        saved: list[AppSettings] = []
        self.page.save_requested.connect(saved.append)
        target = self.page.accent_card.swatches[3]
        target.click()
        self.assertTrue(saved)
        self.assertEqual(saved[-1].accent_color, theme.ACCENT_PRESETS[3][0])
        self.assertTrue(target.isChecked())
        self.assertEqual(
            sum(1 for s in self.page.accent_card.swatches if s.isChecked()), 1
        )

    def test_default_accent_marks_first_swatch(self) -> None:
        # Loaded with the default accent: the first swatch is checked, even if
        # the stored hex uses lower case.
        settings = AppSettings()
        settings.accent_color = theme.DEFAULT_ACCENT.lower()
        self.page.set_values(settings, SecuritySettings())
        self.assertTrue(self.page.accent_card.swatches[0].isChecked())

    def test_arbitrary_color_marks_no_swatch(self) -> None:
        settings = AppSettings()
        settings.accent_color = "#0A0B0C"
        self.page.set_values(settings, SecuritySettings())
        self.assertFalse(any(s.isChecked() for s in self.page.accent_card.swatches))

    def test_collect_normalizes_picker_color(self) -> None:
        saved: list[AppSettings] = []
        self.page.save_requested.connect(saved.append)
        self.page.accent_card.picker.setColor(QColor("#abcdef"))
        self.page._auto_save()
        self.assertTrue(saved)
        self.assertEqual(saved[-1].accent_color, "#ABCDEF")


class AccentStaticGatesTest(unittest.TestCase):
    """AC6/AC9 static gates: subscriptions via theme helpers, hex only in theme.py."""

    _SUBSCRIBED_FILES = (
        "traffic_graph.py",
        "zapret_page.py",
        "subscriptions_page.py",
        "nodes_page.py",
    )

    def _read(self, name: str) -> str:
        return (UI_DIR / name).read_text(encoding="utf-8")

    def test_accent_subscriptions_present(self) -> None:
        pattern = re.compile(r"on_accent_changed|on_theme_or_accent_changed")
        for name in self._SUBSCRIBED_FILES:
            with self.subTest(module=name):
                self.assertRegex(self._read(name), pattern)

    def test_no_direct_theme_color_changed_subscriptions_outside_theme(self) -> None:
        offenders = [
            path.name
            for path in sorted(UI_DIR.glob("*.py"))
            if path.name != "theme.py"
            and "themeColorChanged" in path.read_text(encoding="utf-8")
        ]
        self.assertEqual(offenders, [])

    def test_preset_hexes_only_in_theme_module(self) -> None:
        preset_hexes = [value for value, _name in theme.ACCENT_PRESETS[1:]]
        offenders: list[str] = []
        for path in sorted(UI_DIR.glob("*.py")):
            if path.name == "theme.py":
                continue
            source = path.read_text(encoding="utf-8")
            offenders.extend(
                f"{path.name}:{value}" for value in preset_hexes if value in source
            )
        self.assertEqual(offenders, [])

    def test_zapret_page_does_not_use_success_color(self) -> None:
        self.assertNotIn("success_color", self._read("zapret_page.py"))

    def test_set_theme_color_called_only_from_theme_module(self) -> None:
        offenders: list[str] = []
        for path in sorted((REPO_ROOT / "xray_fluent").rglob("*.py")):
            if path.name == "theme.py":
                continue
            if "setThemeColor(" in path.read_text(encoding="utf-8"):
                offenders.append(str(path.relative_to(REPO_ROOT)))
        self.assertEqual(offenders, [])

    def test_set_theme_color_never_passes_save(self) -> None:
        source = (UI_DIR / "theme.py").read_text(encoding="utf-8")
        for line in source.splitlines():
            if "setThemeColor(" in line and "def " not in line:
                self.assertNotIn("save=", line)


if __name__ == "__main__":
    unittest.main()
