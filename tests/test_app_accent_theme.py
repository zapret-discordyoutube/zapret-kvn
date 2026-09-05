"""Global accent theme tests — theme-level ACs (AC1-AC4, AC7).

Task: .agent/tasks/20260820-global-accent-theme.

Keep the ``test_app_*`` prefix: widget/theme test modules must sort before
``tests/test_engine_process_stop.py`` which creates a bare QCoreApplication
at import time (see tests/test_app_nodes_page_view.py).
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError(
        "A bare QCoreApplication was created before test_app_accent_theme "
        "was imported; widget tests need a QApplication."
    )
app = _existing or QApplication([])

from qfluentwidgets import Theme, qconfig, setTheme, setThemeColor, themeColor

from xray_fluent.constants import DEFAULT_ACCENT_COLOR
from xray_fluent.profiles.models import AppSettings, normalize_accent_color
from xray_fluent.ui import theme

REPO_ROOT = Path(__file__).resolve().parent.parent


class _ThemeAccentRestoreMixin(unittest.TestCase):
    """Save/restore both the theme mode and the accent color."""

    def setUp(self) -> None:
        self._saved_theme = qconfig.themeMode.value
        self._saved_accent = QColor(themeColor())

    def tearDown(self) -> None:
        setTheme(self._saved_theme)
        setThemeColor(self._saved_accent)
        QApplication.processEvents()


class AccentSignalTest(_ThemeAccentRestoreMixin):
    """AC1: on_accent_changed / on_theme_or_accent_changed."""

    def test_on_accent_changed_invokes_callback(self) -> None:
        calls: list[object] = []

        def callback(*args) -> None:
            calls.append(args)

        setThemeColor("#336699")
        QApplication.processEvents()
        returned = theme.on_accent_changed(callback)
        self.assertIs(returned, callback)
        try:
            setThemeColor("#663399")
            QApplication.processEvents()
            self.assertTrue(calls)
        finally:
            qconfig.themeColorChanged.disconnect(callback)

    def test_on_theme_or_accent_changed_fires_for_both(self) -> None:
        calls: list[object] = []

        def callback(*args) -> None:
            calls.append(args)

        setTheme(Theme.DARK)
        setThemeColor("#336699")
        QApplication.processEvents()
        theme.on_theme_or_accent_changed(callback)
        try:
            setThemeColor("#663399")
            QApplication.processEvents()
            accent_calls = len(calls)
            self.assertGreater(accent_calls, 0)

            setTheme(Theme.LIGHT)
            QApplication.processEvents()
            self.assertGreater(len(calls), accent_calls)
        finally:
            qconfig.themeChanged.disconnect(callback)
            qconfig.themeColorChanged.disconnect(callback)


class AccentSoftBgTokenTest(_ThemeAccentRestoreMixin):
    """AC2: accent_soft_bg / accent_soft_bg_hover follow the accent lazily."""

    def test_soft_bg_tokens_match_accent_with_fixed_alpha(self) -> None:
        setThemeColor("#123456")
        soft = theme.accent_soft_bg()
        hover = theme.accent_soft_bg_hover()
        self.assertEqual(soft.getRgb()[:3], themeColor().getRgb()[:3])
        self.assertEqual(hover.getRgb()[:3], themeColor().getRgb()[:3])
        self.assertEqual(soft.alpha(), 38)
        self.assertEqual(hover.alpha(), 51)

    def test_soft_bg_tokens_follow_accent_change(self) -> None:
        setThemeColor("#123456")
        before = theme.accent_soft_bg().getRgb()
        setThemeColor("#654321")
        after = theme.accent_soft_bg().getRgb()
        self.assertNotEqual(before, after)
        self.assertEqual(after[:3], (0x65, 0x43, 0x21))
        self.assertEqual(theme.accent_soft_bg_hover().getRgb()[:3], (0x65, 0x43, 0x21))

    def test_soft_bg_does_not_mutate_qconfig_color(self) -> None:
        setThemeColor("#123456")
        theme.accent_soft_bg()
        theme.accent_soft_bg_hover()
        self.assertEqual(themeColor().alpha(), 255)


class NormalizeAccentTest(unittest.TestCase):
    """AC3: normalization (theme.py) and validation (models.py, no Qt)."""

    def test_normalize_accent_uppercases_valid_hex(self) -> None:
        self.assertEqual(theme.normalize_accent("#0078d4"), theme.DEFAULT_ACCENT)
        self.assertEqual(theme.normalize_accent("#0078D4"), "#0078D4")
        self.assertEqual(theme.normalize_accent("#aabbcc"), "#AABBCC")

    def test_normalize_accent_garbage_falls_back_to_default(self) -> None:
        for garbage in ("", None, "не цвет", "#12", 0):
            with self.subTest(value=garbage):
                self.assertEqual(theme.normalize_accent(garbage), theme.DEFAULT_ACCENT)

    def test_default_accent_comes_from_constants(self) -> None:
        self.assertEqual(DEFAULT_ACCENT_COLOR, "#0078D4")
        self.assertEqual(theme.DEFAULT_ACCENT, DEFAULT_ACCENT_COLOR)

    def test_app_settings_from_dict_validates_accent(self) -> None:
        valid = AppSettings.from_dict({"accent_color": "#123ABC"})
        self.assertEqual(valid.accent_color, "#123ABC")
        lower = AppSettings.from_dict({"accent_color": "#123abc"})
        self.assertEqual(lower.accent_color, "#123abc")
        for garbage in ("мусор", "", None, "#12", "red", "#AABBCCDD"):
            with self.subTest(value=garbage):
                bad = AppSettings.from_dict({"accent_color": garbage})
                self.assertEqual(bad.accent_color, DEFAULT_ACCENT_COLOR)
        self.assertEqual(AppSettings().accent_color, DEFAULT_ACCENT_COLOR)
        self.assertEqual(normalize_accent_color("#0078D4"), "#0078D4")

    def test_models_module_has_no_accent_literal_and_no_qt(self) -> None:
        source = (REPO_ROOT / "xray_fluent" / "profiles" / "models.py").read_text(encoding="utf-8")
        self.assertNotIn("#0078D4", source)
        self.assertNotIn("PyQt6", source)
        self.assertNotIn("qfluentwidgets", source)


class ApplyThemeAccentDedupTest(unittest.TestCase):
    """AC4: hex-case-insensitive deduplication of setThemeColor."""

    def setUp(self) -> None:
        theme.reset_applied_theme()

    def tearDown(self) -> None:
        theme.reset_applied_theme()

    def test_dedup_ignores_hex_case(self) -> None:
        with mock.patch.object(theme, "setTheme") as set_theme, \
                mock.patch.object(theme, "setThemeColor") as set_color:
            self.assertTrue(theme.apply_theme("dark", "#0078d4"))
            self.assertFalse(theme.apply_theme("dark", "#0078D4"))
            self.assertEqual(set_theme.call_count, 1)
            self.assertEqual(set_color.call_count, 1)
            set_color.assert_called_once_with(theme.DEFAULT_ACCENT)


class GraphDownAccentTest(_ThemeAccentRestoreMixin):
    """AC7: the download graph color follows the accent (theme-dependent, D3)."""

    def test_light_graph_down_equals_accent(self) -> None:
        setThemeColor("#345678")
        setTheme(Theme.LIGHT)
        self.assertEqual(
            theme.graph_down_color().getRgb()[:3], themeColor().getRgb()[:3]
        )

    def test_dark_graph_down_differs_from_light_and_follows_accent(self) -> None:
        setThemeColor("#345678")
        setTheme(Theme.LIGHT)
        light = theme.graph_down_color().getRgb()
        setTheme(Theme.DARK)
        dark = theme.graph_down_color().getRgb()
        self.assertNotEqual(dark, light)

        setThemeColor("#873456")
        dark_after = theme.graph_down_color().getRgb()
        self.assertNotEqual(dark_after, dark)

    def test_graph_up_is_independent_of_accent(self) -> None:
        setTheme(Theme.LIGHT)
        setThemeColor("#345678")
        before = theme.graph_up_color().getRgb()
        setThemeColor("#873456")
        after = theme.graph_up_color().getRgb()
        self.assertEqual(before, after)
        self.assertEqual(before, (15, 123, 15, 255))
        setTheme(Theme.DARK)
        self.assertEqual(theme.graph_up_color().getRgb(), (0, 220, 120, 255))


if __name__ == "__main__":
    unittest.main()
