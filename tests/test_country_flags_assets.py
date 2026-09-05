"""AC12/AC13/AC14 + AC6c(country_flags): real flag assets, file-first icon
loading with stripe fallback, themed border, cache invalidation on
themeChanged, and packaging paths.

Needs a full QApplication (QPixmap/QPainter) — created offscreen below.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtGui import QImage
from PyQt6.QtWidgets import QApplication
from qfluentwidgets import Theme, qconfig

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError(
        "A non-QApplication QCoreApplication was created before this module "
        "was imported; widget tests need a QApplication."
    )
_APP = _existing or QApplication([])

from xray_fluent import constants
from xray_fluent.profiles import country_flags
from xray_fluent.profiles.country_flags import _VALID_CODES, get_flag_icon

ROOT = Path(__file__).resolve().parents[1]
FLAGS_DIR = ROOT / "assets" / "flags"


def _image(pixmap) -> QImage:
    return pixmap.toImage().convertToFormat(QImage.Format.Format_ARGB32)


def _icon_image(icon) -> QImage:
    return _image(icon.pixmap(country_flags._W, country_flags._H))


class FlagAssetsTests(unittest.TestCase):
    """AC12 — committed PNG assets + attribution, no network in module."""

    def test_all_valid_codes_have_png_assets(self) -> None:
        missing = [
            code
            for code in sorted(_VALID_CODES)
            if not (FLAGS_DIR / f"{code.lower()}.png").is_file()
        ]
        self.assertEqual(missing, [])
        for code in ("gb", "us", "de"):
            path = FLAGS_DIR / f"{code}.png"
            self.assertTrue(path.is_file(), path)
            self.assertEqual(path.read_bytes()[:8], b"\x89PNG\r\n\x1a\n", path)

    def test_attribution_file_exists_and_names_source(self) -> None:
        attribution = FLAGS_DIR / "ATTRIBUTION.md"
        self.assertTrue(attribution.is_file())
        text = attribution.read_text(encoding="utf-8").lower()
        self.assertIn("flagcdn", text)
        self.assertIn("flagpedia", text)

    def test_country_flags_module_has_no_network_calls(self) -> None:
        source = (ROOT / "xray_fluent" / "profiles" / "country_flags.py").read_text(
            encoding="utf-8"
        )
        for needle in ("urllib", "requests", "QNetwork", "socket", "http"):
            self.assertNotIn(needle, source, needle)


class FlagIconLoadingTests(unittest.TestCase):
    """AC13 — file-first icon, fallback, cache."""

    def setUp(self) -> None:
        country_flags.clear_flag_icon_cache()
        self.addCleanup(country_flags.clear_flag_icon_cache)

    def test_gb_icon_comes_from_file_not_stripes(self) -> None:
        icon = get_flag_icon("gb")
        self.assertIsNotNone(icon)
        file_img = _icon_image(icon)
        self.assertFalse(file_img.isNull())
        self.assertNotEqual(file_img, _icon_image(get_flag_icon("NL")))

    def test_icon_scaled_to_18x13(self) -> None:
        pm = country_flags._load_flag_pixmap("GB")
        self.assertIsNotNone(pm)
        self.assertEqual((pm.width(), pm.height()), (18, 13))
        self.assertEqual((country_flags._W, country_flags._H), (18, 13))

    def test_missing_file_falls_back_to_stripes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(country_flags, "FLAGS_DIR", Path(tmp)):
                icon = get_flag_icon("gb")
        self.assertIsNone(icon)

    def test_unknown_code_falls_back_without_exception(self) -> None:
        icon = get_flag_icon("zz")
        self.assertIsNone(icon)

    def test_empty_code_returns_none(self) -> None:
        self.assertIsNone(get_flag_icon(""))

    def test_repeated_call_hits_cache(self) -> None:
        calls: list[str] = []
        original = country_flags._load_flag_pixmap

        def counting(code: str, ratio=1.0):
            calls.append(code)
            return original(code, ratio)

        with patch.object(country_flags, "_load_flag_pixmap", counting):
            first = get_flag_icon("de")
            second = get_flag_icon("de")
        self.assertIs(first, second)
        self.assertEqual(calls, ["DE"])


class FlagThemeTests(unittest.TestCase):
    """AC6c (country_flags part) — themed border + cache reset on themeChanged."""

    def setUp(self) -> None:
        country_flags.clear_flag_icon_cache()
        self.addCleanup(country_flags.clear_flag_icon_cache)

    def test_border_color_is_theme_dependent(self) -> None:
        with patch.object(country_flags, "isDarkTheme", return_value=True):
            dark = country_flags._border_color()
        with patch.object(country_flags, "isDarkTheme", return_value=False):
            light = country_flags._border_color()
        self.assertNotEqual(dark.getRgb(), light.getRgb())
        self.assertGreater(dark.lightness(), light.lightness())

    def test_rendered_flag_differs_between_themes(self) -> None:
        with patch.object(country_flags, "isDarkTheme", return_value=True):
            dark_file = _image(country_flags._load_flag_pixmap("GB"))
        with patch.object(country_flags, "isDarkTheme", return_value=False):
            light_file = _image(country_flags._load_flag_pixmap("GB"))
        self.assertNotEqual(dark_file, light_file)

    def test_cache_cleared_on_theme_changed_signal(self) -> None:
        get_flag_icon("fr")
        self.assertTrue(country_flags._icon_cache)
        qconfig.themeChanged.emit(Theme.DARK)
        self.assertEqual(country_flags._icon_cache, {})


class FlagPackagingTests(unittest.TestCase):
    """AC14 — dev-mode path via constants.ASSETS_DIR, clean build staging."""

    def test_flags_dir_derives_from_assets_dir(self) -> None:
        self.assertEqual(constants.FLAGS_DIR, constants.ASSETS_DIR / "flags")
        self.assertEqual(country_flags.FLAGS_DIR, constants.FLAGS_DIR)
        self.assertTrue(constants.FLAGS_DIR.is_dir())

    def test_build_stages_assets_tree_into_a_clean_destination(self) -> None:
        source = (ROOT / "build.py").read_text(encoding="utf-8")
        self.assertIn("_copy_tree_strict(ASSETS_DIR, dst_assets)", source)


if __name__ == "__main__":
    unittest.main()
