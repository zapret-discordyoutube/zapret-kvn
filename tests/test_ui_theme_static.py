"""Static (grep-style) gates for the theme architecture (AC2, AC4, AC5, AC6d).

Pure source inspection — no Qt imports, safe at any position in the
alphabetical discovery order.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
UI_DIR = REPO_ROOT / "xray_fluent" / "ui"

# Files whose raw theme-dependent setStyleSheet calls were migrated (AC4).
AC4_FILES = ("zapret_page.py", "updates_page.py", "about_page.py", "routing_page.py")

# Theme-neutral setStyleSheet values that are explicitly allowed (A10):
# plain-Qt widgets with neutral colors or transparency for the Mica effect.
_ALLOWED_NEUTRAL_SNIPPETS = (
    "rgba(128,128,128,0.3)",
    "background: transparent",
    'setCustomStyleSheet(self.status_label, "", "")',
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class ThemeStartupOrderTest(unittest.TestCase):
    """AC2: the persisted theme is applied before MainWindow construction."""

    def test_apply_initial_theme_precedes_main_window(self) -> None:
        source = _read(REPO_ROOT / "main.py")
        apply_call = source.find("apply_initial_theme()")
        window_ctor = source.find("MainWindow(defer_init")
        self.assertGreater(apply_call, -1, "main.py must call apply_initial_theme()")
        self.assertGreater(window_ctor, -1, "MainWindow construction not found")
        self.assertLess(
            apply_call,
            window_ctor,
            "apply_initial_theme() must run before MainWindow is constructed",
        )

    def test_password_dialog_created_after_window(self) -> None:
        # PasswordDialog instances are created only inside MainWindow methods,
        # which run after apply_initial_theme() in main().
        source = _read(REPO_ROOT / "main.py")
        self.assertNotIn("PasswordDialog(", source)
        window_source = _read(UI_DIR / "main_window.py")
        self.assertIn("PasswordDialog(", window_source)


class RawStyleSheetGateTest(unittest.TestCase):
    """AC4: no theme-dependent raw setStyleSheet on the migrated pages."""

    def test_no_hex_colors_in_set_style_sheet_calls(self) -> None:
        offenders: list[str] = []
        for name in AC4_FILES:
            for line_no, line in enumerate(_read(UI_DIR / name).splitlines(), 1):
                if "setStyleSheet" not in line:
                    continue
                if re.search(r"#[0-9a-fA-F]{3,8}", line):
                    offenders.append(f"{name}:{line_no}: {line.strip()}")
        self.assertEqual(offenders, [])

    def test_remaining_set_style_sheets_are_neutral(self) -> None:
        offenders: list[str] = []
        for name in AC4_FILES:
            for line_no, line in enumerate(_read(UI_DIR / name).splitlines(), 1):
                if "setStyleSheet" not in line or "setCustomStyleSheet" in line:
                    continue
                if not any(snippet in line for snippet in _ALLOWED_NEUTRAL_SNIPPETS):
                    offenders.append(f"{name}:{line_no}: {line.strip()}")
        self.assertEqual(offenders, [])

    def test_set_custom_style_sheet_is_used(self) -> None:
        uses = sum(
            _read(path).count("setCustomStyleSheet(")
            for path in UI_DIR.glob("*.py")
        )
        self.assertGreater(uses, 0)


class HardcodedColorGateTest(unittest.TestCase):
    """AC3/AC6d: hardcoded theme colors live only in theme.py."""

    def test_default_accent_only_in_theme_module(self) -> None:
        offenders = [
            path.name
            for path in sorted(UI_DIR.glob("*.py"))
            if path.name != "theme.py" and "#0078D4" in _read(path)
        ]
        self.assertEqual(offenders, [])

    def test_dialog_surface_hack_removed(self) -> None:
        offenders = [
            path.name
            for path in sorted(UI_DIR.glob("*.py"))
            if path.name != "theme.py"
            and ("#2b2b2b" in _read(path) or "#f3f3f3" in _read(path))
        ]
        self.assertEqual(offenders, [])


class ApplyThemeWiringTest(unittest.TestCase):
    """AC5: main_window delegates to the deduplicated theme applier."""

    def test_main_window_uses_theme_module(self) -> None:
        source = _read(UI_DIR / "main_window.py")
        self.assertIn("apply_theme(", source)
        self.assertIn("sync_system_theme_listener(", source)
        # The old direct calls must be gone from _apply_theme.
        self.assertNotIn("setTheme(Theme.DARK)", source)
        self.assertNotIn("setThemeColor(", source)

    def test_theme_module_manages_system_listener(self) -> None:
        source = _read(UI_DIR / "theme.py")
        self.assertIn("SystemThemeListener", source)
        self.assertIn("def sync_system_theme_listener", source)


if __name__ == "__main__":
    unittest.main()
