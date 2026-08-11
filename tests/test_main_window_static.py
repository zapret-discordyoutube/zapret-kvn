"""Static checks on main_window.py (AC11): realistic minimum window size.

Pure source inspection — no Qt imports, safe at any position in the test
discovery order (MainWindow itself is too heavy to instantiate offscreen,
see spec assumption A12).
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MAIN_WINDOW = REPO_ROOT / "xray_fluent" / "ui" / "main_window.py"


class MainWindowMinimumSizeTest(unittest.TestCase):
    def test_minimum_size_is_860_by_560(self) -> None:
        source = MAIN_WINDOW.read_text(encoding="utf-8")
        self.assertRegex(
            source,
            r"self\.setMinimumSize\(\s*860\s*,\s*560\s*\)",
            "MainWindow must set the 860x560 minimum size (AC11)",
        )
        match = re.search(r"setMinimumSize\(\s*600\s*,\s*450\s*\)", source)
        self.assertIsNone(match, "old 600x450 minimum must be gone")


if __name__ == "__main__":
    unittest.main()
