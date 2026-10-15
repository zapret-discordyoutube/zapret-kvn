import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LABEL_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
BOT_URL_RE = re.compile(r"https://t\.me/zapretvpns_bot(?:\?start=([^\s)\"']*))?")


def _labels(path: Path) -> list[str | None]:
    return [m.group(1) for m in BOT_URL_RE.finditer(path.read_text(encoding="utf-8"))]


class BotAdLabelTests(unittest.TestCase):
    def test_about_button_carries_its_own_label(self) -> None:
        source = (ROOT / "xray_fluent/ui/about_page.py").read_text(encoding="utf-8")
        self.assertIn(
            'BOT_ABOUT_URL = "https://t.me/zapretvpns_bot?start=kvnwin_about"', source
        )
        self.assertIn("webbrowser.open(BOT_ABOUT_URL)", source)
        self.assertEqual(_labels(ROOT / "xray_fluent/ui/about_page.py"), ["kvnwin_about"])

    def test_readme_links_have_distinct_labels(self) -> None:
        labels = _labels(ROOT / "docs/README.md")
        self.assertEqual(labels, ["kvnwin_readme_keys", "kvnwin_readme_nokey"])

    def test_labels_follow_ad_source_rules(self) -> None:
        for rel in ("xray_fluent/ui/about_page.py", "docs/README.md"):
            for label in _labels(ROOT / rel):
                with self.subTest(file=rel, label=label):
                    self.assertIsNotNone(label)
                    self.assertRegex(label, LABEL_RE.pattern)
                    self.assertRegex(label, r"^kvnwin_")
                    self.assertFalse(label.startswith("ref_"))


if __name__ == "__main__":
    unittest.main()
