"""`unique_tag` on a user's hand-edited config (field check #7, 2026-11-27: `TypeError` in `unique_tag`, Windows 0.8.130).

The list is the shipped default template's own `route.rule_set` (real data), then edited the way a person can edit the raw JSON:
a `tag` that is a list or an object, which made the set of existing tags fail with `unhashable type`.
"""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xray_fluent.constants import SINGBOX_TEMPLATES_DIR  # noqa: E402
from xray_fluent.singbox_config.document import section_items  # noqa: E402
from xray_fluent.ui.singbox.lists import unique_tag  # noqa: E402


class UniqueTagTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = json.loads((SINGBOX_TEMPLATES_DIR / "default.json").read_text(encoding="utf-8"))
        self.items = section_items(self.document, ("route", "rule_set"))
        self.assertTrue(self.items, "the shipped template has rule sets")

    def test_a_free_tag_is_kept_and_a_taken_one_gets_a_number(self) -> None:
        taken = self.items[0]["tag"]
        self.assertEqual("brand-new", unique_tag("brand-new", self.items))
        self.assertEqual(f"{taken}-2", unique_tag(taken, self.items))

    def test_a_tag_that_is_not_text_does_not_crash_the_page(self) -> None:
        items = copy.deepcopy(self.items)
        items[0]["tag"] = ["not", "text"]
        items.append({"type": "local", "tag": {"nested": 1}})
        items.append("not even an object")
        self.assertEqual("new-set", unique_tag("new-set", items))
        items.append({"type": "local", "tag": "new-set"})
        self.assertEqual("new-set-2", unique_tag("new-set", items))


class MissingSchemaTests(unittest.TestCase):
    """The bundled core schema missing from an install (field check #7: Windows 0.8.123, `FileNotFoundError` in
    `schema.load` from `ui.main_window._open_routing_section`): a message instead of a crash."""

    def test_the_routing_page_says_what_is_wrong_when_the_schema_file_is_missing(self) -> None:
        from types import SimpleNamespace

        from xray_fluent.singbox_config.schema import SingboxSchema
        from xray_fluent.ui.main_window import MainWindow

        def missing(_key: str) -> None:
            SingboxSchema.load(Path("assets/sing-box-schema/does-not-exist.json"))  # the real error of the report

        shown: list[tuple[str, str]] = []
        window = SimpleNamespace(
            switchTo=lambda page: None,
            configs_page=SimpleNamespace(show_section=missing, objectName=lambda: "configs"),
            navigationInterface=SimpleNamespace(setCurrentItem=lambda route: self.fail("the page must not be selected")),
            _show_status=lambda level, message: shown.append((level, message)),
        )
        MainWindow._open_routing_section(window, "rules")
        self.assertEqual(1, len(shown))
        self.assertEqual("error", shown[0][0])
        self.assertIn("схемы маршрутизации", shown[0][1])


if __name__ == "__main__":
    unittest.main()
