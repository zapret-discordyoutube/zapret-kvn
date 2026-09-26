"""The routing GUI is driven by the schema of the pinned sing-box core."""

from __future__ import annotations

import json
from pathlib import Path
import unittest

from xray_fluent.singbox_config.schema import SCHEMA_DIR, SingboxSchema, bundled_schema, schema_meta


ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / "scripts" / "core-lock.windows-x64.json").read_text(encoding="utf-8"))
TEMPLATES = sorted((ROOT / "data" / "templates" / "sing-box").glob("*.json"))

# Sections the GUI edits: none of their fields may be loosened.
GUI_SECTIONS = ("route", "dns", "inbounds", "outbounds", "log", "experimental")


class SchemaSnapshotTests(unittest.TestCase):
    def test_snapshot_matches_pinned_core(self) -> None:
        meta = schema_meta()
        self.assertEqual(meta["module"], LOCK["singbox_build"]["module"])
        self.assertEqual(meta["version"], LOCK["singbox_build"]["version"])

    def test_no_loosened_path_in_gui_sections(self) -> None:
        loose = (SCHEMA_DIR / "loose-paths.txt").read_text(encoding="utf-8").split()
        paths = [item for item in loose if item.startswith("Options.")]
        self.assertTrue(paths, "loose-paths.txt lists the fork types the generator could not map")
        for path in paths:
            section = path.split(".")[1]
            self.assertNotIn(section, GUI_SECTIONS, path)

    def test_route_rule_is_match_group_plus_action_group(self) -> None:
        schema = bundled_schema()
        rule = schema.definition("Rule")
        groups = schema.groups(rule, {"domain_suffix": ["example.org"], "action": "reject"})
        self.assertEqual(groups[0].discriminator, "type")
        self.assertEqual(groups[0].default_variant, "default")
        self.assertIn("domain_suffix", {item.name for item in groups[0].fields})
        self.assertEqual(groups[1].discriminator, "action")
        self.assertEqual(groups[1].default_variant, "route")
        self.assertEqual({item.name for item in groups[1].fields}, {"action", "method", "no_drop"})
        self.assertIn("hijack-dns", groups[1].variants)

    def test_listable_and_tag_reference_shapes(self) -> None:
        schema = bundled_schema()
        fields = schema.fields(schema.definition("Rule"), {"action": "route"})
        self.assertTrue(fields["domain_suffix"].shape.listable)
        self.assertEqual(fields["network"].shape.enum, ("tcp", "udp", "icmp"))
        self.assertEqual(fields["rule_set"].shape.tag_ref, "rule_set")
        self.assertEqual(fields["outbound"].shape.tag_ref, "outbound")
        self.assertFalse(fields["outbound"].shape.listable)

    def test_nested_rules_cannot_carry_actions(self) -> None:
        schema = bundled_schema()
        nested = schema.fields(schema.definition("NestedRule"), {})
        self.assertNotIn("action", nested)
        self.assertNotIn("outbound", nested)

    def test_discriminated_sections_list_core_types(self) -> None:
        schema = bundled_schema()
        outbound_types = {item.value for item in schema.variants(schema.array_item("outbounds"))}
        self.assertTrue({"direct", "block", "selector", "urltest", "vless"} <= outbound_types)
        inbound_types = {item.value for item in schema.variants(schema.array_item("inbounds"))}
        self.assertIn("tun", inbound_types)
        self.assertIsNone(schema.default_variant(schema.array_item("outbounds")))

    def test_shipped_templates_use_only_fields_the_core_knows(self) -> None:
        schema = bundled_schema()
        checks = (
            (("route", "rules"), schema.definition("Rule")),
            (("route", "rule_set"), schema.definition("RuleSet")),
            (("dns", "servers"), schema.definition("DNSServer")),
            (("dns", "rules"), schema.definition("DNSRule")),
            (("outbounds",), schema.array_item("outbounds")),
            (("inbounds",), schema.array_item("inbounds")),
        )
        for template in TEMPLATES:
            document = json.loads(template.read_text(encoding="utf-8"))
            for path, node in checks:
                items = document
                for key in path:
                    items = items.get(key, {}) if isinstance(items, dict) else {}
                for index, item in enumerate(items or []):
                    with self.subTest(template=template.name, path=path, index=index):
                        known = set(schema.fields(node, item))
                        self.assertTrue(known, f"unknown variant {item}")
                        self.assertLessEqual(set(item), known)

    def test_schema_loads_from_path(self) -> None:
        loaded = SingboxSchema.load(SCHEMA_DIR / "schema.json")
        self.assertIn("RouteOptions", loaded.defs)


if __name__ == "__main__":
    unittest.main()
