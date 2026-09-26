from __future__ import annotations

import unittest

from xray_fluent.singbox_config import catalog
from xray_fluent.singbox_config.document import (
    app_owned_note,
    differing_sections,
    dump_document,
    parse_document,
    store_list,
    tags,
)
from xray_fluent.singbox_config.schema import bundled_schema


class DocumentTests(unittest.TestCase):
    def test_single_listable_value_keeps_its_scalar_form(self) -> None:
        shape = bundled_schema().fields(bundled_schema().definition("Rule"), {})["network"].shape
        rule = {"network": "tcp"}
        store_list(rule, "network", ["udp"], shape)
        self.assertEqual(rule["network"], "udp")
        store_list(rule, "network", ["tcp", "udp"], shape)
        self.assertEqual(rule["network"], ["tcp", "udp"])
        store_list(rule, "network", [], shape)
        self.assertNotIn("network", rule)

    def test_tags_come_from_the_document(self) -> None:
        document = {
            "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}],
            "endpoints": [{"type": "wireguard", "tag": "wg"}],
            "dns": {"servers": [{"type": "local", "tag": "local"}]},
            "route": {"rule_set": [{"type": "local", "tag": ["a", "b"], "path": "{tag}.srs"}]},
        }
        self.assertEqual(tags(document, "outbound"), ["direct", "block", "wg"])
        self.assertEqual(tags(document, "dns_server"), ["local"])
        self.assertEqual(tags(document, "rule_set"), ["a", "b"])

    def test_serialisation_keeps_cyrillic_and_order(self) -> None:
        text = '{"route": {"rules": [{"process_name": ["Яндекс Музыка.exe"], "outbound": "direct"}]}, "log": {}}'
        document, error = parse_document(text)
        self.assertEqual(error, "")
        dumped = dump_document(document)
        self.assertIn("Яндекс Музыка.exe", dumped)
        self.assertLess(dumped.index('"route"'), dumped.index('"log"'))

    def test_parse_errors_are_reported(self) -> None:
        self.assertIsNone(parse_document("{")[0])
        self.assertIn("объектом", parse_document("[]")[1])

    def test_differing_sections(self) -> None:
        stock = {"log": {"level": "warn"}, "dns": {"final": "a"}}
        document = {"log": {"level": "warn"}, "dns": {"final": "b"}, "ntp": {}}
        self.assertEqual(differing_sections(document, stock), ["dns", "ntp"])

    def test_app_owned_items_are_explained(self) -> None:
        self.assertIn("выбранный сервер", app_owned_note("outbounds", {"type": "direct", "tag": "proxy"}))
        self.assertIn("удаляет", app_owned_note("inbounds", {"type": "mixed", "tag": "m"}))
        self.assertEqual(app_owned_note("outbounds", {"type": "direct", "tag": "my-direct"}), "")


class CatalogTests(unittest.TestCase):
    def test_rule_summaries(self) -> None:
        rule = {"domain_suffix": ["a.ru", "b.ru", "c.ru"], "action": "route", "outbound": "direct"}
        self.assertEqual(catalog.match_summary(rule), "домены: a.ru, b.ru +1")
        self.assertIn("Напрямую", catalog.action_summary(rule))
        logical = {"type": "logical", "mode": "and", "rules": [{"network": "udp"}, {"port": 443}]}
        self.assertEqual(catalog.match_summary(logical), "(сеть: udp) И (порт: 443)")
        self.assertIn("заблокировать", catalog.action_summary({"ip_is_private": True, "action": "reject"}))

    def test_pinned_fields_follow_discriminators(self) -> None:
        self.assertEqual(catalog.pinned_fields("rule", {"type": "default", "action": "route"}), ("outbound",))
        self.assertIn("path", catalog.pinned_fields("rule_set", {"type": "local"}))


if __name__ == "__main__":
    unittest.main()
