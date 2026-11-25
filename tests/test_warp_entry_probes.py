"""With the WARP entry hop on, pings and speed tests that would dial the server directly are not made (owner 2026-11-25)."""
from __future__ import annotations

import unittest

from xray_fluent.engines.singbox.warp_entry import WARP_ENTRY_TAG  # noqa: F401  (the module must import)
from xray_fluent.importer.link_parser import parse_single
from xray_fluent.network import entry_hop
from xray_fluent.network.latency_probe import probe_node, unmeasurable_reason
from xray_fluent.network.speed_test_worker import should_skip_speed_test

HY2 = "hy2://secret@example.com:443/?insecure=1&pinSHA256=" + "a" * 64 + "#hy"
VLESS = "vless://11111111-1111-1111-1111-111111111111@vless.example.com:443?security=tls&sni=vless.example.com&type=tcp#vl"
SS = "ss://YWVzLTEyOC1nY206cGFzcw@ss.example.com:8388#ss"


class EntryHopProbeTests(unittest.TestCase):
    def tearDown(self) -> None:
        entry_hop.configure(False)

    def test_off_by_default_changes_nothing(self) -> None:
        entry_hop.configure(False)
        self.assertNotEqual(entry_hop.REFUSAL, unmeasurable_reason(parse_single(HY2)))
        self.assertNotEqual((True, entry_hop.REFUSAL), should_skip_speed_test(parse_single(VLESS)))

    def test_pings_are_refused_for_every_protocol_owner(self) -> None:
        entry_hop.configure(True)
        for link in (HY2, VLESS, SS):
            with self.subTest(link[:4]):
                self.assertEqual(entry_hop.REFUSAL, unmeasurable_reason(parse_single(link)))

    def test_probe_node_makes_no_connection_and_reports_the_reason(self) -> None:
        entry_hop.configure(True)
        launched: list[object] = []

        def forbidden(*args, **kwargs):
            launched.append(args)
            raise AssertionError("a probe must not start a core or resolve the server with the hop on")

        result = probe_node(parse_single(HY2), resolve=forbidden)
        self.assertFalse(result.measured)
        self.assertEqual(entry_hop.REFUSAL, result.reason)
        self.assertEqual([], launched)

    def test_speed_tests_are_skipped_softly(self) -> None:
        entry_hop.configure(True)
        for link in (HY2, VLESS):
            with self.subTest(link[:4]):
                self.assertEqual((True, entry_hop.REFUSAL), should_skip_speed_test(parse_single(link)))

    def test_refusal_names_the_way_out(self) -> None:
        self.assertIn("WARP", entry_hop.REFUSAL)
        self.assertIn("Выключите", entry_hop.REFUSAL)


if __name__ == "__main__":
    unittest.main()
