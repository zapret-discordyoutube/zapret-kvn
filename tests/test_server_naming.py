"""Server names as real providers write them (owner's captured state, tests/fixtures/real_server_names.json)."""

import json
import unittest
from collections import Counter, defaultdict
from pathlib import Path

from xray_fluent.profiles.server_naming import parse_server_name

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "real_server_names.json"
ROWS = json.loads(FIXTURE.read_text(encoding="utf-8"))["nodes"]


class ServerNamingTests(unittest.TestCase):
    def test_the_shapes_of_the_owners_providers(self) -> None:
        cases = {
            "🇸🇪 4stok · VLESS gRPC · TLS · V2": ("🇸🇪", "4stok", "VLESS gRPC · TLS · V2", ""),
            "🇫🇮 Hosfinano · VLESS gRPC · TLS · V8 через Россию": ("🇫🇮", "Hosfinano", "VLESS gRPC · TLS · V8", "через Россию"),
            "🇩🇪 Hiphopgen через Россию": ("🇩🇪", "Hiphopgen", "", "через Россию"),
            "🇩🇪 Clequinix": ("🇩🇪", "Clequinix", "", ""),
            "Нидерланды 3": ("", "Нидерланды", "3", ""),
            "🇩🇪 Германия (2)": ("🇩🇪", "Германия", "2", ""),
            "plc31-tcp": ("", "plc31", "tcp", ""),
            "plc31-xhttp": ("", "plc31", "xhttp", ""),
            "BS_0120": ("", "BS_0120", "", ""),
            "proxy": ("", "proxy", "", ""),
            "awg-203.0.113.7:44313": ("", "203.0.113.7", "44313", ""),
            "TCM VPN · по IP": ("", "TCM VPN", "по IP", ""),
            "🇳🇱 NL · Hysteria2": ("🇳🇱", "NL", "Hysteria2", ""),
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                parsed = parse_server_name(name)
                self.assertEqual(expected, (parsed.flag, parsed.server, parsed.variant, parsed.via))

    def test_a_hyphen_inside_a_name_is_not_a_separator(self) -> None:
        self.assertEqual("zepvpn-member-df81ff71f503c0fa-end", parse_server_name("zepvpn-member-df81ff71f503c0fa-end").server)

    def test_every_real_name_reads_to_a_non_empty_server(self) -> None:
        for row in ROWS:
            parsed = parse_server_name(row["name"])
            self.assertTrue(parsed.server, row["name"])

    def test_the_providers_own_names_collapse_into_few_servers(self) -> None:
        """1458 vpnbot servers are keys of a few dozen machines: that is what the «Сервер» level shows."""
        names = [row["name"] for row in ROWS if row["group"] == "vpnbot-xray"]
        servers = {parse_server_name(name).server_key for name in names}
        self.assertGreater(len(names), 300)
        self.assertLess(len(servers), len(names) // 6, (len(names), len(servers)))

    def test_the_same_server_over_another_route_stays_one_server(self) -> None:
        direct = parse_server_name("🇩🇪 Hiphopgen")
        routed = parse_server_name("🇩🇪 Hiphopgen через Россию")
        self.assertEqual(direct.server_key, routed.server_key)
        self.assertNotEqual(direct.via, routed.via)

    def test_a_flag_alone_never_makes_an_empty_server(self) -> None:
        self.assertEqual("🇩🇪", parse_server_name("🇩🇪").server)


if __name__ == "__main__":
    unittest.main()
