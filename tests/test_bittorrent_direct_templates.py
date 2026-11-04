from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SINGBOX_DIRECT_PORT_RANGE = "6881:6889"
XRAY_DIRECT_PORTS = "6881-6889,51413"


def _rules(kind: str, path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload["route"]["rules"] if kind == "sing-box" else payload["routing"]["rules"]


class BitTorrentDirectTemplateTests(unittest.TestCase):
    """Раздачи не должны идти через VPN-серверы: провайдеры банят за торренты."""

    def test_singbox_default_sends_bittorrent_direct_by_protocol_process_and_port(self) -> None:
        rules = _rules("sing-box", ROOT / "data" / "templates" / "sing-box" / "default.json")
        sniff = next(i for i, rule in enumerate(rules) if rule.get("action") == "sniff")
        protocol = next(i for i, rule in enumerate(rules) if rule.get("protocol") == "bittorrent")
        self.assertLess(sniff, protocol, "протокол определяет sniff, он должен идти раньше")
        for rule in rules:
            if rule.get("protocol") == "bittorrent":
                self.assertEqual((rule.get("action"), rule.get("outbound")), ("route", "direct"))
        clients = next(rule for rule in rules if "qbittorrent.exe" in rule.get("process_name", []))
        self.assertEqual(clients.get("outbound"), "direct")
        ports = next(rule for rule in rules if isinstance(rule.get("port"), list) and 51413 in rule["port"])
        self.assertIn(SINGBOX_DIRECT_PORT_RANGE, ports.get("port_range", []))
        self.assertEqual(ports.get("outbound"), "direct")
        # Раньше любого правила «через прокси», иначе раздача уйдёт в VPN.
        first_proxy = next(i for i, rule in enumerate(rules) if rule.get("outbound") == "proxy")
        self.assertLess(max(protocol, rules.index(clients), rules.index(ports)), first_proxy)

    def test_xray_default_sends_bittorrent_direct_before_any_proxy_rule(self) -> None:
        rules = _rules("xray", ROOT / "data" / "templates" / "xray" / "default.json")
        wanted = {
            "protocol": next(i for i, r in enumerate(rules) if r.get("protocol") == ["bittorrent"]),
            "process": next(i for i, r in enumerate(rules) if "qbittorrent.exe" in r.get("process", [])),
            "port": next(i for i, r in enumerate(rules) if r.get("port") == XRAY_DIRECT_PORTS),
        }
        first_proxy = next(i for i, r in enumerate(rules) if r.get("outboundTag") == "proxy")
        for name, index in wanted.items():
            with self.subTest(rule=name):
                self.assertEqual(rules[index].get("outboundTag"), "direct")
                self.assertEqual(rules[index].get("type"), "field")
                self.assertLess(index, first_proxy)

    def test_xray_inbounds_sniff_so_the_protocol_rule_can_match(self) -> None:
        payload = json.loads((ROOT / "data" / "templates" / "xray" / "default.json").read_text(encoding="utf-8"))
        for inbound in payload["inbounds"]:
            with self.subTest(inbound=inbound["tag"]):
                self.assertTrue(inbound["sniffing"]["enabled"])
                # ``bittorrent`` нельзя указывать в destOverride: ядро отвергает конфиг.
                self.assertNotIn("bittorrent", inbound["sniffing"]["destOverride"])


if __name__ == "__main__":
    unittest.main()
