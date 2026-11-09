from __future__ import annotations

import unittest

from xray_fluent.engines.xray_outbound_compat import xray_outbound_incompatibility


def _vless(address: str, *, security: str = "none", encryption: str = "none", flat: bool = False) -> dict:
    user = {"id": "11111111-1111-1111-1111-111111111111", "encryption": encryption}
    settings = {"address": address, "port": 443, **user} if flat else {"vnext": [{"address": address, "port": 443, "users": [user]}]}
    return {"protocol": "vless", "settings": settings, "streamSettings": {"network": "ws", "security": security}}


class PlainTransportTests(unittest.TestCase):
    """Xray 26.11 refuses plain VLESS/Trojan to a public address (field check 2026-11-09)."""

    def test_public_domain_and_ip_without_security_are_flagged(self) -> None:
        for address in ("vpn.example.net", "203.0.113.7", "2001:4860::1"):
            with self.subTest(address=address):
                self.assertIn("без TLS", xray_outbound_incompatibility(_vless(address)))

    def test_private_addresses_are_allowed(self) -> None:
        for address in ("192.168.1.10", "10.0.0.5", "172.20.1.1", "127.0.0.1", "169.254.1.1", "fd00::1",
                        "router", "nas.lan", "vpn.example", "host.internal", "x.home.arpa", "localhost"):
            with self.subTest(address=address):
                self.assertEqual(xray_outbound_incompatibility(_vless(address)), "")

    def test_tls_reality_or_encryption_make_a_public_address_fine(self) -> None:
        self.assertEqual(xray_outbound_incompatibility(_vless("vpn.example.net", security="tls")), "")
        self.assertEqual(xray_outbound_incompatibility(_vless("vpn.example.net", security="reality")), "")
        self.assertEqual(xray_outbound_incompatibility(_vless("vpn.example.net", encryption="mlkem768x25519plus.native.0rtt.abc")), "")

    def test_flat_settings_form_is_checked_too(self) -> None:
        self.assertIn("VLESS", xray_outbound_incompatibility(_vless("vpn.example.net", flat=True)))

    def test_trojan_without_tls_is_flagged_and_other_protocols_are_not(self) -> None:
        trojan = {"protocol": "trojan", "settings": {"servers": [{"address": "vpn.example.net", "port": 443}]},
                  "streamSettings": {"security": "none"}}
        self.assertIn("TROJAN", xray_outbound_incompatibility(trojan))
        self.assertEqual(xray_outbound_incompatibility({"protocol": "vmess", "settings": {}}), "")


if __name__ == "__main__":
    unittest.main()
