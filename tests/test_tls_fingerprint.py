from __future__ import annotations

import unittest

from xray_fluent.engines.singbox.config_builder import build_singbox_outbound
from xray_fluent.engines.tls_fingerprint import BROWSER_TLS_FINGERPRINT, apply_browser_fingerprint
from xray_fluent.engines.xray.config_builder import build_xray_config
from xray_fluent.importer.link_parser import parse_single
from xray_fluent.network.speed_test_worker import build_speed_test_config
from xray_fluent.profiles.models import AppSettings, RoutingSettings

UUID = "11111111-2222-3333-4444-555555555555"
REALITY = (
    f"vless://{UUID}@vpn.example.com:443?security=reality&sni=www.example.com"
    "&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=ab&type=tcp#r"
)


def _proxy(config: dict) -> dict:
    return next(item for item in config["outbounds"] if item.get("tag") == "proxy")


class SingBoxFingerprintTests(unittest.TestCase):
    """Без fp в ссылке рукопожатие с сервером — как у Chrome, а не ClientHello Go."""

    def test_trojan_without_fp_gets_chrome(self) -> None:
        node = parse_single("trojan://secret@vpn.example.com:443?sni=vpn.example.com#t")
        tls = build_singbox_outbound(node)["tls"]
        self.assertEqual(tls["utls"], {"enabled": True, "fingerprint": BROWSER_TLS_FINGERPRINT})

    def test_explicit_fp_is_kept(self) -> None:
        node = parse_single("trojan://secret@vpn.example.com:443?sni=vpn.example.com&fp=firefox#t")
        self.assertEqual(build_singbox_outbound(node)["tls"]["utls"]["fingerprint"], "firefox")

    def test_plain_tcp_without_tls_is_untouched(self) -> None:
        node = parse_single("ss://YWVzLTI1Ni1nY206c2VjcmV0@vpn.example.com:8388#s")
        self.assertNotIn("tls", build_singbox_outbound(node))


class XrayFingerprintTests(unittest.TestCase):
    def test_reality_without_fp_gets_chrome_in_runtime_config(self) -> None:
        node = parse_single(REALITY)
        self.assertNotIn("fingerprint", node.outbound["streamSettings"]["realitySettings"])
        proxy = _proxy(build_xray_config(node, RoutingSettings(), AppSettings()))
        self.assertEqual(proxy["streamSettings"]["realitySettings"]["fingerprint"], BROWSER_TLS_FINGERPRINT)
        # Хранимый узел не меняется: отпечаток подставляется только в конфиг ядра.
        self.assertNotIn("fingerprint", node.outbound["streamSettings"]["realitySettings"])

    def test_speed_test_core_uses_the_same_handshake(self) -> None:
        proxy = _proxy(build_speed_test_config(parse_single(REALITY), 18080))
        self.assertEqual(proxy["streamSettings"]["realitySettings"]["fingerprint"], BROWSER_TLS_FINGERPRINT)

    def test_quic_transport_is_left_alone(self) -> None:
        outbound = {"streamSettings": {"network": "xhttp", "security": "tls", "tlsSettings": {"alpn": ["h3"]}}}
        apply_browser_fingerprint(outbound)
        self.assertNotIn("fingerprint", outbound["streamSettings"]["tlsSettings"])

    def test_explicit_fingerprint_is_kept(self) -> None:
        outbound = {"streamSettings": {"security": "tls", "tlsSettings": {"fingerprint": "safari"}}}
        apply_browser_fingerprint(outbound)
        self.assertEqual(outbound["streamSettings"]["tlsSettings"]["fingerprint"], "safari")


if __name__ == "__main__":
    unittest.main()
