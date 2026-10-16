import base64
import json
import unittest

from xray_fluent.engines.singbox.config_builder import build_singbox_outbound, unenforced_tls_pin_warning
from xray_fluent.importer.link_parser import (
    LinkParseError,
    parse_single,
    validate_node_outbound,
    xray_core_tls_problem,
)
from xray_fluent.network.speed_test_worker import should_skip_speed_test

PIN = "ab" * 32
PIN2 = "cd" * 32
PIN_COLONS = ":".join(PIN[i:i + 2].upper() for i in range(0, 64, 2))
UUID = "11111111-1111-1111-1111-111111111111"


def _tls(node):
    return node.outbound["streamSettings"]["tlsSettings"]


class XrayShareLinkPinTests(unittest.TestCase):
    def test_vless_allow_insecure_with_pin_becomes_pinned_peer_cert(self) -> None:
        node = parse_single(
            f"vless://{UUID}@a.example:443?security=tls&sni=a.example&allowInsecure=1&pcs={PIN}#V"
        )
        tls = _tls(node)
        self.assertEqual(tls["pinnedPeerCertSha256"], PIN)
        self.assertNotIn("allowInsecure", tls)
        self.assertIsNone(validate_node_outbound(node))
        self.assertIsNone(xray_core_tls_problem(node))

    def test_trojan_allow_insecure_with_pin_has_no_allow_insecure(self) -> None:
        node = parse_single(f"trojan://pw@a.example:443?security=tls&allow_insecure=1&pcs={PIN}#T")
        tls = _tls(node)
        self.assertEqual(tls["pinnedPeerCertSha256"], PIN)
        self.assertNotIn("allowInsecure", tls)
        self.assertNotIn("allowInsecure", json.dumps(node.outbound))

    def test_insecure_alias_with_pin(self) -> None:
        node = parse_single(f"trojan://pw@a.example:443?insecure=1&pcs={PIN}#T")
        self.assertNotIn("allowInsecure", _tls(node))

    def test_pin_with_colons_and_list_is_normalized(self) -> None:
        node = parse_single(
            f"vless://{UUID}@a.example:443?security=tls&pcs={PIN_COLONS},{PIN2.upper()}#V"
        )
        self.assertEqual(_tls(node)["pinnedPeerCertSha256"], f"{PIN},{PIN2}")

    def test_full_name_pin_param_is_accepted(self) -> None:
        node = parse_single(f"vless://{UUID}@a.example:443?security=tls&pinnedPeerCertSha256={PIN}#V")
        self.assertEqual(_tls(node)["pinnedPeerCertSha256"], PIN)

    def test_invalid_pin_rejects_link_instead_of_dropping_it(self) -> None:
        for bad in ("abc", "zz" * 32, PIN[:-2]):
            with self.assertRaises(LinkParseError):
                parse_single(f"vless://{UUID}@a.example:443?security=tls&allowInsecure=1&pcs={bad}#V")

    def test_verify_peer_cert_by_name(self) -> None:
        node = parse_single(
            f"vless://{UUID}@a.example:443?security=tls&pcs={PIN}&vcn=one.example,%20two.example#V"
        )
        self.assertEqual(_tls(node)["verifyPeerCertByName"], "one.example,two.example")

    def test_vless_allow_insecure_without_pin_imports_with_normal_verification(self) -> None:
        # Xray нечем заменить allowInsecure без пина: сертификат проверяется
        # обычным образом, сервер импортируется и запускается (как на Android).
        node = parse_single(f"vless://{UUID}@a.example:443?security=tls&allowInsecure=1#V")
        self.assertNotIn("allowInsecure", _tls(node))
        self.assertIsNone(validate_node_outbound(node))
        self.assertIsNone(xray_core_tls_problem(node))

    def test_saved_vless_with_allow_insecure_and_no_link_gets_russian_error(self) -> None:
        node = parse_single(f"vless://{UUID}@a.example:443?security=tls#V")
        _tls(node)["allowInsecure"] = True
        problem = validate_node_outbound(node)
        self.assertIsNotNone(problem)
        self.assertIn("pcs", problem)
        self.assertIn("allowInsecure", problem)

    def test_allow_insecure_zero_is_not_emitted(self) -> None:
        node = parse_single(f"vless://{UUID}@a.example:443?security=tls&allowInsecure=0#V")
        self.assertNotIn("allowInsecure", _tls(node))
        self.assertIsNone(validate_node_outbound(node))

    def test_trojan_allow_insecure_without_pin_stays_runnable_in_singbox(self) -> None:
        node = parse_single("trojan://pw@a.example:443?security=tls&allowInsecure=1#T")
        self.assertIsNone(validate_node_outbound(node))
        self.assertTrue(build_singbox_outbound(node)["tls"]["insecure"])
        # временный xray для замера скорости такой сервер не потянет
        skip, message = should_skip_speed_test(node)
        self.assertTrue(skip)
        self.assertIn("allowInsecure", message)

    def test_vmess_json_fields_are_mapped(self) -> None:
        payload = {
            "add": "a.example", "port": "443", "id": UUID, "net": "tcp", "tls": "tls",
            "allowInsecure": 1, "pcs": PIN, "vcn": "a.example",
        }
        link = "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()
        tls = _tls(parse_single(link))
        self.assertEqual(tls["pinnedPeerCertSha256"], PIN)
        self.assertEqual(tls["verifyPeerCertByName"], "a.example")
        self.assertNotIn("allowInsecure", tls)

        payload.pop("pcs")
        node = parse_single("vmess://" + base64.b64encode(json.dumps(payload).encode()).decode())
        self.assertTrue(_tls(node)["allowInsecure"])

    def test_plain_vless_without_pin_is_unchanged(self) -> None:
        node = parse_single(f"vless://{UUID}@a.example:443?security=tls&sni=a.example#V")
        self.assertEqual(_tls(node), {"serverName": "a.example"})


class SingboxPinConversionTests(unittest.TestCase):
    def test_pin_is_not_enforced_and_warns(self) -> None:
        node = parse_single(f"trojan://pw@a.example:443?security=tls&sni=a.example&allowInsecure=1&pcs={PIN}#T")
        tls = build_singbox_outbound(node)["tls"]
        self.assertTrue(tls["insecure"])
        self.assertNotIn("certificate_public_key_sha256", tls)
        warning = unenforced_tls_pin_warning(node)
        self.assertIn("не проверяется", warning)
        self.assertIn("T", warning)

    def test_no_warning_without_pin_or_for_vless(self) -> None:
        plain = parse_single("trojan://pw@a.example:443?security=tls#T")
        self.assertEqual(unenforced_tls_pin_warning(plain), "")
        self.assertNotIn("insecure", build_singbox_outbound(plain)["tls"])
        vless = parse_single(f"vless://{UUID}@a.example:443?security=tls&pcs={PIN}#V")
        self.assertEqual(unenforced_tls_pin_warning(vless), "")


if __name__ == "__main__":
    unittest.main()
