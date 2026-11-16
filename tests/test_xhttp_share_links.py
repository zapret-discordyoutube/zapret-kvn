"""VLESS XHTTP share links keep path, host, mode and extra (XTLS share-link standard).

Xray owns XHTTP: the parser only writes the native `xhttpSettings` object, where `extra`
is the URL-decoded JSON object that Xray itself merges (see infra/conf SplitHTTPConfig).
"""

import json
import unittest
from urllib.parse import quote

from xray_fluent.importer.link_parser import (
    LinkParseError,
    parse_links_text,
    parse_single,
    repair_node_outbound_from_link,
    validate_node_outbound,
)
from xray_fluent.masking import xray as masking_xray
from xray_fluent.masking.apply import shape_of

UUID = "11111111-1111-1111-1111-111111111111"
EXTRA = {
    "xPaddingObfsMode": True,
    "xPaddingKey": "_dc",
    "xPaddingHeader": "X-Cache",
    "xPaddingMethod": "tokenish",
    "uplinkHTTPMethod": "GET",
    "uplinkDataPlacement": "header",
    "sessionIDLength": "16-32",
    "scMaxEachPostBytes": "12000-16000",
    "xmux": {"maxConcurrency": "16-32"},
}


def _link(query: str, scheme_tail: str = "#x") -> str:
    return f"vless://{UUID}@h.example:443?{query}{scheme_tail}"


def _xhttp(node):
    return node.outbound["streamSettings"]["xhttpSettings"]


class XhttpShareLinkTests(unittest.TestCase):
    def test_path_host_mode_and_extra_are_written_natively(self) -> None:
        extra = quote(json.dumps(EXTRA), safe="")
        node = parse_single(
            _link(f"type=xhttp&security=tls&sni=h.example&mode=packet-up&path=%2Fp&host=cdn.example&extra={extra}")
        )
        stream = node.outbound["streamSettings"]
        self.assertEqual("xhttp", stream["network"])
        self.assertEqual("h.example", stream["tlsSettings"]["serverName"])
        self.assertEqual(
            {"path": "/p", "host": "cdn.example", "mode": "packet-up", "extra": EXTRA},
            stream["xhttpSettings"],
        )
        self.assertIsNone(validate_node_outbound(node))

    def test_reality_xhttp_keeps_reality_settings(self) -> None:
        node = parse_single(_link("type=xhttp&security=reality&pbk=KEY&sid=ab&sni=s.example&path=%2Fr"))
        stream = node.outbound["streamSettings"]
        self.assertEqual("KEY", stream["realitySettings"]["publicKey"])
        self.assertEqual({"path": "/r"}, stream["xhttpSettings"])

    def test_link_without_xhttp_parameters_gets_empty_settings(self) -> None:
        node = parse_single(_link("type=xhttp&security=tls&sni=h.example"))
        self.assertEqual({}, _xhttp(node))

    def test_splithttp_is_the_old_name_of_xhttp(self) -> None:
        node = parse_single(_link("type=splithttp&security=tls&path=%2Fs"))
        self.assertEqual("xhttp", node.outbound["streamSettings"]["network"])
        self.assertEqual({"path": "/s"}, _xhttp(node))

    def test_extra_null_empty_and_blank_mean_unset(self) -> None:
        for value in ("null", "", "%20", "%7B%7D"):
            with self.subTest(extra=value):
                node = parse_single(_link(f"type=xhttp&security=tls&path=%2Fp&extra={value}"))
                self.assertEqual({"path": "/p"}, _xhttp(node))

    def test_mode_is_lowercased_and_validated(self) -> None:
        node = parse_single(_link("type=xhttp&security=tls&mode=Stream-Up"))
        self.assertEqual("stream-up", _xhttp(node)["mode"])
        with self.assertRaisesRegex(LinkParseError, "Неизвестный режим XHTTP"):
            parse_single(_link("type=xhttp&security=tls&mode=turbo"))

    def test_broken_extra_gives_a_russian_error(self) -> None:
        with self.assertRaisesRegex(LinkParseError, "Не удалось разобрать XHTTP extra"):
            parse_single(_link("type=xhttp&security=tls&extra=%7Bnot-json"))
        for value in ("%5B1%2C2%5D", "%22text%22", "12"):
            with self.subTest(extra=value):
                with self.assertRaisesRegex(LinkParseError, "JSON-объектом"):
                    parse_single(_link(f"type=xhttp&security=tls&extra={value}"))

    def test_broken_extra_in_a_subscription_only_drops_that_line(self) -> None:
        good = _link("type=xhttp&security=tls&path=%2Fp")
        bad = _link("type=xhttp&security=tls&extra=%7Bbad")
        nodes, errors = parse_links_text(f"{good}\n{bad}")
        self.assertEqual(1, len(nodes))
        self.assertEqual(1, len(errors))
        self.assertIn("XHTTP extra", errors[0])

    def test_stored_node_without_settings_is_repaired_from_its_link(self) -> None:
        link = _link("type=xhttp&security=tls&sni=h.example&path=%2Fp&mode=stream-up")
        node = parse_single(link)
        del node.outbound["streamSettings"]["xhttpSettings"]  # what 0.8.80 and older saved
        self.assertTrue(repair_node_outbound_from_link(node))
        self.assertEqual({"path": "/p", "mode": "stream-up"}, _xhttp(node))
        self.assertFalse(repair_node_outbound_from_link(node))

    def test_masking_xmux_still_merges_into_extra_or_into_settings(self) -> None:
        with_extra = parse_single(_link(f"type=xhttp&security=tls&extra={quote(json.dumps({'xPaddingBytes': '1-2'}))}"))
        plain = parse_single(_link("type=xhttp&security=tls&path=%2Fp"))
        block = {"xmux": {"maxConnections": "2"}}
        masking_xray.apply_to_outbound(with_extra.outbound, block)
        masking_xray.apply_to_outbound(plain.outbound, block)
        self.assertEqual({"maxConnections": "2"}, _xhttp(with_extra)["extra"]["xmux"])
        self.assertNotIn("xmux", _xhttp(with_extra))
        self.assertEqual({"path": "/p", "xmux": {"maxConnections": "2"}}, _xhttp(plain))
        self.assertEqual("xhttp", shape_of(plain.outbound).network)

    def test_other_transports_are_unchanged(self) -> None:
        node = parse_single(_link("type=ws&security=tls&path=%2Fw&host=w.example"))
        stream = node.outbound["streamSettings"]
        self.assertNotIn("xhttpSettings", stream)
        self.assertEqual("/w", stream["wsSettings"]["path"])


if __name__ == "__main__":
    unittest.main()
