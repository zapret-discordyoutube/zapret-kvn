"""Owner decision 2026-11-16: the official Xray core owns VLESS, VMess and Trojan.

sing-box stays the gasket (TUN, routing, DNS, protected sockets); it never converts these protocols.
"""

import base64
import json
import unittest

from xray_fluent.application.protocol_core import ProtocolCore, protocol_core
from xray_fluent.engines.singbox.config_builder import build_singbox_outbound
from xray_fluent.engines.singbox.runtime_planner import classify_node_for_singbox
from xray_fluent.importer.link_parser import parse_single, validate_node_outbound
from xray_fluent.profiles.models import Node

UUID = "11111111-1111-1111-1111-111111111111"


def _vmess(**overrides) -> str:
    payload = {"v": "2", "ps": "v", "add": "h.example", "port": "443", "id": UUID, "aid": "0", "net": "tcp", "tls": "tls"}
    payload.update(overrides)
    return "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()


class XrayOwnsVmessTrojanTests(unittest.TestCase):
    def test_links_go_to_xray(self) -> None:
        for link in ("trojan://pw@h.example:443?security=tls#t", _vmess(), f"vless://{UUID}@h.example:443#v"):
            with self.subTest(link=link[:12]):
                self.assertIs(ProtocolCore.XRAY, protocol_core(parse_single(link)))

    def test_other_protocols_keep_their_cores(self) -> None:
        self.assertIs(ProtocolCore.SINGBOX, protocol_core(parse_single("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@h.example:8388#s")))
        self.assertIs(ProtocolCore.HYSTERIA, protocol_core(parse_single("hy2://secret@198.51.100.20:443/?insecure=1&pinSHA256=" + "a" * 64 + "#h")))

    def test_a_raw_singbox_json_outbound_stays_with_singbox(self) -> None:
        raw = json.dumps({"type": "trojan", "tag": "t", "server": "h.example", "server_port": 443, "password": "p"})
        node = parse_single(raw)
        self.assertIs(ProtocolCore.SINGBOX, protocol_core(node))
        self.assertEqual("trojan", build_singbox_outbound(node)["type"])

    def test_singbox_never_converts_them(self) -> None:
        for link in ("trojan://pw@h.example:443?security=tls#t", _vmess()):
            with self.assertRaises(ValueError):
                build_singbox_outbound(parse_single(link))

    def test_xhttp_trojan_and_vmess_run_in_the_xray_sidecar(self) -> None:
        for link in (
            "trojan://pw@h.example:443?type=xhttp&security=tls&sni=h.example&path=%2Ft&mode=packet-up#t",
            _vmess(net="xhttp", path="/v", type="packet-up", host="cdn.example"),
        ):
            with self.subTest(link=link[:12]):
                node = parse_single(link)
                self.assertEqual("xhttp", node.outbound["streamSettings"]["network"])
                self.assertEqual("hybrid_xray_sidecar", classify_node_for_singbox(node))

    def test_allow_insecure_without_pin_is_dropped_like_vless(self) -> None:
        trojan = parse_single("trojan://pw@h.example:443?security=tls&allowInsecure=1#t")
        vmess = parse_single(_vmess(allowInsecure=1))
        for node in (trojan, vmess):
            self.assertNotIn("allowInsecure", node.outbound["streamSettings"]["tlsSettings"])
            self.assertIsNone(validate_node_outbound(node))

    def test_vmess_with_alter_id_is_refused_in_russian(self) -> None:
        message = validate_node_outbound(parse_single(_vmess(aid="4")))
        self.assertIn("alterId", message)
        self.assertIn("Xray", message)

    def test_a_node_without_protocol_key_is_not_xray(self) -> None:
        self.assertIs(ProtocolCore.SINGBOX, protocol_core(Node(name="n", scheme="trojan", outbound={"type": "trojan"})))


if __name__ == "__main__":
    unittest.main()
