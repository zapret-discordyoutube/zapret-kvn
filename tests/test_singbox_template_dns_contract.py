from __future__ import annotations

import json
from pathlib import Path
import unittest

from xray_fluent.constants import HYSTERIA_PATH_DEFAULT
from xray_fluent.engines.singbox.runtime_planner import (
    parse_singbox_document,
    plan_singbox_proxy_runtime,
    plan_singbox_runtime,
)
from xray_fluent.link_parser import parse_single


ROOT = Path(__file__).resolve().parents[1]


class SingboxTemplateDnsContractTests(unittest.TestCase):
    def test_all_templates_define_the_runtime_dns_contract(self) -> None:
        template_dir = ROOT / "data" / "templates" / "sing-box"

        for path in sorted(template_dir.glob("*.json")):
            with self.subTest(template=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                dns = payload["dns"]
                servers = {server["tag"]: server for server in dns["servers"]}

                self.assertEqual(
                    servers["bootstrap-dns"],
                    {
                        "tag": "bootstrap-dns",
                        "type": "udp",
                        "server": "1.1.1.1",
                    },
                )
                self.assertEqual(
                    servers["proxy-dns"],
                    {
                        "tag": "proxy-dns",
                        "type": "tcp",
                        "server": "8.8.8.8",
                        "detour": "proxy",
                    },
                )
                self.assertEqual(dns["final"], "proxy-dns")

                route = payload["route"]
                self.assertEqual(route["default_domain_resolver"], "proxy-dns")
                self.assertEqual(route["rules"][0], {"action": "sniff"})
                self.assertEqual(
                    route["rules"][1],
                    {"protocol": "dns", "action": "hijack-dns"},
                )

                direct = next(
                    outbound
                    for outbound in payload["outbounds"]
                    if outbound.get("tag") == "direct"
                )
                self.assertEqual(direct["domain_resolver"], "bootstrap-dns")

    def test_discord_template_accepts_a_domain_based_proxy_node(self) -> None:
        path = ROOT / "data" / "templates" / "sing-box" / "discord-folder-example.json"
        document = parse_singbox_document(path, path.read_text(encoding="utf-8"))

        node = parse_single("hy2://secret@example.com:443/?insecure=1")
        plans = (
            plan_singbox_runtime(document, node),
            plan_singbox_proxy_runtime(
                document,
                node,
                allowed_proxy_ports={1390, 1391},
            ),
        )

        for plan in plans:
            with self.subTest(mode="proxy" if plan.socks_port else "tun"):
                proxy = next(
                    outbound
                    for outbound in plan.singbox_config["outbounds"]
                    if outbound.get("tag") == "proxy"
                )
                self.assertEqual(proxy["type"], "socks")
                self.assertEqual(proxy["server"], "127.0.0.1")
                self.assertNotIn("domain_resolver", proxy)
                self.assertEqual(
                    plan.singbox_config["route"]["rules"][0],
                    {
                        "process_path": [str(HYSTERIA_PATH_DEFAULT.resolve())],
                        "outbound": "direct",
                    },
                )


if __name__ == "__main__":
    unittest.main()
