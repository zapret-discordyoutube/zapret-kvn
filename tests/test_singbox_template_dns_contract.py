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
from xray_fluent.importer.link_parser import parse_single


ROOT = Path(__file__).resolve().parents[1]

# Узел перенаправляет любой plaintext DNS туннеля на собственный resolver, кроме
# своих канонических upstream (1.1.1.1/1.0.0.1). Поэтому адрес-указатель обязан
# быть отличным от них.
NODE_DNS_SENTINEL = "8.8.8.8"


def _reachable(servers: dict, tag: str) -> set[str]:
    """Теги-листья, до которых доходит цепочка fallback-резолверов."""

    seen: set[str] = set()
    pending = [tag]
    while pending:
        current = pending.pop()
        server = servers[current]
        children = server.get("servers")
        if children:
            pending.extend(child for child in children if child not in seen)
            continue
        seen.add(current)
    return seen


class SingboxTemplateDnsContractTests(unittest.TestCase):
    def test_all_templates_define_the_runtime_dns_contract(self) -> None:
        template_dir = ROOT / "data" / "templates" / "sing-box"

        for path in sorted(template_dir.glob("*.json")):
            with self.subTest(template=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                dns = payload["dns"]
                servers = {server["tag"]: server for server in dns["servers"]}

                self.assertEqual(servers["bootstrap-dns"]["servers"], ["direct-doh", "local-system-dns"])
                self.assertEqual(servers["local-system-dns"]["type"], "local")

                # Имена внутри туннеля резолвит DNS узла: обычный 53 через
                # outbound `proxy`. Узел перехватывает его своим resolver'ом и
                # отдаёт управляемые адреса. DoH через туннель этого перехвата
                # не видит и возвращает настоящий origin.
                self.assertEqual(
                    servers["proxy-dns"]["servers"],
                    ["vpn-node-dns-udp", "vpn-node-dns-tcp"],
                )
                self.assertEqual(servers["proxy-dns"]["strategy"], "sequential")
                for tag, transport in (
                    ("vpn-node-dns-udp", "udp"),
                    ("vpn-node-dns-tcp", "tcp"),
                ):
                    server = servers[tag]
                    self.assertEqual(server["type"], transport)
                    self.assertEqual(server["server"], NODE_DNS_SENTINEL)
                    self.assertEqual(server["server_port"], 53)
                    self.assertEqual(server["detour"], "proxy")
                    self.assertNotIn("tls", server)

                # Туннельная цепочка не имеет выхода наружу: ни один резолвер,
                # достижимый из `proxy-dns`, не ходит мимо outbound `proxy`.
                for tag in _reachable(servers, "proxy-dns"):
                    self.assertEqual(
                        servers[tag].get("detour"),
                        "proxy",
                        msg=f"{tag} резолвит мимо туннеля",
                    )

                # bootstrap остаётся защищённым DoH напрямую: он поднимает
                # туннель и обязан пережить подмену DNS провайдером.
                group = servers["direct-doh"]
                self.assertEqual(group["strategy"], "parallel")
                self.assertEqual(len(group["servers"]), 3)
                for tag in group["servers"]:
                    self.assertEqual(servers[tag]["type"], "https")
                    self.assertIsNone(servers[tag].get("detour"))
                    self.assertTrue(servers[tag]["tls"]["enabled"])
                    self.assertNotIn("insecure", servers[tag]["tls"])
                self.assertEqual(dns["final"], "proxy-dns")

                route = payload["route"]
                self.assertEqual(route["default_domain_resolver"], "proxy-dns")
                self.assertEqual(route["rules"][0], {"action": "sniff"})
                self.assertEqual(
                    route["rules"][1],
                    {"protocol": "dns", "action": "hijack-dns"},
                )
                # DoT приложений обошёл бы и hijack-dns, и resolver узла.
                self.assertEqual(
                    route["rules"][2],
                    {
                        "network": "tcp",
                        "port": 853,
                        "action": "reject",
                        "method": "default",
                    },
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

        node = parse_single("hy2://secret@example.com:443/?insecure=1&pinSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
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
