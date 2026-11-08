"""Шаблоны sing-box: TUN забирает и IPv6, DNS не выдаёт AAAA прокси-имён.

Без IPv6-адреса у TUN маршрут ``::/0`` остаётся на физическом адаптере, и на двухстековой сети
приложение, получившее IPv6-адрес (DNS внутри браузера, литерал), идёт в обход туннеля с адреса
провайдера; сервисы с привязкой к региону тогда не пускают. Так же ведёт себя Android с
``proxyIpv4Only``.
"""

import ipaddress
import json
import unittest
from pathlib import Path

from xray_fluent.network.physical_route import tun_networks

_TEMPLATES = Path(__file__).resolve().parents[1] / "data" / "templates" / "sing-box"
_NAMES = ("default.json", "discord-folder-example.json")


def _load(name: str) -> dict:
    return json.loads((_TEMPLATES / name).read_text(encoding="utf-8"))


def _tun(config: dict) -> dict:
    return next(i for i in config["inbounds"] if i.get("type") == "tun")


class TemplateIpv6CaptureTest(unittest.TestCase):
    def test_tun_has_an_ipv4_and_an_ipv6_address(self) -> None:
        for name in _NAMES:
            with self.subTest(template=name):
                versions = {ipaddress.ip_interface(a).version for a in _tun(_load(name))["address"]}
                self.assertEqual(versions, {4, 6})

    def test_dns_never_answers_with_ipv6_addresses(self) -> None:
        for name in _NAMES:
            with self.subTest(template=name):
                self.assertEqual(_load(name)["dns"].get("strategy"), "ipv4_only")

    def test_strategy_is_a_value_the_pinned_core_schema_allows(self) -> None:
        schema = json.loads(
            (_TEMPLATES.parents[2] / "assets" / "sing-box-schema" / "schema.json").read_text(encoding="utf-8")
        )

        def resolve(node: dict) -> dict:
            while isinstance(node, dict) and "$ref" in node:
                target = schema
                for part in node["$ref"].lstrip("#/").split("/"):
                    target = target[part]
                node = target
            return node

        dns = resolve(schema["properties"]["dns"])
        strategy = resolve(dns["properties"]["strategy"])
        self.assertIn("ipv4_only", strategy["enum"])

    def test_physical_fingerprint_still_recognises_only_the_ipv4_tun_network(self) -> None:
        for name in _NAMES:
            with self.subTest(template=name):
                networks = tun_networks(_load(name))
                self.assertEqual([str(n) for n in networks], ["172.19.0.0/30"])

    def test_the_two_templates_agree_on_tun_address_and_dns_strategy(self) -> None:
        first, second = (_load(n) for n in _NAMES)
        self.assertEqual(_tun(first)["address"], _tun(second)["address"])
        self.assertEqual(first["dns"]["strategy"], second["dns"]["strategy"])


if __name__ == "__main__":
    unittest.main()
