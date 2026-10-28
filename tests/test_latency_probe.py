"""Задержка через ядро: адрес без провайдерского DNS, тёплый RTT, «не измерен» ≠ «мёртв»."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from xray_fluent.engines.hysteria.config_adapter import pin_server_address, replace_server_host
from xray_fluent.network import latency_probe
from xray_fluent.network.bootstrap_dns import BootstrapNameNotFound, BootstrapResolution
from xray_fluent.profiles.models import Node


def _vless(server: str = "vpn.example") -> Node:
    return Node(
        id="v", name="v", scheme="vless", server=server, port=443,
        outbound={
            "protocol": "vless",
            "settings": {"vnext": [{"address": server, "port": 443, "users": [{"id": "u", "encryption": "none"}]}]},
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": server}},
        },
    )


def _trojan(server: str = "tr.example") -> Node:
    return Node(
        id="t", name="t", scheme="trojan", server=server, port=443,
        outbound={
            "protocol": "trojan",
            "settings": {"servers": [{"address": server, "port": 443, "password": "p"}]},
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": server}},
        },
    )


class AddressTests(unittest.TestCase):
    def test_system_dns_is_never_asked(self) -> None:
        seen = {}

        def resolve(host, *, system):
            seen["system"] = system(host)
            return BootstrapResolution(frozenset({"203.0.113.5"}), "doh")

        self.assertEqual(latency_probe.server_addresses("vpn.example", resolve), ["203.0.113.5"])
        self.assertEqual(seen["system"], set())

    def test_no_address_is_not_measured_rather_than_dead(self) -> None:
        def resolve(host, *, system):
            raise OSError("doh blocked, nothing cached")

        result = latency_probe.probe_node(_vless(), resolve=resolve)
        self.assertEqual(result.state, latency_probe.UNMEASURED)
        self.assertFalse(result.measured)

    def test_name_that_does_not_exist_is_no_answer(self) -> None:
        def resolve(host, *, system):
            raise BootstrapNameNotFound(host)

        self.assertEqual(latency_probe.probe_node(_vless(), resolve=resolve).state, latency_probe.NO_ANSWER)

    def test_ip_literal_needs_no_lookup(self) -> None:
        self.assertEqual(latency_probe.server_addresses("198.51.100.1", None), ["198.51.100.1"])


class CoreConfigTests(unittest.TestCase):
    def test_xray_gets_the_address_from_its_own_hosts(self) -> None:
        config = latency_probe._xray_config(_vless(), 19102, "vpn.example", ["203.0.113.5"])
        self.assertEqual(config["dns"]["hosts"], {"vpn.example": ["203.0.113.5"]})
        outbound = config["outbounds"][0]
        self.assertEqual(outbound["streamSettings"]["sockopt"]["domainStrategy"], "UseIP")
        # Имя сервера в ссылке не трогается: SNI и маршрут остаются прежними.
        self.assertEqual(outbound["settings"]["vnext"][0]["address"], "vpn.example")
        self.assertEqual(config["inbounds"][0]["port"], 19102)

    def test_singbox_resolves_the_server_from_predefined_hosts(self) -> None:
        config = latency_probe._singbox_config(_trojan(), 19102, "tr.example", ["203.0.113.6"])
        self.assertEqual(config["route"]["default_domain_resolver"], "probe-hosts")
        self.assertEqual(config["dns"]["servers"][0]["predefined"], {"tr.example": ["203.0.113.6"]})
        self.assertEqual(config["outbounds"][0]["tag"], "proxy")
        self.assertEqual(config["inbounds"][0]["listen_port"], 19102)

    def test_hysteria_uri_points_at_the_address_and_keeps_the_name_in_sni(self) -> None:
        uri = replace_server_host("hy2://secret@hy.example:443,5000-6000/?obfs=salamander", "203.0.113.7")
        self.assertEqual(uri, "hy2://secret@203.0.113.7:443,5000-6000/?obfs=salamander")
        self.assertEqual(replace_server_host("hy2://a@[2001:db8::1]:443/", "2001:db8::2"), "hy2://a@[2001:db8::2]:443/")
        pinned = pin_server_address({"server": "hy2://a@hy.example:443/", "tls": {}}, "203.0.113.7")
        self.assertEqual(pinned["server"], "hy2://a@203.0.113.7:443/")
        self.assertEqual(pinned["tls"]["sni"], "hy.example")

    def test_each_protocol_goes_to_the_core_that_connects_it(self) -> None:
        paths = latency_probe.CorePaths()
        with patch("xray_fluent.network.latency_probe.Path.is_file", return_value=True), patch(
            "xray_fluent.network.latency_probe.prepare_speed_test_xray", side_effect=lambda source, target: target,
        ):
            vless = latency_probe._launch(_vless(), 1, "vpn.example", ["203.0.113.5"], paths)
            trojan = latency_probe._launch(_trojan(), 1, "tr.example", ["203.0.113.6"], paths)
        self.assertIn("xray", vless.command[0])
        self.assertIn("sing-box", trojan.command[0])

    def test_amneziawg_is_not_measured(self) -> None:
        node = Node(id="w", name="w", scheme="wireguard", server="wg.example", port=51820,
                    outbound={"type": "wireguard"})
        self.assertEqual(latency_probe.probe_node(node).state, latency_probe.UNMEASURED)


class WarmRttTests(unittest.TestCase):
    def test_best_warm_request_is_the_rtt_not_the_cold_one(self) -> None:
        ticks = iter([0.0, 0.300, 1.0, 1.120, 2.0, 2.045])
        calls = []

        class FakeConnection:
            def __init__(self, *args, **kwargs) -> None:
                pass

            def set_tunnel(self, host, port) -> None:
                calls.append(("tunnel", host, port))

            def close(self) -> None:
                calls.append("close")

        def fake_request(_connection) -> None:
            calls.append("get")

        with patch("xray_fluent.network.latency_probe.http.client.HTTPSConnection", FakeConnection), patch(
            "xray_fluent.network.latency_probe._request", fake_request,
        ):
            rtt = latency_probe.warm_rtt_ms(1, clock=lambda: next(ticks))
        self.assertEqual(rtt, 45)
        self.assertEqual(calls, [("tunnel", "www.gstatic.com", 443), "get", "get", "get", "close"])

    def test_failed_warm_request_still_means_alive(self) -> None:
        ticks = iter([0.0, 0.300, 1.0])
        state = {"n": 0}

        class FakeConnection:
            def __init__(self, *args, **kwargs) -> None:
                pass

            def set_tunnel(self, host, port) -> None:
                pass

            def close(self) -> None:
                pass

        def flaky(_connection) -> None:
            state["n"] += 1
            if state["n"] > 1:
                raise OSError("цель закрыла соединение")

        with patch("xray_fluent.network.latency_probe.http.client.HTTPSConnection", FakeConnection), patch(
            "xray_fluent.network.latency_probe._request", flaky,
        ):
            self.assertEqual(latency_probe.warm_rtt_ms(1, clock=lambda: next(ticks)), 300)

    def test_headers_look_like_chrome(self) -> None:
        self.assertIn("Chrome/", latency_probe._HEADERS["User-Agent"])
        self.assertNotIn("ZapretKVN", " ".join(latency_probe._HEADERS.values()))


if __name__ == "__main__":
    unittest.main()
