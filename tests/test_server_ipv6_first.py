"""IPv6 к VPN-серверу первым (22.11.2026): решения приложения на Windows.

Гонку делают ядра (sing-box, Xray); приложение решает, включено ли это, в каком
порядке закреплять один адрес (Hysteria, замеры) и помнит семейство, которое не
ответило. См. xray_fluent/network/server_family.py и docs/RUNTIME_MODULES.md.
"""
from __future__ import annotations

import time
import unittest
from unittest.mock import patch

from PyQt6.QtCore import QCoreApplication, QProcess

from tests.step_fakes import drive
from xray_fluent.engines.hysteria import manager as hysteria_manager
from xray_fluent.engines.hysteria.manager import HysteriaManager
from xray_fluent.engines.singbox import runtime_planner
from xray_fluent.network import latency_probe, server_family
from xray_fluent.network.bootstrap_dns import BootstrapResolution
from xray_fluent.network.server_family import FamilyMemory, order_addresses
from xray_fluent.platform.windows.win_netinfo import AdapterInfo

_APP = QCoreApplication.instance() or QCoreApplication([])

V4, V6 = "194.87.115.138", "2a03:6f02::175a"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def adapter(*, ipv6: list[str], ipv4: list[str] | None = None, index: int = 25, if_type: int = 6) -> AdapterInfo:
    return AdapterInfo(
        adapter_name="{x}", friendly_name="vEthernet (External)", description="Hyper-V", if_index=index,
        ipv4_addresses=ipv4 if ipv4 is not None else ["192.168.1.2"], ipv6_addresses=ipv6,
        if_type=if_type, oper_status=1, ipv4_metric=25,
    )


class UplinkTests(unittest.TestCase):
    def test_native_global_ipv6_only(self) -> None:
        self.assertTrue(server_family.is_native_global_ipv6("2a00:1370:8186:18d3:59de:5750:748b:4ba9"))
        for value in ("fe80::1", "fd7a:115c:a1e0::a937:dd2f", "::1", "2001:0:4136:e378::1", "2002:c000:204::1",
                      "192.168.1.2", "garbage"):
            self.assertFalse(server_family.is_native_global_ipv6(value), value)

    def test_uplink_with_global_ipv6(self) -> None:
        # The owner's PC on 21.11.2026: the Hyper-V uplink has 2a00:1370:…, Tailscale has fd7a:… only.
        owner = [adapter(ipv6=["2a00:1370:8186:18d3:59de:5750:748b:4ba9"]),
                 adapter(ipv6=["fd7a:115c:a1e0::a937:dd2f"], ipv4=["100.97.152.85"], index=40)]
        self.assertTrue(server_family.uplink_has_ipv6(owner))

    def test_no_ipv6_on_the_uplink(self) -> None:
        self.assertFalse(server_family.uplink_has_ipv6([adapter(ipv6=[])]))
        self.assertFalse(server_family.uplink_has_ipv6([adapter(ipv6=["fd00::5"])]))
        self.assertFalse(server_family.uplink_has_ipv6([]))
        # A tunnel adapter with IPv6 is not the uplink.
        self.assertFalse(server_family.uplink_has_ipv6([adapter(ipv6=["2a00::1"], if_type=131)]))

    def test_setting_off_or_no_ipv6_disables_it(self) -> None:
        self.assertTrue(server_family.server_ipv6_first(True, has_ipv6=lambda: True))
        self.assertFalse(server_family.server_ipv6_first(False, has_ipv6=lambda: True))
        self.assertFalse(server_family.server_ipv6_first(True, has_ipv6=lambda: False))

    def test_probe_flag_follows_setting_and_caches_uplink(self) -> None:
        calls: list[int] = []
        clock = Clock()

        def has_ipv6() -> bool:
            calls.append(1)
            return True

        try:
            server_family.configure(True)
            self.assertTrue(server_family.probe_ipv6_first(clock=clock, has_ipv6=has_ipv6))
            self.assertTrue(server_family.probe_ipv6_first(clock=clock, has_ipv6=has_ipv6))
            self.assertEqual(len(calls), 1)
            clock.now += 31
            server_family.probe_ipv6_first(clock=clock, has_ipv6=has_ipv6)
            self.assertEqual(len(calls), 2)
            server_family.configure(False)
            self.assertFalse(server_family.probe_ipv6_first(clock=clock, has_ipv6=has_ipv6))
        finally:
            server_family.configure(True)


class MemoryTests(unittest.TestCase):
    """The same rules as Go common/familymemory (Android 0020, Windows address-family-memory.patch)."""

    def test_order_follows_memory_until_ttl(self) -> None:
        clock = Clock()
        memory = FamilyMemory(ttl=60, clock=clock)
        self.assertEqual(order_addresses("n", [V4, V6], ipv6_first=True, memory=memory), [V6, V4])
        self.assertEqual(order_addresses("n", [V6, V4], ipv6_first=False, memory=memory), [V4, V6])
        memory.failed("n", V6)
        self.assertEqual(order_addresses("n", [V4, V6], ipv6_first=True, memory=memory), [V4, V6])
        clock.now += 61
        self.assertEqual(order_addresses("n", [V4, V6], ipv6_first=True, memory=memory), [V6, V4])

    def test_success_and_failure_of_the_working_family(self) -> None:
        memory = FamilyMemory()
        memory.succeeded("n", V4)
        self.assertFalse(memory.prefer_ipv6("n", True))
        memory.failed("n", V4)
        self.assertTrue(memory.prefer_ipv6("n", False))
        memory.succeeded("n", "::ffff:194.87.115.138")
        self.assertFalse(memory.prefer_ipv6("n", True), "mapped IPv4 is IPv4")
        memory.reset()
        self.assertTrue(memory.prefer_ipv6("n", True))

    def test_proven_only_needs_a_working_ipv6(self) -> None:
        memory = FamilyMemory()
        self.assertEqual(order_addresses("n", [V4, V6], ipv6_first=True, memory=memory, proven_only=True), [V4, V6])
        memory.succeeded("n", V6)
        self.assertEqual(order_addresses("n", [V4, V6], ipv6_first=True, memory=memory, proven_only=True), [V6, V4])
        self.assertEqual(order_addresses("n", [V4, V6], ipv6_first=False, memory=memory, proven_only=True), [V4, V6])

    def test_other_family(self) -> None:
        self.assertEqual(server_family.has_other_family([V6, "2001:db8::1", V4], V6), V4)
        self.assertIsNone(server_family.has_other_family([V6], V6))


class PlannerTests(unittest.TestCase):
    def _payload(self) -> dict:
        return {"dns": {"servers": [{"tag": "bootstrap-dns", "type": "local"}]}, "route": {"rules": []}}

    def test_native_outbound_gets_prefer_ipv6_resolver(self) -> None:
        payload, outbound = self._payload(), {"type": "shadowsocks", "server": "node.example"}
        with patch.object(runtime_planner, "cached_addresses", return_value=()):
            runtime_planner._ensure_proxy_server_bootstrap_contract(payload, outbound, "node.example", ipv6_first=True)
        self.assertEqual(outbound["domain_resolver"], {"server": "bootstrap-dns", "strategy": "prefer_ipv6"})

    def test_off_or_endpoint_keeps_plain_resolver(self) -> None:
        payload, outbound = self._payload(), {"type": "shadowsocks", "server": "node.example"}
        endpoint = {"type": "wireguard", "peers": [{"address": "wg.example"}]}
        with patch.object(runtime_planner, "cached_addresses", return_value=()):
            runtime_planner._ensure_proxy_server_bootstrap_contract(payload, outbound, "node.example")
            runtime_planner._ensure_proxy_server_bootstrap_contract(payload, endpoint, "", ipv6_first=True)
        self.assertEqual(outbound["domain_resolver"], "bootstrap-dns")
        self.assertEqual(endpoint["domain_resolver"], "bootstrap-dns", "WG takes one address without fallback")

    def _hybrid_rules(self, ipv6_first: bool) -> list[dict]:
        payload = {
            "dns": {"servers": [{"tag": "direct-doh", "type": "fallback"}, {"tag": "bootstrap-dns", "type": "local"}]},
            "route": {"rules": [{"inbound": ["__app_hybrid_protect_in"], "action": "route", "outbound": "direct"}]},
        }
        cached = {"cached.example": ("203.0.113.5",)}
        with patch.object(runtime_planner, "cached_addresses", side_effect=lambda name: cached.get(name, ())):
            runtime_planner._ensure_hybrid_server_bootstrap(
                payload, ["cached.example", "fresh.example", "198.51.100.9"], ipv6_first=ipv6_first)
        return [rule for rule in payload["route"]["rules"] if rule.get("action") == "resolve"]

    def test_hybrid_without_ipv6_first_is_unchanged(self) -> None:
        self.assertEqual(self._hybrid_rules(False), [{
            "inbound": [runtime_planner._APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG],
            "domain": ["cached.example"], "action": "resolve", "server": "app-node-bootstrap",
        }])

    def test_hybrid_tcp_resolves_ipv6_first_udp_keeps_its_order(self) -> None:
        protect = [runtime_planner._APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG]
        rules = self._hybrid_rules(True)
        self.assertIn({"inbound": protect, "network": ["tcp"], "domain": ["cached.example"], "action": "resolve",
                       "server": "app-node-bootstrap", "strategy": "prefer_ipv6"}, rules)
        self.assertIn({"inbound": protect, "network": ["tcp"], "domain": ["fresh.example"], "action": "resolve",
                       "server": "bootstrap-dns", "strategy": "prefer_ipv6"}, rules)
        self.assertIn({"inbound": protect, "network": ["udp"], "domain": ["cached.example"], "action": "resolve",
                       "server": "app-node-bootstrap"}, rules)
        self.assertEqual(len(rules), 3)
        self.assertFalse(any("network" not in rule for rule in rules),
                         "a resolve rule for all networks would overwrite the TCP addresses")


class ProbeConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        server_family.MEMORY.reset()
        self.addCleanup(server_family.MEMORY.reset)

    def test_xray_probe_without_race_uses_one_family(self) -> None:
        with patch.object(latency_probe, "build_speed_test_config", return_value={"outbounds": [{}]}):
            config = latency_probe._xray_config(object(), 1, "node.example", [V4, V6], ipv6_first=False)
        self.assertEqual(config["dns"]["hosts"], {"node.example": [V4]},
                         "UseIP picks at random among both families: one family only")
        self.assertNotIn("happyEyeballs", config["outbounds"][0]["streamSettings"]["sockopt"])

    def test_xray_probe_races_natively_with_ipv6_first(self) -> None:
        with patch.object(latency_probe, "build_speed_test_config", return_value={"outbounds": [{}]}):
            config = latency_probe._xray_config(object(), 1, "node.example", [V6, V4], ipv6_first=True)
        sockopt = config["outbounds"][0]["streamSettings"]["sockopt"]
        self.assertEqual(config["dns"]["hosts"], {"node.example": [V6, V4]})
        self.assertEqual(sockopt["domainStrategy"], "UseIP")
        self.assertEqual(sockopt["happyEyeballs"]["prioritizeIPv6"], True)
        self.assertEqual(sockopt["happyEyeballs"]["tryDelayMs"], 250)

    def test_singbox_probe_resolver(self) -> None:
        with patch.object(latency_probe, "build_singbox_outbound", return_value={"type": "shadowsocks"}), \
                patch.object(latency_probe, "is_singbox_endpoint_node", return_value=False):
            on = latency_probe._singbox_config(object(), 1, "node.example", [V6, V4], ipv6_first=True)
            off = latency_probe._singbox_config(object(), 1, "node.example", [V4, V6], ipv6_first=False)
        self.assertEqual(on["route"]["default_domain_resolver"], {"server": "probe-hosts", "strategy": "prefer_ipv6"})
        self.assertEqual(off["route"]["default_domain_resolver"], "probe-hosts")

    def test_hysteria_probe_pins_ipv6_only_when_proven(self) -> None:
        def pin(addresses: list[str]) -> str:
            with patch.object(latency_probe, "build_hysteria_speed_test_config",
                              return_value={"server": "hy2://p@node.example:443/"}):
                return latency_probe._hysteria_config(object(), 1, "node.example", addresses, ipv6_first=True)["server"]

        self.assertIn(f"@{V4}:", pin([V6, V4]))
        server_family.MEMORY.succeeded("node.example", V6)
        self.assertIn(f"@[{V6}]:", pin([V6, V4]))

    def test_server_addresses_order(self) -> None:
        resolve = lambda host, system=None: BootstrapResolution(frozenset({V4, V6}), "doh")  # noqa: E731
        self.assertEqual(latency_probe.server_addresses("node.example", resolve), [V4, V6])
        self.assertEqual(latency_probe.server_addresses("node.example", resolve, ipv6_first=True), [V6, V4])


_HY_CONFIG = {
    "server": "hy2://secret@hy.example:443/",
    "tls": {"sni": "hy.example"},
    "socks5": {"listen": "127.0.0.1:11809"},
}


class HysteriaFamilyTests(unittest.TestCase):
    def setUp(self) -> None:
        server_family.MEMORY.reset()
        self.addCleanup(server_family.MEMORY.reset)

    def _pin(self, manager: HysteriaManager, *, verify_remote: bool = True) -> dict:
        self.addCleanup(manager.deleteLater)
        resolve = lambda host: BootstrapResolution(frozenset({V4, V6}), "doh")  # noqa: E731
        with patch.object(hysteria_manager, "resolve_bootstrap", resolve):
            return drive(manager._trusted_server_address_steps(_HY_CONFIG, verify_remote=verify_remote))

    def test_ipv6_pinned_first_and_ipv4_is_the_fallback(self) -> None:
        manager = HysteriaManager()
        manager.server_ipv6_first = True
        self.assertIn(f"@[{V6}]:", self._pin(manager)["server"])
        self.assertEqual(manager._ipv6_fallback_address(), V4)
        # The retry attempt pins the fallback and has no further fallback.
        manager._family_retry_address = V4
        self.assertIn(f"@{V4}:", self._pin(manager)["server"])
        self.assertIsNone(manager._ipv6_fallback_address())

    def test_off_or_without_remote_check_keeps_ipv4_first(self) -> None:
        manager = HysteriaManager()
        self.assertIn(f"@{V4}:", self._pin(manager)["server"])
        self.assertIsNone(manager._ipv6_fallback_address())
        manager.server_ipv6_first = True
        self.assertIn(f"@{V4}:", self._pin(manager, verify_remote=False)["server"],
                      "a start without the remote check could not see IPv6 fail")

    def test_ipv6_failure_is_remembered(self) -> None:
        server_family.MEMORY.failed("hy.example", V6)
        manager = HysteriaManager()
        manager.server_ipv6_first = True
        self.assertIn(f"@{V4}:", self._pin(manager)["server"])

    def test_readiness_returns_retry_when_ipv6_probes_fail_fast(self) -> None:
        manager = HysteriaManager()
        self.addCleanup(manager.deleteLater)

        class Running:
            def state(self):
                return QProcess.ProcessState.Running

        def refused(*_args, **_kwargs):
            raise ConnectionRefusedError("refused")

        # Real sleeps: the probes run in worker threads, a no-op sleep would spin the loop.
        with patch.object(manager, "_process", Running()), patch.object(manager, "_probe_remote_endpoint", refused):
            retry = drive(manager._wait_until_remote_ready_steps(1, username="", password="", family_window=4.0),
                          on_sleep=time.sleep)
            plain = drive(manager._wait_until_remote_ready_steps(1, username="", password=""), on_sleep=time.sleep)
        self.assertIs(retry, hysteria_manager._RETRY_OTHER_FAMILY)
        self.assertFalse(plain)


if __name__ == "__main__":
    unittest.main()


class AmneziaFamilyTests(unittest.TestCase):
    """WG/AWG: гонка семейств в zapret-amnezia.exe, приложение даёт два адреса и помнит ответ."""

    def setUp(self) -> None:
        server_family.MEMORY.reset()
        self.addCleanup(server_family.MEMORY.reset)

    @staticmethod
    def _lookup(host: str) -> BootstrapResolution:
        if host == "v4only.example":
            return BootstrapResolution(frozenset({"203.0.113.9"}), "doh")
        return BootstrapResolution(frozenset({"2001:db8::7", "203.0.113.7"}), "doh")

    def _resolve(self, peers: list[dict], *, ipv6_first: bool):
        from xray_fluent.application.async_steps import run_steps_blocking
        from xray_fluent.engines.amnezia import manager as amnezia_manager

        payload = {"endpoint": {"peers": peers}}
        with (
            patch.object(amnezia_manager, "resolve_bootstrap", side_effect=self._lookup),
            patch.object(amnezia_manager, "register_server_aliases"),
        ):
            race_host = run_steps_blocking(amnezia_manager.resolve_peers_steps(payload, ipv6_first=ipv6_first))
        return race_host, payload["endpoint"]["peers"]

    def test_one_peer_races_ipv6_first_with_ipv4_as_race_address(self) -> None:
        race_host, peers = self._resolve([{"address": "wg.example", "port": 51820}], ipv6_first=True)
        self.assertEqual(race_host, "wg.example")
        self.assertEqual(peers[0]["address"], "2001:db8::7")
        self.assertEqual(peers[0]["race_address"], "203.0.113.7")

    def test_switch_off_keeps_ipv4_and_no_race(self) -> None:
        race_host, peers = self._resolve([{"address": "wg.example", "port": 51820}], ipv6_first=False)
        self.assertIsNone(race_host)
        self.assertEqual(peers[0]["address"], "203.0.113.7")
        self.assertNotIn("race_address", peers[0])

    def test_several_peers_or_one_family_do_not_race(self) -> None:
        race_host, peers = self._resolve(
            [{"address": "wg.example", "port": 1}, {"address": "other.example", "port": 2}], ipv6_first=True)
        self.assertIsNone(race_host)
        self.assertTrue(all("race_address" not in peer for peer in peers))
        self.assertEqual(peers[0]["address"], "203.0.113.7")
        race_host, peers = self._resolve([{"address": "v4only.example", "port": 1}], ipv6_first=True)
        self.assertIsNone(race_host)
        self.assertEqual(peers[0]["address"], "203.0.113.9")

    def test_the_family_that_answered_leads_next_time_until_the_network_changes(self) -> None:
        from xray_fluent.engines.amnezia.manager import AmneziaManager

        manager = AmneziaManager()
        self.addCleanup(manager.deleteLater)
        manager._race_host = "wg.example"
        manager._family_answered(4)
        manager._family_answered("6")  # not a family number: ignored
        _host, peers = self._resolve([{"address": "wg.example", "port": 51820}], ipv6_first=True)
        self.assertEqual(peers[0]["address"], "203.0.113.7")
        self.assertEqual(peers[0]["race_address"], "2001:db8::7")
        server_family.MEMORY.reset()  # network change
        _host, peers = self._resolve([{"address": "wg.example", "port": 51820}], ipv6_first=True)
        self.assertEqual(peers[0]["address"], "2001:db8::7")

    def test_physical_uplink_is_found_through_the_ipv4_race_address(self) -> None:
        from xray_fluent.engines.amnezia.manager import _first_peer_ipv4

        config = {"endpoint": {"peers": [{"address": "2001:db8::7", "race_address": "203.0.113.7"}]}}
        self.assertEqual(_first_peer_ipv4(config), "203.0.113.7")
        self.assertIsNone(_first_peer_ipv4({"endpoint": {"peers": [{"address": "2001:db8::7"}]}}))
        self.assertEqual(_first_peer_ipv4({"endpoint": {"peers": [{"address": "203.0.113.5"}]}}), "203.0.113.5")

    def test_succeeded_family_ignores_unknown_families(self) -> None:
        memory = FamilyMemory()
        memory.succeeded_family("wg.example", 5)
        memory.succeeded_family("", 4)
        self.assertTrue(memory.prefer_ipv6("wg.example", True))
        memory.succeeded_family("wg.example", 4)
        self.assertFalse(memory.prefer_ipv6("wg.example", True))
