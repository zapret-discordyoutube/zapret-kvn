from __future__ import annotations

import ctypes
import os
import socket
import unittest
from unittest.mock import Mock, patch

from PyQt6.QtCore import QCoreApplication

from xray_fluent.platform.windows import win_netinfo
from xray_fluent.engines.singbox.manager import SingBoxManager
from xray_fluent.engines.xray.tun_route_manager import WindowsTunInterface, XrayTunRouteManager

_APP = QCoreApplication.instance() or QCoreApplication([])


def _make_sockaddr(family: int, packed: bytes, offset: int) -> win_netinfo._SOCKADDR:
    sockaddr = win_netinfo._SOCKADDR()
    sockaddr.sa_family = family
    data = bytearray(26)
    data[offset : offset + len(packed)] = packed
    sockaddr.sa_data = (ctypes.c_ubyte * 26)(*data)
    return sockaddr


def _ipv4_sockaddr(address: str) -> win_netinfo._SOCKADDR:
    # sockaddr_in: sa_data = port(2) + address(4)
    return _make_sockaddr(win_netinfo._AF_INET, socket.inet_aton(address), 2)


def _ipv6_sockaddr(address: str) -> win_netinfo._SOCKADDR:
    # sockaddr_in6: sa_data = port(2) + flowinfo(4) + address(16)
    return _make_sockaddr(win_netinfo._AF_INET6, socket.inet_pton(socket.AF_INET6, address), 6)


def _build_address_chain(sockaddrs, keep_alive):
    """Build a {Length, Flags, Next, Address} node chain (unicast/DNS/gateway)."""
    first = None
    previous = None
    for sockaddr in sockaddrs:
        node = win_netinfo._IP_ADAPTER_UNICAST_ADDRESS()
        node.Address.lpSockaddr = ctypes.pointer(sockaddr)
        keep_alive.extend([sockaddr, node])
        if previous is None:
            first = node
        else:
            previous.Next = ctypes.pointer(node)
        previous = node
    return ctypes.pointer(first) if first is not None else None


def _make_adapter_chain(specs, keep_alive):
    """Build a linked _IP_ADAPTER_ADDRESSES chain from python specs."""
    adapters = []
    for spec in specs:
        adapter = win_netinfo._IP_ADAPTER_ADDRESSES()
        adapter.IfIndex = spec.get("if_index", 0)
        adapter.AdapterName = spec.get("adapter_name", b"{00000000-0000-0000-0000-000000000000}")
        adapter.FriendlyName = spec.get("friendly_name", "")
        adapter.Description = spec.get("description", "")
        adapter.IfType = spec.get("if_type", 0)
        adapter.OperStatus = spec.get("oper_status", 0)
        adapter.Ipv4Metric = spec.get("ipv4_metric", 0)
        unicast = _build_address_chain(spec.get("sockaddrs", []), keep_alive)
        if unicast is not None:
            adapter.FirstUnicastAddress = unicast
        gateways = _build_address_chain(spec.get("gateways", []), keep_alive)
        if gateways is not None:
            adapter.FirstGatewayAddress = gateways
        dns = _build_address_chain(spec.get("dns", []), keep_alive)
        if dns is not None:
            adapter.FirstDnsServerAddress = dns
        keep_alive.append(adapter)
        adapters.append(adapter)
    for left, right in zip(adapters, adapters[1:]):
        left.Next = ctypes.pointer(right)
    return ctypes.pointer(adapters[0]) if adapters else None


def _uplink(name, *, if_index, metric, oper_status=win_netinfo._IF_OPER_STATUS_UP,
            ipv4=("192.168.1.8",), gateways=("192.168.1.1",), dns=("192.168.1.1",)) -> win_netinfo.AdapterInfo:
    return win_netinfo.AdapterInfo(
        adapter_name="{guid}", friendly_name=name, description="", if_index=if_index,
        ipv4_addresses=list(ipv4), ipv6_addresses=[], oper_status=oper_status,
        ipv4_metric=metric, ipv4_gateways=list(gateways), dns_servers=list(dns),
    )


def _adapter(name: str, description: str = "", if_index: int = 1, ipv4=(), ipv6=()) -> win_netinfo.AdapterInfo:
    return win_netinfo.AdapterInfo(
        adapter_name="{guid}",
        friendly_name=name,
        description=description,
        if_index=if_index,
        ipv4_addresses=list(ipv4),
        ipv6_addresses=list(ipv6),
    )


class ParseAdapterChainTests(unittest.TestCase):
    def test_parses_adapters_addresses_and_filters_noise(self) -> None:
        keep_alive: list = []
        first = _make_adapter_chain(
            [
                {
                    "friendly_name": "xftun0",
                    "description": "sing-box TUN",
                    "adapter_name": b"{TUN-GUID}",
                    "if_index": 21,
                    "sockaddrs": [
                        _ipv4_sockaddr("172.19.0.1"),
                        _ipv4_sockaddr("0.0.0.0"),  # unassigned, filtered
                        _ipv6_sockaddr("fe80::1"),  # link-local, filtered
                        _ipv6_sockaddr("fd00::2"),
                    ],
                },
                {
                    "friendly_name": "Ethernet",
                    "description": "Realtek PCIe",
                    "if_index": 7,
                    "sockaddrs": [],
                },
            ],
            keep_alive,
        )

        adapters = win_netinfo._parse_adapter_chain(first)

        self.assertEqual(len(adapters), 2)
        tun = adapters[0]
        self.assertEqual(tun.friendly_name, "xftun0")
        self.assertEqual(tun.description, "sing-box TUN")
        self.assertEqual(tun.adapter_name, "{TUN-GUID}")
        self.assertEqual(tun.if_index, 21)
        self.assertEqual(tun.ipv4_addresses, ["172.19.0.1"])
        self.assertEqual(tun.ipv6_addresses, ["fd00::2"])
        ethernet = adapters[1]
        self.assertEqual(ethernet.friendly_name, "Ethernet")
        self.assertEqual(ethernet.ipv4_addresses, [])
        self.assertEqual(ethernet.ipv6_addresses, [])

    def test_empty_chain_parses_to_empty_list(self) -> None:
        self.assertEqual(win_netinfo._parse_adapter_chain(None), [])


class WinNetInfoHelperTests(unittest.TestCase):
    def test_list_adapters_raises_off_windows(self) -> None:
        if os.name == "nt":
            self.skipTest("non-Windows guard")
        with self.assertRaises(win_netinfo.WinNetInfoError):
            win_netinfo.list_adapters()

    def test_is_available_false_off_windows(self) -> None:
        if os.name == "nt":
            self.skipTest("non-Windows guard")
        win_netinfo._reset_availability_cache_for_tests()
        try:
            self.assertFalse(win_netinfo.is_available())
        finally:
            win_netinfo._reset_availability_cache_for_tests()

    def test_find_adapter_matches_name_or_description_case_insensitive(self) -> None:
        adapters = [
            _adapter("xftun0", description="sing-box TUN", if_index=21, ipv4=["172.19.0.1"]),
            _adapter("Ethernet", description="Realtek PCIe", if_index=7),
        ]
        with patch("xray_fluent.platform.windows.win_netinfo.list_adapters", return_value=adapters):
            self.assertIs(win_netinfo.find_adapter("XFTUN0"), adapters[0])
            self.assertIs(win_netinfo.find_adapter("sing-box tun"), adapters[0])
            self.assertIs(win_netinfo.find_adapter("Ethernet"), adapters[1])
            self.assertIsNone(win_netinfo.find_adapter("missing"))
            self.assertIsNone(win_netinfo.find_adapter(""))

    def test_adapter_has_ipv4(self) -> None:
        adapters = [
            _adapter("xftun0", if_index=21, ipv4=["172.19.0.1"]),
            _adapter("Ethernet", if_index=7),
        ]
        with patch("xray_fluent.platform.windows.win_netinfo.list_adapters", return_value=adapters):
            self.assertTrue(win_netinfo.adapter_has_ipv4("xftun0"))
            self.assertFalse(win_netinfo.adapter_has_ipv4("Ethernet"))
            self.assertFalse(win_netinfo.adapter_has_ipv4("missing"))

    def test_any_adapter_name_contains(self) -> None:
        adapters = [_adapter("xftun3", description="wintun")]
        with patch("xray_fluent.platform.windows.win_netinfo.list_adapters", return_value=adapters):
            self.assertTrue(win_netinfo.any_adapter_name_contains("xftun"))
            self.assertTrue(win_netinfo.any_adapter_name_contains("WINTUN"))
            self.assertFalse(win_netinfo.any_adapter_name_contains("tap-windows"))
            self.assertFalse(win_netinfo.any_adapter_name_contains(""))

    def test_list_adapters_requests_all_ndis_interfaces(self) -> None:
        captured_flags: list[int] = []

        def fake_get_adapters_addresses(_family, flags, _reserved, _buffer, _size) -> int:
            captured_flags.append(int(flags))
            return win_netinfo._ERROR_NO_DATA

        with patch.object(win_netinfo.os, "name", "nt"), patch(
            "xray_fluent.platform.windows.win_netinfo._resolve_get_adapters_addresses",
            return_value=fake_get_adapters_addresses,
        ):
            self.assertEqual(win_netinfo.list_adapters(), [])

        self.assertEqual(len(captured_flags), 1)
        self.assertTrue(captured_flags[0] & win_netinfo._GAA_FLAG_INCLUDE_ALL_INTERFACES)


class SingBoxTunProbeTests(unittest.TestCase):
    def test_fast_path_skips_powershell(self) -> None:
        with patch("xray_fluent.platform.windows.win_netinfo.is_available", return_value=True), patch(
            "xray_fluent.platform.windows.win_netinfo.adapter_has_ipv4", return_value=True
        ) as fast_mock, patch.object(
            SingBoxManager, "_tun_interface_has_ipv4"
        ) as powershell_mock:
            self.assertEqual(SingBoxManager._probe_tun_interface_has_ipv4("xftun0"), (True, True))

        fast_mock.assert_called_once_with("xftun0")
        powershell_mock.assert_not_called()

    def test_fast_negative_is_verified_by_powershell(self) -> None:
        with patch("xray_fluent.platform.windows.win_netinfo.is_available", return_value=True), patch(
            "xray_fluent.platform.windows.win_netinfo.adapter_has_ipv4", return_value=False
        ) as fast_mock, patch.object(
            SingBoxManager, "_tun_interface_has_ipv4", return_value=True
        ) as powershell_mock:
            self.assertEqual(SingBoxManager._probe_tun_interface_has_ipv4("xftun0"), (True, False))

        fast_mock.assert_called_once_with("xftun0")
        powershell_mock.assert_called_once_with("xftun0")

    def test_both_providers_must_report_negative_before_waiting_again(self) -> None:
        with patch("xray_fluent.platform.windows.win_netinfo.is_available", return_value=True), patch(
            "xray_fluent.platform.windows.win_netinfo.adapter_has_ipv4", return_value=False
        ), patch.object(
            SingBoxManager, "_tun_interface_has_ipv4", return_value=False
        ) as powershell_mock:
            self.assertEqual(SingBoxManager._probe_tun_interface_has_ipv4("xftun0"), (False, False))

        powershell_mock.assert_called_once_with("xftun0")

    def test_ctypes_failure_falls_back_to_powershell(self) -> None:
        with patch("xray_fluent.platform.windows.win_netinfo.is_available", return_value=True), patch(
            "xray_fluent.platform.windows.win_netinfo.adapter_has_ipv4",
            side_effect=win_netinfo.WinNetInfoError("boom"),
        ), patch.object(
            SingBoxManager, "_tun_interface_has_ipv4", return_value=True
        ) as powershell_mock:
            self.assertEqual(SingBoxManager._probe_tun_interface_has_ipv4("xftun0"), (True, False))

        powershell_mock.assert_called_once_with("xftun0")

    def test_unavailable_ctypes_uses_powershell(self) -> None:
        with patch("xray_fluent.platform.windows.win_netinfo.is_available", return_value=False), patch(
            "xray_fluent.platform.windows.win_netinfo.adapter_has_ipv4"
        ) as fast_mock, patch.object(
            SingBoxManager, "_tun_interface_has_ipv4", return_value=False
        ):
            self.assertEqual(SingBoxManager._probe_tun_interface_has_ipv4("xftun0"), (False, False))

        fast_mock.assert_not_called()

    def test_tun_gone_fast_path(self) -> None:
        with patch("xray_fluent.platform.windows.win_netinfo.is_available", return_value=True), patch(
            "xray_fluent.platform.windows.win_netinfo.any_adapter_name_contains", return_value=False
        ) as fast_mock, patch(
            "xray_fluent.engines.singbox.manager.run_text_pumped"
        ) as netsh_mock:
            self.assertEqual(SingBoxManager._probe_tun_adapter_gone(), (True, True))

        fast_mock.assert_called_once_with("xftun")
        netsh_mock.assert_not_called()

    def test_tun_gone_falls_back_to_netsh(self) -> None:
        completed = Mock(returncode=0, stdout=b"Ethernet\n", stderr=b"")
        with patch("xray_fluent.platform.windows.win_netinfo.is_available", return_value=True), patch(
            "xray_fluent.platform.windows.win_netinfo.any_adapter_name_contains",
            side_effect=win_netinfo.WinNetInfoError("boom"),
        ), patch(
            "xray_fluent.engines.singbox.manager.run_text_pumped", return_value=completed
        ) as netsh_mock:
            self.assertEqual(SingBoxManager._probe_tun_adapter_gone(), (True, False))

        netsh_mock.assert_called_once()

    def test_tun_gone_netsh_still_lists_adapter(self) -> None:
        completed = Mock(returncode=0, stdout=b"xftun0\n", stderr=b"")
        with patch("xray_fluent.platform.windows.win_netinfo.is_available", return_value=False), patch(
            "xray_fluent.engines.singbox.manager.run_text_pumped", return_value=completed
        ):
            self.assertEqual(SingBoxManager._probe_tun_adapter_gone(), (False, False))


class XrayTunRouteProbeTests(unittest.TestCase):
    def test_fast_path_builds_interface_from_adapter_info(self) -> None:
        adapter = _adapter("xftun0", if_index=33, ipv4=["172.19.0.1"], ipv6=["fd00::2"])
        with patch("xray_fluent.platform.windows.win_netinfo.is_available", return_value=True), patch(
            "xray_fluent.platform.windows.win_netinfo.find_adapter", return_value=adapter
        ), patch.object(
            XrayTunRouteManager, "_read_tun_interface_powershell"
        ) as powershell_mock:
            interface, fast_probe = XrayTunRouteManager._read_tun_interface("xftun0")

        self.assertTrue(fast_probe)
        self.assertEqual(
            interface,
            WindowsTunInterface(interface_index=33, ipv4_address="172.19.0.1", ipv6_address="fd00::2"),
        )
        powershell_mock.assert_not_called()

    def test_fast_path_reports_missing_adapter_without_fallback(self) -> None:
        with patch("xray_fluent.platform.windows.win_netinfo.is_available", return_value=True), patch(
            "xray_fluent.platform.windows.win_netinfo.find_adapter", return_value=None
        ), patch.object(
            XrayTunRouteManager, "_read_tun_interface_powershell"
        ) as powershell_mock:
            interface, fast_probe = XrayTunRouteManager._read_tun_interface("xftun0")

        self.assertIsNone(interface)
        self.assertTrue(fast_probe)
        powershell_mock.assert_not_called()

    def test_adapter_without_ipv4_is_not_ready(self) -> None:
        adapter = _adapter("xftun0", if_index=33, ipv4=[], ipv6=["fd00::2"])
        with patch("xray_fluent.platform.windows.win_netinfo.is_available", return_value=True), patch(
            "xray_fluent.platform.windows.win_netinfo.find_adapter", return_value=adapter
        ):
            interface, fast_probe = XrayTunRouteManager._read_tun_interface("xftun0")

        self.assertIsNone(interface)
        self.assertTrue(fast_probe)

    def test_ctypes_failure_falls_back_to_powershell(self) -> None:
        sentinel = WindowsTunInterface(interface_index=5, ipv4_address="172.19.0.1", ipv6_address="")
        with patch("xray_fluent.platform.windows.win_netinfo.is_available", return_value=True), patch(
            "xray_fluent.platform.windows.win_netinfo.find_adapter",
            side_effect=win_netinfo.WinNetInfoError("boom"),
        ), patch.object(
            XrayTunRouteManager, "_read_tun_interface_powershell", return_value=sentinel
        ) as powershell_mock:
            interface, fast_probe = XrayTunRouteManager._read_tun_interface("xftun0")

        self.assertIs(interface, sentinel)
        self.assertFalse(fast_probe)
        powershell_mock.assert_called_once_with("xftun0")


class ParseGatewayDnsTests(unittest.TestCase):
    def test_parses_gateways_dns_and_scalars(self) -> None:
        keep_alive: list = []
        first = _make_adapter_chain(
            [
                {
                    "friendly_name": "Ethernet",
                    "if_index": 7,
                    "if_type": 6,
                    "oper_status": win_netinfo._IF_OPER_STATUS_UP,
                    "ipv4_metric": 25,
                    "sockaddrs": [_ipv4_sockaddr("192.168.1.8")],
                    "gateways": [_ipv4_sockaddr("192.168.1.1")],
                    "dns": [_ipv4_sockaddr("192.168.1.1"), _ipv6_sockaddr("2001:4860:4860::8888"),
                            _ipv6_sockaddr("fe80::1")],
                }
            ],
            keep_alive,
        )

        [adapter] = win_netinfo._parse_adapter_chain(first)
        self.assertEqual(adapter.if_type, 6)
        self.assertEqual(adapter.oper_status, win_netinfo._IF_OPER_STATUS_UP)
        self.assertEqual(adapter.ipv4_metric, 25)
        self.assertEqual(adapter.ipv4_gateways, ["192.168.1.1"])
        # IPv4 first, link-local IPv6 dropped.
        self.assertEqual(adapter.dns_servers, ["192.168.1.1", "2001:4860:4860::8888"])


class PhysicalUplinkTests(unittest.TestCase):
    def test_prefers_lowest_metric_uplink_with_gateway(self) -> None:
        wifi = _uplink("Wi-Fi", if_index=12, metric=50)
        ethernet = _uplink("Ethernet", if_index=7, metric=25)
        self.assertIs(win_netinfo.select_physical_uplink([wifi, ethernet]), ethernet)

    def test_wireguard_tun_without_gateway_is_excluded(self) -> None:
        # WireGuard/AmneziaWG TUN: up, has address, but no gateway -> not chosen.
        tun = _uplink("xftun0", if_index=33, metric=0, ipv4=("10.9.0.49",), gateways=())
        ethernet = _uplink("Ethernet", if_index=7, metric=25)
        self.assertIs(win_netinfo.select_physical_uplink([tun, ethernet]), ethernet)

    def test_hyper_v_vethernet_uplink_is_accepted(self) -> None:
        # The PowerShell HardwareInterface filter dropped this; the gateway rule
        # keeps it.
        vethernet = _uplink("vEthernet (WSL)", if_index=40, metric=15)
        self.assertIs(win_netinfo.select_physical_uplink([vethernet]), vethernet)

    def test_down_or_apipa_only_adapters_are_ignored(self) -> None:
        down = _uplink("Ethernet", if_index=7, metric=10, oper_status=2)
        apipa = _uplink("Wi-Fi", if_index=12, metric=20, ipv4=("169.254.5.5",))
        self.assertIsNone(win_netinfo.select_physical_uplink([down, apipa]))

    def test_resolve_returns_index_and_bootstrap_dns(self) -> None:
        ethernet = _uplink("Ethernet", if_index=7, metric=25, dns=("192.168.1.1", "1.1.1.1"))
        with patch("xray_fluent.platform.windows.win_netinfo.list_adapters", return_value=[ethernet]):
            self.assertEqual(win_netinfo.resolve_physical_uplink(), (7, ["192.168.1.1", "1.1.1.1"]))

    def test_resolve_returns_none_when_no_uplink(self) -> None:
        with patch("xray_fluent.platform.windows.win_netinfo.list_adapters", return_value=[]):
            self.assertIsNone(win_netinfo.resolve_physical_uplink())


if __name__ == "__main__":
    unittest.main()
