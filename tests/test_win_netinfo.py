from __future__ import annotations

import ctypes
import os
import socket
import unittest
from unittest.mock import Mock, patch

from PyQt6.QtCore import QCoreApplication

from xray_fluent import win_netinfo
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


def _make_adapter_chain(specs, keep_alive):
    """Build a linked _IP_ADAPTER_ADDRESSES chain from python specs."""
    adapters = []
    for spec in specs:
        adapter = win_netinfo._IP_ADAPTER_ADDRESSES()
        adapter.IfIndex = spec.get("if_index", 0)
        adapter.AdapterName = spec.get("adapter_name", b"{00000000-0000-0000-0000-000000000000}")
        adapter.FriendlyName = spec.get("friendly_name", "")
        adapter.Description = spec.get("description", "")
        previous = None
        for sockaddr in spec.get("sockaddrs", []):
            unicast = win_netinfo._IP_ADAPTER_UNICAST_ADDRESS()
            unicast.Address.lpSockaddr = ctypes.pointer(sockaddr)
            keep_alive.extend([sockaddr, unicast])
            if previous is None:
                adapter.FirstUnicastAddress = ctypes.pointer(unicast)
            else:
                previous.Next = ctypes.pointer(unicast)
            previous = unicast
        keep_alive.append(adapter)
        adapters.append(adapter)
    for left, right in zip(adapters, adapters[1:]):
        left.Next = ctypes.pointer(right)
    return ctypes.pointer(adapters[0]) if adapters else None


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
        with patch("xray_fluent.win_netinfo.list_adapters", return_value=adapters):
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
        with patch("xray_fluent.win_netinfo.list_adapters", return_value=adapters):
            self.assertTrue(win_netinfo.adapter_has_ipv4("xftun0"))
            self.assertFalse(win_netinfo.adapter_has_ipv4("Ethernet"))
            self.assertFalse(win_netinfo.adapter_has_ipv4("missing"))

    def test_any_adapter_name_contains(self) -> None:
        adapters = [_adapter("xftun3", description="wintun")]
        with patch("xray_fluent.win_netinfo.list_adapters", return_value=adapters):
            self.assertTrue(win_netinfo.any_adapter_name_contains("xftun"))
            self.assertTrue(win_netinfo.any_adapter_name_contains("WINTUN"))
            self.assertFalse(win_netinfo.any_adapter_name_contains("tap-windows"))
            self.assertFalse(win_netinfo.any_adapter_name_contains(""))


class SingBoxTunProbeTests(unittest.TestCase):
    def test_fast_path_skips_powershell(self) -> None:
        with patch("xray_fluent.win_netinfo.is_available", return_value=True), patch(
            "xray_fluent.win_netinfo.adapter_has_ipv4", return_value=True
        ) as fast_mock, patch.object(
            SingBoxManager, "_tun_interface_has_ipv4"
        ) as powershell_mock:
            self.assertEqual(SingBoxManager._probe_tun_interface_has_ipv4("xftun0"), (True, True))

        fast_mock.assert_called_once_with("xftun0")
        powershell_mock.assert_not_called()

    def test_ctypes_failure_falls_back_to_powershell(self) -> None:
        with patch("xray_fluent.win_netinfo.is_available", return_value=True), patch(
            "xray_fluent.win_netinfo.adapter_has_ipv4",
            side_effect=win_netinfo.WinNetInfoError("boom"),
        ), patch.object(
            SingBoxManager, "_tun_interface_has_ipv4", return_value=True
        ) as powershell_mock:
            self.assertEqual(SingBoxManager._probe_tun_interface_has_ipv4("xftun0"), (True, False))

        powershell_mock.assert_called_once_with("xftun0")

    def test_unavailable_ctypes_uses_powershell(self) -> None:
        with patch("xray_fluent.win_netinfo.is_available", return_value=False), patch(
            "xray_fluent.win_netinfo.adapter_has_ipv4"
        ) as fast_mock, patch.object(
            SingBoxManager, "_tun_interface_has_ipv4", return_value=False
        ):
            self.assertEqual(SingBoxManager._probe_tun_interface_has_ipv4("xftun0"), (False, False))

        fast_mock.assert_not_called()

    def test_tun_gone_fast_path(self) -> None:
        with patch("xray_fluent.win_netinfo.is_available", return_value=True), patch(
            "xray_fluent.win_netinfo.any_adapter_name_contains", return_value=False
        ) as fast_mock, patch(
            "xray_fluent.engines.singbox.manager.run_text_pumped"
        ) as netsh_mock:
            self.assertEqual(SingBoxManager._probe_tun_adapter_gone(), (True, True))

        fast_mock.assert_called_once_with("xftun")
        netsh_mock.assert_not_called()

    def test_tun_gone_falls_back_to_netsh(self) -> None:
        completed = Mock(returncode=0, stdout=b"Ethernet\n", stderr=b"")
        with patch("xray_fluent.win_netinfo.is_available", return_value=True), patch(
            "xray_fluent.win_netinfo.any_adapter_name_contains",
            side_effect=win_netinfo.WinNetInfoError("boom"),
        ), patch(
            "xray_fluent.engines.singbox.manager.run_text_pumped", return_value=completed
        ) as netsh_mock:
            self.assertEqual(SingBoxManager._probe_tun_adapter_gone(), (True, False))

        netsh_mock.assert_called_once()

    def test_tun_gone_netsh_still_lists_adapter(self) -> None:
        completed = Mock(returncode=0, stdout=b"xftun0\n", stderr=b"")
        with patch("xray_fluent.win_netinfo.is_available", return_value=False), patch(
            "xray_fluent.engines.singbox.manager.run_text_pumped", return_value=completed
        ):
            self.assertEqual(SingBoxManager._probe_tun_adapter_gone(), (False, False))


class XrayTunRouteProbeTests(unittest.TestCase):
    def test_fast_path_builds_interface_from_adapter_info(self) -> None:
        adapter = _adapter("xftun0", if_index=33, ipv4=["172.19.0.1"], ipv6=["fd00::2"])
        with patch("xray_fluent.win_netinfo.is_available", return_value=True), patch(
            "xray_fluent.win_netinfo.find_adapter", return_value=adapter
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
        with patch("xray_fluent.win_netinfo.is_available", return_value=True), patch(
            "xray_fluent.win_netinfo.find_adapter", return_value=None
        ), patch.object(
            XrayTunRouteManager, "_read_tun_interface_powershell"
        ) as powershell_mock:
            interface, fast_probe = XrayTunRouteManager._read_tun_interface("xftun0")

        self.assertIsNone(interface)
        self.assertTrue(fast_probe)
        powershell_mock.assert_not_called()

    def test_adapter_without_ipv4_is_not_ready(self) -> None:
        adapter = _adapter("xftun0", if_index=33, ipv4=[], ipv6=["fd00::2"])
        with patch("xray_fluent.win_netinfo.is_available", return_value=True), patch(
            "xray_fluent.win_netinfo.find_adapter", return_value=adapter
        ):
            interface, fast_probe = XrayTunRouteManager._read_tun_interface("xftun0")

        self.assertIsNone(interface)
        self.assertTrue(fast_probe)

    def test_ctypes_failure_falls_back_to_powershell(self) -> None:
        sentinel = WindowsTunInterface(interface_index=5, ipv4_address="172.19.0.1", ipv6_address="")
        with patch("xray_fluent.win_netinfo.is_available", return_value=True), patch(
            "xray_fluent.win_netinfo.find_adapter",
            side_effect=win_netinfo.WinNetInfoError("boom"),
        ), patch.object(
            XrayTunRouteManager, "_read_tun_interface_powershell", return_value=sentinel
        ) as powershell_mock:
            interface, fast_probe = XrayTunRouteManager._read_tun_interface("xftun0")

        self.assertIs(interface, sentinel)
        self.assertFalse(fast_probe)
        powershell_mock.assert_called_once_with("xftun0")


if __name__ == "__main__":
    unittest.main()
