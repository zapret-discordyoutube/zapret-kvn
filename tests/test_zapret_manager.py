from __future__ import annotations

import socket
import unittest
from unittest.mock import PropertyMock, patch

from xray_fluent.link_parser import parse_single
from xray_fluent.zapret_manager import ZapretManager


class ZapretManagerTests(unittest.TestCase):
    def test_ip_exclusion_is_added_to_every_profile(self) -> None:
        args = [
            "--wf-udp-out=443",
            "--filter-udp=443",
            "--new",
            "--filter-tcp=443",
            "--ipset-exclude-ip=192.0.2.0/24",
            "--new=catch-all",
            "--filter-udp=*",
        ]

        updated = ZapretManager._with_ip_exclusions(args, {"203.0.113.7", "2001:db8::7"})

        self.assertEqual(
            [arg for arg in updated if arg.startswith("--ipset-exclude-ip=")],
            [
                "--ipset-exclude-ip=203.0.113.7,2001:db8::7",
                "--ipset-exclude-ip=192.0.2.0/24,203.0.113.7,2001:db8::7",
                "--ipset-exclude-ip=203.0.113.7,2001:db8::7",
            ],
        )

    def test_server_resolution_normalizes_and_deduplicates_addresses(self) -> None:
        answers = [
            (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("203.0.113.7", 0)),
            (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("203.0.113.7", 0)),
            (socket.AF_INET6, socket.SOCK_DGRAM, 17, "", ("2001:0db8::7", 0, 0, 0)),
        ]
        with patch("xray_fluent.zapret_manager.socket.getaddrinfo", return_value=answers):
            resolved = ZapretManager._resolve_server_ips("proxy.example.com")

        self.assertEqual(resolved, {"203.0.113.7", "2001:db8::7"})

    def test_hysteria2_node_protects_resolved_endpoint(self) -> None:
        manager = ZapretManager()
        node = parse_single(
            "hysteria2://secret@203.0.113.7:443/"
            "?obfs=salamander&obfs-password=cover&sni=cdn.example.com"
        )

        resolved = manager.protect_proxy_node(node)

        self.assertEqual(resolved, {"203.0.113.7"})
        self.assertEqual(manager._protected_proxy_ips, {"203.0.113.7"})

    def test_running_zapret_restarts_after_new_udp_proxy_endpoint(self) -> None:
        manager = ZapretManager()
        manager._current_preset = "Default"
        node = parse_single("hy2://secret@203.0.113.7:443/?insecure=1")

        with (
            patch.object(ZapretManager, "running", new_callable=PropertyMock, return_value=True),
            patch.object(manager, "start") as start,
        ):
            manager.protect_proxy_node(node)

        start.assert_called_once_with("Default")

    def test_tcp_proxy_node_is_not_excluded(self) -> None:
        manager = ZapretManager()
        node = parse_single("vless://00000000-0000-4000-8000-000000000001@example.com:443")

        with patch.object(manager, "_resolve_server_ips") as resolve:
            self.assertEqual(manager.protect_proxy_node(node), set())

        resolve.assert_not_called()
        self.assertEqual(manager._protected_proxy_ips, set())


if __name__ == "__main__":
    unittest.main()
