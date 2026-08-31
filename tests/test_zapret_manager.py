from __future__ import annotations

import socket
import unittest
from unittest.mock import PropertyMock, patch

from xray_fluent.link_parser import parse_single
from xray_fluent.zapret_manager import ZapretManager


class ZapretManagerTests(unittest.TestCase):
    def test_pass_profile_is_inserted_before_original_profiles(self) -> None:
        args = [
            "--lua-init=@lua/zapret-lib.lua",
            "--wf-udp-out=443",
            "--filter-udp=443",
            "--new",
            "--filter-tcp=443",
            "--ipset-exclude-ip=192.0.2.0/24",
            "--new=catch-all",
            "--filter-udp=*",
        ]

        updated = ZapretManager._with_proxy_pass_profile(args, {"203.0.113.7", "2001:db8::7"})

        self.assertEqual(
            updated,
            [
                "--lua-init=@lua/zapret-lib.lua",
                "--wf-udp-out=443",
                "--filter-udp=*",
                "--ipset-ip=203.0.113.7,2001:db8::7",
                "--lua-desync=pass",
                "--new",
                "--filter-udp=443",
                "--new",
                "--filter-tcp=443",
                "--ipset-exclude-ip=192.0.2.0/24",
                "--new=catch-all",
                "--filter-udp=*",
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
        node = parse_single("hy2://secret@203.0.113.7:443/?insecure=1&pinSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

        with (
            patch.object(ZapretManager, "running", new_callable=PropertyMock, return_value=True),
            patch.object(manager, "_restart_for_proxy_protection") as restart,
            patch.object(manager, "_arm_proxy_protection_timeout"),
        ):
            manager.protect_proxy_node(node)

        restart.assert_called_once_with("Default")

    def test_running_zapret_is_not_ready_until_replacement_starts(self) -> None:
        manager = ZapretManager()
        manager._current_preset = "Default"
        node = parse_single("hy2://secret@203.0.113.7:443/?insecure=1&pinSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manager.cache_proxy_resolution("203.0.113.7", {"203.0.113.7"})
        ready: list[int] = []
        manager.proxy_protection_ready.connect(ready.append)

        with (
            patch.object(ZapretManager, "running", new_callable=PropertyMock, return_value=True),
            patch.object(manager, "_restart_for_proxy_protection") as restart,
            patch.object(manager, "_arm_proxy_protection_timeout"),
            patch.object(manager._health_timer, "start"),
        ):
            self.assertTrue(manager.apply_cached_proxy_node(node))
            generation = manager.proxy_protection_generation
            self.assertGreater(generation, 0)
            self.assertFalse(manager.proxy_protection_is_ready(node))
            restart.assert_called_once_with("Default")

            manager._on_started()

        self.assertTrue(manager.proxy_protection_is_ready(node))
        self.assertEqual(ready, [generation])

    def test_stopped_zapret_is_ready_noop_without_restart(self) -> None:
        manager = ZapretManager()
        node = parse_single("hy2://secret@203.0.113.7:443/?insecure=1&pinSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manager.cache_proxy_resolution("203.0.113.7", {"203.0.113.7"})

        with (
            patch.object(ZapretManager, "running", new_callable=PropertyMock, return_value=False),
            patch.object(manager, "_restart_for_proxy_protection") as restart,
        ):
            self.assertTrue(manager.apply_cached_proxy_node(node))
            self.assertTrue(manager.proxy_protection_is_ready(node))

        restart.assert_not_called()

    def test_proxy_protection_timeout_emits_failure_generation(self) -> None:
        manager = ZapretManager()
        manager._current_preset = "Default"
        node = parse_single("hy2://secret@203.0.113.7:443/?insecure=1&pinSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manager.cache_proxy_resolution("203.0.113.7", {"203.0.113.7"})
        failed: list[tuple[int, str]] = []
        manager.proxy_protection_failed.connect(lambda generation, reason: failed.append((generation, reason)))

        with (
            patch.object(ZapretManager, "running", new_callable=PropertyMock, return_value=True),
            patch.object(manager, "_restart_for_proxy_protection"),
            patch.object(manager, "_arm_proxy_protection_timeout"),
        ):
            self.assertTrue(manager.apply_cached_proxy_node(node))
            generation = manager.proxy_protection_generation
            self.assertFalse(manager.proxy_protection_is_ready(node))

            manager._on_proxy_protection_timeout(generation)

            self.assertFalse(manager.proxy_protection_is_ready(node))

        self.assertEqual(failed, [(generation, "timeout")])

    def test_second_endpoint_during_process_start_remains_pending(self) -> None:
        manager = ZapretManager()
        manager._current_preset = "Default"
        first = parse_single("hy2://secret@203.0.113.7:443/?insecure=1&pinSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        second = parse_single("hy2://secret@203.0.113.8:443/?insecure=1&pinSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manager.cache_proxy_resolution("203.0.113.7", {"203.0.113.7"})
        manager.cache_proxy_resolution("203.0.113.8", {"203.0.113.8"})

        with (
            patch.object(ZapretManager, "running", new_callable=PropertyMock, return_value=True),
            patch.object(manager, "_restart_for_proxy_protection"),
            patch.object(manager, "_arm_proxy_protection_timeout"),
        ):
            self.assertTrue(manager.apply_cached_proxy_node(first))
            first_generation = manager.proxy_protection_generation

        # Model the QProcess.Starting gap: start() consumed the restart marker,
        # the old process is gone, and the replacement has not emitted started.
        manager._pending_restart_preset = ""
        with (
            patch.object(ZapretManager, "running", new_callable=PropertyMock, return_value=False),
            patch.object(manager, "_arm_proxy_protection_timeout"),
        ):
            self.assertTrue(manager.apply_cached_proxy_node(second))
            second_generation = manager.proxy_protection_generation
            self.assertGreater(second_generation, first_generation)
            self.assertFalse(manager.proxy_protection_is_ready(second))
            self.assertEqual(
                manager._proxy_protection_pending_generation,
                second_generation,
            )

    def test_cached_endpoint_is_applied_without_dns(self) -> None:
        manager = ZapretManager()
        node = parse_single("hy2://secret@proxy.example.com:443/?insecure=1&pinSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manager.cache_proxy_resolution("proxy.example.com", {"203.0.113.7"})

        with patch.object(manager, "_resolve_server_ips") as resolve:
            applied = manager.apply_cached_proxy_node(node)

        self.assertTrue(applied)
        resolve.assert_not_called()
        self.assertEqual(manager._protected_proxy_ips, {"203.0.113.7"})

    def test_uncached_endpoint_never_falls_back_to_gui_thread_dns(self) -> None:
        manager = ZapretManager()
        node = parse_single("hy2://secret@proxy.example.com:443/?insecure=1&pinSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

        with patch.object(manager, "_resolve_server_ips") as resolve:
            applied = manager.apply_cached_proxy_node(node)

        self.assertFalse(applied)
        resolve.assert_not_called()

    def test_new_hysteria2_node_replaces_previous_pass_endpoint(self) -> None:
        manager = ZapretManager()
        manager._protected_proxy_ips = {"203.0.113.7"}
        node = parse_single("hy2://secret@203.0.113.8:443/?insecure=1&pinSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

        manager.protect_proxy_node(node)

        self.assertEqual(manager._protected_proxy_ips, {"203.0.113.8"})

    def test_tcp_proxy_node_clears_previous_pass_profile(self) -> None:
        manager = ZapretManager()
        manager._protected_proxy_ips = {"203.0.113.7"}
        node = parse_single("vless://00000000-0000-4000-8000-000000000001@example.com:443")

        with patch.object(manager, "_resolve_server_ips") as resolve:
            self.assertEqual(manager.protect_proxy_node(node), set())

        resolve.assert_not_called()
        self.assertEqual(manager._protected_proxy_ips, set())


if __name__ == "__main__":
    unittest.main()
