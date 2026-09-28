"""winws2 command line and the revisioned process manager."""

from __future__ import annotations

import socket
import unittest
from unittest.mock import patch

from PyQt6.QtCore import QCoreApplication

from xray_fluent.engines.zapret.blobs import lua_init_arguments
from xray_fluent.engines.zapret.command import SERVER_PROFILE_NAME, ServerRule, build_arguments
from xray_fluent.engines.zapret.endpoint import (
    ResolvedEndpoint,
    ServerEndpoint,
    resolve_endpoint,
    resolve_host,
)
from xray_fluent.engines.zapret.manager import ZapretManager, ZapretPlan
from xray_fluent.engines.zapret.strategies import load_strategy_catalog, pass_strategy

_APP = QCoreApplication.instance() or QCoreApplication([])


def _rule(kind: str, ports: tuple[str, ...], ips: tuple[str, ...], strategy) -> ServerRule:
    return ServerRule(ResolvedEndpoint(ServerEndpoint(kind, ("one.example",), ports), ips), strategy)


class ServerRuleArgumentTests(unittest.TestCase):
    def test_no_rule_leaves_the_preset_untouched(self) -> None:
        args = ["--wf-tcp-out=443", "--filter-tcp=443", "--lua-desync=pass"]
        self.assertEqual(build_arguments(args, None), args)

    def test_rule_is_the_first_profile_and_does_not_mutate_the_preset(self) -> None:
        original = ["--wf-tcp-out=80", "--filter-udp=443", "--lua-desync=pass"]
        rule = _rule(
            "tcp", ("443",), ("2001:0db8::7", "203.0.113.7", "203.0.113.7"),
            load_strategy_catalog("tcp")["alt9"],
        )

        updated = build_arguments(original, rule)

        self.assertEqual(original, ["--wf-tcp-out=80", "--filter-udp=443", "--lua-desync=pass"])
        self.assertIn("--wf-tcp-out=80,443", updated)
        name_index = updated.index(SERVER_PROFILE_NAME)
        self.assertLess(name_index, updated.index("--filter-udp=443"))
        self.assertEqual(updated[name_index + 1], "--filter-tcp=443")
        self.assertEqual(updated[name_index + 2], "--ipset-ip=203.0.113.7,2001:db8::7")
        self.assertEqual(updated[name_index + 3], rule.strategy.args[0])
        self.assertEqual(updated[name_index + 3 + len(rule.strategy.args)], "--new")

    def test_pass_rule_is_inserted_before_original_profiles(self) -> None:
        args = [
            "--lua-init=@lua/zapret-lib.lua",
            "--wf-udp-out=443",
            "--filter-udp=443",
            "--new",
            "--filter-tcp=443",
            "--new=catch-all",
            "--filter-udp=*",
        ]
        rule = _rule("quic", ("8443",), ("203.0.113.7",), pass_strategy("udp"))

        self.assertEqual(
            build_arguments(args, rule),
            [
                "--lua-init=@lua/zapret-antidpi.lua",
                "--lua-init=@lua/zapret-lib.lua",
                "--wf-udp-out=443,8443",
                SERVER_PROFILE_NAME,
                "--filter-udp=8443",
                "--ipset-ip=203.0.113.7",
                "--lua-desync=pass",
                "--new",
                "--filter-udp=443",
                "--new",
                "--filter-tcp=443",
                "--new=catch-all",
                "--filter-udp=*",
            ],
        )

    def test_tcp_and_udp_capture_filters_are_not_mixed(self) -> None:
        args = ["--wf-tcp-out=443", "--filter-tcp=443", "--lua-desync=pass"]
        rule = _rule("quic", ("8443",), ("203.0.113.8",), load_strategy_catalog("udp")["general_bf_32"])
        updated = build_arguments(args, rule)
        self.assertIn("--wf-tcp-out=443", updated)
        self.assertIn("--wf-udp-out=8443", updated)
        self.assertIn("--filter-udp=8443", updated)
        self.assertIn("--blob=quic_google:@bin/quic_initial_www_google_com.bin", updated)

    def test_repeated_capture_filters_keep_every_original_port(self) -> None:
        args = ["--wf-tcp-out=80", "--wf-tcp-out=443,8080", "--filter-tcp=80", "--lua-desync=pass"]
        rule = _rule("tcp", ("8443",), ("203.0.113.8",), load_strategy_catalog("tcp")["alt9"])
        captures = [arg for arg in build_arguments(args, rule) if arg.startswith("--wf-tcp-out=")]
        self.assertEqual(captures, ["--wf-tcp-out=80,443,8080,8443"])

    def test_wildcard_capture_filter_stays_a_wildcard(self) -> None:
        args = ["--wf-udp-out=*", "--wf-udp-out=443", "--filter-udp=443", "--lua-desync=pass"]
        rule = _rule("wireguard", ("51820",), ("203.0.113.8",), pass_strategy("udp"))
        captures = [arg for arg in build_arguments(args, rule) if arg.startswith("--wf-udp-out=")]
        self.assertEqual(captures, ["--wf-udp-out=*"])

    def test_extension_lua_is_injected_after_the_core_libraries(self) -> None:
        rule = _rule("tcp", ("443",), ("203.0.113.8",), load_strategy_catalog("tcp")["fakemultisplit_google_ultra"])
        lua = [arg for arg in build_arguments([], rule) if arg.startswith("--lua-init=")]
        self.assertEqual(
            lua,
            [
                "--lua-init=@lua/zapret-lib.lua",
                "--lua-init=@lua/zapret-antidpi.lua",
                "--lua-init=@lua/fakemultisplit.lua",
            ],
        )

    def test_core_only_strategy_gets_no_extension_lua(self) -> None:
        rule = _rule("tcp", ("443",), ("203.0.113.8",), load_strategy_catalog("tcp")["multisplit_pos1"])
        lua = [arg for arg in build_arguments([], rule) if arg.startswith("--lua-init=")]
        self.assertEqual(len(lua), 2)

    def test_every_catalog_strategy_gets_its_lua_and_blobs(self) -> None:
        for transport, kind in (("tcp", "tcp"), ("udp", "quic")):
            for entry in load_strategy_catalog(transport).values():
                with self.subTest(transport=transport, strategy=entry.strategy_id):
                    updated = build_arguments([], _rule(kind, ("443",), ("203.0.113.8",), entry))
                    core = updated.index("--lua-init=@lua/zapret-antidpi.lua")
                    for extension in lua_init_arguments(entry.args):
                        self.assertGreater(updated.index(extension), core)
                    for dependency in entry.blob_dependencies:
                        self.assertTrue(
                            any(arg.startswith(f"--blob={dependency}:") for arg in updated), dependency,
                        )


class ResolutionTests(unittest.TestCase):
    def test_host_resolution_normalizes_and_deduplicates(self) -> None:
        answers = [
            (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("203.0.113.7", 0)),
            (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("203.0.113.7", 0)),
            (socket.AF_INET6, socket.SOCK_DGRAM, 17, "", ("2001:0db8::7", 0, 0, 0)),
        ]
        with (
            patch("xray_fluent.engines.zapret.endpoint.socket.getaddrinfo", return_value=answers),
            patch("xray_fluent.engines.zapret.endpoint.register_server_aliases") as aliases,
        ):
            resolved = resolve_host("proxy.example.com")
        self.assertEqual(resolved, {"203.0.113.7", "2001:db8::7"})
        # Log redaction learns the IPs before anything can print them.
        aliases.assert_called_once_with("proxy.example.com", resolved)

    def test_literal_ip_needs_no_dns(self) -> None:
        with patch("xray_fluent.engines.zapret.endpoint.socket.getaddrinfo") as lookup:
            self.assertEqual(resolve_host("[2001:db8::7]"), {"2001:db8::7"})
        lookup.assert_not_called()

    def test_every_host_is_resolved_afresh(self) -> None:
        endpoint = ServerEndpoint("wireguard", ("one.example", "two.example"), ("51820",))
        with patch(
            "xray_fluent.engines.zapret.endpoint.resolve_host",
            side_effect=({"203.0.113.1"}, {"2001:db8::2", "203.0.113.1"}),
        ) as resolver:
            result = resolve_endpoint(endpoint)
        self.assertEqual(resolver.call_count, 2)
        self.assertEqual(result.ips, ("203.0.113.1", "2001:db8::2"))

    def test_no_address_is_an_error(self) -> None:
        endpoint = ServerEndpoint("tcp", ("one.example",), ("443",))
        with patch("xray_fluent.engines.zapret.endpoint.resolve_host", return_value=set()):
            with self.assertRaises(OSError):
                resolve_endpoint(endpoint)


class _NoLaunchManager(ZapretManager):
    """Records launches instead of running the step generator."""

    def __init__(self) -> None:
        super().__init__()
        self.launches: list[tuple[ZapretPlan, int]] = []

    def _start_runner(self, plan: ZapretPlan, revision: int) -> None:
        self.launches.append((plan, revision))


class ManagerRevisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manager = _NoLaunchManager()
        self.applied: list[int] = []
        self.failed: list[tuple[int, str]] = []
        self.manager.plan_applied.connect(self.applied.append)
        self.manager.plan_failed.connect(lambda revision, reason: self.failed.append((revision, reason)))

    def test_apply_is_pending_until_its_own_process_starts(self) -> None:
        revision = self.manager.apply(ZapretPlan("Default"))
        self.assertTrue(self.manager.pending)
        self.assertTrue(self.manager.active)
        self.manager._on_started(revision)
        self.assertFalse(self.manager.pending)
        self.assertEqual(self.applied, [revision])

    def test_late_start_of_an_older_revision_proves_nothing(self) -> None:
        first = self.manager.apply(ZapretPlan("Default"))
        second = self.manager.apply(ZapretPlan("Default", _rule("tcp", ("443",), ("203.0.113.7",), pass_strategy("tcp"))))
        self.assertGreater(second, first)
        self.manager._on_started(first)
        self.assertEqual(self.applied, [])
        self.assertTrue(self.manager.pending)
        self.manager._on_started(second)
        self.assertEqual(self.applied, [second])

    def test_same_plan_again_is_free(self) -> None:
        plan = ZapretPlan("Default")
        revision = self.manager.apply(plan)
        self.assertEqual(self.manager.apply(plan), revision)
        self.assertEqual(len(self.manager.launches), 1)

    def test_timeout_fails_only_the_pending_revision(self) -> None:
        revision = self.manager.apply(ZapretPlan("Default"))
        self.manager._on_apply_timeout(revision - 1)
        self.assertEqual(self.failed, [])
        self.manager._on_apply_timeout(revision)
        self.assertEqual(self.failed, [(revision, "timeout")])
        self.assertFalse(self.manager.pending)

    def test_stop_fails_a_pending_request_instead_of_marking_it_ready(self) -> None:
        stopped: list[bool] = []
        self.manager.stopped.connect(lambda: stopped.append(True))
        revision = self.manager.apply(ZapretPlan("Default"))
        self.manager.stop()
        self.assertEqual(self.applied, [])
        self.assertEqual(self.failed, [(revision, "stopped")])
        self.assertIsNone(self.manager.plan)
        self.assertFalse(self.manager.active)
        self.assertEqual(stopped, [True])

    def test_stop_with_nothing_running_is_silent(self) -> None:
        stopped: list[bool] = []
        self.manager.stopped.connect(lambda: stopped.append(True))
        self.manager.stop()
        self.assertEqual(stopped, [])

    def test_launch_failure_reports_error_and_stop(self) -> None:
        errors: list[str] = []
        self.manager.error.connect(errors.append)
        revision = self.manager.apply(ZapretPlan("Default"))
        self.manager._fail("winws2.exe не найден", "missing_executable")
        self.assertEqual(errors, ["winws2.exe не найден"])
        self.assertEqual(self.failed, [(revision, "missing_executable")])
        self.assertIsNone(self.manager.plan)

    def test_clean_exit_is_a_stop_not_an_error(self) -> None:
        errors: list[str] = []
        self.manager.error.connect(errors.append)
        self.manager.apply(ZapretPlan("Default"))
        self.manager._fail("", "exited")
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
