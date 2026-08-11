from __future__ import annotations

import subprocess
import unittest
from unittest.mock import Mock, patch

from PyQt6.QtCore import QCoreApplication

from xray_fluent.engines.tun2socks import manager as tun2socks_manager
from xray_fluent.engines.tun2socks.manager import TUN_GW, Tun2SocksManager

_APP = QCoreApplication.instance() or QCoreApplication([])


def _completed(returncode: int, output: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=output.encode("utf-8"), stderr=b""
    )


_CLEANUP_CMDS = [
    ["route", "delete", "0.0.0.0", "mask", "128.0.0.0", TUN_GW],
    ["netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/1", "interface=5"],
    ["route", "delete", "10.0.0.0", "mask", "255.0.0.0", "192.168.1.1"],
]

_ADD_CMDS = [
    ["route", "add", "192.168.0.0", "mask", "255.255.0.0", "192.168.1.1", "metric", "1"],
    ["netsh", "interface", "ipv4", "add", "route", "0.0.0.0/1", "interface=5", f"nexthop={TUN_GW}", "metric=0"],
    ["netsh", "interface", "ipv6", "add", "route", "::/0", "interface=5", "metric=1"],
]


class RouteBatchingTests(unittest.TestCase):
    def test_batched_plan_uses_one_spawn_per_phase(self) -> None:
        manager = Tun2SocksManager()
        with patch(
            "xray_fluent.engines.tun2socks.manager.run_text_pumped",
            return_value=_completed(0),
        ) as run_mock:
            self.assertTrue(manager._apply_route_plan_batched(_CLEANUP_CMDS, _ADD_CMDS))

        self.assertEqual(run_mock.call_count, 2)
        cleanup_call = run_mock.call_args_list[0].args[0]
        add_call = run_mock.call_args_list[1].args[0]
        self.assertEqual(cleanup_call[:2], ["cmd", "/c"])
        self.assertEqual(add_call[:2], ["cmd", "/c"])
        # Best-effort deletes keep going on failure, adds stop at the first one.
        expected_cleanup = " & ".join(" ".join(cmd) for cmd in _CLEANUP_CMDS)
        expected_add = " && ".join(" ".join(cmd) for cmd in _ADD_CMDS)
        self.assertEqual(cleanup_call[2], expected_cleanup)
        self.assertEqual(add_call[2], expected_add)

    def test_failed_add_batch_returns_false(self) -> None:
        manager = Tun2SocksManager()
        with patch(
            "xray_fluent.engines.tun2socks.manager.run_text_pumped",
            side_effect=[_completed(0), _completed(1, "The object already exists")],
        ):
            self.assertFalse(manager._apply_route_plan_batched(_CLEANUP_CMDS, _ADD_CMDS))

    def test_spawn_error_returns_false(self) -> None:
        manager = Tun2SocksManager()
        with patch(
            "xray_fluent.engines.tun2socks.manager.run_text_pumped",
            side_effect=OSError("cmd not found"),
        ):
            self.assertFalse(manager._apply_route_plan_batched(_CLEANUP_CMDS, _ADD_CMDS))

    def test_sequential_fallback_preserves_per_command_semantics(self) -> None:
        manager = Tun2SocksManager()
        with patch(
            "xray_fluent.engines.tun2socks.manager.run_text_pumped",
            return_value=_completed(0),
        ) as run_mock:
            self.assertTrue(manager._apply_route_plan_sequential(_CLEANUP_CMDS, _ADD_CMDS))

        spawned = [call.args[0] for call in run_mock.call_args_list]
        self.assertEqual(spawned, _CLEANUP_CMDS + _ADD_CMDS)

    def test_sequential_add_failure_cleans_up_and_emits_error(self) -> None:
        manager = Tun2SocksManager()
        manager._cleanup_routes = Mock()
        errors: list[str] = []
        manager.error.connect(errors.append)

        def fake_run(command, **kwargs):
            if command[:2] == ["route", "add"]:
                return _completed(1, "route add failed")
            return _completed(0)

        with patch(
            "xray_fluent.engines.tun2socks.manager.run_text_pumped",
            side_effect=fake_run,
        ):
            self.assertFalse(manager._apply_route_plan_sequential(_CLEANUP_CMDS, _ADD_CMDS))

        manager._cleanup_routes.assert_called_once_with()
        self.assertEqual(len(errors), 1)
        self.assertIn("failed to configure route", errors[0])

    def test_delete_batch_success_uses_single_spawn(self) -> None:
        manager = Tun2SocksManager()
        with patch(
            "xray_fluent.engines.tun2socks.manager.run_text_pumped",
            return_value=_completed(0),
        ) as run_mock:
            self.assertTrue(manager._run_delete_commands_batched(_CLEANUP_CMDS))

        self.assertEqual(run_mock.call_count, 1)
        self.assertEqual(run_mock.call_args.args[0][:2], ["cmd", "/c"])

    def test_delete_batch_error_reports_fallback_needed(self) -> None:
        manager = Tun2SocksManager()
        with patch(
            "xray_fluent.engines.tun2socks.manager.run_text_pumped",
            side_effect=OSError("cmd not found"),
        ):
            self.assertFalse(manager._run_delete_commands_batched(_CLEANUP_CMDS))

    def test_delete_batch_with_no_commands_spawns_nothing(self) -> None:
        manager = Tun2SocksManager()
        with patch(
            "xray_fluent.engines.tun2socks.manager.run_text_pumped"
        ) as run_mock:
            self.assertTrue(manager._run_delete_commands_batched([]))

        run_mock.assert_not_called()


class SetupRoutesFallbackTests(unittest.TestCase):
    def test_setup_routes_falls_back_to_sequential_when_batch_fails(self) -> None:
        manager = Tun2SocksManager()
        errors: list[str] = []
        manager.error.connect(errors.append)

        netsh_interfaces = "Idx  Met  MTU   State      Name\n  5   25   1500  connected  ZapretKVN_TUN\n"
        route_print = "  0.0.0.0          0.0.0.0      192.168.1.1       10.0.0.5     25\n"
        spawned: list[list[str]] = []

        def fake_run(command, **kwargs):
            spawned.append(list(command))
            if command[0] == "netsh" and "show" in command:
                return _completed(0, netsh_interfaces)
            if command[:2] == ["cmd", "/c"] and command[2:] == ["route", "print", "0.0.0.0"]:
                return _completed(0, route_print)
            if command[:2] == ["cmd", "/c"] and len(command) == 3 and "&&" in command[2]:
                return _completed(1, "batch flavour not supported")
            return _completed(0)

        with patch("xray_fluent.engines.tun2socks.manager.os.name", "nt"), patch(
            "xray_fluent.engines.tun2socks.manager.run_text_pumped",
            side_effect=fake_run,
        ):
            self.assertTrue(manager._setup_routes())

        # The failed composite add batch must be retried per command.
        self.assertIn(
            ["netsh", "interface", "ipv4", "add", "route", "0.0.0.0/1", "interface=5", f"nexthop={TUN_GW}", "metric=0"],
            spawned,
        )
        self.assertIn(
            ["route", "add", "192.168.0.0", "mask", "255.255.0.0", "192.168.1.1", "metric", "1"],
            spawned,
        )
        self.assertEqual(errors, [])
        self.assertEqual(manager._tun_idx, "5")
        self.assertEqual(manager._orig_gateway, "192.168.1.1")


if __name__ == "__main__":
    unittest.main()
