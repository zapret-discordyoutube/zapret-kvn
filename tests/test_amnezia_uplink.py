from __future__ import annotations

import types
import unittest
from unittest.mock import patch

from PyQt6.QtCore import QCoreApplication

from xray_fluent.engines.amnezia import manager
from xray_fluent.platform.windows import win_netinfo

_APP = QCoreApplication.instance() or QCoreApplication([])


class PhysicalNetworkTests(unittest.TestCase):
    def test_off_windows_returns_no_bind(self) -> None:
        # posix host: nothing to bind, the core no-ops on index 0 off Windows.
        with patch.object(manager.os, "name", "posix"):
            self.assertEqual(manager.physical_network(), {"interface_index": 0, "bootstrap_dns": []})

    def test_uses_winapi_resolver(self) -> None:
        with patch.object(manager.os, "name", "nt"), patch.object(
            win_netinfo, "resolve_physical_uplink", return_value=(7, ["192.168.1.1"])
        ):
            self.assertEqual(
                manager.physical_network(),
                {"interface_index": 7, "bootstrap_dns": ["192.168.1.1"]},
            )

    def test_retries_transient_miss_then_raises(self) -> None:
        sleeps: list[float] = []
        with patch.object(manager.os, "name", "nt"), patch.object(
            win_netinfo, "resolve_physical_uplink", return_value=None
        ) as resolve, patch.object(manager, "sleep_with_events", side_effect=sleeps.append):
            with self.assertRaises(OSError):
                manager.physical_network(attempts=3, retry_delay=0.01)
        self.assertEqual(resolve.call_count, 3)
        self.assertEqual(len(sleeps), 2)  # no sleep after the final attempt

    def test_recovers_on_a_later_attempt(self) -> None:
        with patch.object(manager.os, "name", "nt"), patch.object(
            win_netinfo, "resolve_physical_uplink", side_effect=[None, (5, [])]
        ), patch.object(manager, "sleep_with_events"):
            self.assertEqual(manager.physical_network(attempts=3), {"interface_index": 5, "bootstrap_dns": []})

    def test_winapi_unavailable_is_retried_and_reported(self) -> None:
        with patch.object(manager.os, "name", "nt"), patch.object(
            win_netinfo, "resolve_physical_uplink", side_effect=win_netinfo.WinNetInfoError("no iphlpapi")
        ), patch.object(manager, "sleep_with_events"):
            with self.assertRaises(OSError) as ctx:
                manager.physical_network(attempts=2, retry_delay=0.01)
        self.assertIn("no iphlpapi", str(ctx.exception))


class NetworkChangeGuardTests(unittest.TestCase):
    """The tunnel's own address must never be misread as a network change."""

    @staticmethod
    def _controller_with_plan(addresses):
        from xray_fluent.application.controller import AppController

        sidecar = types.SimpleNamespace(config={"endpoint": {"address": addresses}})
        plan = types.SimpleNamespace(amnezia_sidecar=sidecar)
        stub = types.SimpleNamespace(_active_singbox_plan=plan)
        return AppController._active_tunnel_addresses(stub)

    def test_extracts_tunnel_ips_without_cidr(self) -> None:
        self.assertEqual(
            self._controller_with_plan(["10.9.0.49/32", "fd00::2/128"]),
            {"10.9.0.49", "fd00::2"},
        )

    def test_no_plan_yields_empty_set(self) -> None:
        from xray_fluent.application.controller import AppController

        self.assertEqual(AppController._active_tunnel_addresses(types.SimpleNamespace()), set())

    def test_non_amnezia_plan_yields_empty_set(self) -> None:
        from xray_fluent.application.controller import AppController

        plan = types.SimpleNamespace(amnezia_sidecar=None)
        stub = types.SimpleNamespace(_active_singbox_plan=plan)
        self.assertEqual(AppController._active_tunnel_addresses(stub), set())


if __name__ == "__main__":
    unittest.main()
