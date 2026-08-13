"""Dead-link detection in the auto-switch service.

A dead server produces down_bps == 0, which the speed-drop path reads as
"user is idle" and can never act on. These tests pin the new trigger: the
metrics worker's TCP-ping verdict (link_alive) switches away from a node
whose pings keep failing while no payload traffic flows.
"""

from __future__ import annotations

import ctypes
import sys
import unittest
from unittest.mock import patch

from xray_fluent.application import auto_switch_service
from xray_fluent.application.auto_switch_service import (
    AUTO_SWITCH_DEAD_LINK_SEC,
    check_auto_switch,
)
from xray_fluent.models import AppSettings, Node


class _Recorder:
    def __init__(self):
        self.calls: list = []

    def emit(self, *args) -> None:
        self.calls.append(args)


class _State:
    def __init__(self, nodes):
        self.settings = AppSettings()
        self.nodes = nodes
        self.selected_node_id = nodes[0].id if nodes else ""


class FakeController:
    """Bare attribute bag: the service only touches state and signals."""

    def __init__(self, node_count: int = 3):
        nodes = [
            Node(id=f"n{i}", name=f"node-{i}", server=f"s{i}.example.com", port=443, scheme="vless")
            for i in range(node_count)
        ]
        self.state = _State(nodes)
        self.connected = True
        self._switching = False
        self._reconnecting = False
        self._auto_switch_low_since = 0.0
        self._auto_switch_last_switch = 0.0
        self._auto_switch_high_ticks = 0
        self._auto_switch_active_download = False
        self._auto_switch_cycle_attempts = 0
        self._auto_switch_exhausted = False
        self._auto_switch_transitioning = False
        self._auto_switch_link_down_since = 0.0
        self.status = _Recorder()
        self.auto_switch_triggered = _Recorder()
        self.logs: list[str] = []
        self.selected: list[tuple] = []

    def _log(self, message: str) -> None:
        self.logs.append(message)

    def set_selected_node(self, node_id: str, *, reset_auto_switch: bool = True) -> None:
        self.selected.append((node_id, reset_auto_switch))


def _tick(controller, at: float, *, down_bps: float = 0.0, link_alive=None) -> None:
    with patch.object(auto_switch_service.time, "monotonic", return_value=at):
        check_auto_switch(controller, down_bps, link_alive)


class DeadLinkTriggerTests(unittest.TestCase):
    def test_sustained_ping_failures_trigger_switch(self) -> None:
        controller = FakeController()
        _tick(controller, 100.0, link_alive=False)          # arm
        _tick(controller, 100.0 + AUTO_SWITCH_DEAD_LINK_SEC - 1, link_alive=False)
        self.assertEqual(controller.selected, [])            # not yet
        _tick(controller, 100.0 + AUTO_SWITCH_DEAD_LINK_SEC + 1, link_alive=False)
        self.assertEqual(len(controller.selected), 1)
        node_id, reset = controller.selected[0]
        self.assertNotEqual(node_id, controller.state.selected_node_id)
        self.assertFalse(reset)                              # анти-дребезг сохранён
        self.assertTrue(any("unreachable" in line for line in controller.logs))
        self.assertTrue(controller._auto_switch_transitioning)

    def test_successful_ping_resets_the_window(self) -> None:
        controller = FakeController()
        _tick(controller, 100.0, link_alive=False)
        _tick(controller, 110.0, link_alive=True)            # link recovered
        _tick(controller, 100.0 + AUTO_SWITCH_DEAD_LINK_SEC + 5, link_alive=False)
        # Window restarted at the last failure, so no switch yet.
        self.assertEqual(controller.selected, [])

    def test_traffic_flow_blocks_dead_verdict(self) -> None:
        # Ping fails but payload bytes still arrive: not a dead server.
        controller = FakeController()
        _tick(controller, 100.0, down_bps=500 * 1024.0, link_alive=False)
        _tick(controller, 200.0, down_bps=500 * 1024.0, link_alive=False)
        self.assertEqual(controller.selected, [])
        self.assertEqual(controller._auto_switch_link_down_since, 0.0)

    def test_no_ping_configured_never_triggers(self) -> None:
        controller = FakeController()
        _tick(controller, 100.0, link_alive=None)
        _tick(controller, 100.0 + AUTO_SWITCH_DEAD_LINK_SEC * 10, link_alive=None)
        self.assertEqual(controller.selected, [])

    def test_cooldown_defers_the_switch(self) -> None:
        controller = FakeController()
        controller._auto_switch_last_switch = 95.0           # just switched
        _tick(controller, 100.0, link_alive=False)
        at = 100.0 + AUTO_SWITCH_DEAD_LINK_SEC + 1
        _tick(controller, at, link_alive=False)
        self.assertEqual(controller.selected, [])            # cooldown holds
        cooled = 95.0 + controller.state.settings.auto_switch_cooldown_sec + 1
        _tick(controller, max(at, cooled), link_alive=False)
        self.assertEqual(len(controller.selected), 1)

    def test_exhaustion_applies_to_dead_link_path(self) -> None:
        controller = FakeController(node_count=2)
        controller._auto_switch_cycle_attempts = 1           # max_attempts == 1
        _tick(controller, 100.0, link_alive=False)
        _tick(controller, 100.0 + AUTO_SWITCH_DEAD_LINK_SEC + 1, link_alive=False)
        self.assertEqual(controller.selected, [])
        self.assertTrue(controller._auto_switch_exhausted)
        self.assertEqual(len(controller.status.calls), 1)

    def test_disabled_setting_wins(self) -> None:
        controller = FakeController()
        controller.state.settings.auto_switch_enabled = False
        _tick(controller, 100.0, link_alive=False)
        _tick(controller, 100.0 + AUTO_SWITCH_DEAD_LINK_SEC + 1, link_alive=False)
        self.assertEqual(controller.selected, [])

    def test_speed_drop_path_still_works(self) -> None:
        controller = FakeController()
        # Arm active download: 10 ticks above threshold.
        for i in range(10):
            _tick(controller, 100.0 + i, down_bps=200 * 1024.0, link_alive=True)
        self.assertTrue(controller._auto_switch_active_download)
        # Sustained narrow-band slowdown for delay_sec.
        _tick(controller, 111.0, down_bps=10 * 1024.0, link_alive=True)
        delay = controller.state.settings.auto_switch_delay_sec
        _tick(controller, 111.0 + delay + 1, down_bps=10 * 1024.0, link_alive=True)
        self.assertEqual(len(controller.selected), 1)
        self.assertTrue(any("KB/s" in line for line in controller.logs))


class MetricsWorkerPingTargetTests(unittest.TestCase):
    """set_ping_target re-points the surviving worker after a hot-switch."""

    def _worker_class(self):
        if sys.platform == "win32":
            from xray_fluent.live_metrics_worker import LiveMetricsWorker
            return LiveMetricsWorker
        original_windll = getattr(ctypes, "windll", None)

        class _AnyLib:
            def __getattr__(self, name):
                lib = _AnyLib()
                setattr(self, name, lib)
                return lib

            def __call__(self, *args, **kwargs):
                return 0

        ctypes.windll = _AnyLib()  # type: ignore[attr-defined]
        try:
            from xray_fluent.live_metrics_worker import LiveMetricsWorker
        finally:
            if original_windll is None:
                del ctypes.windll
            else:
                ctypes.windll = original_windll  # type: ignore[attr-defined]
        return LiveMetricsWorker

    def test_set_ping_target_repoints_and_forces_probe(self) -> None:
        worker_class = self._worker_class()
        worker = worker_class("xray.exe", 0, ping_host="old.example.com", ping_port=443)
        worker._last_ping_ms = 42
        worker._last_ping_ts = 1234.5
        worker.set_ping_target("new.example.com", 8443)
        self.assertEqual(worker._ping_host, "new.example.com")
        self.assertEqual(worker._ping_port, 8443)
        self.assertIsNone(worker._last_ping_ms)     # stale verdict cleared
        self.assertEqual(worker._last_ping_ts, 0.0)  # next tick probes now
        self.assertTrue(worker.pings_active_node())

    def test_pings_active_node_requires_target(self) -> None:
        worker_class = self._worker_class()
        worker = worker_class("xray.exe", 0)
        self.assertFalse(worker.pings_active_node())


if __name__ == "__main__":
    unittest.main()
