"""Dead-link detection in the auto-switch service.

A dead TCP server produces down_bps == 0, which the speed-drop path reads as
"user is idle" and can never act on. These tests pin the new trigger: the
metrics worker's TCP-ping verdict (link_alive) switches away from a node
whose pings keep failing while no payload traffic flows, while UDP/QUIC
protocols explicitly avoid that verdict.
"""

from __future__ import annotations

import ctypes
import sys
import unittest
from unittest.mock import patch

from xray_fluent.application import auto_switch_service
from xray_fluent.application.auto_switch_service import (
    AUTO_SWITCH_DEAD_LINK_SEC,
    AUTO_SWITCH_HYSTERIA_LOW_SEC,
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
        self._auto_switch_manual_hold = False
        self._auto_switch_warmup_until = 0.0
        self._transition_active = False
        self._transition_pending = False
        self._connecting = False
        self._disconnecting = False
        self.status = _Recorder()
        self.auto_switch_triggered = _Recorder()
        self.logs: list[str] = []
        self.selected: list[tuple] = []

    def _log(self, message: str) -> None:
        self.logs.append(message)

    @property
    def selected_node(self):
        return next(
            (node for node in self.state.nodes if node.id == self.state.selected_node_id),
            None,
        )

    def set_selected_node(self, node_id: str, *, reset_auto_switch: bool = True) -> None:
        self.selected.append((node_id, reset_auto_switch))


def _tick(
    controller,
    at: float,
    *,
    down_bps: float = 0.0,
    link_alive=None,
    traffic_valid: bool = True,
) -> None:
    with patch.object(auto_switch_service.time, "monotonic", return_value=at):
        check_auto_switch(
            controller,
            down_bps,
            link_alive,
            traffic_valid=traffic_valid,
        )


def _hysteria_controller() -> FakeController:
    controller = FakeController()
    from xray_fluent.link_parser import parse_single

    node = parse_single(
        "hysteria2://secret@udp.example:443/?obfs=salamander"
        "&obfs-password=cover&sni=udp.example#Hysteria"
    )
    node.id = "hysteria-active"
    controller.state.nodes[0] = node
    controller.state.selected_node_id = node.id
    return controller


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

    def test_hysteria_tcp_failure_never_uses_dead_link_fallback(self) -> None:
        controller = _hysteria_controller()

        _tick(controller, 100.0, link_alive=False)
        _tick(controller, 100.0 + AUTO_SWITCH_DEAD_LINK_SEC * 2, link_alive=False)

        self.assertEqual(controller.selected, [])
        self.assertEqual(controller._auto_switch_link_down_since, 0.0)

    def test_invalid_traffic_sample_is_not_treated_as_zero_speed(self) -> None:
        controller = FakeController()

        _tick(controller, 100.0, down_bps=0.0, link_alive=False, traffic_valid=False)
        _tick(
            controller,
            100.0 + AUTO_SWITCH_DEAD_LINK_SEC * 2,
            down_bps=0.0,
            link_alive=False,
            traffic_valid=False,
        )

        self.assertEqual(controller.selected, [])
        self.assertEqual(controller._auto_switch_link_down_since, 0.0)

    def test_hysteria_requires_confirmed_activity_and_sixty_second_degradation(self) -> None:
        controller = _hysteria_controller()
        controller.state.settings.auto_switch_delay_sec = 1
        controller.state.settings.auto_switch_cooldown_sec = 1
        base = 1000.0

        for offset in range(10):
            _tick(controller, base + offset, down_bps=200 * 1024.0, link_alive=False)
        self.assertTrue(controller._auto_switch_active_download)

        low_start = base + 10
        _tick(controller, low_start, down_bps=10 * 1024.0, link_alive=False)
        _tick(
            controller,
            low_start + AUTO_SWITCH_HYSTERIA_LOW_SEC - 1,
            down_bps=10 * 1024.0,
            link_alive=False,
        )
        self.assertEqual(controller.selected, [])

        _tick(
            controller,
            low_start + AUTO_SWITCH_HYSTERIA_LOW_SEC + 1,
            down_bps=10 * 1024.0,
            link_alive=False,
        )
        self.assertEqual(len(controller.selected), 1)

    def test_manual_hold_and_transition_guard_block_switch(self) -> None:
        controller = FakeController()
        controller._auto_switch_manual_hold = True
        _tick(controller, 100.0, link_alive=False)
        _tick(controller, 100.0 + AUTO_SWITCH_DEAD_LINK_SEC + 1, link_alive=False)
        self.assertEqual(controller.selected, [])

        controller._auto_switch_manual_hold = False
        controller._transition_active = True
        _tick(controller, 200.0, link_alive=False)
        _tick(controller, 200.0 + AUTO_SWITCH_DEAD_LINK_SEC + 1, link_alive=False)
        self.assertEqual(controller.selected, [])

    def test_startup_warmup_blocks_dead_link_until_runtime_is_observed(self) -> None:
        controller = FakeController()
        controller._auto_switch_warmup_until = 200.0

        _tick(controller, 100.0, link_alive=False)
        _tick(controller, 199.0, link_alive=False)
        self.assertEqual(controller.selected, [])

        _tick(controller, 200.0, link_alive=False)  # warmup has just ended
        _tick(controller, 200.0 + AUTO_SWITCH_DEAD_LINK_SEC + 1, link_alive=False)
        self.assertEqual(len(controller.selected), 1)


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

    def test_udp_transport_does_not_start_tcp_probe(self) -> None:
        worker_class = self._worker_class()
        worker = worker_class(
            "xray.exe",
            0,
            ping_host="udp.example.com",
            ping_port=443,
            transport_kind="udp",
        )

        self.assertFalse(worker.pings_active_node())
        worker.set_ping_target("tcp.example.com", 443, "tcp")
        self.assertTrue(worker.pings_active_node())

    def test_pings_active_node_requires_target(self) -> None:
        worker_class = self._worker_class()
        worker = worker_class("xray.exe", 0)
        self.assertFalse(worker.pings_active_node())


if __name__ == "__main__":
    unittest.main()
