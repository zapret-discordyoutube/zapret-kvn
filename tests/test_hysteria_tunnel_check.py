"""A transport error in the log of a working tunnel is evidence, not a verdict.

Regression for 0.8.4 (2026-10-01): one "timeout: no recent network activity"
line — an idle QUIC session the official client re-established within the same
second — started recovery, replaced a healthy server with a broken one and left
the app disconnected.  The manager now verifies the tunnel first; the failure
is published only when the tunnel really did not come back.
"""
from __future__ import annotations

from concurrent.futures import Future
import unittest
from unittest.mock import Mock, patch

from PyQt6.QtCore import QCoreApplication, QProcess

from xray_fluent.application.controller import AppController
from xray_fluent.engines.hysteria.manager import HysteriaManager
from xray_fluent.engines.hysteria.runtime_contract import HysteriaFailureCode

_APP = QCoreApplication.instance() or QCoreApplication([])

TIMEOUT = ('2026-10-01T18:45:45+03:00\tWARN\tSOCKS5 TCP error\t'
           '{"addr": "127.0.0.1:38705", "reqAddr": "example.com:443", '
           '"error": "timeout: no recent network activity"}')
RECONNECTED = ('2026-10-01T18:45:45+03:00\tINFO\tconnected to server\t'
               '{"addr": "203.0.113.7:443", "udpEnabled": true, "tx": 0, "count": 2}')
AUTH_REJECTED = ('2026-10-01T18:45:46+03:00\tWARN\tSOCKS5 TCP error\t'
                 '{"addr": "127.0.0.1:19864", "reqAddr": "example.com:443", '
                 '"error": "authentication error, HTTP status code: 301"}')


class TunnelCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manager = HysteriaManager()
        self.manager._begin_attempt(None, {})
        self.manager._relay_probe = (11809, "u", "p")
        self.manager._remote_authenticated = True
        self.manager._mark_running()
        self.addCleanup(self.manager.deleteLater)
        self.addCleanup(self.manager._cancel_health)
        self.failures: list[str] = []
        self.logs: list[str] = []
        self.manager.failure.connect(lambda code, _message, _generation: self.failures.append(code))
        self.manager.log_received.connect(self.logs.append)
        state = patch.object(
            self.manager._process, "state", return_value=QProcess.ProcessState.Running
        )
        state.start()
        self.addCleanup(state.stop)
        self.futures: list[Future] = []
        executor = Mock()

        def submit(*_args, **_kwargs) -> Future:
            future: Future = Future()
            self.futures.append(future)
            return future

        executor.submit.side_effect = submit
        pool = patch("xray_fluent.engines.hysteria.manager.ThreadPoolExecutor", return_value=executor)
        pool.start()
        self.addCleanup(pool.stop)

    def _finish_wave(self, *, ok: bool) -> None:
        for future in [item for item in self.futures if not item.done()]:
            if ok:
                future.set_result(None)
            else:
                future.set_exception(TimeoutError("timed out"))
        self.manager._tunnel_check.poll()

    def test_timeout_line_starts_a_check_instead_of_a_failure(self) -> None:
        self.manager._emit_process_line(TIMEOUT)
        self.manager._emit_process_line(TIMEOUT)
        self.assertEqual(self.failures, [])
        self.assertTrue(self.manager._tunnel_check.active)
        self.assertEqual(self.manager.stats["tunnel_checks"], 1)

    def test_reauthenticated_server_is_retained(self) -> None:
        self.manager._emit_process_line(TIMEOUT)
        self.manager._emit_process_line(RECONNECTED)
        self.assertEqual(self.failures, [])
        self.assertFalse(self.manager._tunnel_check.active)
        self.assertEqual(self.manager.stats["tunnel_recoveries"], 1)
        self.assertTrue(any("server retained" in line for line in self.logs))

    def test_successful_probe_retains_the_server(self) -> None:
        self.manager._emit_process_line(TIMEOUT)
        self._finish_wave(ok=True)
        self.assertEqual(self.failures, [])
        self.assertFalse(self.manager._tunnel_check.active)
        # The next unrelated error is verified again, not swallowed.
        self.manager._emit_process_line(TIMEOUT)
        self.assertTrue(self.manager._tunnel_check.active)

    def test_failure_is_published_only_after_every_wave_failed(self) -> None:
        self.manager._emit_process_line(TIMEOUT)
        self._finish_wave(ok=False)
        self.assertEqual(self.failures, [])
        self.assertTrue(self.manager._tunnel_check.active)
        self._finish_wave(ok=False)
        self.assertEqual(self.failures, [HysteriaFailureCode.TARGET_NETWORK_TIMEOUT.value])
        self.assertFalse(self.manager._tunnel_check.active)

    def test_security_failure_is_never_delayed_by_a_check(self) -> None:
        self.manager._emit_process_line(TIMEOUT)
        self.manager._emit_process_line(AUTH_REJECTED)
        self.assertEqual(self.failures, [HysteriaFailureCode.TARGET_AUTH_REJECTED.value])


class ReturnToSelectedServerTests(unittest.TestCase):
    def _controller(self) -> Mock:
        controller = Mock()
        controller._hysteria_return_episode = 3
        controller.locked = False
        controller._transition_active = False
        controller._transition_pending = False
        controller._disconnecting = False
        controller.connected = False
        controller._desired_connected = False
        return controller

    def test_rejected_replacement_is_excluded_and_return_is_scheduled(self) -> None:
        controller = Mock()
        controller._pending_transport_node_id = "replacement"
        controller._hysteria_cooldown_until = {}
        AppController._reject_hysteria_replacement(controller, 3600.0, "replacement rejected")
        self.assertIn("replacement", controller._hysteria_cooldown_until)
        controller._schedule_return_to_selected.assert_called_once_with("replacement rejected")

    def test_return_reconnects_the_selected_server(self) -> None:
        controller = self._controller()
        AppController._return_to_selected_server(controller, 3, 0)
        self.assertTrue(controller._desired_connected)
        controller._request_transition.assert_called_once_with("return to selected server")

    def test_return_is_dropped_after_a_manual_action_or_when_connected(self) -> None:
        manual = self._controller()
        manual._hysteria_return_episode = 0
        AppController._return_to_selected_server(manual, 3, 0)
        manual._request_transition.assert_not_called()

        connected = self._controller()
        connected.connected = True
        AppController._return_to_selected_server(connected, 3, 0)
        connected._request_transition.assert_not_called()

    def test_return_waits_for_the_failed_transition_to_finish(self) -> None:
        controller = self._controller()
        controller._transition_active = True
        with patch("xray_fluent.application.controller.QTimer.singleShot") as single_shot:
            AppController._return_to_selected_server(controller, 3, 0)
        controller._request_transition.assert_not_called()
        single_shot.assert_called_once()


if __name__ == "__main__":
    unittest.main()
