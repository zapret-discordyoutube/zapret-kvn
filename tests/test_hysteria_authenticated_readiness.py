"""A confirmed Hysteria handshake survives blocked external probe addresses."""
import unittest
from concurrent.futures import Future
from types import SimpleNamespace
from unittest.mock import Mock, patch

from PyQt6.QtCore import QCoreApplication, QProcess
from xray_fluent.application.controller import AppController
from xray_fluent.engines.hysteria.manager import HysteriaManager
from xray_fluent.engines.hysteria.runtime_contract import HysteriaFailureCode
from xray_fluent.diagnostics.export import collect_runtime_diagnostics

_APP = QCoreApplication.instance() or QCoreApplication([])
CONNECTED = ('2026-09-06T14:07:47+03:00\tINFO\tconnected to server\t'
             '{"addr":"192.0.2.1:443","udpEnabled":true,"tx":0,"ech":false,"count":1}')


class AuthenticatedReadinessTests(unittest.TestCase):
    def setUp(self):
        self.manager = HysteriaManager()
        self.manager._begin_attempt(None, {})
        self.manager._starting = True
        self.addCleanup(self.manager.deleteLater)
        self.addCleanup(self.manager._cancel_health)
        self.errors, self.warnings, self.logs = [], [], []
        self.manager.error.connect(self.errors.append)
        self.manager.warning.connect(self.warnings.append)
        self.manager.log_received.connect(self.logs.append)
        self.process = patch.object(self.manager._process, 'state', return_value=QProcess.ProcessState.Running)
        self.process.start(); self.addCleanup(self.process.stop)

    def start_with_pending_checks(self):
        clock, pending = [0.0], []
        executor = Mock()
        def submit(*args, **kwargs):
            future = Future(); pending.append(future); return future
        executor.submit.side_effect = submit
        def pump(seconds):
            clock[0] += seconds
            self.manager._emit_process_line(CONNECTED)
        with patch('xray_fluent.engines.hysteria.manager.ThreadPoolExecutor', return_value=executor), \
             patch('xray_fluent.engines.hysteria.manager.time.monotonic', side_effect=lambda: clock[0]), \
             patch('xray_fluent.engines.hysteria.manager.sleep_with_events', side_effect=pump):
            self.assertTrue(self.manager._wait_until_remote_ready(11809, username='u', password='p'))
        self.assertLess(clock[0], 0.2, 'an authenticated connection must not wait for probe timeouts')
        self.assertEqual(len(pending), 3)
        self.manager._starting = False
        self.manager._mark_running()
        return pending, executor

    def test_authenticated_connection_survives_all_https_timeouts(self):
        pending, executor = self.start_with_pending_checks()
        for future in pending:
            future.set_exception(TimeoutError('_ssl.c:993: The handshake operation timed out'))
        self.manager._poll_health()
        self.assertTrue(self.manager.is_running)
        self.assertEqual(self.errors, [])
        self.assertEqual(len(self.warnings), 1)
        self.assertEqual(self.manager.stats, {'remote_authenticated': True, 'https_check': 'warning'})
        self.assertTrue(any('stage=health_check' in line and 'TimeoutError' in line for line in self.logs))
        executor.shutdown.assert_called_once_with(wait=False, cancel_futures=True)
        self.manager._poll_health()
        self.assertEqual(len(self.warnings), 1)

    def test_one_success_completes_health_without_warning(self):
        pending, executor = self.start_with_pending_checks()
        pending[0].set_exception(TimeoutError('blocked'))
        pending[1].set_result(None)
        self.manager._poll_health()
        self.assertEqual(self.manager.stats['https_check'], 'passed')
        self.assertEqual(self.warnings, [])
        executor.shutdown.assert_called_once_with(wait=False, cancel_futures=True)

    def test_old_probe_results_cannot_warn_after_stop_or_replace(self):
        pending, _ = self.start_with_pending_checks()
        self.manager._clear_compatibility_state()
        for future in pending:
            future.set_exception(TimeoutError('old attempt'))
        self.manager._poll_health()
        self.assertEqual(self.warnings, [])
        self.assertEqual(self.manager.stats['https_check'], 'cancelled')
        self.manager._begin_attempt(None, {})
        self.assertFalse(self.manager.stats['remote_authenticated'])

    def test_listener_and_malformed_logs_are_not_handshake_proof(self):
        for line in (
            CONNECTED.replace('connected to server', 'SOCKS5 server listening'),
            CONNECTED.replace('\tINFO\t', '\tWARN\t'),
            CONNECTED.replace('"count":1', '"count":0'),
            CONNECTED.replace('"count":1', '"count":true'),
            CONNECTED.replace('"ech":false', '"ech":<hidden>'),
        ):
            self.manager._emit_process_line(line)
            self.assertFalse(self.manager._remote_authenticated)

    def test_handshake_does_not_override_certificate_rejection(self):
        self.manager._emit_process_line(CONNECTED)
        self.manager._emit_process_line('no certificate matches the pinned hash')
        with patch.object(self.manager, '_probe_remote_endpoint') as probe:
            self.assertFalse(self.manager._wait_until_remote_ready(11809, username='u', password='p'))
        probe.assert_not_called()
        self.assertEqual(self.manager.last_failure_code, HysteriaFailureCode.TARGET_PIN_MISMATCH)

    def test_probe_destination_refusal_is_not_a_transport_failure(self):
        self.start_with_pending_checks()
        self.manager._emit_process_line('2026-09-06T14:07:48+03:00\tWARN\tSOCKS5 TCP error\t'
            '{"reqAddr":"1.1.1.1:443","error":"connection refused"}')
        self.assertEqual(self.errors, [])
        self.assertTrue(self.manager.is_running)
        self.assertIn('stage=health_check', self.logs[-1])
        self.manager._emit_process_line('2026-09-06T14:07:48+03:00\tWARN\tSOCKS5 TCP error\t'
            '{"reqAddr":"1.1.1.1:443","error":"no certificate matches the pinned hash"}')
        self.assertEqual(self.manager.last_failure_code, HysteriaFailureCode.TARGET_PIN_MISMATCH)
        self.assertEqual(len(self.errors), 1)

    def test_diagnostics_distinguish_authentication_and_https_health(self):
        self.manager.stats = {'remote_authenticated': True, 'https_check': 'warning'}
        ctrl = SimpleNamespace(hysteria=self.manager, connected=True, _core_log_contexts={})
        snapshot = collect_runtime_diagnostics(ctrl)
        self.assertEqual(snapshot['components']['hysteria']['transport_stats'], self.manager.stats)

    def test_health_warning_is_logged_without_a_core_failure_episode(self):
        ctrl = SimpleNamespace(_core_log_contexts={}, _transition_generation=1,
            state=SimpleNamespace(settings=SimpleNamespace(tun_mode=False)),
            _record_core_failure=Mock(), _log=Mock())
        line = '[hysteria][attempt=1 stage=health_check] WARNING: HTTPS timeout'
        AppController._on_core_log(ctrl, 'hysteria', line)
        ctrl._record_core_failure.assert_not_called()
        ctrl._log.assert_called_once()
        AppController._on_core_log(ctrl, 'hysteria', '[hysteria][attempt=1 stage=remote_handshake] ERROR authentication failed')
        ctrl._record_core_failure.assert_called_once()

    def test_warning_from_retired_manager_does_not_reach_ui(self):
        current = SimpleNamespace(process_generation=5)
        ctrl = SimpleNamespace(hysteria=current, _hysteria_active_generation=5, status=Mock())
        AppController._on_hysteria_warning(ctrl, SimpleNamespace(process_generation=4), 'old')
        ctrl.status.emit.assert_not_called()
        AppController._on_hysteria_warning(ctrl, current, 'health warning')
        ctrl.status.emit.assert_called_once_with('warning', 'health warning')
