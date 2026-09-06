"""Post-front diagnostics cannot undo an authenticated, HTTPS-proven transport."""
from concurrent.futures import Future
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from PyQt6.QtCore import QProcess
from PyQt6.QtWidgets import QApplication
from xray_fluent.engines.amnezia.manager import AmneziaManager
from xray_fluent.application.controller import AppController

_APP = QApplication.instance() or QApplication([])


class AmneziaHealthTests(unittest.TestCase):
    def setUp(self):
        self.manager = AmneziaManager()
        self.addCleanup(self.manager.deleteLater)
        self.addCleanup(self.manager._cancel_health)
        self.manager._running = True
        self.manager.stats = {'peers': [{'last_handshake_time_sec': 123}], 'https_check': 'passed'}
        process = patch.object(self.manager._process, 'state', return_value=QProcess.ProcessState.Running)
        process.start(); self.addCleanup(process.stop)
        self.errors, self.warnings = [], []
        self.manager.error.connect(self.errors.append)
        self.manager.warning.connect(self.warnings.append)

    def start_check(self):
        futures = []
        executor = Mock()
        def submit(*args, **kwargs):
            future = Future(); futures.append(future); return future
        executor.submit.side_effect = submit
        with patch('xray_fluent.engines.amnezia.manager.ThreadPoolExecutor', return_value=executor):
            self.assertTrue(self.manager.verify_front_dns({'listen': '127.0.0.1:11819', 'username': 'u', 'password': 'p'}))
        self.assertEqual(len(futures), 3)
        return futures

    def start_transport_check(self):
        futures = []
        executor = Mock()
        def submit(*args, **kwargs):
            future = Future(); futures.append(future); return future
        executor.submit.side_effect = submit
        with patch('xray_fluent.engines.amnezia.manager.ThreadPoolExecutor', return_value=executor):
            self.assertTrue(self.manager._ready(11819, {'username': 'u', 'password': 'p'}))
        executor.shutdown.assert_not_called()
        self.assertEqual(len(futures), 3)
        return futures, executor

    def test_authenticated_handshake_survives_all_initial_https_timeouts(self):
        futures, executor = self.start_transport_check()
        for future in futures:
            future.set_exception(TimeoutError('timed out'))
        self.manager._health.poll()
        self.assertTrue(self.manager.is_running)
        self.assertTrue(self.manager.stats['remote_authenticated'])
        self.assertEqual(self.manager.stats['https_check'], 'warning')
        self.assertEqual(self.errors, [])
        self.assertEqual(len(self.warnings), 1)
        executor.shutdown.assert_called_once_with(wait=False, cancel_futures=True)

    def test_front_check_is_queued_without_parallel_duplicate_wave(self):
        futures, _ = self.start_transport_check()
        config = {'listen': '127.0.0.1:11819', 'username': 'u', 'password': 'p'}
        with patch.object(self.manager, '_start_front_health') as start:
            self.assertTrue(self.manager.verify_front_dns(config))
            start.assert_not_called()
            futures[0].set_result(None)
            self.manager._health.poll()
            start.assert_called_once_with(config)
        self.assertEqual(self.manager.stats['https_check'], 'passed')

    def test_stop_discards_queued_front_check_and_old_probe_warning(self):
        futures, _ = self.start_transport_check()
        self.manager.verify_front_dns({'listen': '127.0.0.1:11819', 'username': 'u', 'password': 'p'})
        self.manager._cancel_health()
        for future in futures:
            future.set_exception(TimeoutError('old'))
        with patch.object(self.manager, '_start_front_health') as start:
            self.manager._health.poll()
            start.assert_not_called()
        self.assertEqual(self.warnings, [])
        self.assertIsNone(self.manager._pending_front_config)
        self.assertEqual(self.manager.stats['front_dns_check'], 'cancelled')

    def test_domain_dns_failure_keeps_proven_transport_and_warns_once(self):
        futures = self.start_check()
        for future in futures:
            future.set_exception(OSError('SOCKS CONNECT rejected (reply=4)'))
        self.manager._health.poll()
        self.manager._health.poll()
        self.assertTrue(self.manager.is_running)
        self.assertEqual(self.errors, [])
        self.assertEqual(len(self.warnings), 1)
        self.assertEqual(self.manager.stats['front_dns_check'], 'warning')
        self.assertEqual(self.manager.stats['https_check'], 'passed')

    def test_success_and_cancel_do_not_warn(self):
        futures = self.start_check()
        futures[1].set_result(None)
        self.manager._health.poll()
        self.assertEqual(self.manager.stats['front_dns_check'], 'passed')
        futures = self.start_check()
        self.manager._cancel_health()
        for future in futures:
            future.set_exception(TimeoutError('old attempt'))
        self.manager._health.poll()
        self.assertEqual(self.warnings, [])
        self.assertEqual(self.manager.stats['front_dns_check'], 'cancelled')

    def test_stale_warning_cannot_affect_replacement(self):
        ctrl = SimpleNamespace(amnezia=object(), status=Mock())
        AppController._on_amnezia_warning(ctrl, self.manager, 'old')
        ctrl.status.emit.assert_not_called()
        ctrl.amnezia = self.manager
        AppController._on_amnezia_warning(ctrl, self.manager, 'warning')
        ctrl.status.emit.assert_called_once_with('warning', 'warning')
