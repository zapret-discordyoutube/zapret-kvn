"""Bounded readiness and visible DNS fallback without network or core processes."""
from concurrent.futures import Future
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from PyQt6.QtCore import QProcess
from xray_fluent.application.controller import AppController
from xray_fluent.application.node_runtime_service import start_country_ip_resolution, on_countries_resolved
from xray_fluent.engines.amnezia.manager import AmneziaManager
from xray_fluent.profiles.models import Node


class ReadinessTests(unittest.TestCase):
    def run_probe(self, *, refused=False, cancel_at=None, handshake_at=float("inf")):
        elapsed = [0.0]
        manager = SimpleNamespace(_failed=False, _expected=False, stats={'peers': []},
                                  _process=Mock(), _report=Mock(), _monitor_transport_health=Mock())
        manager._process.state.return_value = QProcess.ProcessState.Running
        manager._is_current = lambda: cancel_at is None or elapsed[0] < cancel_at
        manager._cancelled = lambda: AmneziaManager._cancelled(manager)
        def sleep(seconds):
            elapsed[0] += seconds
            if elapsed[0] >= handshake_at:
                manager.stats = {'peers': [{'last_handshake_time_sec': 1}]}
        def submit(*args, **kwargs):
            future = Future()
            if refused:
                future.set_exception(OSError('DNS REFUSED'))
            else:
                future.set_result(None)
            return future
        executor = Mock()
        executor.submit.side_effect = submit
        with patch('xray_fluent.engines.amnezia.manager.ThreadPoolExecutor', return_value=executor), \
             patch('xray_fluent.engines.amnezia.manager.time.monotonic', side_effect=lambda: elapsed[0]), \
             patch('xray_fluent.engines.amnezia.manager.sleep_with_events', side_effect=sleep):
            result = AmneziaManager._ready(manager, 1234, {'username': 'test', 'password': 'test'})
        if result:
            executor.shutdown.assert_not_called()
            manager._monitor_transport_health.assert_called_once()
        else:
            executor.shutdown.assert_called_once_with(wait=False, cancel_futures=True)
        return result, manager, executor

    def test_missing_handshake_has_one_bounded_wave_and_one_failure(self):
        result, manager, executor = self.run_probe(refused=True)
        self.assertFalse(result)
        self.assertEqual(executor.submit.call_count, 3)
        manager._report.assert_called_once()

    def test_success_waits_for_handshake_observation_without_more_probes(self):
        result, manager, executor = self.run_probe(handshake_at=2)
        self.assertTrue(result)
        self.assertEqual(executor.submit.call_count, 3)
        manager._report.assert_not_called()

    def test_stop_cancels_remaining_attempts_without_spurious_failure(self):
        result, manager, executor = self.run_probe(refused=True, cancel_at=0.2)
        self.assertFalse(result)
        self.assertEqual(executor.submit.call_count, 3)
        manager._report.assert_not_called()


class DnsWarningTests(unittest.TestCase):
    def test_warning_escalates_once_per_connection_generation(self):
        controller = SimpleNamespace(_transition_generation=1, status=Mock())
        warn = lambda server: AppController._report_dns_fallback(controller, 'WARN DNS_FALLBACK server=' + server)
        for _ in range(3):
            warn('bootstrap-dns')
        self.assertEqual(controller.status.emit.call_count, 1)
        warn('local-system-dns')
        self.assertEqual(controller.status.emit.call_count, 2)
        self.assertIn('видны провайдеру', controller.status.emit.call_args.args[1])
        warn('bootstrap-dns')
        warn('local-system-dns')
        self.assertEqual(controller.status.emit.call_count, 2)
        controller._transition_generation += 1
        warn('local-system-dns')
        self.assertEqual(controller.status.emit.call_count, 3)
        self.assertTrue(all(call.args[0] == 'warning' for call in controller.status.emit.call_args_list))


class CountrySourceTests(unittest.TestCase):
    def test_explicit_flags_need_no_geoip_worker_and_ignore_late_geoip(self):
        node = Node(id='one', name='🇺🇸 Server', server='8.8.8.8')
        controller = SimpleNamespace(state=SimpleNamespace(nodes=[node]), countries_changed=Mock())
        with patch('xray_fluent.application.node_runtime_service.CountryResolver') as worker:
            start_country_ip_resolution(controller)
            worker.assert_not_called()
        on_countries_resolved(controller, {'one': (('8.8.8.8',), 'NL')})
        self.assertEqual(node.country_code, '')
        controller.countries_changed.emit.assert_not_called()

    def test_geoip_change_emits_ids_without_full_catalogue_refresh(self):
        node = Node(id='one', name='IP endpoint', server='8.8.8.8')
        controller = SimpleNamespace(state=SimpleNamespace(nodes=[node]), countries_changed=Mock(), nodes_changed=Mock())
        on_countries_resolved(controller, {'one': (('8.8.8.8',), 'US')})
        controller.countries_changed.emit.assert_called_once_with({'one'})
        controller.nodes_changed.emit.assert_not_called()
