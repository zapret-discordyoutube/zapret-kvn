"""Regressions from 0.6.1 diagnostics: DNS bootstrap and misleading startup errors."""
import ipaddress
import unittest
from unittest.mock import Mock, patch
from concurrent.futures import Future
from PyQt6.QtCore import QProcess
from xray_fluent.engines.hysteria.manager import HysteriaManager, _FUNCTIONAL_HTTPS_ENDPOINTS
from xray_fluent.engines.socks_probe import probe_https
from xray_fluent.engines.hysteria.runtime_contract import HysteriaFailureCode
from xray_fluent.diagnostics.connection_message import connection_message


class HysteriaStartupRegressions(unittest.TestCase):
    def test_bootstrap_probes_use_literal_addresses_but_keep_tls_names(self):
        for address, name, path in _FUNCTIONAL_HTTPS_ENDPOINTS:
            ipaddress.ip_address(address)
            raw = Mock()
            raw.recv.side_effect = [b'\x05\x02', b'\x01\x00', b'\x05\x00\x00\x01', b'\0' * 6]
            tls = Mock()
            tls.recv.return_value = b'HTTP/'
            context = Mock()
            context.wrap_socket.return_value.__enter__ = Mock(return_value=tls)
            context.wrap_socket.return_value.__exit__ = Mock(return_value=False)
            with patch('xray_fluent.engines.socks_probe.socket.create_connection', return_value=raw), \
                 patch('xray_fluent.engines.socks_probe.ssl.create_default_context', return_value=context):
                probe_https(11809, username='user', password='secret', endpoint=(address,name,path), timeout=4)
            request = raw.sendall.call_args_list[-1].args[0]
            self.assertEqual(request[:4], b'\x05\x01\x00\x01')
            self.assertEqual(request[4:8], ipaddress.ip_address(address).packed)
            context.wrap_socket.assert_called_once_with(raw, server_hostname=name)
            self.assertIn(('Host: '+name).encode(), tls.sendall.call_args.args[0])
            raw.close.assert_called_once()

    def test_initial_timeout_is_logged_without_premature_error_and_success_clears_it(self):
        manager = HysteriaManager()
        manager._starting = True
        errors = []
        manager.error.connect(errors.append)
        manager._emit_process_line('WARN connect error: timeout: no recent network activity')
        self.assertEqual(errors, [])
        self.assertEqual(manager.last_failure_code, HysteriaFailureCode.TARGET_NETWORK_TIMEOUT)
        self.assertTrue(manager._last_output_lines)
        manager._mark_running()
        self.assertIsNone(manager.last_failure_code)
        manager.deleteLater()

    def test_security_failure_is_not_deferred_or_retried_with_identical_quic(self):
        manager = HysteriaManager()
        manager._starting = True
        manager._compatibility_config = {'quic': {'disableChromeParrot': True}}
        errors = []
        manager.error.connect(errors.append)
        with patch.object(manager, '_schedule_chrome_parrot_fallback') as retry:
            manager._emit_process_line('connect error: CRYPTO_ERROR 0x150 (remote): tls: internal error')
            retry.assert_not_called()
        self.assertEqual(len(errors), 1)
        manager.deleteLater()

    def test_cancelled_readiness_stops_without_another_probe_wave(self):
        manager = HysteriaManager()
        clock = [0.0]
        executor = Mock()
        def submit(*args, **kwargs):
            future = Future(); future.set_exception(TimeoutError('timed out')); return future
        executor.submit.side_effect = submit
        def cancel(seconds):
            clock[0] += seconds
            manager._compatibility_generation += 1
        with patch.object(manager._process, 'state', return_value=QProcess.ProcessState.Running), \
             patch('xray_fluent.engines.hysteria.manager.ThreadPoolExecutor', return_value=executor), \
             patch('xray_fluent.engines.hysteria.manager.time.monotonic', side_effect=lambda: clock[0]), \
             patch('xray_fluent.engines.hysteria.manager.sleep_with_events', side_effect=cancel):
            self.assertFalse(manager._wait_until_remote_ready(11809, username='u', password='p'))
        self.assertEqual(executor.submit.call_count, 3)
        manager.deleteLater()

    def test_ui_distinguishes_transport_timeout_from_https_probe_timeout(self):
        remote = '[hysteria][attempt=3 node="Server"] SOCKS5 TCP error {"error":"connect error: timeout: no recent network activity"}'
        https = 'Hysteria relay локально открыт, но удалённый handshake не готов: functional HTTPS probes failed: _ssl.c:993: timed out'
        self.assertIn('соединение с сервером', connection_message(remote))
        self.assertIn('Проверка HTTPS', connection_message(https))
        self.assertNotIn('attempt=', connection_message(remote))
        self.assertEqual(connection_message('Неверный пароль профиля'), 'Неверный пароль профиля')
