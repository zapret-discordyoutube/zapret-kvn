import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile

from PyQt6.QtCore import QByteArray, QCoreApplication, QProcess

from xray_fluent.application.controller import AppController
from xray_fluent.engines.hysteria.runtime_contract import HysteriaTransitionContract, classify_hysteria_failure
from xray_fluent.diagnostics.runtime_errors import RuntimeErrorJournal, core_failure
from xray_fluent.diagnostics.export import export_diagnostics
from xray_fluent.engines.hysteria.manager import HysteriaManager
from xray_fluent.profiles.models import AppState
from xray_fluent.importer.link_parser import parse_single


_APP = QCoreApplication.instance() or QCoreApplication([])


class RuntimeErrorTests(unittest.TestCase):
    def test_loopback_reset_from_process_pipe_does_not_abort_ready_session(self):
        line = 'WARN SOCKS5 TCP error {"addr":"127.0.0.1:28327","reqAddr":"dns.quad9.net:443","error":"read tcp4 127.0.0.1:11809->127.0.0.1:28327: wsarecv: An existing connection was forcibly closed by the remote host."}'
        for running in (False, True):
            with self.subTest(running=running):
                manager = HysteriaManager()
                manager._running = running
                manager._process_generation = 8
                controller = Mock()
                controller.hysteria = manager
                controller._hysteria_active_generation = 8
                journal = RuntimeErrorJournal()
                manager.log_received.connect(lambda message: journal.record(core_failure('hysteria', 'runtime', message)))
                manager.failure.connect(lambda code, message, generation:
                    AppController._on_hysteria_failure(controller, manager, code, message, generation))
                with patch.object(manager._process, 'readAllStandardOutput', return_value=QByteArray((line + '\n').encode())):
                    manager._on_ready_read()
                self.assertFalse(manager._failure_reported)
                self.assertIsNone(manager.last_failure_code)
                controller.singbox.stop.assert_not_called()
                controller._request_transition.assert_not_called()
                with patch.object(manager._process, 'state', return_value=QProcess.ProcessState.Running), \
                     patch.object(manager, '_probe_remote_endpoint', return_value=None):
                    self.assertTrue(manager._wait_until_remote_ready(11809, username='', password='', timeout=1))
                record = journal.snapshot()[0].failure
                self.assertEqual(record.code, 'LOCAL_CLIENT_CONNECTION_CLOSED')
                self.assertEqual(record.action, 'record_only')
                self.assertIn(line, record.message)
                self.assertIn('stage=local_client', record.message)

    def test_loopback_diagnostic_does_not_hide_remote_or_process_failure(self):
        for address in ('127.0.0.1:11809->127.0.0.1:20000', '[::1]:11809->[::1]:20000'):
            message = f'write tcp {address}: write: broken pipe'
            self.assertEqual(core_failure('hysteria', 'runtime', message).action, 'record_only')
            self.assertIsNone(classify_hysteria_failure(message))
            self.assertEqual(classify_hysteria_failure(message, process_exited=True).value, 'LOCAL_PROCESS_EXITED')
        for text, expected in (
            ('connect error: connection refused', 'TARGET_CONNECTION_REFUSED'),
            ('read tcp4 127.0.0.1:11809->198.51.100.3:443: connection reset by peer', 'TARGET_CONNECTION_CLOSED'),
            ('connect error: An existing connection was forcibly closed by the remote host.', 'TARGET_CONNECTION_CLOSED'),
            ('connect error: timeout: no recent network activity', 'TARGET_NETWORK_TIMEOUT'),
            ('connect error: INTERNAL_ERROR (local): no certificate matches the pinned hash', 'TARGET_PIN_MISMATCH'),
        ):
            self.assertEqual(classify_hysteria_failure(text).value, expected)

    def test_manager_security_escalation_reaches_controller_after_timeout(self):
        current = parse_single('hy2://current@one.example:443/#current')
        replacement = parse_single('hy2://replacement@two.example:443/#replacement')
        manager = HysteriaManager()
        manager._running = True
        manager._process_generation = 7
        controller = Mock()
        controller.hysteria = manager
        controller._hysteria_active_generation = 7
        controller._hysteria_contract = HysteriaTransitionContract()
        controller._hysteria_contract.begin(3, current.id, 'official_hysteria_sidecar')
        controller.connected = True
        controller._disconnecting = False
        controller._desired_connected = True
        controller._hysteria_recovery_active = False
        controller._hysteria_cooldown_until = {}
        controller._hysteria_failure_episode_id = 0
        controller.selected_node = current
        controller.state = AppState(nodes=[current, replacement], selected_node_id=current.id)
        journal = RuntimeErrorJournal()
        manager.log_received.connect(lambda message: journal.record(core_failure('hysteria', 'runtime', message)))
        manager.failure.connect(lambda code, message, generation:
            AppController._on_hysteria_failure(controller, manager, code, message, generation))
        manager._emit_process_line('WARN connect error: timeout: no recent network activity')
        manager._emit_process_line('WARN x509: certificate signed by unknown authority')
        manager._emit_process_line('WARN connect error: timeout: no recent network activity')
        self.assertEqual(controller._request_transition.call_count, 1)
        self.assertFalse(controller._desired_connected)
        self.assertEqual(controller._hysteria_last_failure_code.value, 'TARGET_TLS_UNKNOWN_AUTHORITY')
        self.assertIn('unknown authority', controller._set_connection_status.call_args.args[1])
        self.assertEqual([record.failure.code for record in journal.snapshot()],
                         ['TARGET_NETWORK_TIMEOUT', 'TARGET_TLS_UNKNOWN_AUTHORITY'])
        self.assertEqual(controller.state.selected_node_id, current.id)
        self.assertEqual(controller._hysteria_contract.session.failure_episode_id, 1)

    def test_unknown_error_is_kept_with_no_invented_diagnosis(self):
        message = 'ERROR upstream returned odd status 781: untouched details'
        failure = core_failure('xray', 'dial', message)
        self.assertEqual(failure.message, message)
        self.assertEqual(failure.code, 'CORE_UNCLASSIFIED')
        self.assertEqual(failure.target_id, '')

    def test_journal_export_is_independent_of_traffic_limit(self):
        journal = RuntimeErrorJournal()
        for number in range(2100):
            journal.record(core_failure('sing-box', 'dial', f'ERROR evidence {number}'))
        journal.record(core_failure('sing-box', 'dial', 'ERROR evidence 0'))
        with tempfile.TemporaryDirectory() as directory:
            path = export_diagnostics(Path(directory) / 'report.zip', AppState(), [],
                                      runtime_errors=journal.snapshot())
            with zipfile.ZipFile(path) as archive:
                records = json.loads(archive.read('runtime_errors.json'))
        self.assertEqual(len(records), 2100)
        self.assertEqual(records[0]['occurrences'], 2)
        self.assertEqual(records[0]['failure']['message'], 'ERROR evidence 0')

    def test_manager_log_reaches_security_policy_after_ready(self):
        for line, code in (
            ('ERROR x509: certificate signed by unknown authority', 'TARGET_TLS_UNKNOWN_AUTHORITY'),
            ('ERROR server certificate SHA-256 mismatch', 'TARGET_PIN_MISMATCH'),
            ('ERROR authentication error: invalid user', 'TARGET_AUTH_REJECTED'),
            ('WARN obfs rejected', 'TARGET_OBFS_REJECTED'),
        ):
            with self.subTest(line=line), patch.object(HysteriaManager, '_cleanup_config'), \
                    patch.object(HysteriaManager, '_cleanup_stale_generation_configs'):
                manager = HysteriaManager()
                manager._running = True
                manager._process_generation = 7
                contract = HysteriaTransitionContract()
                contract.begin(3, 'node', 'official_hysteria_sidecar')
                controller = SimpleNamespace(
                    hysteria=manager, _hysteria_active_generation=7,
                    connected=True, _disconnecting=False, _desired_connected=True,
                    _hysteria_contract=contract, singbox=Mock(is_running=True),
                    _log=Mock(), _set_connection_status=Mock(), _request_transition=Mock(),
                )
                journal = RuntimeErrorJournal()
                manager.log_received.connect(lambda message: journal.record(core_failure('hysteria', 'runtime', message)))
                manager.failure.connect(lambda failure_code, message, generation:
                    AppController._on_hysteria_failure(controller, manager, failure_code, message, generation))
                manager._emit_process_line(line)
                controller.singbox.stop.assert_called_once_with(expected=True)
                controller._request_transition.assert_not_called()
                self.assertFalse(controller._desired_connected)
                self.assertEqual(controller._hysteria_last_failure_code.value, code)
                self.assertIn(line, controller._set_connection_status.call_args.args[1])
                self.assertEqual(journal.snapshot()[0].failure.code, code)


if __name__ == '__main__':
    unittest.main()
