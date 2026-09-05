import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile

from PyQt6.QtCore import QCoreApplication

from xray_fluent.app_controller import AppController
from xray_fluent.application.hysteria_runtime_contract import HysteriaTransitionContract
from xray_fluent.application.runtime_errors import RuntimeErrorJournal, core_failure
from xray_fluent.diagnostics import export_diagnostics
from xray_fluent.engines.hysteria.manager import HysteriaManager
from xray_fluent.models import AppState


_APP = QCoreApplication.instance() or QCoreApplication([])


class RuntimeErrorTests(unittest.TestCase):
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
