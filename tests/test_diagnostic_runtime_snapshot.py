import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from PyQt6.QtCore import QCoreApplication

from xray_fluent.application.controller import AppController
from xray_fluent.diagnostics.runtime_errors import RuntimeErrorJournal, core_failure
from xray_fluent.diagnostics.export import capture_runtime_config, export_diagnostics
from xray_fluent.engines.singbox.manager import SingBoxManager
from xray_fluent.profiles.models import AppState
from xray_fluent.diagnostics.runtime_logging import RuntimeLogContext, RuntimeNodeIdentity

_APP = QCoreApplication.instance() or QCoreApplication([])


class DiagnosticRuntimeSnapshotTests(unittest.TestCase):
    def config(self):
        return {
            'dns': {'servers': [{'tag': 'proxy-dns', 'type': 'udp', 'server': '10.9.0.1', 'detour': 'proxy'}]},
            'route': {'final': 'proxy', 'rules': [{'domain_suffix': ['example.com'], 'outbound': 'direct'}]},
            'endpoints': [{'type': 'wireguard', 'tag': 'proxy', 'address': ['10.9.0.3/32'],
                           'private_key': 'PRIVATE-SENTINEL', 'detour': 'awg3-direct',
                           'amnezia': {'header_protection_key': 'HPK-SENTINEL', 's1': 12},
                           'peers': [{'public_key': 'PUBLIC-SENTINEL', 'pre_shared_key': 'PSK-SENTINEL'}]}],
            'outbounds': [{'type': 'socks', 'username': 'USER-SENTINEL', 'password': 'PASSWORD-SENTINEL'}],
        }

    def test_snapshot_keeps_routing_but_detaches_and_redacts_credentials(self):
        config = self.config()
        snapshot = capture_runtime_config(Path('core/sing-box.exe'), config)
        self.assertEqual(snapshot['config']['dns'], config['dns'])
        self.assertEqual(snapshot['config']['route'], config['route'])
        self.assertEqual(snapshot['config']['endpoints'][0]['detour'], 'awg3-direct')
        self.assertNotIn('SENTINEL', json.dumps(snapshot))
        config['dns']['servers'][0]['server'] = '8.8.8.8'
        self.assertEqual(snapshot['config']['dns']['servers'][0]['server'], '10.9.0.1')
        self.assertEqual(config['endpoints'][0]['private_key'], 'PRIVATE-SENTINEL')

    def test_runtime_redactor_handles_aliases_embedded_uris_and_headers(self):
        config = {
            'server': 'hy2://AUTH-SENTINEL@example.com:443/',
            'uri': 'vless://URI-SENTINEL@example.com',
            'tls': {'clientKey': 'TLS-SENTINEL', 'pinSHA256': 'PIN-SENTINEL'},
            'settings': {'encryption': 'ENCRYPTION-SENTINEL', 'headers': {'Authorization': 'Bearer HEADER-SENTINEL'}},
            'HeaderProtectionKey': 'CAMEL-SENTINEL',
            'message': 'header_protection_key=LOG-SENTINEL',
        }
        snapshot = capture_runtime_config(Path('core/hysteria.exe'), config)
        self.assertNotIn('SENTINEL', json.dumps(snapshot))

    def test_singbox_captures_actual_written_attempt_even_if_core_check_fails(self):
        config = self.config()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            exe = root / 'sing-box.exe'
            exe.touch()
            runtime_path = root / 'runtime.json'
            manager = SingBoxManager()
            with (
                patch('xray_fluent.engines.singbox.manager.resolve_configured_path', return_value=exe),
                patch('xray_fluent.engines.singbox.manager.RUNTIME_DIR', root),
                patch('xray_fluent.engines.singbox.manager.SINGBOX_CONFIG_FILE', runtime_path),
                patch('xray_fluent.engines.singbox.manager.check_config', return_value=(False, 'core config rejected')),
            ):
                self.assertFalse(manager.start(str(exe), config))
            self.assertEqual(json.loads(runtime_path.read_text()), config)
            self.assertEqual(manager.diagnostic_config['config']['dns'], config['dns'])
            self.assertNotIn('SENTINEL', json.dumps(manager.diagnostic_config))

    def test_controller_export_includes_config_and_session_identity_without_replanning(self):
        snapshot = capture_runtime_config(Path('core/sing-box.exe'), self.config())
        context = RuntimeLogContext('sing-box', 'front', 'proxy', 9,
                                    selected=RuntimeNodeIdentity('safe-ref', 'AWG', 'awg'))
        controller = SimpleNamespace(
            state=AppState(), recent_logs=['DNS lookup failed'], connected=True,
            runtime_errors=RuntimeErrorJournal(),
            _core_log_contexts={'sing-box': context},
            singbox=SimpleNamespace(is_running=True, diagnostic_config=snapshot),
            xray=SimpleNamespace(is_running=False, diagnostic_config=None),
            hysteria=SimpleNamespace(is_running=False, diagnostic_config=None),
        )
        with tempfile.TemporaryDirectory() as folder:
            with patch('xray_fluent.application.controller.LOG_DIR', Path(folder)):
                path = AppController.build_diagnostics(controller)
            with zipfile.ZipFile(path) as archive:
                runtime = json.loads(archive.read('runtime_redacted.json'))
                text = '\n'.join(archive.read(name).decode() for name in archive.namelist())
        component = runtime['components']['sing-box']
        self.assertEqual(component['log_context']['generation'], 9)
        self.assertEqual(component['log_context']['selected']['ref'], 'safe-ref')
        self.assertTrue(component['running'])
        self.assertEqual(component['last_written_config'], snapshot)
        self.assertIsNone(runtime['components']['hysteria']['last_written_config'])
        self.assertNotIn('SENTINEL', text)

    def test_absent_snapshot_is_explicit_and_journal_retains_raw_cause(self):
        journal = RuntimeErrorJournal()
        journal.record(core_failure('sing-box', 'runtime', 'lookup example.com: context deadline exceeded'))
        with tempfile.TemporaryDirectory() as folder:
            path = export_diagnostics(Path(folder) / 'diagnostic.zip', AppState(), [], runtime_errors=journal.snapshot())
            with zipfile.ZipFile(path) as archive:
                runtime = json.loads(archive.read('runtime_redacted.json'))
                errors = json.loads(archive.read('runtime_errors.json'))
        self.assertFalse(runtime['available'])
        self.assertEqual(errors[0]['failure']['message'], 'lookup example.com: context deadline exceeded')


if __name__ == '__main__':
    unittest.main()


class SingboxParallelCheckTests(unittest.TestCase):
    """`sing-box check` идёт параллельно с запуском, а не перед ним."""

    def _start(self, check_result):
        config = {'log': {'level': 'warn'}, 'inbounds': [], 'outbounds': [{'type': 'direct', 'tag': 'direct'}]}
        errors: list[str] = []
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            exe = root / 'sing-box.exe'
            exe.touch()
            manager = SingBoxManager()
            manager.error.connect(errors.append)
            with (
                patch('xray_fluent.engines.singbox.manager.resolve_configured_path', return_value=exe),
                patch('xray_fluent.engines.singbox.manager.RUNTIME_DIR', root),
                patch('xray_fluent.engines.singbox.manager.SINGBOX_CONFIG_FILE', root / 'runtime.json'),
                patch('xray_fluent.engines.singbox.manager._kill_orphaned_blocking', return_value=False),
                patch('xray_fluent.engines.singbox.manager.check_config', return_value=check_result) as check,
            ):
                started = manager.start(str(exe), config)
        return started, errors, check

    def test_failed_launch_reports_core_check_explanation(self):
        started, errors, check = self._start((False, 'Ядро не знает поле «Tag»'))
        self.assertFalse(started)
        self.assertEqual(errors, ['Ядро не знает поле «Tag»'])
        check.assert_called_once()

    def test_failed_launch_with_valid_config_reports_launch_failure_once(self):
        started, errors, _check = self._start((True, ''))
        self.assertFalse(started)
        self.assertEqual(len(errors), 1)
        self.assertIn('sing-box process', errors[0])
