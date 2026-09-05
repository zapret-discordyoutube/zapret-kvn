"""Validate shipped native JSON with the actual Windows release cores."""
import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'nt', 'Windows release cores')
class NativeTemplateCoreValidationTests(unittest.TestCase):
    def test_all_native_templates_are_core_valid(self):
        for engine, executable, command in (
                ('sing-box', 'sing-box.exe', ['check']),
                ('xray', 'xray.exe', ['run', '-test'])):
            for path in sorted((ROOT / 'data' / 'templates' / engine).glob('*.json')):
                with self.subTest(engine=engine, template=path.name):
                    result = subprocess.run([str(ROOT / 'core' / executable), *command, '-c', str(path)],
                        cwd=ROOT / 'core', capture_output=True, timeout=30)
                    self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode('utf-8', errors='replace'))
