from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from xray_fluent.ui.file_manager import reveal_file


class FileManagerTests(TestCase):
    def test_windows_reveals_exact_export_with_spaces_and_unicode(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / 'диагностика 0.6.0.zip'
            path.write_bytes(b'archive')
            with patch('xray_fluent.ui.file_manager.sys.platform', 'win32'), patch(
                    'xray_fluent.ui.file_manager.subprocess.Popen') as launch:
                self.assertTrue(reveal_file(path))
            launch.assert_called_once_with(['explorer.exe', '/select,', str(path.resolve())])
