from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from xray_fluent.application.singbox_editor_check import CHECK_FILE_NAME, SingboxEditorCheck


class EditorCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.runtime = Path(self.temp.name)
        self.checker = SingboxEditorCheck(runtime_dir=self.runtime)

    def tearDown(self) -> None:
        self.checker.shutdown()
        self.temp.cleanup()

    def test_missing_core_is_a_warning_not_success(self) -> None:
        level, message = self.checker.check_blocking(self.runtime / "absent.exe", "{}")
        self.assertEqual(level, "warning")
        self.assertIn("не выполнена", message)

    def test_core_verdict_is_reported_and_temp_file_removed(self) -> None:
        exe = self.runtime / "sing-box.exe"
        exe.write_bytes(b"")
        seen: list[str] = []

        def fake_check(_exe, path):
            seen.append(path.read_text(encoding="utf-8"))
            return False, "Ядро не приняло конфигурацию: bad"

        with mock.patch("xray_fluent.application.singbox_editor_check.check_config", fake_check):
            level, message = self.checker.check_blocking(exe, '{"log": {}}')
        self.assertEqual((level, message), ("error", "Ядро не приняло конфигурацию: bad"))
        self.assertEqual(seen, ['{"log": {}}'])
        self.assertFalse((self.runtime / CHECK_FILE_NAME).exists())

        with mock.patch("xray_fluent.application.singbox_editor_check.check_config", lambda *_: (True, "")):
            self.assertEqual(self.checker.check_blocking(exe, "{}")[0], "success")


if __name__ == "__main__":
    unittest.main()
