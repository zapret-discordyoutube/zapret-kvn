import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from xray_fluent.application.profile_service import apply_singbox_config_text
from xray_fluent.application.singbox_config_recovery import (
    repair_singbox_config_file,
    try_repair_singbox_config_text,
)


class SingboxConfigRecoveryTests(unittest.TestCase):
    def test_unwraps_single_object_array(self) -> None:
        repair = try_repair_singbox_config_text('[{"log": {"level": "info"}}]')

        self.assertIsNotNone(repair)
        assert repair is not None
        self.assertEqual(json.loads(repair.repaired_text), {"log": {"level": "info"}})
        self.assertIn("квадратные скобки", repair.description)

    def test_decodes_config_stored_as_json_string(self) -> None:
        source = json.dumps(json.dumps({"route": {"final": "proxy"}}))

        repair = try_repair_singbox_config_text(source)

        self.assertIsNotNone(repair)
        assert repair is not None
        self.assertEqual(json.loads(repair.repaired_text), {"route": {"final": "proxy"}})
        self.assertIn("кавычки и экранирование", repair.description)

    def test_decodes_string_and_unwraps_single_object_array(self) -> None:
        source = json.dumps(json.dumps([{"outbounds": []}]))

        repair = try_repair_singbox_config_text(source)

        self.assertIsNotNone(repair)
        assert repair is not None
        self.assertEqual(json.loads(repair.repaired_text), {"outbounds": []})
        self.assertIn("кавычки и экранирование", repair.description)
        self.assertIn("квадратные скобки", repair.description)

    def test_refuses_ambiguous_or_syntactically_invalid_values(self) -> None:
        for text in ("{}", "[]", "[{}, {}]", "null", "42", '"not json"', "{"):
            with self.subTest(text=text):
                self.assertIsNone(try_repair_singbox_config_text(text))

    def test_file_recovery_preserves_original_in_unique_backups(self) -> None:
        original = '[{"log": {}}]'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "default.json"
            path.write_text(original, encoding="utf-8")

            first = repair_singbox_config_file(path, original)
            path.write_text(original, encoding="utf-8")
            second = repair_singbox_config_file(path, original)

            self.assertIsNotNone(first)
            self.assertIsNotNone(second)
            assert first is not None and first.backup_path is not None
            assert second is not None and second.backup_path is not None
            self.assertEqual(first.backup_path.name, "default.json.invalid.bak")
            self.assertEqual(second.backup_path.name, "default.json.invalid.1.bak")
            self.assertEqual(first.backup_path.read_text(encoding="utf-8"), original)
            self.assertEqual(second.backup_path.read_text(encoding="utf-8"), original)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"log": {}})

    def test_apply_persists_repair_before_requesting_runtime_transition(self) -> None:
        original = '[{"route": {"final": "proxy"}}]'

        class Controller:
            _active_core = ""
            connected = False
            _desired_connected = False

            @staticmethod
            def try_repair_singbox_json_text(text: str):
                return try_repair_singbox_config_text(text)

            @staticmethod
            def validate_singbox_json_text(text: str) -> tuple[bool, str]:
                return isinstance(json.loads(text), dict), "validated"

            @staticmethod
            def is_singbox_editor_mode() -> bool:
                return False

            @staticmethod
            def _request_transition(_reason: str) -> None:
                raise AssertionError("Disconnected apply must not request a transition")

            @staticmethod
            def _persist_singbox_config_repair(path: Path, text: str):
                repair = repair_singbox_config_file(path, text)
                return (object(), repair) if repair is not None else None

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "default.json"
            path.write_text('{"old": true}', encoding="utf-8")
            with patch(
                "xray_fluent.application.profile_service.ensure_active_config",
                return_value=path,
            ):
                ok, applied_path, message = apply_singbox_config_text(Controller(), original)

            self.assertTrue(ok)
            self.assertEqual(applied_path, path)
            self.assertIn("автоматически восстановлен", message)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"route": {"final": "proxy"}})
            self.assertEqual(
                path.with_name("default.json.invalid.bak").read_text(encoding="utf-8"),
                original,
            )


if __name__ == "__main__":
    unittest.main()
