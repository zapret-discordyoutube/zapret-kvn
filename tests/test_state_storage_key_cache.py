"""Сохранение состояния: PBKDF2 один раз за сессию, формат файла прежний."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from xray_fluent.platform.windows import security
from xray_fluent.profiles import storage as storage_module
from xray_fluent.profiles.models import AppState, Node
from xray_fluent.profiles.storage import StateStorage


class StateStorageKeyCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state_file = Path(self._tmp.name) / "state.json"
        patcher = mock.patch.object(StateStorage, "_ensure_dirs", lambda self: None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _state(self, name: str) -> AppState:
        state = AppState()
        state.nodes = [Node(id="a", name=name)]
        return state

    def test_repeated_saves_derive_key_once(self) -> None:
        storage = StateStorage(self.state_file)
        storage.passphrase = "secret"
        with mock.patch.object(
            storage_module, "derive_passphrase_key", wraps=security.derive_passphrase_key
        ) as derive:
            for index in range(3):
                storage.save(self._state(f"n{index}"))
        self.assertEqual(derive.call_count, 1)

    def test_saved_file_decrypts_with_the_standard_routine(self) -> None:
        storage = StateStorage(self.state_file)
        storage.passphrase = "secret"
        storage.save(self._state("first"))
        storage.save(self._state("second"))
        text = self.state_file.read_text(encoding="utf-8")
        self.assertTrue(security.is_passphrase_encrypted(text))
        self.assertIn(b'"second"', security.decrypt_with_passphrase(text, "secret"))

    def test_passphrase_change_derives_new_key(self) -> None:
        storage = StateStorage(self.state_file)
        storage.passphrase = "one"
        storage.save(self._state("x"))
        storage.passphrase = "two"
        storage.save(self._state("y"))
        text = self.state_file.read_text(encoding="utf-8")
        with self.assertRaises(ValueError):
            security.decrypt_with_passphrase(text, "one")
        self.assertIn(b'"y"', security.decrypt_with_passphrase(text, "two"))

    def test_plain_save_without_passphrase(self) -> None:
        storage = StateStorage(self.state_file)
        storage.save(self._state("plain"))
        self.assertTrue(self.state_file.read_text(encoding="utf-8").lstrip().startswith("{"))


if __name__ == "__main__":
    unittest.main()
