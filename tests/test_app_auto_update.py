from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from xray_fluent.updates import auto_update
from xray_fluent.updates.auto_update import (
    MAX_AUTO_ATTEMPTS,
    RESUME_WINDOW_S,
    RETRY_BACKOFF_S,
    auto_install_block_reason,
    purge_update_leftovers,
    record_attempt,
    resolve_startup,
)

NOW = 1_800_000_000.0


class AttemptRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "runtime" / "app_update_attempt.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_successful_update_clears_record_and_resumes_connection(self) -> None:
        record_attempt("0.8.2", reconnect=True, now=NOW, path=self.path)
        outcome = resolve_startup("0.8.2", now=NOW + 20, path=self.path)
        self.assertTrue(outcome.updated)
        self.assertIs(outcome.resume, True)
        self.assertFalse(self.path.exists())

    def test_disconnected_state_is_restored_as_disconnected(self) -> None:
        record_attempt("0.8.2", reconnect=False, now=NOW, path=self.path)
        outcome = resolve_startup("0.8.2", now=NOW + 20, path=self.path)
        self.assertIs(outcome.resume, False)

    def test_rollback_keeps_counter_and_consumes_resume_once(self) -> None:
        record_attempt("0.8.2", reconnect=True, now=NOW, path=self.path)
        first = resolve_startup("0.8.1", now=NOW + 20, path=self.path)
        self.assertFalse(first.updated)
        self.assertIs(first.resume, True)
        second = resolve_startup("0.8.1", now=NOW + 40, path=self.path)
        self.assertIsNone(second.resume)
        self.assertEqual(second.attempts, 1)
        self.assertTrue(self.path.exists())

    def test_script_success_with_stale_version_counts_as_failure(self) -> None:
        # Скрипт отработал без ошибок, но запущенная сборка всё ещё старая.
        record_attempt("0.8.2", reconnect=False, now=NOW, path=self.path)
        self.assertFalse(resolve_startup("0.8.1", now=NOW + 5, path=self.path).updated)

    def test_resume_ignored_after_window(self) -> None:
        record_attempt("0.8.2", reconnect=True, now=NOW, path=self.path)
        outcome = resolve_startup("0.8.2", now=NOW + RESUME_WINDOW_S + 1, path=self.path)
        self.assertIsNone(outcome.resume)

    def test_unparsable_or_corrupt_record_is_discarded(self) -> None:
        self.path.parent.mkdir(parents=True)
        self.path.write_text(json.dumps({"version": "nightly", "attempts": 1}), encoding="utf-8")
        self.assertIsNone(resolve_startup("0.8.1", now=NOW, path=self.path))
        self.assertFalse(self.path.exists())
        self.path.write_text("{broken", encoding="utf-8")
        self.assertIsNone(resolve_startup("0.8.1", now=NOW, path=self.path))
        self.assertFalse(self.path.exists())

    def test_rejected_archive_counts_without_resuming_anything(self) -> None:
        record_attempt("0.8.2", reconnect=False, restarting=False, now=NOW, path=self.path)
        outcome = resolve_startup("0.8.1", now=NOW + 5, path=self.path)
        self.assertIsNone(outcome.resume)
        self.assertEqual(record_attempt("0.8.2", reconnect=True, now=NOW, path=self.path).attempts, 2)

    def test_attempts_accumulate_per_version_and_reset_on_new_release(self) -> None:
        record_attempt("0.8.2", reconnect=False, now=NOW, path=self.path)
        self.assertEqual(record_attempt("0.8.2", reconnect=False, now=NOW, path=self.path).attempts, 2)
        self.assertEqual(record_attempt("0.8.3", reconnect=False, now=NOW, path=self.path).attempts, 1)


class AutoInstallPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "app_update_attempt.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def reason(self, version: str = "0.8.2", current: str = "0.8.1", now: float = NOW) -> str:
        return auto_install_block_reason(version, current, now=now, path=self.path)

    def test_fresh_newer_version_is_allowed(self) -> None:
        self.assertEqual(self.reason(), "")

    def test_unparsable_versions_never_auto_install(self) -> None:
        # Строковое сравнение «не равно» считало бы такой тег вечно новым.
        self.assertTrue(self.reason(version="latest"))
        self.assertTrue(self.reason(current="dev"))

    def test_not_newer_is_refused(self) -> None:
        self.assertTrue(self.reason(version="0.8.1"))
        self.assertTrue(self.reason(version="0.8.0"))

    def test_failed_attempt_backs_off_then_retries(self) -> None:
        record_attempt("0.8.2", reconnect=False, now=NOW, path=self.path)
        self.assertIn("через", self.reason(now=NOW + 60))
        self.assertEqual(self.reason(now=NOW + RETRY_BACKOFF_S + 1), "")
        record_attempt("0.8.2", reconnect=False, now=NOW, path=self.path)
        self.assertTrue(self.reason(now=NOW + RETRY_BACKOFF_S + 1))
        self.assertEqual(self.reason(now=NOW + 2 * RETRY_BACKOFF_S + 1), "")

    def test_attempt_cap_stops_the_restart_loop(self) -> None:
        for _ in range(MAX_AUTO_ATTEMPTS):
            record_attempt("0.8.2", reconnect=False, now=NOW, path=self.path)
        self.assertIn("не удалась", self.reason(now=NOW + 365 * 86400))
        # Новый релиз снова ставится сам.
        self.assertEqual(self.reason(version="0.8.3"), "")


class LeftoverPurgeTests(unittest.TestCase):
    def test_only_old_leftovers_are_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temp_dir = root / "temp"
            runtime = root / "runtime"

            def make(path: Path, age: float) -> Path:
                path.mkdir(parents=True)
                (path / "payload").write_bytes(b"x")
                os.utime(path, (NOW - age, NOW - age))
                return path

            old_temp = make(temp_dir / "zapretkvn_update_old", auto_update.TEMP_LEFTOVER_MIN_AGE_S + 5)
            fresh_temp = make(temp_dir / "zapretkvn_update_new", 30)
            foreign = make(temp_dir / "other_app", 10 ** 6)
            old_backup = make(runtime / "update_backups" / "a", auto_update.BACKUP_LEFTOVER_MIN_AGE_S + 5)
            fresh_backup = make(runtime / "update_backups" / "b", auto_update.TEMP_LEFTOVER_MIN_AGE_S + 5)
            legacy = make(runtime / "update_backup", auto_update.BACKUP_LEFTOVER_MIN_AGE_S + 5)

            removed = purge_update_leftovers(runtime_dir=runtime, temp_dir=temp_dir, now=NOW)

            self.assertEqual(removed, 3)
            for gone in (old_temp, old_backup, legacy):
                self.assertFalse(gone.exists(), gone)
            for kept in (fresh_temp, foreign, fresh_backup):
                self.assertTrue(kept.exists(), kept)


class ResumeAfterUpdateTests(unittest.TestCase):
    def _controller(self, auto_connect_last: bool = False):
        from xray_fluent.application.controller import AppController

        controller = SimpleNamespace(
            state=SimpleNamespace(settings=SimpleNamespace(auto_connect_last=auto_connect_last)),
            auto_connect_if_needed=Mock(),
            locked=False,
            selected_node=object(),
            _desired_connected=False,
            _log=Mock(),
            _request_transition=Mock(),
            _can_connect_without_selected_node=Mock(return_value=False),
        )
        return AppController, controller

    def test_was_connected_reconnects(self) -> None:
        cls, controller = self._controller()
        cls.resume_after_app_update(controller, True)
        self.assertTrue(controller._desired_connected)
        controller._request_transition.assert_called_once()

    def test_was_disconnected_suppresses_auto_connect(self) -> None:
        cls, controller = self._controller(auto_connect_last=True)
        cls.resume_after_app_update(controller, False)
        self.assertFalse(controller._desired_connected)
        controller._request_transition.assert_not_called()
        controller.auto_connect_if_needed.assert_not_called()

    def test_auto_connect_setting_keeps_its_startup_order(self) -> None:
        cls, controller = self._controller(auto_connect_last=True)
        cls.resume_after_app_update(controller, True)
        controller.auto_connect_if_needed.assert_called_once()
        controller._request_transition.assert_not_called()


if __name__ == "__main__":
    unittest.main()
