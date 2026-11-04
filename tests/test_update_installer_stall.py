from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from xray_fluent.updates.installer import phrases, runner


class StallTextTests(unittest.TestCase):
    def test_jokes_continue_while_the_step_moves(self) -> None:
        self.assertIsNone(phrases.stalled_text(0))
        self.assertIsNone(phrases.stalled_text(phrases.STALL_AFTER_S - 1))

    def test_a_stuck_step_gets_an_honest_text_with_the_log_names(self) -> None:
        text = phrases.stalled_text(phrases.STALL_AFTER_S)
        self.assertIsNotNone(text)
        self.assertIn("update.log", text)
        self.assertIn("update_stall.log", text)
        self.assertNotIn("ТСПУ", text)


class StallDumpTests(unittest.TestCase):
    def test_dump_is_armed_into_its_own_file_and_cancelled_afterwards(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app_dir = Path(directory)
            with patch.object(runner.faulthandler, "dump_traceback_later") as arm, patch.object(
                runner.faulthandler, "cancel_dump_traceback_later"
            ) as cancel:
                handle = runner.arm_stall_dump(app_dir)
                self.assertIsNotNone(handle)
                arm.assert_called_once()
                args, kwargs = arm.call_args
                self.assertEqual(args[0], runner.STALL_DUMP_AFTER_S)
                self.assertTrue(kwargs["repeat"])
                runner.disarm_stall_dump(handle)
                cancel.assert_called_once()
            stall_log = app_dir / "data" / "logs" / runner.STALL_LOG_NAME
            self.assertFalse(stall_log.exists(), "нормальная установка не оставляет файл дампа")
            self.assertNotEqual(stall_log.name, "update.log")  # общий журнал ротируется

    def test_a_dump_that_was_written_is_kept_for_support(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(runner.faulthandler, "dump_traceback_later"), patch.object(
                runner.faulthandler, "cancel_dump_traceback_later"
            ):
                dump = runner.arm_stall_dump(Path(directory))
                dump.handle.write("Thread 0x1 (most recent call first):\n  File swap.py, line 1\n")
                dump.handle.flush()
                runner.disarm_stall_dump(dump)
            kept = Path(directory) / "data" / "logs" / runner.STALL_LOG_NAME
            self.assertTrue(kept.is_file())
            self.assertIn("swap.py", kept.read_text(encoding="utf-8"))

    def test_a_failing_dump_never_blocks_the_install(self) -> None:
        with patch.object(runner.faulthandler, "dump_traceback_later", side_effect=RuntimeError("boom")):
            with tempfile.TemporaryDirectory() as directory:
                self.assertIsNone(runner.arm_stall_dump(Path(directory)))
                # Файл закрыт и убран: на Windows открытый дескриптор не дал бы удалить каталог.
                self.assertFalse((Path(directory) / "data" / "logs" / runner.STALL_LOG_NAME).exists())
        runner.disarm_stall_dump(None)


if __name__ == "__main__":
    unittest.main()
