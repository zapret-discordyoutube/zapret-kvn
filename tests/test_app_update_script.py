from pathlib import Path
import re
import unittest

from xray_fluent.app_updater import _build_update_script


class UpdateScriptTests(unittest.TestCase):
    """Скрипт заменяет файлы уже после выхода приложения, поэтому его ошибки
    видны только на устройстве пользователя и стоят ему сломанной установки."""

    def script(self, *, restart_in_tray: bool = True) -> str:
        return _build_update_script(
            current_pid=4242,
            source_dir=Path(r"C:\Temp\src"),
            app_dir=Path(r"J:\ZapretKVN"),
            exe_name="ZapretKVN.exe",
            tmp_dir=Path(r"C:\Temp\upd"),
            restart_in_tray=restart_in_tray,
        )

    def test_cores_are_stopped_before_files_are_moved(self) -> None:
        # Ядра живут отдельными процессами внутри каталога приложения и держат
        # core\ открытым: ожидания одного основного процесса не хватает, и
        # перемещение падало с "файл занят другим процессом".
        script = self.script()
        self.assertIn("function Stop-AppProcesses", script)
        stop_call = script.index("Stop-AppProcesses -root $appRoot")
        first_move_call = script.index("Move-WithRetry -path")
        self.assertLess(stop_call, first_move_call)

    def test_every_move_retries_and_fails_loudly(self) -> None:
        # Windows освобождает файл не мгновенно даже после выхода процесса.
        script = self.script()
        self.assertIn("function Move-WithRetry", script)
        for line in script.splitlines():
            stripped = line.strip()
            if stripped.startswith("Move-Item") or "    Move-Item" in line:
                # Без -ErrorAction Stop ошибка не терминирующая: catch не сработает,
                # функция отчитается об успехе, а файл останется на месте.
                self.assertIn("-ErrorAction Stop", stripped, stripped)

    def test_moves_go_through_the_retry_helper(self) -> None:
        script = self.script()
        lines = script.splitlines()
        start = next(i for i, line in enumerate(lines) if line.startswith("function Move-WithRetry"))
        end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}")
        outside_helper = [
            line.strip()
            for index, line in enumerate(lines)
            if re.match(r"^\s*Move-Item\b", line) and not start <= index <= end
        ]
        self.assertEqual([], outside_helper)

    def test_paths_are_quoted_for_powershell(self) -> None:
        script = self.script()
        self.assertIn("$appDir = 'J:\\ZapretKVN'", script)
        self.assertIn("$preserveNames = @('data')", script)

    def test_tray_flag_selects_the_restart_command(self) -> None:
        self.assertIn("'--tray'", self.script(restart_in_tray=True))
        self.assertNotIn("'--tray'", self.script(restart_in_tray=False))


if __name__ == "__main__":
    unittest.main()
