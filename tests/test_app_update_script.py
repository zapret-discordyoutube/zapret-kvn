from pathlib import Path
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

    def test_directory_moves_are_atomic_and_have_unique_destinations(self) -> None:
        # Move-Item каталога в существующий контейнер способен оставить там
        # частичную копию. Повтор после блокировки тогда падает уже из-за того,
        # что destination существует. Directory.Move на одном томе переименует
        # весь top-level каталог либо не изменит его.
        script = self.script()
        self.assertIn("function Move-WithRetry", script)
        self.assertNotIn("Move-Item", script)
        self.assertIn("[System.IO.Directory]::Move($path, $destination)", script)
        self.assertIn("[System.IO.File]::Move($path, $destination)", script)
        self.assertIn("$backupPath = Join-Path $backupTarget $_.Name", script)
        self.assertIn("$restorePath = Join-Path $appDir $_.Name", script)

    def test_each_attempt_uses_a_unique_backup_directory(self) -> None:
        script = self.script()
        self.assertIn("$backupRootDir = Join-Path $runtimeDir 'update_backups'", script)
        self.assertIn(
            "$backupDir = Join-Path $backupRootDir (Split-Path -Leaf $tempDir)",
            script,
        )
        self.assertNotIn("Join-Path $runtimeDir 'update_backup'", script)

    def test_moves_go_through_the_retry_helper(self) -> None:
        script = self.script()
        self.assertEqual(2, script.count("Move-WithRetry -path"))

    def test_rollback_stops_children_and_publishes_error_before_restart(self) -> None:
        script = self.script()
        catch = script.index("catch {", script.index("Updated application exited immediately"))
        rollback = script[catch:]
        self.assertIn("Stop-AppProcesses -root $appRoot", rollback)
        write_error = rollback.index("Set-Content -LiteralPath $errorLog")
        restart = rollback.index("$rollbackStarted = Start-Process")
        self.assertLess(write_error, restart)
        self.assertIn("$rollbackStarted.HasExited", rollback)
        self.assertIn("[System.Windows.Forms.MessageBox]::Show", rollback)

    def test_rollback_does_not_delete_original_items_that_never_moved(self) -> None:
        script = self.script()
        self.assertIn("$originalNames = @($installedItems | ForEach-Object { $_.Name })", script)
        self.assertIn(
            "($sourceNames -contains $_.Name) -and ($originalNames -notcontains $_.Name)",
            script,
        )
        self.assertIn("Remove-WithRetry -path $restorePath", script)
        self.assertIn("$rollbackErrors.Count -eq 0", script)

    def test_backup_preparation_is_inside_the_rollback_boundary(self) -> None:
        script = self.script()
        transaction = script.index("try {", script.index("$sourceNames = @()"))
        prepare_backup = script.index(
            "New-Item -ItemType Directory -Path $backupReplaceDir", transaction
        )
        wait_for_exit = script.index("Get-Process -Id $pidToWait", transaction)
        outer_catch = script.index("catch {", wait_for_exit)
        self.assertLess(transaction, prepare_backup)
        self.assertLess(prepare_backup, wait_for_exit)
        self.assertLess(wait_for_exit, outer_catch)

    def test_paths_are_quoted_for_powershell(self) -> None:
        script = self.script()
        self.assertIn("$appDir = 'J:\\ZapretKVN'", script)
        self.assertIn("$preserveNames = @('data')", script)

    def test_tray_flag_selects_the_restart_command(self) -> None:
        self.assertIn("'--tray'", self.script(restart_in_tray=True))
        self.assertNotIn("'--tray'", self.script(restart_in_tray=False))


if __name__ == "__main__":
    unittest.main()


class SelectorRetryTests(unittest.TestCase):
    """Переключение узла идёт по loopback, но отказ там означает полный
    перезапуск ядра, поэтому единичный таймаут не должен решать исход."""

    def test_transient_timeout_is_retried(self) -> None:
        from urllib.error import URLError

        from xray_fluent.engines.singbox import selector_api

        attempts = []

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        class Opener:
            def open(self, request, timeout):
                attempts.append(timeout)
                if len(attempts) < 3:
                    raise URLError("timed out")
                return Response()

        original_opener = selector_api.build_opener
        original_delay = selector_api.RETRY_DELAY_SEC
        selector_api.build_opener = lambda *args, **kwargs: Opener()
        selector_api.RETRY_DELAY_SEC = 0
        try:
            ok, output = selector_api.select_outbound(9090, "select", "node")
        finally:
            selector_api.build_opener = original_opener
            selector_api.RETRY_DELAY_SEC = original_delay

        self.assertTrue(ok, output)
        self.assertEqual(3, len(attempts))
        self.assertGreaterEqual(attempts[0], 5.0)

    def test_rejection_by_the_core_is_not_retried(self) -> None:
        from urllib.error import HTTPError

        from xray_fluent.engines.singbox import selector_api

        attempts = []

        class Opener:
            def open(self, request, timeout):
                attempts.append(timeout)
                raise HTTPError("url", 404, "Not Found", None, None)

        original_opener = selector_api.build_opener
        selector_api.build_opener = lambda *args, **kwargs: Opener()
        try:
            ok, output = selector_api.select_outbound(9090, "select", "node")
        finally:
            selector_api.build_opener = original_opener

        self.assertFalse(ok)
        self.assertEqual(1, len(attempts))
        self.assertIn("404", output)
