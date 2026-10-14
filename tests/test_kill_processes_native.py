"""Осиротевшие ядра ищутся снимком WinAPI, PowerShell — только запасной путь."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from xray_fluent.platform.windows import subprocess_utils
from zapret_update import processes as win_processes


class KillProcessesByPathTests(unittest.TestCase):
    def test_native_snapshot_kills_and_waits_without_powershell(self) -> None:
        exe = Path("C:/app/core/sing-box.exe")
        with patch.object(subprocess_utils.os, "name", "nt"), patch.object(
            win_processes, "processes_at", return_value=[101, 202]
        ) as found, patch.object(win_processes, "terminate") as terminate, patch.object(
            win_processes, "wait_for_exit", return_value=True
        ) as waited, patch.object(subprocess_utils, "run_text") as run_text:
            self.assertTrue(subprocess_utils.kill_processes_by_path("sing-box.exe", exe, pump=False))

        found.assert_called_once()
        self.assertEqual(found.call_args.args[0].as_posix(), exe.as_posix())
        self.assertEqual([call.args[0] for call in terminate.call_args_list], [101, 202])
        self.assertEqual([call.args[0] for call in waited.call_args_list], [101, 202])
        run_text.assert_not_called()

    def test_nothing_found_is_false_without_powershell(self) -> None:
        with patch.object(subprocess_utils.os, "name", "nt"), patch.object(
            win_processes, "processes_at", return_value=[]
        ), patch.object(subprocess_utils, "run_text") as run_text:
            self.assertFalse(
                subprocess_utils.kill_processes_by_path("winws2.exe", Path("C:/app/zapret/winws2.exe"), pump=False)
            )
        run_text.assert_not_called()

    def test_powershell_remains_the_fallback_when_winapi_fails(self) -> None:
        class _Result:
            returncode = 0
            stdout = b"1"
            stderr = b""

        with patch.object(subprocess_utils.os, "name", "nt"), patch.object(
            win_processes, "processes_at", side_effect=OSError(5, "denied")
        ), patch.object(subprocess_utils, "run_text", return_value=_Result()) as run_text:
            self.assertTrue(
                subprocess_utils.kill_processes_by_path("xray.exe", Path("C:/app/core/xray.exe"), pump=False)
            )
        self.assertEqual(run_text.call_args.args[0][0], "powershell")


if __name__ == "__main__":
    unittest.main()
