"""Раннер выпуска, возобновлённый в новом процессе, должен находить zapret_update.

Случай 2026-11-04: перезагрузка хоста оборвала выпуск на фазе draft_created; повторный запуск
упал в upload_store с «No module named 'zapret_update'», потому что корень репозитория
попадал в sys.path только побочным эффектом более ранних фаз.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release_windows.py"

CODE = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location("release_windows_under_test", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
# То, что поздние фазы импортируют лениво (строки upload_store, подпись, список выпуска, заметки):
from zapret_update import manifest, publish, release_notes, sign
print("imports ok")
"""


class ResumeImportsTests(unittest.TestCase):
    def test_a_fresh_isolated_process_finds_zapret_update_after_loading_the_runner(self) -> None:
        # -I: без текущей папки и PYTHONPATH, как новый процесс после перезагрузки.
        result = subprocess.run(
            [sys.executable, "-I", "-c", CODE, str(SCRIPT)],
            capture_output=True, text=True, timeout=60, cwd="/",
        )
        self.assertEqual(result.returncode, 0, result.stderr[-800:])
        self.assertIn("imports ok", result.stdout)


if __name__ == "__main__":
    unittest.main()
