"""Приложение — оконная программа: ни своей консоли, ни консолей дочерних процессов.

Консольная сборка прятала своё окно через ShowWindow, но в Windows 11 консоль
открывается во вкладке Windows Terminal, и её так не спрятать (жалоба 0.8.46).
Оконной программе консоль не нужна, но тогда любой консольный дочерний процесс
без CREATE_NO_WINDOW откроет своё окно — это и проверяется по исходникам.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SPAWNERS = {"run", "Popen", "check_output", "check_call", "call"}
# Окна у этих программ свои, а не консольные.
_GUI_TARGETS = {"explorer.exe", "open"}


def _spawn_calls(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        owner = node.func.value
        if node.func.attr in _SPAWNERS and isinstance(owner, ast.Name) and owner.id in ("subprocess", "_sp"):
            yield node


def _gui_target(call: ast.Call) -> bool:
    if not call.args or not isinstance(call.args[0], ast.List) or not call.args[0].elts:
        return False
    first = call.args[0].elts[0]
    return isinstance(first, ast.Constant) and first.value in _GUI_TARGETS


class WindowedBuildTests(unittest.TestCase):
    def test_builder_makes_a_windowed_program(self) -> None:
        source = (ROOT / "build.py").read_text(encoding="utf-8")
        self.assertIn('"--windowed"', source)
        self.assertNotIn('"--console"', source)

    def test_every_child_process_starts_without_a_console_window(self) -> None:
        files = [ROOT / "main.py", *sorted((ROOT / "xray_fluent").rglob("*.py"))]
        offenders = []
        for path in files:
            for call in _spawn_calls(path):
                keywords = {keyword.arg for keyword in call.keywords}
                if "creationflags" in keywords or None in keywords or _gui_target(call):
                    continue
                offenders.append(f"{path.relative_to(ROOT)}:{call.lineno}")
        self.assertEqual(offenders, [], "subprocess без creationflags=CREATE_NO_WINDOW")


if __name__ == "__main__":
    unittest.main()
