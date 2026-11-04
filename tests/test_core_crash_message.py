"""Авария ядра: код выхода простыми словами и подсказка про чужой Zapret в режиме TUN."""
from __future__ import annotations

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from PyQt6.QtCore import QProcess

from xray_fluent.application import controller as controller_module
from xray_fluent.application.controller import AppController
from xray_fluent.application.zapret_conflict import CRASH_HINT, foreign_crash_hint
from xray_fluent.diagnostics.runtime_logging import RuntimeLogContext
from xray_fluent.engines.exit_codes import describe_exit_code
from xray_fluent.engines.singbox.manager import SingBoxManager


class ExitCodeTests(TestCase):
    def test_the_crash_from_the_field_is_shown_as_hex_with_a_reason(self) -> None:
        text = describe_exit_code(-1073740777)
        self.assertIn("0xC0000417", text)
        self.assertIn("WinDivert", text)

    def test_unsigned_and_signed_forms_give_the_same_answer(self) -> None:
        self.assertEqual(describe_exit_code(-1073740777), describe_exit_code(0xC0000417))

    def test_small_codes_stay_numbers_and_unknown_big_ones_get_only_hex(self) -> None:
        self.assertEqual(describe_exit_code(1), "код 1")
        self.assertEqual(describe_exit_code(62097), "код 62097")
        self.assertEqual(describe_exit_code(0xDEADBEEF), "код 0xDEADBEEF")
        self.assertEqual(describe_exit_code(None), "код неизвестен")


class ManagerCrashMessageTests(TestCase):
    def crash_message(self, exit_code: int, *, stop_requested: bool = False) -> list[str]:
        manager = SingBoxManager()
        manager._process = SimpleNamespace(exitCode=lambda: exit_code, errorString=lambda: "")
        manager._stop_requested = stop_requested
        manager._starting = False
        manager._runtime_error_reported = False
        seen: list[str] = []
        manager.error.connect(seen.append)
        manager._on_error(QProcess.ProcessError.Crashed)
        return seen

    def test_a_crash_names_the_exit_code_instead_of_an_empty_parenthesis(self) -> None:
        (message,) = self.crash_message(-1073740777)
        self.assertIn("аварийно завершился", message)
        self.assertIn("0xC0000417", message)
        self.assertNotIn("Crashed ()", message)

    def test_a_requested_stop_is_not_reported_as_a_crash(self) -> None:
        self.assertEqual(self.crash_message(-1, stop_requested=True), [])


class HintTests(TestCase):
    def test_hint_names_the_foreign_zapret_files_only(self) -> None:
        text = foreign_crash_hint(lambda: ["winws2.exe"])
        self.assertEqual(text, CRASH_HINT.format(names="winws2.exe"))
        self.assertIn("«Прокси»", text)

    def test_no_foreign_zapret_or_a_failing_search_gives_no_hint(self) -> None:
        self.assertEqual(foreign_crash_hint(lambda: []), "")

        def broken() -> list[str]:
            raise OSError("snapshot failed")

        self.assertEqual(foreign_crash_hint(broken), "")


class ControllerCrashTests(TestCase):
    def run_handler(self, mode: str, message: str) -> str:
        context = RuntimeLogContext(engine="sing-box", role="front", mode=mode, generation=2)
        fake = SimpleNamespace(
            _record_core_failure=Mock(),
            _core_log_contexts={"sing-box": context},
            state=SimpleNamespace(settings=SimpleNamespace(tun_mode=mode == "tun")),
            _transition_generation=2,
            _log=Mock(),
            _fail_transition=Mock(),
        )
        with patch.object(controller_module, "foreign_crash_hint", lambda: " [ПОДСКАЗКА про Zapret]"):
            AppController._on_core_error(fake, "sing-box", message)
        return fake._fail_transition.call_args.args[0]

    def test_a_tun_crash_gets_the_foreign_zapret_hint(self) -> None:
        shown = self.run_handler("tun", "sing-box аварийно завершился: код 0xC0000417")
        self.assertIn("ПОДСКАЗКА про Zapret", shown)

    def test_a_proxy_mode_crash_and_ordinary_errors_do_not(self) -> None:
        self.assertNotIn("ПОДСКАЗКА", self.run_handler("proxy", "sing-box аварийно завершился: код 0xC0000417"))
        self.assertNotIn("ПОДСКАЗКА", self.run_handler("tun", "sing-box process error: ReadError"))
