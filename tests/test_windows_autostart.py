from __future__ import annotations

import subprocess
import sys
import unittest
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from xray_fluent.platform.windows import startup
from xray_fluent.platform.windows.startup import StartupError, StartupTarget

NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
TARGET = StartupTarget(
    Path(r"C:\Игры & VPN\Zapret KVN\ZapretKVN.exe"), "--tray", Path(r"C:\Игры & VPN\Zapret KVN")
)


def _completed(code: int, text: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], code, stdout=text.encode(), stderr=b"")


class TaskDefinitionTests(unittest.TestCase):
    """Автозапуск — задание Планировщика: запись в Run для программы,
    требующей прав администратора, Windows при входе молча пропускает."""

    def setUp(self) -> None:
        self.root = ElementTree.fromstring(
            startup.build_task_xml(TARGET, r"ПК\Пользователь").split("?>", 1)[1]
        )

    def text(self, path: str) -> str:
        return self.root.find(path, NS).text

    def test_task_starts_at_logon_of_this_user_without_a_uac_prompt(self) -> None:
        self.assertEqual(self.text("t:Triggers/t:LogonTrigger/t:UserId"), r"ПК\Пользователь")
        self.assertEqual(self.text("t:Principals/t:Principal/t:RunLevel"), "HighestAvailable")
        self.assertEqual(self.text("t:Principals/t:Principal/t:LogonType"), "InteractiveToken")

    def test_task_runs_the_app_in_tray_from_its_own_directory(self) -> None:
        self.assertEqual(self.text("t:Actions/t:Exec/t:Command"), str(TARGET.executable))
        self.assertEqual(self.text("t:Actions/t:Exec/t:Arguments"), "--tray")
        self.assertEqual(self.text("t:Actions/t:Exec/t:WorkingDirectory"), str(TARGET.working_dir))

    def test_task_is_not_stopped_or_skipped_by_scheduler_defaults(self) -> None:
        # По умолчанию Планировщик не запускает задания на батарее и
        # завершает их через 72 часа — для VPN-клиента это недопустимо.
        self.assertEqual(self.text("t:Settings/t:DisallowStartIfOnBatteries"), "false")
        self.assertEqual(self.text("t:Settings/t:StopIfGoingOnBatteries"), "false")
        self.assertEqual(self.text("t:Settings/t:ExecutionTimeLimit"), "PT0S")


class ApplyTests(unittest.TestCase):
    def setUp(self) -> None:
        for name, value in (("platform", "win32"),):
            patcher = patch.object(startup.sys, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.calls: list[tuple[str, ...]] = []
        self.results: dict[str, subprocess.CompletedProcess] = {}
        patcher = patch.object(startup, "_schtasks", self._schtasks)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.legacy = Mock()
        patcher = patch.object(startup, "_remove_legacy_run_entries", self.legacy)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _schtasks(self, *arguments: str):
        self.calls.append(arguments)
        return self.results.get(arguments[0], _completed(0))

    def test_enabling_registers_the_task_and_drops_the_dead_registry_entry(self) -> None:
        startup.enable(TARGET)
        (call,) = self.calls
        self.assertEqual(call[:3], ("/Create", "/TN", startup.TASK_NAME))
        self.assertIn("/F", call)
        self.legacy.assert_called_once()

    def test_scheduler_refusal_is_reported_with_its_own_text(self) -> None:
        self.results["/Create"] = _completed(1, "ERROR: Access is denied.")
        with self.assertRaises(StartupError) as caught:
            startup.enable(TARGET)
        self.assertIn("Access is denied", str(caught.exception))

    def test_disabling_removes_an_existing_task(self) -> None:
        startup.disable()
        self.assertEqual([call[0] for call in self.calls], ["/Query", "/Delete"])
        self.legacy.assert_called_once()

    def test_disabling_without_a_task_is_not_an_error(self) -> None:
        self.results["/Query"] = _completed(1)
        startup.disable()
        self.assertEqual([call[0] for call in self.calls], ["/Query"])

    def test_launch_repair_reregisters_the_current_path_and_never_raises(self) -> None:
        self.results["/Create"] = _completed(1, "denied")
        with patch.object(startup.sys, "frozen", True, create=True), \
                patch.object(startup, "startup_target", return_value=TARGET):
            startup.repair(True)
        self.assertEqual(self.calls[0][0], "/Create")

    def test_launch_repair_leaves_a_development_checkout_alone(self) -> None:
        with patch.object(startup.sys, "frozen", False, create=True):
            startup.repair(True)
        self.assertEqual(self.calls, [])


class ControllerSettingTests(unittest.TestCase):
    """Переключатель обязан показывать правду, а не то, что хотели сохранить."""

    def _controller(self, enabled_before: bool):
        from xray_fluent.application.controller import AppController
        from xray_fluent.profiles.models import AppSettings

        controller = SimpleNamespace(
            state=SimpleNamespace(settings=AppSettings(launch_on_startup=enabled_before)),
            settings_changed=Mock(),
            status=Mock(),
            schedule_save=Mock(),
            _apply_subscription_timer_interval=Mock(),
            _handle_auto_switch_setting_change=Mock(),
            _rotation_settings_signature=Mock(return_value=()),
            connected=False,
            _desired_connected=False,
        )
        return AppController, controller, AppSettings

    def test_rejected_autostart_is_rolled_back_in_settings(self) -> None:
        AppController, controller, AppSettings = self._controller(False)
        with patch(
            "xray_fluent.application.controller.windows_startup.apply",
            side_effect=StartupError("Access is denied"),
        ), patch("xray_fluent.application.controller.cancel_smart_check"):
            AppController.update_settings(controller, AppSettings(launch_on_startup=True))
        self.assertFalse(controller.state.settings.launch_on_startup)
        self.assertEqual(controller.settings_changed.emit.call_count, 2)
        self.assertIn("Access is denied", controller.status.emit.call_args.args[1])

    def test_accepted_autostart_is_applied_once(self) -> None:
        AppController, controller, AppSettings = self._controller(False)
        with patch("xray_fluent.application.controller.windows_startup.apply") as apply, \
                patch("xray_fluent.application.controller.cancel_smart_check"):
            AppController.update_settings(controller, AppSettings(launch_on_startup=True))
        apply.assert_called_once_with(True)
        self.assertTrue(controller.state.settings.launch_on_startup)


@unittest.skipUnless(sys.platform == "win32", "Планировщик заданий Windows")
class RealSchedulerTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = patch.object(startup, "TASK_NAME", "ZapretKVN Autostart Test")
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(startup, "_remove_legacy_run_entries")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(startup.disable)

    def test_task_is_accepted_by_windows_and_removed_again(self) -> None:
        self.assertFalse(startup.is_registered())
        startup.enable(TARGET)
        self.assertTrue(startup.is_registered())
        # Повторное включение перезаписывает задание, а не падает.
        startup.enable(TARGET)
        startup.disable()
        self.assertFalse(startup.is_registered())


if __name__ == "__main__":
    unittest.main()
