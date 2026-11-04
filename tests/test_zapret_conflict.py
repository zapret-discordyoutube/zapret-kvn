"""Самопроверка «Zapret мешает туннелю»: поиск чужого winws и ветки проверки своего."""
from __future__ import annotations

import os
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from PyQt6.QtCore import QObject

from xray_fluent.application import zapret_conflict as zc
from xray_fluent.application.zapret_conflict import CONFLICT_NOTICE, ZapretConflictCheck
from xray_fluent.engines.zapret.foreign import foreign_zapret_processes

OWN2 = r"C:\Apps\ZapretKVN\zapret\exe\winws2.exe"
OWN1 = r"C:\Apps\ZapretKVN\zapret\exe\winws.exe"
THEIRS = r"D:\Zapret2GUI\bin\winws2.exe"


class ForeignProcessesTests(TestCase):
    def test_own_processes_are_not_foreign_and_unknown_paths_are(self) -> None:
        listing = [(10, OWN2), (11, THEIRS), (12, ""), (os.getpid(), THEIRS)]
        found = foreign_zapret_processes([OWN2, OWN1], enumerate_processes=lambda: listing)
        self.assertEqual(found, [(11, THEIRS), (12, "")])

    def test_path_comparison_ignores_case_on_windows_style_paths(self) -> None:
        if os.name != "nt":
            self.skipTest("регистр пути значим только на Windows")
        found = foreign_zapret_processes([OWN2], enumerate_processes=lambda: [(1, OWN2.upper())])
        self.assertEqual(found, [])

    def test_nothing_running_means_nothing_foreign(self) -> None:
        self.assertEqual(foreign_zapret_processes([OWN2], enumerate_processes=lambda: []), [])


class FakeController(QObject):
    def __init__(self, *, running=True, rule=None, required=False, tun=True) -> None:
        super().__init__()
        self.connected = True
        self.locked = False
        self._active_session = SimpleNamespace(tun_mode=tun)
        self.zapret = SimpleNamespace(running=running, plan="PLAN" if running else None, rule=rule, stop=Mock(), apply=Mock())
        self.bypass = SimpleNamespace(required=lambda node: required)
        self.selected_node = object()
        self._log = Mock()
        self.status = Mock()
        self.save = Mock()
        self.settings_changed = Mock()
        self.state = SimpleNamespace(settings=SimpleNamespace(zapret_autostart=True))


def make_check(controller: FakeController, probes: list[bool], *, foreign: list[str] | None = None) -> ZapretConflictCheck:
    script = iter(probes)
    check = ZapretConflictCheck(
        controller, probe=lambda: next(script), finder=lambda: list(foreign or []),
        sleep=lambda _s: None,
    )
    check._call = lambda action, arg=None: check._handle(action, arg)  # без GUI-потока: всё синхронно
    return check


class SequenceTests(TestCase):
    def run_sequence(self, controller, probes, **kwargs):
        check = make_check(controller, probes, **kwargs)
        return check, check._sequence(check._generation)

    def test_a_working_tunnel_changes_nothing(self) -> None:
        controller = FakeController()
        _check, outcome = self.run_sequence(controller, [True])
        self.assertEqual(outcome, "ok")
        controller.zapret.stop.assert_not_called()
        self.assertTrue(controller.state.settings.zapret_autostart)

    def test_a_single_failed_probe_is_retried_before_anything_is_stopped(self) -> None:
        controller = FakeController()
        _check, outcome = self.run_sequence(controller, [False, True])
        self.assertEqual(outcome, "ok")
        controller.zapret.stop.assert_not_called()

    def test_conflict_stops_own_zapret_disables_autostart_and_explains(self) -> None:
        controller = FakeController()
        _check, outcome = self.run_sequence(controller, [False, False, True])
        self.assertEqual(outcome, "conflict")
        controller.zapret.stop.assert_called_once()
        controller.zapret.apply.assert_not_called()
        self.assertFalse(controller.state.settings.zapret_autostart)
        controller.save.assert_called_once()
        controller.settings_changed.emit.assert_called_once()
        controller.status.emit.assert_called_with("warning-long", CONFLICT_NOTICE)

    def test_when_the_tunnel_fails_without_zapret_too_zapret_is_restored(self) -> None:
        controller = FakeController()
        _check, outcome = self.run_sequence(controller, [False, False, False])
        self.assertEqual(outcome, "not-zapret")
        controller.zapret.stop.assert_called_once()
        controller.zapret.apply.assert_called_once_with("PLAN")
        self.assertTrue(controller.state.settings.zapret_autostart, "настройки не тронуты: виноват не Zapret")
        controller.save.assert_not_called()

    def test_a_winws2_that_carries_the_vpn_rule_is_never_stopped(self) -> None:
        for kwargs in ({"rule": object()}, {"required": True}):
            with self.subTest(kwargs=kwargs):
                controller = FakeController(**kwargs)
                _check, outcome = self.run_sequence(controller, [])
                self.assertEqual(outcome, "own-carries-rule")
                controller.zapret.stop.assert_not_called()

    def test_without_own_zapret_nothing_is_probed_or_stopped(self) -> None:
        controller = FakeController(running=False)
        _check, outcome = self.run_sequence(controller, [])
        self.assertEqual(outcome, "own-not-running")
        controller.zapret.stop.assert_not_called()

    def test_disconnect_after_the_stop_restores_zapret_and_disables_nothing(self) -> None:
        controller = FakeController()
        check = make_check(controller, [False, False, True])
        original = check._handle

        def handle(action, arg=None):
            result = original(action, arg)
            if action == "stop_own":
                controller.connected = False  # человек отключил VPN посреди проверки
            return result

        check._call = lambda action, arg=None: handle(action, arg)
        outcome = check._sequence(check._generation)
        self.assertEqual(outcome, "not-zapret")
        self.assertTrue(controller.state.settings.zapret_autostart)
        controller.save.assert_not_called()

    def test_a_probe_that_crashes_after_the_stop_still_restores_zapret(self) -> None:
        controller = FakeController()
        calls = iter([False, False])

        def probe():
            try:
                return next(calls)
            except StopIteration:
                raise RuntimeError("проба упала после остановки") from None

        check = ZapretConflictCheck(controller, probe=probe, finder=lambda: [], sleep=lambda _s: None)
        check._call = lambda action, arg=None: check._handle(action, arg)
        with self.assertRaises(RuntimeError):
            check._sequence(check._generation)
        controller.zapret.stop.assert_called_once()
        controller.zapret.apply.assert_called_once_with("PLAN")
        self.assertTrue(controller.state.settings.zapret_autostart)

    def test_an_already_stale_check_stops_nothing(self) -> None:
        controller = FakeController()
        check = make_check(controller, [False, False, True])
        outcome = check._sequence(check._generation - 1)  # поколение устарело
        self.assertEqual(outcome, "cancelled")
        controller.zapret.stop.assert_not_called()


class ForeignWarningTests(TestCase):
    def test_a_foreign_zapret_is_only_warned_about_once_and_never_touched(self) -> None:
        controller = FakeController(running=False)
        check = make_check(controller, [], foreign=["winws2.exe"])
        self.assertEqual(check._sequence(check._generation), "own-not-running+foreign")
        controller.status.emit.assert_called_once()
        level, text = controller.status.emit.call_args.args
        self.assertEqual(level, "warning-long")
        self.assertIn("winws2.exe", text)
        self.assertIn("чужие процессы сам не останавливает", text)
        self.assertNotIn("D:\\", text, "путь к чужой программе в сообщение не попадает")
        check._sequence(check._generation)
        controller.status.emit.assert_called_once()  # повторно в этот запуск не пишется

    def test_names_come_from_file_names_only(self) -> None:
        with patch.object(zc, "foreign_zapret_processes", lambda own: [(5, THEIRS), (6, THEIRS), (7, "")]):
            self.assertEqual(ZapretConflictCheck._find_foreign(), ["winws2.exe", "winws"])


class StartTests(TestCase):
    def test_only_a_tun_connection_starts_the_check_in_a_thread(self) -> None:
        for tun, connected, expected in ((True, True, 1), (False, True, 0), (True, False, 0)):
            with self.subTest(tun=tun, connected=connected):
                controller = FakeController(tun=tun)
                check = ZapretConflictCheck(controller, sleep=lambda _s: None)
                with patch.object(zc.threading, "Thread") as thread:
                    check.on_connection_changed(connected)
                self.assertEqual(thread.call_count, expected)

    def test_a_crashing_check_ends_quietly_and_can_run_again(self) -> None:
        controller = FakeController()
        check = ZapretConflictCheck(controller, probe=Mock(side_effect=RuntimeError("boom")), finder=lambda: [], sleep=lambda _s: None)
        check._call = lambda action, arg=None: check._handle(action, arg)
        check._busy = True
        check._run(check._generation)
        self.assertEqual(check.last_outcome, "error")
        self.assertFalse(check._busy)
