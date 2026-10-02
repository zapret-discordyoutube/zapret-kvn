from __future__ import annotations

import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from xray_fluent.updates.installer import file_swap, handoff, phrases, processes, runner
from xray_fluent.updates.installer.file_swap import FileSwap, InstallError
from xray_fluent.updates.installer.plan import InstallPlan
from xray_fluent.updates.installer.runner import Stage, run_install

INSTALLED = {
    "ZapretKVN.exe": "exe v1",
    "_internal/base.dll": "same dll",
    "_internal/app.pyd": "app v1",
    "core/xray.exe": "xray v1",
    "core/old-core.exe": "stale core",
    "zapret/WinDivert64.sys": "driver",
    "data/state.json": "user state",
    "data/logs/app.log": "user log",
}
RELEASE = {
    "ZapretKVN.exe": "exe v2",
    "_internal/base.dll": "same dll",
    "_internal/app.pyd": "app v2",
    "_internal/new/module.pyd": "new module",
    "core/xray.exe": "xray v2",
    "zapret/WinDivert64.sys": "driver",
    # Архив несёт собственный data/: пользовательский он заменять не должен.
    "data/state.json": "packaged default state",
}
EXPECTED = {
    **{name: text for name, text in RELEASE.items() if not name.startswith("data/")},
    "data/state.json": "user state",
    "data/logs/app.log": "user log",
}


def write_tree(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def read_tree(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class InstallerCase(unittest.TestCase):
    def setUp(self) -> None:
        # Windows отпускает образ завершённого процесса не мгновенно: уборка
        # временного каталога не должна превращать это в провал теста.
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.app_dir = root / "app"
        self.work_dir = root / "zapretkvn_update_test"
        self.source_dir = self.work_dir / "extracted"
        write_tree(self.app_dir, INSTALLED)
        write_tree(self.source_dir, RELEASE)

    def swap(self, **kwargs) -> FileSwap:
        kwargs.setdefault("lock_wait_s", 0.0)
        return FileSwap(self.source_dir, self.app_dir, "attempt", **kwargs)


class FileSwapTests(InstallerCase):
    def test_install_replaces_changed_files_and_keeps_user_data(self) -> None:
        swap = self.swap()
        swap.prepare()
        swap.commit()
        swap.discard()
        self.assertEqual(read_tree(self.app_dir), EXPECTED)
        self.assertEqual(
            (swap.unchanged, swap.replaced, swap.added, swap.removed), (2, 3, 1, 1)
        )

    def test_unchanged_files_are_never_touched(self) -> None:
        # Драйвер WinDivert и общие DLL между версиями не меняются и нередко
        # остаются открытыми: файл, который не трогают, не может сорвать замену.
        driver = self.app_dir / "zapret" / "WinDivert64.sys"
        before = driver.stat()
        real_replace = os.replace
        moved: list[str] = []

        def tracking_replace(source, destination):
            moved.append(Path(source).name)
            real_replace(source, destination)

        swap = self.swap()
        swap.prepare()
        with patch.object(file_swap.os, "replace", tracking_replace):
            swap.commit()
        self.assertNotIn("WinDivert64.sys", moved)
        self.assertNotIn("base.dll", moved)
        self.assertEqual(driver.stat().st_ino, before.st_ino)
        self.assertEqual(driver.stat().st_mtime_ns, before.st_mtime_ns)

    def test_prepare_leaves_installed_copy_intact(self) -> None:
        swap = self.swap()
        swap.prepare()
        self.assertEqual(
            {name: text for name, text in read_tree(self.app_dir).items() if "app_update" not in name},
            INSTALLED,
        )

    def test_rollback_restores_the_previous_version_exactly(self) -> None:
        swap = self.swap()
        swap.prepare()
        swap.commit()
        self.assertEqual(swap.rollback(), [])
        swap.discard()
        self.assertEqual(read_tree(self.app_dir), INSTALLED)
        self.assertFalse((self.app_dir / "_internal" / "new").exists())

    def test_locked_replaced_file_stops_install_and_names_the_file(self) -> None:
        real_replace = os.replace

        def locked_replace(source, destination):
            if Path(source) == self.app_dir / "core" / "xray.exe":
                raise PermissionError(13, "The process cannot access the file")
            real_replace(source, destination)

        swap = self.swap()
        swap.prepare()
        with patch.object(file_swap.os, "replace", locked_replace):
            with self.assertRaises(InstallError) as caught:
                swap.commit()
        self.assertEqual(caught.exception.path, self.app_dir / "core" / "xray.exe")
        self.assertEqual(swap.rollback(), [])
        swap.discard()
        self.assertEqual(read_tree(self.app_dir), INSTALLED)

    def test_locked_stale_file_does_not_stop_install(self) -> None:
        real_replace = os.replace
        stale = self.app_dir / "core" / "old-core.exe"

        def locked_replace(source, destination):
            if Path(source) == stale:
                raise PermissionError(13, "The process cannot access the file")
            real_replace(source, destination)

        swap = self.swap()
        swap.prepare()
        with patch.object(file_swap.os, "replace", locked_replace):
            swap.commit()
        self.assertEqual(swap.left_behind, [stale])
        self.assertEqual((self.app_dir / "core" / "xray.exe").read_text(encoding="utf-8"), "xray v2")

    def test_briefly_locked_file_is_retried_after_the_holder_is_stopped(self) -> None:
        real_replace = os.replace
        target = self.app_dir / "core" / "xray.exe"
        state = {"locked": True}
        stopped: list[Path] = []

        def replace(source, destination):
            if Path(source) == target and state["locked"]:
                raise PermissionError(13, "The process cannot access the file")
            real_replace(source, destination)

        def on_locked(path: Path) -> None:
            stopped.append(path)
            state["locked"] = False

        swap = self.swap(lock_wait_s=5.0, on_locked=on_locked)
        swap.prepare()
        with patch.object(file_swap.os, "replace", replace), patch.object(file_swap.time, "sleep"):
            swap.commit()
        self.assertEqual(stopped, [target])
        self.assertEqual(target.read_text(encoding="utf-8"), "xray v2")

    def test_file_and_directory_can_trade_places(self) -> None:
        write_tree(self.app_dir, {"assets/theme/dark.qss": "old", "plugin": "old file"})
        write_tree(self.source_dir, {"assets/theme": "now a file", "plugin/main.dll": "now a dir"})
        before = read_tree(self.app_dir)
        swap = self.swap()
        swap.prepare()
        swap.commit()
        self.assertEqual((self.app_dir / "assets" / "theme").read_text(encoding="utf-8"), "now a file")
        self.assertEqual(
            (self.app_dir / "plugin" / "main.dll").read_text(encoding="utf-8"), "now a dir"
        )
        self.assertEqual(swap.rollback(), [])
        swap.discard()
        self.assertEqual(read_tree(self.app_dir), before)

    def test_directories_emptied_by_the_update_are_removed(self) -> None:
        write_tree(self.app_dir, {"legacy/deep/tool.exe": "gone in v2"})
        swap = self.swap()
        swap.prepare()
        swap.commit()
        self.assertFalse((self.app_dir / "legacy").exists())

    def test_full_disk_is_detected_before_anything_changes(self) -> None:
        usage = shutil.disk_usage(self.app_dir)
        with patch.object(file_swap.shutil, "disk_usage", return_value=usage._replace(free=1024)):
            with self.assertRaises(InstallError):
                self.swap().prepare()
        self.assertEqual(read_tree(self.app_dir), INSTALLED)

    def test_prepare_reports_progress_up_to_completion(self) -> None:
        seen: list[float] = []
        self.swap().prepare(seen.append)
        self.assertEqual(seen, sorted(seen))
        self.assertEqual(seen[-1], 1.0)


class RunnerTests(InstallerCase):
    def setUp(self) -> None:
        super().setUp()
        self.plan = InstallPlan(
            version="9.9.9",
            app_pid=4242,
            app_dir=self.app_dir,
            source_dir=self.source_dir,
            work_dir=self.work_dir,
            start_in_tray=True,
        )
        self.started: list[list[str]] = []
        self.exit_codes: list[int | None] = []
        for target, replacement in (
            (runner.processes, {"wait_for_exit": Mock(return_value=True)}),
            (runner.processes, {"stop_processes_under": Mock(return_value=[])}),
            (runner.processes, {"lock_holders": Mock(return_value=["Antivirus (C:\\av.exe)"])}),
            (runner.processes, {"start_detached": self._start}),
            (runner, {"NEW_VERSION_READY_WAIT_S": 0.05, "OLD_VERSION_READY_WAIT_S": 0.05}),
            (runner, {"_log": Mock()}),
        ):
            patcher = patch.multiple(target, **replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _start(self, command, *, cwd, console, env):
        self.started.append(list(command))
        self.start_env = env
        code = self.exit_codes.pop(0) if self.exit_codes else None
        return Mock(poll=Mock(return_value=code), returncode=code)

    def error_log(self) -> Path:
        return self.app_dir / "data" / "logs" / "update_error.log"

    def tree(self) -> dict[str, str]:
        # Замок снимает точка входа установщика, когда закрывается его окно.
        handoff.release(self.plan.hold_marker)
        return read_tree(self.app_dir)

    def test_successful_install_restarts_the_new_version(self) -> None:
        stages: list[Stage] = []
        self.assertTrue(run_install(self.plan, lambda stage, fraction: stages.append(stage)))
        # Приложение запущено за кулисами: окно покажет, когда снимут замок.
        self.assertTrue(self.plan.hold_marker.exists())
        self.assertEqual(self.start_env, {handoff.HOLD_ENV: str(self.plan.hold_marker)})
        self.assertEqual(self.tree(), EXPECTED)
        self.assertEqual(self.started, [[str(self.app_dir / "ZapretKVN.exe"), "--tray"]])
        self.assertEqual(
            list(dict.fromkeys(stages)),
            [Stage.PREPARE, Stage.WAIT_APP, Stage.SWAP, Stage.START, Stage.DONE],
        )
        self.assertFalse(self.error_log().exists())

    def test_install_finishes_as_soon_as_the_new_version_reports_ready(self) -> None:
        patcher = patch.multiple(runner, NEW_VERSION_READY_WAIT_S=60.0)
        patcher.start()
        self.addCleanup(patcher.stop)
        real_start = self._start

        def start_and_report(command, **kwargs):
            process = real_start(command, **kwargs)
            hold = handoff.claim_from(kwargs["env"])
            handoff.confirm_ready(hold)
            return process

        with patch.object(runner.processes, "start_detached", start_and_report):
            started = time.monotonic()
            self.assertTrue(run_install(self.plan))
        self.assertLess(time.monotonic() - started, 30.0)

    def test_application_is_closed_before_files_are_replaced(self) -> None:
        order: list[str] = []
        runner.processes.wait_for_exit.side_effect = lambda *a: order.append("wait") or True
        runner.processes.stop_processes_under.side_effect = lambda *a: order.append("stop") or []
        real_commit = FileSwap.commit

        def commit(swap):
            order.append("commit")
            real_commit(swap)

        with patch.object(FileSwap, "commit", commit):
            run_install(self.plan)
        self.assertEqual(order[:3], ["wait", "stop", "commit"])

    def test_new_version_that_dies_on_start_is_rolled_back(self) -> None:
        self.exit_codes = [3, None]
        stages: list[Stage] = []
        self.assertFalse(run_install(self.plan, lambda stage, fraction: stages.append(stage)))
        tree = self.tree()
        log = tree.pop("data/logs/update_error.log")
        self.assertEqual(tree, INSTALLED)
        self.assertIn("код 3", log)
        self.assertIn("Прежняя версия возвращена", log)
        # Вторая попытка запуска — уже прежняя версия.
        self.assertEqual(len(self.started), 2)
        self.assertEqual(stages[-2:], [Stage.ROLLBACK, Stage.FAILED])

    def test_locked_file_is_reported_with_its_holder(self) -> None:
        real_replace = os.replace
        locked = self.app_dir / "_internal" / "app.pyd"

        def replace(source, destination):
            if Path(source) == locked:
                raise PermissionError(13, "The process cannot access the file")
            real_replace(source, destination)

        with patch.object(file_swap.os, "replace", replace), \
                patch.object(file_swap.FileSwap, "_move", _move_without_waiting):
            self.assertFalse(run_install(self.plan))
        runner.processes.lock_holders.assert_called_once_with(locked)
        log = self.error_log().read_text(encoding="utf-8")
        self.assertIn(os.path.join("_internal", "app.pyd"), log)
        self.assertIn("Antivirus", log)
        # Прежняя версия цела и запущена заново.
        self.assertEqual((self.app_dir / "ZapretKVN.exe").read_text(encoding="utf-8"), "exe v1")
        self.assertEqual(len(self.started), 1)

    def test_failed_preparation_still_waits_for_the_app_and_restarts_it(self) -> None:
        # Приложение выходит сразу после запуска установщика, не дожидаясь
        # подготовки: после сбоя его всё равно надо вернуть.
        shutil.rmtree(self.source_dir)
        self.source_dir.mkdir()
        self.assertFalse(run_install(self.plan))
        runner.processes.wait_for_exit.assert_called()
        self.assertEqual(len(self.started), 1)
        self.assertTrue(self.error_log().exists())


def _move_without_waiting(swap, source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.replace(source, destination)


class PlanTests(unittest.TestCase):
    def test_plan_survives_a_round_trip_through_json(self) -> None:
        plan = InstallPlan(
            version="1.2.3",
            app_pid=7,
            app_dir=Path("C:/Игры/Zapret KVN"),
            source_dir=Path("C:/Temp/zapretkvn_update_x/extracted"),
            work_dir=Path("C:/Temp/zapretkvn_update_x"),
            start_in_tray=True,
            theme="dark",
            accent="#E3008C",
            anchor=(10, 20, 900, 600),
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plan.json"
            plan.save(path)
            loaded = InstallPlan.load(path)
        for field in InstallPlan.__slots__:
            self.assertEqual(getattr(loaded, field), getattr(plan, field), field)
        self.assertEqual(loaded.restart_args, ["--tray"])


class LaunchTests(InstallerCase):
    def test_launch_runs_the_new_build_and_clears_a_stale_ready_marker(self) -> None:
        from xray_fluent.updates.installer.launch import launch_installer

        plan = InstallPlan("9.9.9", 1, self.app_dir, self.source_dir, self.work_dir)
        plan.ready_marker.write_text("left by a previous attempt", encoding="utf-8")
        with patch.object(processes, "start_detached", return_value="process") as start:
            self.assertEqual(launch_installer(plan), "process")
        self.assertFalse(plan.ready_marker.exists())
        command = start.call_args.args[0]
        self.assertEqual(command[:2], [str(self.source_dir / "ZapretKVN.exe"), "--apply-update"])
        self.assertEqual(InstallPlan.load(Path(command[2])).app_dir, self.app_dir)
        self.assertEqual(start.call_args.kwargs, {"cwd": self.source_dir, "console": False})


class HandoffTests(unittest.TestCase):
    """Приложение не показывает окно, пока открыто окно обновления."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.hold = Path(self._tmp.name) / "runtime" / "update_hold"

    def test_ordinary_start_has_nothing_to_wait_for(self) -> None:
        self.assertIsNone(handoff.claim_from({}))
        # Замок от прошлого обновления, которого уже нет на диске.
        self.assertIsNone(handoff.claim_from({handoff.HOLD_ENV: str(self.hold)}))

    def test_app_reports_ready_and_waits_until_the_installer_releases_it(self) -> None:
        environment = handoff.arm(self.hold)
        self.assertFalse(handoff.is_ready(self.hold))
        hold = handoff.claim_from(environment)
        self.assertEqual(hold, self.hold)
        # Переменная не достаётся ядрам и прочим дочерним процессам приложения.
        self.assertNotIn(handoff.HOLD_ENV, environment)
        handoff.confirm_ready(hold)
        self.assertTrue(handoff.is_ready(self.hold))
        self.assertTrue(hold.exists())
        handoff.release(self.hold)
        self.assertFalse(hold.exists())
        self.assertFalse(handoff.is_ready(self.hold))

    def test_arming_again_forgets_the_previous_readiness(self) -> None:
        handoff.confirm_ready(handoff.claim_from(handoff.arm(self.hold)))
        handoff.arm(self.hold)
        self.assertFalse(handoff.is_ready(self.hold))


class PhraseTests(unittest.TestCase):
    def test_phrases_do_not_repeat_until_the_deck_is_exhausted(self) -> None:
        deck = phrases.PhraseDeck(rng=random.Random(1))
        first = [deck.next() for _ in phrases.WAITING]
        self.assertEqual(sorted(first), sorted(phrases.WAITING))
        self.assertNotEqual(deck.next(), first[-1])

    def test_phrases_are_many_distinct_and_fit_the_window(self) -> None:
        # Большие наборы — чтобы от обновления к обновлению текст был разный.
        for pool, minimum in ((phrases.WAITING, 60), (phrases.DONE, 8), (phrases.FAILED, 6)):
            self.assertGreaterEqual(len(pool), minimum)
            self.assertEqual(len(set(pool)), len(pool))
        # Окно подгоняет высоту под самую длинную фразу: длиннее не делаем.
        for text in (*phrases.WAITING, *phrases.DONE, *phrases.FAILED):
            self.assertLessEqual(len(text), 76, text)

    def test_farewell_varies_and_matches_the_outcome(self) -> None:
        rng = random.Random(2)
        done = {phrases.farewell(True, rng=rng) for _ in range(60)}
        failed = {phrases.farewell(False, rng=rng) for _ in range(60)}
        self.assertGreater(len(done), 1)
        self.assertGreater(len(failed), 1)
        self.assertTrue(done <= set(phrases.DONE))
        self.assertTrue(failed <= set(phrases.FAILED))


class WindowProgressTests(unittest.TestCase):
    def test_overall_progress_never_moves_backwards(self) -> None:
        from xray_fluent.updates.installer.window import overall_progress

        points = [
            overall_progress(stage, fraction)
            for stage in (Stage.PREPARE, Stage.WAIT_APP, Stage.SWAP, Stage.START)
            for fraction in (0.0, 0.5, 1.0)
        ] + [overall_progress(Stage.DONE, 1.0)]
        self.assertEqual(points, sorted(points))
        self.assertEqual(points[0], 0.0)
        self.assertEqual(points[-1], 1.0)
        self.assertIsNone(overall_progress(Stage.ROLLBACK, 0.0))


@unittest.skipUnless(sys.platform == "win32", "WinAPI")
class WindowsProcessTests(InstallerCase):
    def _hold_open(self, path: Path) -> subprocess.Popen:
        holder = subprocess.Popen(
            [sys.executable, "-c", "import sys, time; f = open(sys.argv[1], 'rb'); print('ok', flush=True); time.sleep(60)", str(path)],
            stdout=subprocess.PIPE,
        )
        self.addCleanup(holder.stdout.close)
        self.addCleanup(holder.wait)
        self.addCleanup(holder.kill)
        self.assertEqual(holder.stdout.readline().strip(), b"ok")
        return holder

    def test_open_unchanged_file_no_longer_breaks_the_update(self) -> None:
        # Регрессия: открытый файл не давал переименовать весь каталог zapret\.
        self._hold_open(self.app_dir / "zapret" / "WinDivert64.sys")
        swap = self.swap()
        swap.prepare()
        swap.commit()
        swap.discard()
        self.assertEqual(read_tree(self.app_dir), EXPECTED)

    def test_lock_holders_names_the_process_keeping_a_file_open(self) -> None:
        target = self.app_dir / "core" / "xray.exe"
        self._hold_open(target)
        holders = processes.lock_holders(target)
        self.assertTrue(any("python" in holder.lower() for holder in holders), holders)

    def test_wait_for_exit_and_terminate(self) -> None:
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        self.assertFalse(processes.wait_for_exit(child.pid, 0.2))
        processes.terminate(child.pid)
        self.assertTrue(processes.wait_for_exit(child.pid, 10.0))

    def test_processes_inside_the_app_directory_are_found_and_stopped(self) -> None:
        tool = self.app_dir / "core" / "ping.exe"
        shutil.copy2(Path(os.environ["SystemRoot"]) / "System32" / "ping.exe", tool)
        child = subprocess.Popen(
            [str(tool), "-n", "60", "127.0.0.1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        time.sleep(0.5)
        found = processes.processes_under(self.app_dir)
        self.assertEqual([pid for pid, _ in found], [child.pid])
        self.assertEqual(processes.stop_processes_under(self.app_dir, 10.0), [])
        self.assertIsNotNone(child.wait(timeout=10))
        self.assertEqual(processes.processes_under(self.app_dir), [])


if __name__ == "__main__":
    unittest.main()
