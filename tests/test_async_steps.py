"""AC21/AC22: генераторные шаги переходов и TransitionRunner.

Проверяется контракт async_steps:
- полный проход генератора через TransitionRunner (run_in_worker + sleep_ms);
- отмена по устареванию generation посреди шага (finally выполняется,
  оставшиеся шаги не выполняются);
- доставка исключения шага в генератор через throw() (существующие
  try/except в операциях продолжают работать);
- wait_process_finished: по сигналу finished и по таймауту, без
  waitForFinished/processEvents в продуктовом коде;
- синхронный драйвер run_steps_blocking (холодные совместимые пути).
"""

from __future__ import annotations

import shutil
import time
import unittest

from PyQt6.QtCore import QCoreApplication, QProcess

from xray_fluent.application.async_steps import (
    TransitionRunner,
    run_in_worker,
    run_steps_blocking,
    sleep_ms,
    wait_process_finished,
    wait_process_started,
)

_APP = QCoreApplication.instance() or QCoreApplication([])


def _drive_until(condition, timeout_ms: int = 5000) -> bool:
    """Прокачивает event loop теста, пока condition() не станет истинным."""
    deadline = time.monotonic() + timeout_ms / 1000.0
    while time.monotonic() < deadline:
        if condition():
            return True
        _APP.processEvents()
        time.sleep(0.002)
    return condition()


def _boom() -> None:
    raise ValueError("boom")


class TransitionRunnerTests(unittest.TestCase):
    def test_full_pass_delivers_worker_result_and_sleeps(self) -> None:
        events: list[object] = []

        def gen():
            value = yield run_in_worker(lambda: 21 * 2)
            events.append(("worker", value))
            yield sleep_ms(10)
            events.append("slept")
            return value + 1

        runner = TransitionRunner(gen())
        runner.start()

        self.assertTrue(_drive_until(lambda: runner.done))
        self.assertEqual(runner.result, 43)
        self.assertIsNone(runner.error)
        self.assertFalse(runner.cancelled)
        self.assertEqual(events, [("worker", 42), "slept"])

    def test_stale_generation_cancels_mid_step_and_runs_finally(self) -> None:
        current = {"ok": True}
        trace: list[str] = []

        def gen():
            try:
                yield sleep_ms(10)
                trace.append("after_step1")
                yield sleep_ms(10)
                trace.append("after_step2")
                return True
            finally:
                trace.append("finally")

        runner = TransitionRunner(gen(), is_current=lambda: current["ok"])
        runner.start()
        # Первый шаг уже запущен; новый "запрос перехода" делает текущий устаревшим.
        current["ok"] = False

        self.assertTrue(_drive_until(lambda: runner.done))
        self.assertTrue(runner.cancelled)
        self.assertIsNone(runner.result)
        self.assertIsNone(runner.error)
        # Генератор закрыт на первом yield: тело после шага не выполнялось,
        # finally (cleanup/rollback операций) выполнен.
        self.assertEqual(trace, ["finally"])

    def test_step_error_is_delivered_into_generator_via_throw(self) -> None:
        def gen():
            try:
                yield run_in_worker(_boom)
            except ValueError as exc:
                return f"caught:{exc}"
            return "not raised"

        runner = TransitionRunner(gen())
        runner.start()

        self.assertTrue(_drive_until(lambda: runner.done))
        self.assertEqual(runner.result, "caught:boom")
        self.assertIsNone(runner.error)

    def test_uncaught_step_error_finishes_run_with_error(self) -> None:
        def gen():
            yield run_in_worker(_boom)
            return "unreachable"

        runner = TransitionRunner(gen())
        runner.start()

        self.assertTrue(_drive_until(lambda: runner.done))
        self.assertIsInstance(runner.error, ValueError)
        self.assertFalse(runner.cancelled)
        self.assertIsNone(runner.result)

    def test_run_in_worker_returns_result_to_generator_step(self) -> None:
        def gen():
            first = yield run_in_worker(lambda: "abc")
            second = yield run_in_worker(lambda: first * 2)
            return second

        runner = TransitionRunner(gen())
        runner.start()

        self.assertTrue(_drive_until(lambda: runner.done))
        self.assertEqual(runner.result, "abcabc")

    def test_on_finished_callback_receives_runner(self) -> None:
        seen: list[TransitionRunner] = []

        def gen():
            yield sleep_ms(1)
            return 7

        runner = TransitionRunner(gen(), on_finished=seen.append)
        runner.start()

        self.assertTrue(_drive_until(lambda: runner.done))
        self.assertEqual(seen, [runner])
        self.assertEqual(seen[0].result, 7)


@unittest.skipIf(shutil.which("sleep") is None, "требуется бинарь sleep")
class WaitProcessFinishedTests(unittest.TestCase):
    def test_resolves_true_when_process_finishes(self) -> None:
        process = QProcess()
        process.start("sleep", ["0.15"])

        def gen():
            return (yield wait_process_finished(process, 5000))

        runner = TransitionRunner(gen())
        began = time.monotonic()
        runner.start()

        self.assertTrue(_drive_until(lambda: runner.done, timeout_ms=8000))
        self.assertIs(runner.result, True)
        # Резюм пришёл по сигналу finished, а не по 5-секундному таймауту.
        self.assertLess(time.monotonic() - began, 4.0)

    def test_resolves_false_on_timeout(self) -> None:
        process = QProcess()
        process.start("sleep", ["5"])

        def gen():
            return (yield wait_process_finished(process, 150))

        runner = TransitionRunner(gen())
        runner.start()
        try:
            self.assertTrue(_drive_until(lambda: runner.done, timeout_ms=8000))
            self.assertIs(runner.result, False)
        finally:
            process.kill()
            process.waitForFinished(2000)

    def test_resolves_immediately_for_not_running_process(self) -> None:
        process = QProcess()

        def gen():
            return (yield wait_process_finished(process, 5000))

        runner = TransitionRunner(gen())
        runner.start()

        self.assertTrue(_drive_until(lambda: runner.done))
        self.assertIs(runner.result, True)

    def test_wait_process_started_resolves_true(self) -> None:
        process = QProcess()
        process.start("sleep", ["0.15"])

        def gen():
            started = yield wait_process_started(process, 5000)
            finished = yield wait_process_finished(process, 5000)
            return started, finished

        runner = TransitionRunner(gen())
        runner.start()

        self.assertTrue(_drive_until(lambda: runner.done, timeout_ms=8000))
        self.assertEqual(runner.result, (True, True))


class RunStepsBlockingTests(unittest.TestCase):
    def test_executes_steps_synchronously_and_returns_value(self) -> None:
        def gen():
            value = yield run_in_worker(lambda: 5)
            yield sleep_ms(1)
            return value * 2

        self.assertEqual(run_steps_blocking(gen()), 10)

    def test_delivers_step_error_via_throw(self) -> None:
        def gen():
            try:
                yield run_in_worker(_boom)
            except ValueError:
                return "handled"
            return "not raised"

        self.assertEqual(run_steps_blocking(gen()), "handled")


if __name__ == "__main__":
    unittest.main()
