from __future__ import annotations

"""Сигнал сервера о новой версии: слушатель и его связка с окном."""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from xray_fluent.updates import release_watch
from xray_fluent.updates.release_watch import ReleaseWatcher


def _quiet(version: str = "0.8.19") -> dict:
    return {"channel": "stable", "version": version, "changed": False}


def _news(version: str) -> dict:
    return {"channel": "stable", "version": version, "changed": True}


class _Harness:
    """Сервер и часы слушателя: ответы идут по сценарию, паузы не ждут."""

    def __init__(self, script: list, **options) -> None:
        self.script = list(script)
        self.urls: list[str] = []
        self.pauses: list[float] = []
        self.released: list[str] = []
        self.queued: list[str] = []
        self.now = 0.0
        options.setdefault("is_busy", lambda: False)
        self.watcher = ReleaseWatcher(
            current_version="0.8.19",
            on_release=self.released.append,
            on_queued=self.queued.append,
            ask=self._ask,
            clock=lambda: self.now,
            **options,
        )
        self.watcher._pause = self._pause

    def _ask(self, url: str, timeout: float) -> dict:
        self.urls.append(url)
        if not self.script:
            self.watcher.stop()
            raise OSError("сценарий кончился")
        step = self.script.pop(0)
        took, answer = step if isinstance(step, tuple) else (0.2 if "hold=0" in url else 300.0, step)
        self.now += took
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def _pause(self, seconds: float) -> bool:
        self.pauses.append(float(seconds))
        return self.watcher._stop.is_set()


class ReleaseWatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = patch.object(release_watch, "_log")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_first_question_is_a_probe_then_questions_wait(self) -> None:
        harness = _Harness([_quiet(), _quiet(), _quiet()])

        harness.watcher.run()

        self.assertIn("hold=0", harness.urls[0])
        self.assertIn("known=0.8.19", harness.urls[0])
        self.assertIn("channel=stable", harness.urls[0])
        # Сразу после запуска вопрос короче, дальше — в полный срок.
        self.assertIn(f"hold={release_watch.WARMUP_HOLD_S}", harness.urls[1])
        self.assertNotIn("hold=", harness.urls[2])
        self.assertIs(harness.watcher.reachable, False)  # сценарий кончился ошибкой

    def test_permission_is_reported_once_and_version_becomes_known(self) -> None:
        harness = _Harness([_quiet(), _news("0.8.20"), _quiet("0.8.20")])

        harness.watcher.run()

        self.assertEqual(harness.released, ["0.8.20"])
        self.assertIn("known=0.8.20", harness.urls[2])

    def test_older_or_strange_version_is_not_a_permission(self) -> None:
        harness = _Harness([_news("0.8.18"), _news("мусор"), _news("0.8.19")])

        harness.watcher.run()

        self.assertEqual(harness.released, [])

    def test_queue_ticket_is_kept_and_named_in_next_questions(self) -> None:
        queued = lambda ticket: {"version": "0.8.20", "changed": False, "queued": True, "ticket": ticket}  # noqa: E731
        harness = _Harness([queued(1791570000), queued(1791579999), _news("0.8.20"), _quiet("0.8.20")])

        harness.watcher.run()

        self.assertNotIn("ticket=", harness.urls[0])
        # Талон — время первой постановки: программа держится за него.
        self.assertIn("ticket=1791570000", harness.urls[1])
        self.assertIn("ticket=1791570000", harness.urls[2])
        self.assertNotIn("ticket=", harness.urls[3])
        self.assertEqual(harness.queued, ["0.8.20"])

    def test_answer_wait_for_your_stage_is_not_a_permission(self) -> None:
        held = {"version": "0.8.20", "changed": False, "held": "stage"}
        harness = _Harness([held, held, {"version": "0.8.20", "changed": False, "held": "halted"}, _news("0.8.20")])

        harness.watcher.run()

        self.assertEqual(harness.queued, [])
        self.assertEqual(harness.released, ["0.8.20"])
        self.assertNotIn(release_watch.QUICK_ANSWER_PAUSE_S, harness.pauses)

    def test_busy_program_says_so_and_asks_shorter(self) -> None:
        busy = [True, True, True, False]
        harness = _Harness([_quiet()] * 4, is_busy=lambda: busy.pop(0) if busy else False)

        harness.watcher.run()

        self.assertIn("busy=1", harness.urls[0])
        self.assertIn("busy=1", harness.urls[2])
        self.assertIn(f"hold={release_watch.BUSY_HOLD_S}", harness.urls[2])
        self.assertNotIn("busy=", harness.urls[3])

    def test_program_tells_what_it_is_doing_and_nothing_else(self) -> None:
        harness = _Harness([_quiet()], activity=lambda: {"act": "tray", "run": "1", "server": "secret.example"})

        harness.watcher.run()

        self.assertIn("act=tray", harness.urls[0])
        self.assertIn("run=1", harness.urls[0])
        self.assertNotIn("secret", harness.urls[0])

    def test_update_outcome_is_reported_until_the_server_hears_it(self) -> None:
        pending = [{"prev": "0.8.18", "took": "24"}]
        harness = _Harness(
            [OSError("нет сети"), _quiet(), _quiet()],
            pending_report=lambda: dict(pending[0]) if pending else {},
            report_delivered=lambda _report: pending.clear(),
        )

        harness.watcher.run()

        self.assertIn("prev=0.8.18", harness.urls[0])
        self.assertIn("took=24", harness.urls[1])
        self.assertNotIn("prev=", harness.urls[2])

    def test_pauses_grow_when_the_server_is_away_and_program_lives_on_its_own(self) -> None:
        harness = _Harness([OSError("нет"), OSError("нет"), OSError("нет")])

        harness.watcher.run()

        self.assertEqual(harness.pauses[:3], [60.0, 120.0, 240.0])
        self.assertIs(harness.watcher.reachable, False)

    def test_quick_empty_answer_is_followed_by_a_pause(self) -> None:
        harness = _Harness([_quiet(), (0.3, _quiet())])

        harness.watcher.run()

        self.assertIn(release_watch.QUICK_ANSWER_PAUSE_S, harness.pauses)

    def test_switched_off_updates_keep_no_connection(self) -> None:
        enabled = [False, False]
        harness = _Harness([_quiet()], is_enabled=lambda: enabled.pop(0) if enabled else True)

        harness.watcher.run()

        self.assertEqual(harness.pauses[:2], [release_watch.DISABLED_RECHECK_S] * 2)
        self.assertEqual(len(harness.urls), 2)


class UpdateSignalTests(unittest.TestCase):
    def _signal(self, **options):
        from xray_fluent.updates.update_signal import UpdateSignal

        self.watcher = SimpleNamespace(reachable=None, start=Mock(), stop=Mock())
        captured: dict = {}

        def factory(**kwargs):
            captured.update(kwargs)
            return self.watcher

        signal = UpdateSignal(
            is_enabled=lambda: True,
            window_shown=options.get("window_shown", lambda: True),
            connected=options.get("connected", lambda: False),
            watcher_factory=factory,
        )
        return signal, captured

    def test_permission_is_remembered_with_its_moment(self) -> None:
        signal, hooks = self._signal()
        heard: list[str] = []
        signal.granted.connect(heard.append)

        self.assertFalse(signal.is_granted("0.8.20"))
        hooks["on_release"]("0.8.20")

        self.assertTrue(signal.is_granted("0.8.20"))
        self.assertGreater(signal.granted_at("0.8.20"), 0)
        self.assertEqual(signal.granted_at("0.8.21"), 0.0)
        self.assertEqual(heard, ["0.8.20"])

    def test_queue_counts_only_when_the_server_answered(self) -> None:
        signal, _hooks = self._signal()

        self.assertFalse(signal.queue_reachable())  # ещё не знаем — живём как раньше
        self.watcher.reachable = True
        self.assertTrue(signal.queue_reachable())

    def test_activity_names_window_tray_game_and_connection(self) -> None:
        from xray_fluent.updates import update_signal

        shown = [True]
        signal, hooks = self._signal(window_shown=lambda: shown[0], connected=lambda: True)
        with patch.object(update_signal, "fullscreen_app_active", return_value=False):
            self.assertEqual(hooks["activity"](), {})  # окно о себе ещё не сказало
            signal.refresh_presence()
            self.assertEqual(hooks["activity"](), {"act": "window", "run": "1"})
            shown[0] = False
            signal.refresh_presence()
            self.assertEqual(hooks["activity"](), {"act": "tray", "run": "1"})
        with patch.object(update_signal, "fullscreen_app_active", return_value=True):
            self.assertEqual(hooks["activity"]()["act"], "fullscreen")
            self.assertTrue(signal.busy_reason())

    def test_report_is_given_once(self) -> None:
        signal, hooks = self._signal()
        signal.set_report({"prev": "0.8.18", "took": "30"})

        self.assertEqual(hooks["pending_report"](), {"prev": "0.8.18", "took": "30"})
        hooks["report_delivered"]({"prev": "0.8.18"})

        self.assertEqual(hooks["pending_report"](), {})


class BackgroundInstallGateTests(unittest.TestCase):
    """Фоновая установка ждёт разрешения сервера и простоя."""

    def _reason(self, *, reachable: bool, granted: bool, busy: str = "") -> str:
        from xray_fluent.ui import main_window
        from xray_fluent.ui.main_window import MainWindow

        signal = SimpleNamespace(
            queue_reachable=lambda: reachable,
            is_granted=lambda _version: granted,
            busy_reason=lambda: busy,
        )
        window = SimpleNamespace(_update_signal=signal, _recheck_update_when_free=Mock())
        with patch.object(main_window.QTimer, "singleShot") as self.single_shot:
            return MainWindow._update_wait_reason(window, SimpleNamespace(version="0.8.20"))

    def test_version_waits_for_the_server_permission(self) -> None:
        self.assertIn("разрешения сервера", self._reason(reachable=True, granted=False))
        self.assertEqual(self._reason(reachable=True, granted=True), "")

    def test_without_a_queue_server_program_installs_as_before(self) -> None:
        self.assertEqual(self._reason(reachable=False, granted=False), "")

    def test_game_on_screen_postpones_the_update_and_plans_a_recheck(self) -> None:
        reason = self._reason(reachable=True, granted=True, busy="на экране игра или видео на весь экран")

        self.assertIn("игра", reason)
        self.single_shot.assert_called_once()

    def test_no_listener_means_no_extra_waiting(self) -> None:
        from xray_fluent.ui.main_window import MainWindow

        self.assertEqual(MainWindow._update_wait_reason(SimpleNamespace(_update_signal=None), SimpleNamespace(version="1")), "")


if __name__ == "__main__":
    unittest.main()
