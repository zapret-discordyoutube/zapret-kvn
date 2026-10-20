"""Проверка сервисов через узел: вывод по времени до первого байта и серия запросов по одному соединению."""

from __future__ import annotations

import unittest

from xray_fluent.network import service_check as sc

YOUTUBE = sc.SERVICES[0]
DISCORD = sc.SERVICES[1]


def _run(host: str, *times: float, failed: bool = False, reason: str = "") -> sc.EndpointRun:
    return sc.EndpointRun(host, tuple(times), failed=failed, reason=reason)


class JudgeTests(unittest.TestCase):
    def test_fast_answers_are_ok(self) -> None:
        verdict = sc.judge(YOUTUBE, [_run("www.youtube.com", 90, 80, 85, 95), _run("i.ytimg.com", 60, 70, 65, 62)])

        self.assertEqual(verdict.code, sc.CODE_OK)
        self.assertIn("быстрые", verdict.text)

    def test_one_long_wait_among_fast_ones_is_a_pause(self) -> None:
        verdict = sc.judge(YOUTUBE, [_run("www.youtube.com", 90, 80, 2900, 95)])

        self.assertEqual(verdict.code, sc.CODE_PAUSE)
        self.assertIn("2.9 с", verdict.text)

    def test_every_request_slow_is_slow_not_a_pause(self) -> None:
        verdict = sc.judge(YOUTUBE, [_run("www.youtube.com", 3100, 3000, 2900, 3200)])

        self.assertEqual(verdict.code, sc.CODE_SLOW)

    def test_a_name_that_does_not_open_makes_the_service_partial(self) -> None:
        verdict = sc.judge(DISCORD, [_run("discord.com", 100, 90), _run("gateway.discord.gg", failed=True, reason="timeout")])

        self.assertEqual(verdict.code, sc.CODE_PARTIAL)
        self.assertIn("gateway.discord.gg", verdict.text)

    def test_nothing_opens_is_blocked_with_the_reason(self) -> None:
        verdict = sc.judge(DISCORD, [_run("discord.com", failed=True, reason="ConnectionResetError")])

        self.assertEqual(verdict.code, sc.CODE_BLOCKED)
        self.assertIn("ConnectionResetError", verdict.text)

    def test_no_runs_is_unknown(self) -> None:
        self.assertEqual(sc.judge(YOUTUBE, []).code, sc.CODE_UNKNOWN)

    def test_one_slow_answer_without_enough_samples_is_not_a_pause(self) -> None:
        self.assertEqual(sc.judge(YOUTUBE, [_run("www.youtube.com", 90, 2900)]).code, sc.CODE_OK)


class _Response:
    def __init__(self, will_close: bool = False) -> None:
        self.will_close = will_close

    def read(self, _size: int) -> bytes:
        return b"x"


class _Connection:
    """Подставное соединение: каждый ответ «приходит» за заданное время по подставным часам."""

    def __init__(self, clock: "_Clock", delays: list[float], *, fail_after: int | None = None, will_close: bool = False) -> None:
        self.clock, self.delays, self.fail_after, self.will_close = clock, list(delays), fail_after, will_close
        self.requests = 0
        self.closed = False

    def request(self, method, path, headers=None) -> None:
        if self.fail_after is not None and self.requests >= self.fail_after:
            raise ConnectionResetError("reset")
        self.requests += 1

    def getresponse(self) -> _Response:
        self.clock.now += self.delays.pop(0) / 1000
        return _Response(self.will_close)

    def close(self) -> None:
        self.closed = True


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class ProbeTests(unittest.TestCase):
    def test_first_request_with_the_handshake_is_not_counted(self) -> None:
        clock = _Clock()
        connection = _Connection(clock, [800, 90, 80, 85, 95])

        run = sc.probe_endpoint("127.0.0.1", 1, "www.youtube.com", "/", connect=lambda *_a: connection, clock=clock)

        self.assertEqual([round(value) for value in run.ttfb_ms], [90, 80, 85, 95])
        self.assertTrue(connection.closed)
        self.assertFalse(run.failed)

    def test_connection_that_closes_after_the_answer_gives_one_measurement(self) -> None:
        clock = _Clock()
        connection = _Connection(clock, [300], will_close=True)

        run = sc.probe_endpoint("127.0.0.1", 1, "x.com", "/", connect=lambda *_a: connection, clock=clock)

        self.assertEqual([round(value) for value in run.ttfb_ms], [300])
        self.assertEqual(connection.requests, 1)

    def test_reset_on_the_first_request_is_a_failure_with_its_name(self) -> None:
        clock = _Clock()
        connection = _Connection(clock, [], fail_after=0)

        run = sc.probe_endpoint("127.0.0.1", 1, "x.com", "/", connect=lambda *_a: connection, clock=clock)

        self.assertTrue(run.failed)
        self.assertEqual((run.ttfb_ms, run.reason), ((), "ConnectionResetError"))

    def test_reset_in_the_middle_keeps_what_was_measured(self) -> None:
        clock = _Clock()
        connection = _Connection(clock, [500, 90, 95], fail_after=3)

        run = sc.probe_endpoint("127.0.0.1", 1, "x.com", "/", connect=lambda *_a: connection, clock=clock)

        self.assertTrue(run.failed)
        self.assertEqual([round(value) for value in run.ttfb_ms], [90, 95])

    def test_proxy_that_refuses_the_tunnel_is_a_failure(self) -> None:
        def refuse(*_args):
            raise ConnectionRefusedError("no proxy")

        run = sc.probe_endpoint("127.0.0.1", 1, "x.com", "/", connect=refuse)

        self.assertTrue(run.failed)

    def test_stop_ends_the_series(self) -> None:
        clock = _Clock()
        connection = _Connection(clock, [300, 90, 90, 90, 90])

        run = sc.probe_endpoint("127.0.0.1", 1, "x.com", "/", connect=lambda *_a: connection, clock=clock, cancelled=lambda: True)

        self.assertEqual(connection.requests, 0)
        self.assertEqual(run.ttfb_ms, ())


class CheckAllTests(unittest.TestCase):
    def test_every_service_of_the_catalog_gets_a_verdict(self) -> None:
        def probe(_h, _p, host, path, cancelled):
            return _run(host, 80, 90, 85, 88) if host != "gateway.discord.gg" else _run(host, failed=True, reason="timeout")

        verdicts = sc.check_all("127.0.0.1", 1, probe=probe)

        self.assertEqual(set(verdicts), {spec.key for spec in sc.SERVICES})
        self.assertEqual(verdicts["youtube"].code, sc.CODE_OK)
        self.assertEqual(verdicts["discord"].code, sc.CODE_PARTIAL)

    def test_summary_line_names_every_service_with_a_mark(self) -> None:
        verdicts = {
            "youtube": sc.ServiceVerdict("youtube", sc.CODE_OK),
            "discord": sc.ServiceVerdict("discord", sc.CODE_BLOCKED),
            "telegram": {"code": "pause"},
        }

        self.assertEqual(sc.summary_text(verdicts), "✓ YouTube  ✗ Discord  ⚠ Telegram")

    def test_catalog_is_free_of_duplicates(self) -> None:
        self.assertEqual(len({spec.key for spec in sc.SERVICES}), len(sc.SERVICES))
        self.assertTrue(all(spec.endpoints for spec in sc.SERVICES))


class NodeStorageTests(unittest.TestCase):
    def test_services_survive_saving_and_old_nodes_load_without_them(self) -> None:
        from xray_fluent.profiles.models import Node

        node = Node(name="n", services={"youtube": {"code": "ok", "text": "быстро"}}, services_checked_at="2026-10-20T12:00:00+00:00")
        restored = Node.from_dict(node.to_dict())

        self.assertEqual(restored.services, node.services)
        self.assertEqual(restored.services_checked_at, node.services_checked_at)
        old = {key: value for key, value in node.to_dict().items() if not key.startswith("services")}
        self.assertEqual(Node.from_dict(old).services, {})


class DetailTextTests(unittest.TestCase):
    def test_card_lists_marks_and_words_only_for_problems(self) -> None:
        from xray_fluent.profiles.models import Node
        from xray_fluent.ui.node_detail_widget import NodeDetailWidget

        node = Node(
            name="n",
            services={
                "youtube": {"code": "ok", "text": "быстро"},
                "discord": {"code": "pause", "text": "ответы идут с паузами"},
            },
            services_checked_at="2026-10-20T12:00:00+00:00",
        )
        text = NodeDetailWidget._services_text(_Format(), node)

        self.assertIn("✓ YouTube  ⚠ Discord", text)
        self.assertIn("Discord: ответы идут с паузами", text)
        self.assertNotIn("YouTube: быстро", text)
        self.assertEqual(NodeDetailWidget._services_text(_Format(), Node(name="n")), "")


class WorkerAndControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def _worker(self, **kwargs):
        from xray_fluent.network.speed_test_worker import SpeedTestWorker

        return SpeedTestWorker([], "xray.exe", **kwargs)

    def test_worker_emits_the_verdicts_only_when_asked(self) -> None:
        from unittest.mock import patch

        from xray_fluent.profiles.models import Node

        verdicts = {"youtube": sc.ServiceVerdict("youtube", sc.CODE_OK, "быстро")}
        node = Node(name="n")
        for asked, expected in ((True, [(node.id, {"youtube": verdicts["youtube"].as_dict()})]), (False, [])):
            worker = self._worker(check_services=asked)
            got: list = []
            worker.services.connect(lambda node_id, data: got.append((node_id, data)))
            with patch.object(sc, "check_all", return_value=verdicts) as check:
                worker._check_node_services(node, 4321)

            self.assertEqual(got, expected)
            self.assertEqual(check.call_count, 1 if asked else 0)

    def test_failed_check_does_not_break_the_speed_result(self) -> None:
        from unittest.mock import patch

        from xray_fluent.profiles.models import Node

        worker = self._worker(check_services=True)
        with patch.object(sc, "check_all", side_effect=RuntimeError("boom")):
            worker._check_node_services(Node(name="n"), 4321)

    def test_stop_skips_the_check(self) -> None:
        from unittest.mock import patch

        from xray_fluent.profiles.models import Node

        worker = self._worker(check_services=True)
        worker._cancelled = True
        with patch.object(sc, "check_all") as check:
            worker._check_node_services(Node(name="n"), 4321)

        check.assert_not_called()

    def test_controller_stores_verdicts_in_the_node_and_refreshes_the_list(self) -> None:
        from types import SimpleNamespace

        from xray_fluent.application import worker_service
        from xray_fluent.profiles.models import Node

        node = Node(name="n", speed_mbps=3.0, is_alive=True)
        emitted: list = []
        worker = object()
        controller = SimpleNamespace(
            sender=lambda: worker,
            _speed_worker=worker,
            _get_node_by_id=lambda node_id: node if node_id == node.id else None,
            speed_updated=SimpleNamespace(emit=lambda *args: emitted.append(args)),
        )

        worker_service.on_services_result(controller, node.id, {"youtube": {"code": "ok", "text": "быстро"}, "bad": "x"})

        self.assertEqual(set(node.services), {"youtube"})
        self.assertTrue(node.services_checked_at)
        self.assertEqual(emitted, [(node.id, 3.0, True)])
        # Чужой сигнал (не от текущего теста) игнорируется.
        controller.sender = lambda: object()
        worker_service.on_services_result(controller, node.id, {"x": {"code": "ok"}})
        self.assertEqual(set(node.services), {"youtube"})


class _Format:
    @staticmethod
    def _format_ts(value: str) -> str:
        return value[:10]


if __name__ == "__main__":
    unittest.main()
