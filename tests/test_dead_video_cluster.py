"""Мёртвый кеш-кластер YouTube: чистая логика трекера (без сети и Qt).

Числа взяты из архива Android 0.5.43 (2026-11-13): кластер sn-8ph2xajvh не отвечал ни байтом на любом сервере.
"""

from __future__ import annotations

import unittest

from xray_fluent.diagnostics.dead_video_cluster import ClusterEvent, DeadVideoClusterTracker, cluster_of

DEAD = "rr2---sn-8ph2xajvh-3a4l.googlevideo.com"


def conn(conn_id: str, host: str = DEAD, up: int = 2048, down: int = 0, network: str = "tcp", chains=None) -> dict:
    return {
        "id": conn_id,
        "metadata": {"host": host, "network": network},
        "upload": up,
        "download": down,
        "chains": ["proxy"] if chains is None else chains,
    }


class ClusterNameTests(unittest.TestCase):
    def test_cluster_is_read_from_the_cache_node_name(self) -> None:
        self.assertEqual(cluster_of("rr2---sn-8ph2xajvh-3a4l.googlevideo.com"), "sn-8ph2xajvh")
        self.assertEqual(cluster_of("r6---sn-8ph2xajvh-n8vs.googlevideo.com"), "sn-8ph2xajvh")
        self.assertEqual(cluster_of("RR5---SN-2OI5H5-5J.GoogleVideo.com."), "sn-2oi5h5")
        self.assertEqual(cluster_of("rr1---sn-gxuo03g.googlevideo.com"), "sn-gxuo03g")

    def test_dotted_name_from_dns_answer_gives_the_same_cluster(self) -> None:
        # Поток получает имя по ответу DNS (CNAME на форму с точкой): архив Android 0.5.47, 2026-11-13 23:02:51.
        self.assertEqual(cluster_of("rr2.sn-8ph2xajvh-3a4l.googlevideo.com"), "sn-8ph2xajvh")
        self.assertEqual(cluster_of("rr1.sn-8ph2xajvh-3a4s.googlevideo.com"), "sn-8ph2xajvh")
        self.assertEqual(cluster_of("rr1.sn-gxuo03g.googlevideo.com."), "sn-gxuo03g")

    def test_names_without_a_cluster_belong_to_none(self) -> None:
        for host in ("redirector.googlevideo.com", "googlevideo.com", "rr2---sn-x-y.example.com", "rr2.sn-x-y.example.com", "sn-x.googlevideo.com", "", None):
            self.assertIsNone(cluster_of(host), host)


class TrackerTests(unittest.TestCase):
    def silent_round(self, tracker: DeadVideoClusterTracker, now: float, ids: list[str], **kwargs):
        """Два опроса: первый видит соединения, второй через 9 с видит их молчаливыми."""

        tracker.observe(now, [conn(i, **kwargs) for i in ids])
        return tracker.observe(now + 9.0, [conn(i, **kwargs) for i in ids])

    def test_three_silent_connections_make_the_cluster_dead_once(self) -> None:
        tracker = DeadVideoClusterTracker()
        events = self.silent_round(tracker, 100.0, ["a", "b", "c"])
        self.assertEqual(events, [ClusterEvent("dead", "sn-8ph2xajvh", 3, 0.0)])
        self.assertEqual(tracker.active_dead(109.0), ["sn-8ph2xajvh"])
        self.assertEqual(self.silent_round(tracker, 120.0, ["d"]), [], "one event per episode")

    def test_dotted_names_from_the_dns_answer_make_the_cluster_dead(self) -> None:
        # Архив Android 0.5.47, 23:02:51: rr2, rr1, rr2 одного кластера, имена с точкой, вниз 948 Б.
        tracker = DeadVideoClusterTracker()
        rows = [
            conn("a", host="rr2.sn-8ph2xajvh-3a4l.googlevideo.com", down=948),
            conn("b", host="rr1.sn-8ph2xajvh-3a4s.googlevideo.com", down=948),
            conn("c", host="rr2.sn-8ph2xajvh-3a4l.googlevideo.com", down=948),
        ]
        tracker.observe(100.0, rows)
        self.assertEqual(tracker.observe(109.0, rows), [ClusterEvent("dead", "sn-8ph2xajvh", 3, 0.0)])

    def test_zero_byte_connections_are_silent_after_three_seconds(self) -> None:
        tracker = DeadVideoClusterTracker()
        rows = [conn("a", down=0), conn("b", down=0), conn("c", down=0)]
        tracker.observe(100.0, rows)
        self.assertEqual(tracker.observe(102.9, rows), [])
        self.assertEqual(tracker.observe(103.0, rows), [ClusterEvent("dead", "sn-8ph2xajvh", 3, 0.0)])
        # соединения с несколькими байтами по-прежнему ждут 8 с
        other = DeadVideoClusterTracker()
        few = [conn("x", down=647), conn("y", down=647), conn("z", down=647)]
        other.observe(200.0, few)
        self.assertEqual(other.observe(203.0, few), [])
        self.assertEqual(len(other.observe(208.0, few)), 1)

    def test_two_silent_connections_are_not_a_verdict(self) -> None:
        tracker = DeadVideoClusterTracker()
        self.assertEqual(self.silent_round(tracker, 100.0, ["a", "b"]), [])
        self.assertEqual(tracker.active_dead(109.0), [])

    def test_young_connections_are_not_counted(self) -> None:
        # с несколькими байтами ответа (рукопожатие начато) молчание считается с 8 с; без байт - с 3 с (см. тест ниже)
        tracker = DeadVideoClusterTracker()
        rows = [conn("a", down=647), conn("b", down=647), conn("c", down=647)]
        tracker.observe(100.0, rows)
        self.assertEqual(tracker.observe(107.9, rows), [])
        self.assertEqual(len(tracker.observe(108.0, rows)), 1)

    def test_only_silent_proxied_tcp_connections_that_sent_a_request_count(self) -> None:
        tracker = DeadVideoClusterTracker()
        rows = [
            conn("with-data", down=20_000),
            conn("udp", network="udp"),
            conn("nothing-sent", up=0),
            conn("direct", chains=["direct"]),
            conn("over-limit", down=4097),
            conn("redirector", host="redirector.googlevideo.com"),
            conn("other-site", host="example.com"),
        ]
        tracker.observe(100.0, rows)
        self.assertEqual(tracker.observe(109.0, rows), [])
        self.assertEqual(tracker.active_dead(109.0), [])
        # ровно на границе 4096 байт - ещё молчаливое
        tracker.observe(110.0, [conn("x", down=4096), conn("y"), conn("z")])
        events = tracker.observe(119.0, [conn("x", down=4096), conn("y"), conn("z")])
        self.assertEqual([e.kind for e in events], ["dead"])

    def test_same_connection_seen_in_many_polls_is_counted_once(self) -> None:
        tracker = DeadVideoClusterTracker()
        rows = [conn("same")]
        for step in range(12):
            tracker.observe(100.0 + step * 2.0, rows)
        self.assertEqual(tracker.active_dead(130.0), [])

    def test_connections_spread_wider_than_the_window_do_not_add_up(self) -> None:
        tracker = DeadVideoClusterTracker(window_sec=90.0)
        self.silent_round(tracker, 100.0, ["a"])
        self.silent_round(tracker, 160.0, ["b"])
        events = self.silent_round(tracker, 220.0, ["c"])
        self.assertEqual(events, [], "a was counted at t=109, c at t=229: 120 s apart")

    def test_clusters_are_independent(self) -> None:
        tracker = DeadVideoClusterTracker()
        other = "rr1---sn-gxuo03g-aaaa.googlevideo.com"
        rows = [conn("a"), conn("b"), conn("x", host=other)]
        tracker.observe(100.0, rows)
        self.assertEqual(tracker.observe(109.0, rows), [])
        self.assertEqual(self.silent_round(tracker, 110.0, ["c"]), [ClusterEvent("dead", "sn-8ph2xajvh", 3, 10.0)])
        self.assertEqual(tracker.active_dead(119.0), ["sn-8ph2xajvh"])

    def test_a_healthy_connection_of_the_cluster_clears_the_verdict_and_the_count(self) -> None:
        tracker = DeadVideoClusterTracker()
        self.silent_round(tracker, 100.0, ["a", "b", "c"])
        events = tracker.observe(130.0, [conn("ok", down=2_000_000)])
        self.assertEqual(events, [ClusterEvent("recovered", "sn-8ph2xajvh", 0, 21.0)])
        self.assertEqual(tracker.active_dead(130.0), [])
        self.assertEqual(self.silent_round(tracker, 140.0, ["d", "e"]), [], "the count starts over")

    def test_a_healthy_connection_before_the_verdict_forgets_earlier_silent_ones(self) -> None:
        tracker = DeadVideoClusterTracker()
        self.silent_round(tracker, 100.0, ["a", "b"])
        self.assertEqual(tracker.observe(115.0, [conn("ok", down=5_000_000)]), [])
        self.assertEqual(self.silent_round(tracker, 120.0, ["c"]), [])

    def test_the_verdict_fades_when_the_player_stops_retrying(self) -> None:
        tracker = DeadVideoClusterTracker(window_sec=90.0)
        self.silent_round(tracker, 100.0, ["a", "b", "c"])
        self.assertEqual(tracker.active_dead(199.0), ["sn-8ph2xajvh"])
        self.assertEqual(tracker.active_dead(199.1), [])
        # плеер повторяет запрос: кластер снова активен без нового события
        self.assertEqual(self.silent_round(tracker, 300.0, ["d"]), [])
        self.assertEqual(tracker.active_dead(309.0), ["sn-8ph2xajvh"])

    def test_reset_forgets_everything(self) -> None:
        tracker = DeadVideoClusterTracker()
        self.silent_round(tracker, 100.0, ["a", "b", "c"])
        tracker.reset()
        self.assertEqual(tracker.active_dead(109.0), [])
        self.assertEqual(self.silent_round(tracker, 110.0, ["d", "e"]), [])
        self.assertEqual([e.kind for e in self.silent_round(tracker, 130.0, ["f"])], ["dead"])

    def test_broken_rows_do_not_raise(self) -> None:
        tracker = DeadVideoClusterTracker()
        rows = [None, "x", {}, {"id": "a"}, {"id": "b", "metadata": "no"}, {"id": "c", "metadata": {"host": DEAD}, "upload": "bad"}]
        self.assertEqual(tracker.observe(100.0, rows), [])
        self.assertEqual(tracker.observe(109.0, None), [])



class WorkerIntegrationTests(unittest.TestCase):
    """``LiveMetricsWorker`` кормит трекер списком соединений Clash API и отдаёт вердикт один раз (без сети и Qt-цикла)."""

    @staticmethod
    def _worker_class():
        """Класс воркера: на Linux модуль тянет ctypes.windll, поэтому на время импорта подставляется заглушка
        (как в test_probe_silence_scenario)."""

        import ctypes
        import sys

        if sys.platform == "win32":
            from xray_fluent.diagnostics.live_metrics_worker import LiveMetricsWorker

            return LiveMetricsWorker
        original = getattr(ctypes, "windll", None)

        class _AnyLib:
            def __getattr__(self, name):
                lib = _AnyLib()
                setattr(self, name, lib)
                return lib

            def __call__(self, *args, **kwargs):
                return 0

        ctypes.windll = _AnyLib()  # type: ignore[attr-defined]
        try:
            from xray_fluent.diagnostics.live_metrics_worker import LiveMetricsWorker
        finally:
            if original is None:
                del ctypes.windll
            else:
                ctypes.windll = original  # type: ignore[attr-defined]
        return LiveMetricsWorker

    def make_worker(self):
        from PyQt6.QtCore import QCoreApplication

        QCoreApplication.instance() or QCoreApplication([])
        return self._worker_class()("xray.exe", 10085, mode="singbox", clash_api_port=19090)

    @staticmethod
    def response(connections: list[dict]):
        import io
        import json

        class _Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        return _Resp(json.dumps({"uploadTotal": 1, "downloadTotal": 2, "connections": connections}).encode())

    def test_three_silent_googlevideo_connections_become_a_dead_cluster_event_once(self) -> None:
        from unittest.mock import patch

        worker = self.make_worker()
        rows = [conn(name) for name in ("a", "b", "c")]
        clock = {"now": 1000.0}
        with patch("xray_fluent.diagnostics.live_metrics_worker.time.monotonic", lambda: clock["now"]), patch(
            "xray_fluent.diagnostics.live_metrics_worker.urlopen", lambda *a, **k: self.response(rows)
        ):
            worker._query_clash_api_totals()
            clock["now"] = 1009.0
            worker._query_clash_api_totals()
        first = worker._take_dead_video()
        self.assertEqual(first, {"clusters": ["sn-8ph2xajvh"], "events": [("dead", "sn-8ph2xajvh", 3, 0.0)]})
        again = worker._take_dead_video()
        self.assertEqual(again, {"clusters": ["sn-8ph2xajvh"], "events": []}, "events are handed out once")

    def test_failed_query_gives_no_verdict(self) -> None:
        from unittest.mock import patch

        worker = self.make_worker()

        def boom(*args, **kwargs):
            raise OSError("api down")

        with patch("xray_fluent.diagnostics.live_metrics_worker.urlopen", boom):
            self.assertEqual(worker._query_clash_api_totals(), (None, None))
        self.assertIsNone(worker._take_dead_video())


if __name__ == "__main__":
    unittest.main()
