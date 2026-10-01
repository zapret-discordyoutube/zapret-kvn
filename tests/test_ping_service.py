"""Служба пинга (xray_fluent/network/ping_service.py): очередь без QThread."""

from __future__ import annotations

import threading
import time
import unittest

from PyQt6.QtCore import QCoreApplication, QEventLoop, QThread, QTimer

from xray_fluent.network.ping_service import PingOutcome, PingService, PingTarget
from xray_fluent.profiles.models import Node

_APP = QCoreApplication.instance() or QCoreApplication([])


def _spin_until(predicate, timeout_ms: int = 3000) -> bool:
    deadline = time.monotonic() + timeout_ms / 1000.0
    while time.monotonic() < deadline:
        if predicate():
            return True
        loop = QEventLoop()
        QTimer.singleShot(5, loop.quit)
        loop.exec()
    return predicate()


def _node(index: int) -> Node:
    return Node(id=f"n{index}", name=f"n{index}", server=f"host{index}.example", port=443)


class _GatedProbe:
    """Замер, который ждёт разрешения; считает одновременные вызовы."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.calls: list[str] = []
        self.active = 0
        self.peak = 0

    def __call__(self, target: PingTarget, _timeout: float):
        with self.lock:
            self.calls.append(target.node_id)
            self.active += 1
            self.peak = max(self.peak, self.active)
        self.release.wait(5)
        with self.lock:
            self.active -= 1
        return 10, ()


class PingServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.probe = _GatedProbe()
        self.service = PingService(probe=self.probe, max_parallel=4, idle_exit_sec=0.2)
        self.outcomes: list[PingOutcome] = []
        self.progress: list[tuple[int, int, bool]] = []
        self.service.measured.connect(self.outcomes.append)
        self.service.progress.connect(lambda d, t, f: self.progress.append((d, t, f)))

    def tearDown(self) -> None:
        self.probe.release.set()
        self.service.close()

    def test_repeated_request_for_a_node_in_flight_is_ignored(self) -> None:
        node = _node(1)
        self.assertEqual(self.service.request([node]), 1)
        for _ in range(50):
            self.assertEqual(self.service.request([node]), 0)
        self.probe.release.set()
        self.assertTrue(_spin_until(lambda: not self.service.busy))
        self.assertEqual(self.probe.calls, ["n1"])
        self.assertEqual([o.target.node_id for o in self.outcomes], ["n1"])
        self.assertEqual(self.progress[-1], (1, 1, True))

    def test_new_nodes_join_the_running_round(self) -> None:
        self.service.request([_node(1), _node(2)])
        self.service.request([_node(2), _node(3)])
        self.assertEqual(self.progress, [(0, 2, False), (0, 3, False)])
        self.probe.release.set()
        self.assertTrue(_spin_until(lambda: not self.service.busy))
        self.assertEqual(sorted(o.target.node_id for o in self.outcomes), ["n1", "n2", "n3"])
        self.assertEqual(self.progress[-1], (3, 3, True))
        self.assertEqual([p for p in self.progress if p[2]], [(3, 3, True)])

    def test_parallelism_is_bounded(self) -> None:
        self.service.request([_node(i) for i in range(20)])
        self.assertTrue(_spin_until(lambda: self.probe.active == 4))
        self.probe.release.set()
        self.assertTrue(_spin_until(lambda: not self.service.busy))
        self.assertEqual(len(self.outcomes), 20)
        self.assertLessEqual(self.probe.peak, 4)

    def test_signals_arrive_in_the_gui_thread(self) -> None:
        threads: list[bool] = []
        self.service.measured.connect(
            lambda _o: threads.append(QThread.currentThread() is _APP.thread())
        )
        self.probe.release.set()
        self.service.request([_node(1), _node(2)])
        self.assertTrue(_spin_until(lambda: len(threads) == 2))
        self.assertEqual(threads, [True, True])

    def test_close_drops_queue_and_late_results(self) -> None:
        self.service.request([_node(i) for i in range(10)])
        self.assertTrue(_spin_until(lambda: self.probe.active == 4))
        self.service.close()
        self.assertFalse(self.service.busy)
        self.probe.release.set()
        _spin_until(lambda: False, timeout_ms=200)
        self.assertEqual(self.outcomes, [])
        self.assertEqual(self.service.request([_node(99)]), 0)

    def test_servers_sharing_an_endpoint_are_measured_once(self) -> None:
        # В подписках один адрес:порт повторяется под разными именами: одно
        # соединение вместо десятка — и быстрее, и незаметнее на линии.
        nodes = [Node(id=f"s{i}", name=f"s{i}", server="Shared.Example", port=443) for i in range(5)]
        nodes.append(Node(id="other", name="other", server="shared.example", port=8443))
        self.probe.release.set()
        self.assertEqual(self.service.request(nodes), 6)
        self.assertTrue(_spin_until(lambda: not self.service.busy))
        self.assertEqual(len(self.probe.calls), 2)
        self.assertEqual(sorted(o.target.node_id for o in self.outcomes),
                         ["other", "s0", "s1", "s2", "s3", "s4"])
        self.assertEqual({o.ping_ms for o in self.outcomes}, {10})
        self.assertEqual(self.progress[-1], (6, 6, True))

    def test_late_request_joins_a_measurement_in_flight(self) -> None:
        first = Node(id="a", name="a", server="shared.example", port=443)
        second = Node(id="b", name="b", server="shared.example", port=443)
        self.service.request([first])
        self.assertTrue(_spin_until(lambda: self.probe.active == 1))
        self.service.request([second])
        self.probe.release.set()
        self.assertTrue(_spin_until(lambda: not self.service.busy))
        self.assertEqual(len(self.probe.calls), 1)
        self.assertEqual(sorted(o.target.node_id for o in self.outcomes), ["a", "b"])

    def test_cancel_drops_queued_servers_and_finishes_the_round(self) -> None:
        self.service.request([_node(i) for i in range(20)])
        self.assertTrue(_spin_until(lambda: self.probe.active == 4))
        self.assertEqual(self.service.cancel(), 16)
        self.assertTrue(self.service.busy)  # четыре соединения ещё идут
        self.assertEqual(self.progress[-1], (0, 4, False))
        self.probe.release.set()
        self.assertTrue(_spin_until(lambda: not self.service.busy))
        self.assertEqual(len(self.probe.calls), 4)
        self.assertEqual(len(self.outcomes), 4)
        self.assertEqual(self.progress[-1], (4, 4, True))
        # После отмены служба принимает новые запросы.
        self.assertEqual(self.service.request([_node(50)]), 1)
        self.assertTrue(_spin_until(lambda: not self.service.busy))

    def test_cancel_with_nothing_queued_changes_nothing(self) -> None:
        self.assertEqual(self.service.cancel(), 0)
        self.assertEqual(self.progress, [])

    def test_measurement_order_is_shuffled(self) -> None:
        service = PingService(probe=self.probe, max_parallel=1, start_jitter_sec=0.0)
        self.probe.release.set()
        nodes = [_node(i) for i in range(40)]
        service.request(nodes)
        self.assertTrue(_spin_until(lambda: not service.busy))
        self.assertEqual(sorted(self.probe.calls), sorted(node.id for node in nodes))
        self.assertNotEqual(self.probe.calls, [node.id for node in nodes])
        service.close()

    def test_idle_threads_exit(self) -> None:
        self.probe.release.set()
        self.service.request([_node(1), _node(2)])
        self.assertTrue(_spin_until(lambda: not self.service.busy))
        alive = lambda: [t for t in threading.enumerate() if t.name == "ping"]  # noqa: E731
        self.assertTrue(_spin_until(lambda: not alive(), timeout_ms=3000))

    def test_probe_error_is_reported_as_unreachable(self) -> None:
        def broken(_target, _timeout):
            raise OSError("boom")

        service = PingService(probe=broken)
        outcomes: list[PingOutcome] = []
        service.measured.connect(outcomes.append)
        service.request([_node(1)])
        self.assertTrue(_spin_until(lambda: bool(outcomes)))
        self.assertIsNone(outcomes[0].ping_ms)
        service.close()

    def test_target_snapshot_detects_moved_server(self) -> None:
        node = _node(1)
        target = PingTarget.of(node)
        self.assertTrue(target.matches(node))
        node.port = 8443
        self.assertFalse(target.matches(node))


if __name__ == "__main__":
    unittest.main()
