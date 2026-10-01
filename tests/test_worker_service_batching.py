import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from xray_fluent.application.worker_service import (
    on_ping_measured,
    on_ping_progress,
    on_speed_complete,
    on_speed_result,
)
from xray_fluent.network.ping_service import PingOutcome, PingTarget
from xray_fluent.profiles.models import Node


class _Signal:
    def __init__(self):
        self.emit = Mock()


class WorkerServiceBatchingTests(unittest.TestCase):
    def test_speed_results_are_saved_once_when_the_batch_finishes(self) -> None:
        node = Node(id="node-1")
        worker = SimpleNamespace(was_cancelled=False, completed_nodes=1)
        controller = SimpleNamespace(
            _speed_worker=worker,
            _speed_total=1,
            _speed_completed=0,
            sender=lambda: worker,
            _get_node_by_id=lambda node_id: node if node_id == node.id else None,
            speed_updated=_Signal(),
            speed_test_cancelled=_Signal(),
            bulk_task_progress=_Signal(),
            status=_Signal(),
            save=Mock(),
        )

        on_speed_result(controller, node.id, 12.5, True)
        controller.save.assert_not_called()
        self.assertEqual(node.speed_mbps, 12.5)

        on_speed_complete(controller)
        controller.save.assert_called_once_with()
        controller.bulk_task_progress.emit.assert_called_once_with("speed", 1, 1, True)

    def test_ping_round_end_uses_debounced_schedule_save(self) -> None:
        controller = SimpleNamespace(
            bulk_task_progress=_Signal(),
            save=Mock(),
            schedule_save=Mock(),
        )

        on_ping_progress(controller, 2, 3, False)
        controller.schedule_save.assert_not_called()

        on_ping_progress(controller, 3, 3, True)

        controller.save.assert_not_called()
        controller.schedule_save.assert_called_once_with()
        controller.bulk_task_progress.emit.assert_called_with("ping", 3, 3, True)

    def test_ping_result_for_a_moved_server_is_not_applied(self) -> None:
        node = Node(id="node-1", server="old.example", port=443, ping_ms=40)
        target = PingTarget.of(node)
        node.server = "new.example"
        controller = SimpleNamespace(
            _get_node_by_id=lambda node_id: node if node_id == node.id else None,
            ping_updated=_Signal(),
        )

        on_ping_measured(controller, PingOutcome(target, 999, ("1.2.3.4",)))

        self.assertEqual(node.ping_ms, 40)
        self.assertEqual(node.ping_history, [])
        controller.ping_updated.emit.assert_called_once_with("node-1", 40)

    def test_ping_result_is_applied_and_recorded(self) -> None:
        node = Node(id="node-1", server="vpn.example", port=443)
        controller = SimpleNamespace(
            _get_node_by_id=lambda node_id: node if node_id == node.id else None,
            ping_updated=_Signal(),
        )

        on_ping_measured(controller, PingOutcome(PingTarget.of(node), 25, ()))

        self.assertEqual(node.ping_ms, 25)
        self.assertTrue(node.is_alive)
        self.assertEqual(len(node.ping_history), 1)
        controller.ping_updated.emit.assert_called_once_with("node-1", 25)


if __name__ == "__main__":
    unittest.main()
