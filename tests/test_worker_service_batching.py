import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from xray_fluent.application.worker_service import (
    on_ping_complete,
    on_speed_complete,
    on_speed_result,
)
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

    def test_ping_complete_uses_debounced_schedule_save(self) -> None:
        worker = object()
        controller = SimpleNamespace(
            _ping_worker=worker,
            _ping_total=3,
            _ping_completed=3,
            sender=lambda: worker,
            bulk_task_progress=_Signal(),
            save=Mock(),
            schedule_save=Mock(),
        )

        on_ping_complete(controller)

        controller.save.assert_not_called()
        controller.schedule_save.assert_called_once_with()
        controller.bulk_task_progress.emit.assert_called_once_with("ping", 3, 3, True)
        self.assertIsNone(controller._ping_worker)


if __name__ == "__main__":
    unittest.main()
