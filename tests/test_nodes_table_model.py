import unittest

from PyQt6.QtCore import Qt

from xray_fluent.models import Node
from xray_fluent.ui.nodes_table_model import (
    PING_BUSY_ROLE,
    SPEED_PROGRESS_ROLE,
    NodesTableModel,
)


class NodesTableModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.node = Node(
            id="node-1",
            name="Test server",
            scheme="vless",
            server="example.com",
            port=443,
            ping_ms=42,
            speed_mbps=12.5,
        )
        self.model = NodesTableModel()
        self.model.set_nodes([self.node])

    def test_ping_activity_is_model_data_not_a_cell_widget(self) -> None:
        changes = []
        self.model.dataChanged.connect(lambda *args: changes.append(args))

        self.model.set_ping_busy_ids({self.node.id})
        index = self.model.index(0, 6)

        self.assertTrue(index.data(PING_BUSY_ROLE))
        self.assertEqual(index.data(Qt.ItemDataRole.DisplayRole), "")
        self.assertEqual(index.data(Qt.ItemDataRole.ToolTipRole), "Проверка пинга...")
        self.assertEqual(len(changes), 1)

        self.model.clear_ping_busy()
        self.assertFalse(index.data(PING_BUSY_ROLE))
        self.assertEqual(index.data(Qt.ItemDataRole.DisplayRole), "42 ms")

    def test_speed_progress_is_clamped_and_cleared_addressably(self) -> None:
        index = self.model.index(0, 7)

        self.model.set_speed_progress(self.node.id, 140)
        self.assertEqual(index.data(SPEED_PROGRESS_ROLE), 100)
        self.assertEqual(index.data(Qt.ItemDataRole.DisplayRole), "")
        self.assertEqual(index.data(Qt.ItemDataRole.ToolTipRole), "Тест скорости: 100%")

        self.model.set_speed_progress(self.node.id, None)
        self.assertIsNone(index.data(SPEED_PROGRESS_ROLE))
        self.assertEqual(index.data(Qt.ItemDataRole.DisplayRole), "12.5 MB/s")

    def test_progress_batch_and_result_each_emit_one_repaint(self) -> None:
        other = Node(id="node-2", name="Other")
        self.model.set_nodes([self.node, other])
        changes = []
        self.model.dataChanged.connect(lambda *args: changes.append(args))

        self.model.set_speed_progress_batch({self.node.id: 25, other.id: 50})
        self.assertEqual(len(changes), 1)
        self.assertEqual(self.model.index(0, 7).data(SPEED_PROGRESS_ROLE), 25)
        self.assertEqual(self.model.index(1, 7).data(SPEED_PROGRESS_ROLE), 50)

        changes.clear()
        self.model.finish_speed(self.node.id)
        self.assertEqual(len(changes), 1)
        self.assertIsNone(self.model.index(0, 7).data(SPEED_PROGRESS_ROLE))

    def test_batch_ping_update_emits_one_table_range_change(self) -> None:
        other = Node(id="node-2", name="Other")
        self.model.set_nodes([self.node, other])
        changes = []
        self.model.dataChanged.connect(lambda top, bottom, roles: changes.append((top, bottom, roles)))

        self.model.set_ping_busy_ids({self.node.id, other.id})

        self.assertEqual(len(changes), 1)
        top, bottom, roles = changes[0]
        self.assertEqual((top.row(), top.column()), (0, 6))
        self.assertEqual((bottom.row(), bottom.column()), (1, 6))
        self.assertIn(PING_BUSY_ROLE, roles)


if __name__ == "__main__":
    unittest.main()
