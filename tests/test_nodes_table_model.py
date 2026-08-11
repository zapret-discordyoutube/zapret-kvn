import unittest

from PyQt6.QtCore import Qt

from xray_fluent.models import Node
from xray_fluent.ui.nodes_table_model import (
    ACTIVE_ROLE,
    COL_ADDRESS,
    COL_GROUP,
    COL_LAST_USED,
    COL_NAME,
    COL_PING,
    COL_SOURCE,
    COL_SPEED,
    COL_TAGS,
    COL_TYPE,
    COLUMN_KEYS,
    DEFAULT_VISIBLE_COLUMNS,
    NODE_ID_ROLE,
    PING_BUSY_ROLE,
    SPEED_PROGRESS_ROLE,
    NodesTableModel,
)


class _SignalCounter:
    """Collects emissions of structural model signals."""

    def __init__(self, model: NodesTableModel):
        self.resets = 0
        self.inserts = []
        self.removes = []
        self.data_changes = []
        model.modelReset.connect(self._on_reset)
        model.rowsInserted.connect(lambda parent, first, last: self.inserts.append((first, last)))
        model.rowsRemoved.connect(lambda parent, first, last: self.removes.append((first, last)))
        model.dataChanged.connect(lambda top, bottom, roles=None: self.data_changes.append((top, bottom, roles)))

    def _on_reset(self):
        self.resets += 1


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

    # ── Columns (AC6) ──

    def test_column_layout_has_address_and_no_status(self) -> None:
        self.assertEqual(self.model.columnCount(), 9)
        self.assertEqual(len(COLUMN_KEYS), 9)
        headers = [
            self.model.headerData(col, Qt.Orientation.Horizontal)
            for col in range(self.model.columnCount())
        ]
        self.assertEqual(
            headers,
            [
                "Имя",
                "Тип",
                "Адрес",
                "Группа",
                "Теги",
                "Пинг",
                "Скорость",
                "Последнее использование",
                "Источник",
            ],
        )
        self.assertNotIn("Статус", headers)
        self.assertNotIn("Сервер", headers)
        self.assertNotIn("Порт", headers)
        self.assertEqual(
            (COL_NAME, COL_TYPE, COL_ADDRESS, COL_GROUP, COL_TAGS, COL_PING, COL_SPEED, COL_LAST_USED, COL_SOURCE),
            (0, 1, 2, 3, 4, 5, 6, 7, 8),
        )
        self.assertEqual(DEFAULT_VISIBLE_COLUMNS, ["name", "ping", "speed"])

    def test_address_cell_combines_server_and_port(self) -> None:
        index = self.model.index(0, COL_ADDRESS)
        self.assertEqual(index.data(Qt.ItemDataRole.DisplayRole), "example.com:443")

    def test_node_id_role_is_available_for_all_columns(self) -> None:
        for col in range(self.model.columnCount()):
            self.assertEqual(self.model.index(0, col).data(NODE_ID_ROLE), "node-1")

    # ── update_nodes diff (AC2) ──

    def test_update_nodes_add_and_remove_do_not_reset(self) -> None:
        a = Node(id="a", name="A")
        b = Node(id="b", name="B")
        c = Node(id="c", name="C")
        d = Node(id="d", name="D")
        self.model.set_nodes([a, b, c])
        counter = _SignalCounter(self.model)

        # Add one node → rowsInserted, no reset.
        self.model.update_nodes([a, b, c, d])
        self.assertEqual(counter.resets, 0)
        self.assertEqual(counter.inserts, [(3, 3)])
        self.assertEqual(counter.removes, [])
        self.assertEqual(self.model.rowCount(), 4)
        self.assertEqual(self.model.row_for_node("d"), 3)

        # Remove one node → rowsRemoved, no reset.
        self.model.update_nodes([a, c, d])
        self.assertEqual(counter.resets, 0)
        self.assertEqual(counter.removes, [(1, 1)])
        self.assertEqual(self.model.rowCount(), 3)
        self.assertIsNone(self.model.row_for_node("b"))
        self.assertEqual(
            [self.model.index(row, 0).data(NODE_ID_ROLE) for row in range(3)],
            ["a", "c", "d"],
        )

    def test_update_nodes_point_edit_emits_datachanged_only(self) -> None:
        a = Node(id="a", name="A")
        b = Node(id="b", name="B")
        self.model.set_nodes([a, b])
        counter = _SignalCounter(self.model)

        edited = Node(id="b", name="B-renamed")
        self.model.update_nodes([a, edited])

        self.assertEqual(counter.resets, 0)
        self.assertEqual(counter.inserts, [])
        self.assertEqual(counter.removes, [])
        self.assertGreaterEqual(len(counter.data_changes), 1)
        self.assertEqual(self.model.index(1, COL_NAME).data(Qt.ItemDataRole.DisplayRole), "B-renamed")

    def test_update_nodes_falls_back_to_reset_on_large_change(self) -> None:
        nodes = [Node(id=f"n{i}", name=f"N{i}") for i in range(4)]
        self.model.set_nodes(nodes)
        counter = _SignalCounter(self.model)

        replacement = [nodes[0]] + [Node(id=f"x{i}", name=f"X{i}") for i in range(3)]
        self.model.update_nodes(replacement)

        self.assertEqual(counter.resets, 1)
        self.assertEqual(self.model.rowCount(), 4)

    # ── Ping batching (AC4) ──

    def test_finish_ping_batch_emits_single_datachanged(self) -> None:
        a = Node(id="a", name="A")
        b = Node(id="b", name="B")
        c = Node(id="c", name="C")
        self.model.set_nodes([a, b, c])
        self.model.set_ping_busy_ids({"a", "b", "c"})
        changes = []
        self.model.dataChanged.connect(lambda top, bottom, roles: changes.append((top, bottom, roles)))

        self.model.finish_ping_batch({"a", "c"})

        self.assertEqual(len(changes), 1)
        top, bottom, _roles = changes[0]
        self.assertEqual(top.row(), 0)
        self.assertEqual(bottom.row(), 2)
        self.assertFalse(self.model.index(0, COL_PING).data(PING_BUSY_ROLE))
        self.assertTrue(self.model.index(1, COL_PING).data(PING_BUSY_ROLE))
        self.assertFalse(self.model.index(2, COL_PING).data(PING_BUSY_ROLE))

    # ── Active node (AC9) ──

    def test_set_active_node_id_changes_exactly_two_rows(self) -> None:
        a = Node(id="a", name="A")
        b = Node(id="b", name="B")
        c = Node(id="c", name="C")
        self.model.set_nodes([a, b, c])
        self.model.set_active_node_id("a")

        changes = []
        self.model.dataChanged.connect(lambda top, bottom, roles: changes.append((top.row(), bottom.row(), roles)))
        self.model.set_active_node_id("c")

        self.assertEqual(len(changes), 2)
        self.assertEqual({change[0] for change in changes}, {0, 2})
        for top_row, bottom_row, roles in changes:
            self.assertEqual(top_row, bottom_row)
            self.assertIn(ACTIVE_ROLE, roles)
            self.assertIn(Qt.ItemDataRole.FontRole, roles)

        self.assertTrue(self.model.index(2, COL_NAME).data(ACTIVE_ROLE))
        self.assertFalse(self.model.index(0, COL_NAME).data(ACTIVE_ROLE))
        font = self.model.index(2, COL_NAME).data(Qt.ItemDataRole.FontRole)
        self.assertIsNotNone(font)
        self.assertTrue(font.bold())
        self.assertIsNone(self.model.index(0, COL_NAME).data(Qt.ItemDataRole.FontRole))

    # ── Ping cell status semantics (AC7) ──

    def test_ping_cell_is_green_for_alive_node(self) -> None:
        node = Node(id="ok", name="OK", ping_ms=42, speed_mbps=12.5, is_alive=True)
        self.model.set_nodes([node])
        index = self.model.index(0, COL_PING)
        brush = index.data(Qt.ItemDataRole.ForegroundRole)
        self.assertIsNotNone(brush)
        self.assertEqual(brush.color().name(), "#4caf50")
        self.assertIn("Сервер работает", index.data(Qt.ItemDataRole.ToolTipRole))

    def test_ping_cell_is_red_for_dead_node(self) -> None:
        node = Node(id="dead", name="Dead", ping_ms=None, is_alive=False)
        self.model.set_nodes([node])
        index = self.model.index(0, COL_PING)
        self.assertEqual(index.data(Qt.ItemDataRole.DisplayRole), "--")
        brush = index.data(Qt.ItemDataRole.ForegroundRole)
        self.assertIsNotNone(brush)
        self.assertEqual(brush.color().name(), "#dc3232")
        self.assertIn("Сервер недоступен", index.data(Qt.ItemDataRole.ToolTipRole))

    def test_ping_cell_is_orange_for_probably_blocked_node(self) -> None:
        node = Node(
            id="blocked",
            name="Blocked",
            ping_ms=42,
            speed_mbps=None,
            is_alive=True,
            speed_history=[("2026-01-01T00:00:00+00:00", None)],
        )
        self.model.set_nodes([node])
        index = self.model.index(0, COL_PING)
        brush = index.data(Qt.ItemDataRole.ForegroundRole)
        self.assertIsNotNone(brush)
        self.assertEqual(brush.color().name(), "#ff9800")
        self.assertIn("вероятно заблокирован", index.data(Qt.ItemDataRole.ToolTipRole))

    # ── Existing activity behaviour ──

    def test_ping_activity_is_model_data_not_a_cell_widget(self) -> None:
        changes = []
        self.model.dataChanged.connect(lambda *args: changes.append(args))

        self.model.set_ping_busy_ids({self.node.id})
        index = self.model.index(0, COL_PING)

        self.assertTrue(index.data(PING_BUSY_ROLE))
        self.assertEqual(index.data(Qt.ItemDataRole.DisplayRole), "")
        self.assertEqual(index.data(Qt.ItemDataRole.ToolTipRole), "Проверка пинга...")
        self.assertEqual(len(changes), 1)

        self.model.clear_ping_busy()
        self.assertFalse(index.data(PING_BUSY_ROLE))
        self.assertEqual(index.data(Qt.ItemDataRole.DisplayRole), "42 ms")

    def test_speed_progress_is_clamped_and_cleared_addressably(self) -> None:
        index = self.model.index(0, COL_SPEED)

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
        self.assertEqual(self.model.index(0, COL_SPEED).data(SPEED_PROGRESS_ROLE), 25)
        self.assertEqual(self.model.index(1, COL_SPEED).data(SPEED_PROGRESS_ROLE), 50)

        changes.clear()
        self.model.finish_speed(self.node.id)
        self.assertEqual(len(changes), 1)
        self.assertIsNone(self.model.index(0, COL_SPEED).data(SPEED_PROGRESS_ROLE))

    def test_batch_ping_update_emits_one_table_range_change(self) -> None:
        other = Node(id="node-2", name="Other")
        self.model.set_nodes([self.node, other])
        changes = []
        self.model.dataChanged.connect(lambda top, bottom, roles: changes.append((top, bottom, roles)))

        self.model.set_ping_busy_ids({self.node.id, other.id})

        self.assertEqual(len(changes), 1)
        top, bottom, roles = changes[0]
        self.assertEqual((top.row(), top.column()), (0, COL_PING))
        self.assertEqual((bottom.row(), bottom.column()), (1, COL_PING))
        self.assertIn(PING_BUSY_ROLE, roles)

    def test_source_column_distinguishes_local_and_subscription_nodes(self) -> None:
        subscribed = Node(id="node-2", name="Remote", subscription_id="sub-1")
        self.model.set_source_names({"sub-1": "Provider"})
        self.model.set_nodes([self.node, subscribed])

        self.assertEqual(self.model.index(0, COL_SOURCE).data(Qt.ItemDataRole.DisplayRole), "Локальные")
        self.assertEqual(self.model.index(1, COL_SOURCE).data(Qt.ItemDataRole.DisplayRole), "Provider")


if __name__ == "__main__":
    unittest.main()
