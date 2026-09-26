import unittest

from PyQt6.QtCore import QCoreApplication, QItemSelectionModel, QPersistentModelIndex, Qt
from PyQt6.QtTest import QTest

from xray_fluent.profiles.models import Node
from xray_fluent.ui.theme import error_color, positive_color, success_color, warning_color
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
    COLUMN_BY_KEY,
    COLUMN_KEYS,
    COLUMN_SPECS,
    DEFAULT_VISIBLE_COLUMNS,
    GROUP_KEY_ROLE,
    NODE_ID_ROLE,
    PING_BUSY_ROLE,
    SPEED_PROGRESS_ROLE,
    NodesTableModel,
)


# Таймер пересортировки после метрик требует цикла событий.
_APP = QCoreApplication.instance() or QCoreApplication([])

# Окно троттлинга пересортировки по метрикам (300 мс) плюс запас.
_AFTER_RELAYOUT_WINDOW_MS = 400


class _SignalCounter:
    """Collects emissions of structural model signals."""

    def __init__(self, model: NodesTableModel):
        self.model = model
        self.resets = 0
        self.layouts = 0
        self.inserts = []
        self.removes = []
        self.data_changes = []
        model.modelReset.connect(self._on_reset)
        model.layoutChanged.connect(self._on_layout)
        model.rowsInserted.connect(lambda parent, first, last: self.inserts.append((first, last)))
        model.rowsRemoved.connect(lambda parent, first, last: self.removes.append((first, last)))
        model.dataChanged.connect(
            lambda top, bottom, roles=None: self.data_changes.append(
                (top.row(), bottom.row(), top.column(), bottom.column())
            )
        )

    def _on_reset(self):
        self.resets += 1

    def _on_layout(self, *_args):
        self.layouts += 1

    def changed_rows(self) -> set[int]:
        return {row for top, bottom, _l, _r in self.data_changes for row in range(top, bottom + 1)}


def _flat_model(nodes: list[Node]) -> NodesTableModel:
    """Модель без группировки: строка N — N-й сервер."""
    model = NodesTableModel()
    model.set_group_mode("none")
    model.set_nodes(nodes)
    return model


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
        self.model = _flat_model([self.node])

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
        self.assertEqual(
            DEFAULT_VISIBLE_COLUMNS,
            ["name", "type", "ping", "speed"],
        )

    def test_address_cell_masks_server_and_port(self) -> None:
        index = self.model.index(0, COL_ADDRESS)
        self.assertEqual(index.data(Qt.ItemDataRole.DisplayRole), "********")
        self.assertNotIn("example.com", index.data(Qt.ItemDataRole.DisplayRole))

    def test_address_is_visible_only_while_model_reveal_is_active(self) -> None:
        index = self.model.index(0, COL_ADDRESS)
        self.model.set_endpoints_revealed(True)
        self.assertEqual(index.data(Qt.ItemDataRole.DisplayRole), "example.com:443")
        self.assertIn(
            "Адрес: example.com:443",
            self.model.index(0, COL_NAME).data(Qt.ItemDataRole.ToolTipRole),
        )

        self.model.set_endpoints_revealed(False)
        self.assertEqual(index.data(Qt.ItemDataRole.DisplayRole), "********")
        self.assertNotIn(
            "example.com",
            self.model.index(0, COL_NAME).data(Qt.ItemDataRole.ToolTipRole),
        )

    def test_ipv6_address_is_bracketed_while_revealed(self) -> None:
        self.model.set_nodes(
            [Node(id="ipv6", name="IPv6", server="2001:db8::1", port=443)]
        )
        self.model.set_endpoints_revealed(True)
        self.assertEqual(
            self.model.index(0, COL_ADDRESS).data(Qt.ItemDataRole.DisplayRole),
            "[2001:db8::1]:443",
        )

    def test_type_falls_back_to_native_outbound_for_legacy_node(self) -> None:
        self.model.set_nodes(
            [Node(id="legacy", scheme="", outbound={"type": "hysteria2"})]
        )
        self.assertEqual(
            self.model.index(0, COL_TYPE).data(Qt.ItemDataRole.DisplayRole),
            "HYSTERIA2",
        )

    def test_name_tooltip_masks_server_and_port(self) -> None:
        tooltip = self.model.index(0, COL_NAME).data(Qt.ItemDataRole.ToolTipRole)
        self.assertIn("Адрес: ********", tooltip)
        self.assertNotIn("example.com", tooltip)

    def test_node_id_role_is_available_for_all_columns(self) -> None:
        for col in range(self.model.columnCount()):
            self.assertEqual(self.model.index(0, col).data(NODE_ID_ROLE), "node-1")

    # ── Группировка: строки-заголовки ──

    def test_default_mode_groups_by_source_with_header_rows(self) -> None:
        model = NodesTableModel()
        self.assertEqual(model.group_mode(), "source")
        model.set_source_names({"sub-1": "Мой провайдер"})
        model.set_nodes([self.node, Node(id="remote", name="Remote", subscription_id="sub-1")])

        header = model.index(0, COL_NAME)
        self.assertEqual(header.data(GROUP_KEY_ROLE), "source:local")
        self.assertEqual(header.data(Qt.ItemDataRole.DisplayRole), "Локальные · 1")
        self.assertIsNone(header.data(NODE_ID_ROLE))
        self.assertTrue(header.data(Qt.ItemDataRole.FontRole).bold())
        self.assertFalse(model.flags(header) & Qt.ItemFlag.ItemIsSelectable)
        # Группы — по названию (casefold), ноды внутри — в порядке сортировки.
        self.assertEqual(model.group_keys(), ["source:local", "source:sub-1"])
        self.assertEqual(
            [model.index(row, COL_NAME).data(GROUP_KEY_ROLE) or model.index(row, 0).data(NODE_ID_ROLE)
             for row in range(model.rowCount())],
            ["source:local", "node-1", "source:sub-1", "remote"],
        )

    def test_collapsed_group_children_are_not_rows_but_stay_counted(self) -> None:
        model = NodesTableModel()
        model.set_nodes([Node(id="a", name="A"), Node(id="b", name="B")])
        counter = _SignalCounter(model)

        model.set_collapsed_groups({"source:local"})

        self.assertEqual(counter.resets, 1)
        self.assertEqual(model.rowCount(), 1)
        self.assertIsNone(model.row_of_node("a"))
        self.assertEqual(model.collapsed_group_of("a"), "source:local")
        self.assertEqual(model.visible_node_count(), 2)
        self.assertEqual(model.visible_node_ids(), ["a", "b"])
        self.assertEqual(model.index(0, COL_NAME).data(), "Локальные · 2")

        model.set_collapsed_groups(set())
        self.assertEqual(model.row_of_node("b"), 2)
        self.assertIsNone(model.collapsed_group_of("b"))

    # ── set_nodes diff (AC2) ──

    def test_set_nodes_add_and_remove_rebuild_once_in_catalog_order(self) -> None:
        a = Node(id="a", name="A")
        b = Node(id="b", name="B")
        c = Node(id="c", name="C")
        d = Node(id="d", name="D")
        self.model.set_nodes([a, b, c])
        counter = _SignalCounter(self.model)

        # Добавление меняет состав строк — ровно один reset (выделение вид
        # восстанавливает по ключам строк), без поштучных insert/remove.
        self.model.set_nodes([a, b, c, d])
        self.assertEqual(counter.resets, 1)
        self.assertEqual(counter.inserts, [])
        self.assertEqual(self.model.rowCount(), 4)
        self.assertEqual(self.model.row_of_node("d"), 3)

        self.model.set_nodes([a, c, d])
        self.assertEqual(counter.resets, 2)
        self.assertEqual(counter.removes, [])
        self.assertEqual(self.model.rowCount(), 3)
        self.assertIsNone(self.model.row_of_node("b"))
        self.assertEqual(
            [self.model.index(row, 0).data(NODE_ID_ROLE) for row in range(3)],
            ["a", "c", "d"],
        )

    def test_set_nodes_point_edit_emits_datachanged_for_that_row_only(self) -> None:
        a = Node(id="a", name="A")
        b = Node(id="b", name="B")
        self.model.set_nodes([a, b])
        counter = _SignalCounter(self.model)

        edited = Node(id="b", name="B-renamed")
        self.model.set_nodes([a, edited])

        self.assertEqual(counter.resets, 0)
        self.assertEqual(counter.layouts, 0)
        self.assertEqual(counter.changed_rows(), {1})
        self.assertEqual(self.model.index(1, COL_NAME).data(Qt.ItemDataRole.DisplayRole), "B-renamed")

    def test_set_nodes_unchanged_catalog_emits_nothing(self) -> None:
        a = Node(id="a", name="A")
        b = Node(id="b", name="B")
        self.model.set_nodes([a, b])
        counter = _SignalCounter(self.model)

        self.model.set_nodes([a, b])

        self.assertEqual((counter.resets, counter.layouts, counter.data_changes), (0, 0, []))

    def test_set_nodes_replacing_catalog_resets_once(self) -> None:
        nodes = [Node(id=f"n{i}", name=f"N{i}") for i in range(4)]
        self.model.set_nodes(nodes)
        counter = _SignalCounter(self.model)

        replacement = [nodes[0]] + [Node(id=f"x{i}", name=f"X{i}") for i in range(3)]
        self.model.set_nodes(replacement)

        self.assertEqual(counter.resets, 1)
        self.assertEqual(self.model.rowCount(), 4)

    # ── Ping batching (AC4) ──

    def test_finish_ping_batch_repaints_only_finished_rows(self) -> None:
        a = Node(id="a", name="A")
        b = Node(id="b", name="B")
        c = Node(id="c", name="C")
        self.model.set_nodes([a, b, c])
        self.model.set_ping_busy_ids({"a", "b", "c"})
        counter = _SignalCounter(self.model)

        a.ping_ms, c.ping_ms = 10, 20
        self.model.finish_ping_batch({"a", "c"})

        self.assertEqual(counter.changed_rows(), {0, 2})
        for top, bottom, _left, _right in counter.data_changes:
            self.assertEqual(top, bottom)
        self.assertEqual((counter.resets, counter.layouts), (0, 0))
        self.assertFalse(self.model.index(0, COL_PING).data(PING_BUSY_ROLE))
        self.assertTrue(self.model.index(1, COL_PING).data(PING_BUSY_ROLE))
        self.assertFalse(self.model.index(2, COL_PING).data(PING_BUSY_ROLE))
        self.assertEqual(self.model.index(0, COL_PING).data(), "10 ms")
        self.assertEqual(self.model.index(2, COL_PING).data(), "20 ms")

    def test_single_ping_result_is_a_point_update(self) -> None:
        nodes = [Node(id=f"n{i}", name=f"N{i}", sort_order=i) for i in range(5)]
        self.model.set_nodes(nodes)
        counter = _SignalCounter(self.model)

        nodes[3].ping_ms = 77
        self.model.finish_ping_batch({"n3"})
        QTest.qWait(_AFTER_RELAYOUT_WINDOW_MS)

        self.assertEqual(counter.changed_rows(), {3})
        self.assertEqual((counter.resets, counter.layouts), (0, 0))
        self.assertEqual(self.model.index(3, COL_PING).data(), "77 ms")

    # ── Метрики при сортировке по ним: одна пересортировка на окно ──

    def test_ping_sort_resorts_once_after_throttle_window_and_selection_follows(self) -> None:
        nodes = [Node(id=f"n{i}", name=f"N{i}", ping_ms=10 * (i + 1), sort_order=i) for i in range(4)]
        self.model.set_nodes(nodes)
        self.model.set_sort("ping", False)
        selection = QItemSelectionModel(self.model)
        selection.select(
            self.model.index(0, 0),
            QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
        )
        persistent = QPersistentModelIndex(self.model.index(0, COL_PING))
        counter = _SignalCounter(self.model)

        # Пачка результатов подряд: таблица не прыгает на каждый ответ.
        nodes[0].ping_ms = 500
        self.model.finish_ping_batch({"n0"})
        nodes[1].ping_ms = 400
        self.model.finish_ping_batch({"n1"})
        self.assertEqual(counter.layouts, 0)
        self.assertEqual(self.model.visible_node_ids(), ["n0", "n1", "n2", "n3"])

        QTest.qWait(_AFTER_RELAYOUT_WINDOW_MS)

        self.assertEqual(counter.layouts, 1)
        self.assertEqual(counter.resets, 0)
        self.assertEqual(self.model.visible_node_ids(), ["n2", "n3", "n1", "n0"])
        self.assertEqual(persistent.row(), 3)
        self.assertEqual(persistent.column(), COL_PING)
        self.assertEqual(persistent.data(NODE_ID_ROLE), "n0")
        self.assertEqual({index.data(NODE_ID_ROLE) for index in selection.selectedRows()}, {"n0"})

    def test_metrics_in_collapsed_group_do_not_touch_hidden_rows(self) -> None:
        model = NodesTableModel()
        nodes = [Node(id=f"n{i}", name=f"N{i}", sort_order=i) for i in range(3)]
        model.set_nodes(nodes)
        model.set_collapsed_groups({"source:local"})
        counter = _SignalCounter(model)

        nodes[1].ping_ms = 33
        model.finish_ping_batch({"n1"})
        model.set_ping_busy_ids({"n0", "n2"})
        model.set_speed_progress_batch({"n0": 50})
        model.set_active_node_id("n2")
        QTest.qWait(_AFTER_RELAYOUT_WINDOW_MS)

        self.assertEqual(counter.data_changes, [])
        self.assertEqual((counter.resets, counter.layouts), (0, 0))

        # После раскрытия строка сразу показывает свежие данные.
        model.set_collapsed_groups(set())
        self.assertEqual(model.index(model.row_of_node("n1"), COL_PING).data(), "33 ms")

    # ── Active node (AC9) ──

    def test_set_active_node_id_changes_exactly_two_rows(self) -> None:
        a = Node(id="a", name="A")
        b = Node(id="b", name="B")
        c = Node(id="c", name="C")
        self.model.set_nodes([a, b, c])
        self.model.set_active_node_id("a")

        counter = _SignalCounter(self.model)
        self.model.set_active_node_id("c")

        self.assertEqual(len(counter.data_changes), 2)
        self.assertEqual({change[0] for change in counter.data_changes}, {0, 2})
        for top_row, bottom_row, _left, _right in counter.data_changes:
            self.assertEqual(top_row, bottom_row)

        self.assertTrue(self.model.index(2, COL_NAME).data(ACTIVE_ROLE))
        self.assertFalse(self.model.index(0, COL_NAME).data(ACTIVE_ROLE))
        self.assertEqual(self.model.active_node_id(), "c")
        # Выделение активной строки рисует делегат (заливка акцентом); модель
        # не отдаёт FontRole для строк-серверов.
        self.assertIsNone(self.model.index(2, COL_NAME).data(Qt.ItemDataRole.FontRole))

    # ── Ping cell status semantics (AC7) ──

    def test_ping_cell_is_green_for_alive_node(self) -> None:
        node = Node(id="ok", name="OK", ping_ms=42, speed_mbps=12.5, is_alive=True)
        self.model.set_nodes([node])
        index = self.model.index(0, COL_PING)
        brush = index.data(Qt.ItemDataRole.ForegroundRole)
        self.assertIsNotNone(brush)
        self.assertEqual(brush.color().name(), positive_color().name())
        self.assertIn("Сервер работает", index.data(Qt.ItemDataRole.ToolTipRole))

    def test_ping_cell_is_red_for_dead_node(self) -> None:
        node = Node(id="dead", name="Dead", ping_ms=None, is_alive=False)
        self.model.set_nodes([node])
        index = self.model.index(0, COL_PING)
        self.assertEqual(index.data(Qt.ItemDataRole.DisplayRole), "--")
        brush = index.data(Qt.ItemDataRole.ForegroundRole)
        self.assertIsNotNone(brush)
        self.assertEqual(brush.color().name(), error_color().name())
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
        self.assertEqual(brush.color().name(), warning_color().name())
        self.assertIn("вероятно заблокирован", index.data(Qt.ItemDataRole.ToolTipRole))

    # ── Existing activity behaviour ──

    def test_ping_activity_is_model_data_not_a_cell_widget(self) -> None:
        changes = []
        self.model.dataChanged.connect(lambda *args: changes.append(args))

        self.model.set_ping_busy_ids({self.node.id})
        index = self.model.index(0, COL_PING)

        self.assertTrue(index.data(PING_BUSY_ROLE))
        self.assertTrue(self.model.is_ping_busy(self.node.id))
        self.assertEqual(index.data(Qt.ItemDataRole.DisplayRole), "")
        self.assertEqual(index.data(Qt.ItemDataRole.ToolTipRole), "Проверка пинга...")
        self.assertEqual(len(changes), 1)

        self.model.clear_ping_busy()
        self.assertFalse(index.data(PING_BUSY_ROLE))
        self.assertEqual(index.data(Qt.ItemDataRole.DisplayRole), "42 ms")

    def test_speed_progress_is_clamped_and_cleared_addressably(self) -> None:
        other = Node(id="node-2", name="Other")
        self.model.set_nodes([self.node, other])
        index = self.model.index(0, COL_SPEED)

        self.model.set_speed_progress_batch({self.node.id: 140, other.id: -5})
        self.assertEqual(index.data(SPEED_PROGRESS_ROLE), 100)
        self.assertEqual(self.model.speed_progress(other.id), 0)
        self.assertEqual(index.data(Qt.ItemDataRole.DisplayRole), "")
        self.assertEqual(index.data(Qt.ItemDataRole.ToolTipRole), "Тест скорости: 100%")

        # Результат одного сервера снимает прогресс только с него.
        self.model.finish_speed(self.node.id)
        self.assertIsNone(index.data(SPEED_PROGRESS_ROLE))
        self.assertEqual(index.data(Qt.ItemDataRole.DisplayRole), "12.5 MB/s")
        self.assertEqual(self.model.speed_progress(other.id), 0)

        self.model.clear_speed_progress()
        self.assertIsNone(self.model.speed_progress(other.id))

    def test_progress_batch_and_result_each_emit_one_repaint(self) -> None:
        other = Node(id="node-2", name="Other")
        self.model.set_nodes([self.node, other])
        changes = []
        self.model.dataChanged.connect(lambda *args: changes.append(args))

        self.model.set_speed_progress_batch({self.node.id: 25, other.id: 50})
        self.assertEqual(len(changes), 1)
        top, bottom = changes[0][0], changes[0][1]
        self.assertEqual((top.row(), top.column()), (0, COL_SPEED))
        self.assertEqual((bottom.row(), bottom.column()), (1, COL_SPEED))
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
        top, bottom, _roles = changes[0]
        self.assertEqual((top.row(), top.column()), (0, COL_PING))
        self.assertEqual((bottom.row(), bottom.column()), (1, COL_PING))

    def test_source_column_distinguishes_local_and_subscription_nodes(self) -> None:
        subscribed = Node(id="node-2", name="Remote", subscription_id="sub-1")
        self.model.set_source_names({"sub-1": "Provider"})
        self.model.set_nodes([self.node, subscribed])

        self.assertEqual(self.model.index(0, COL_SOURCE).data(Qt.ItemDataRole.DisplayRole), "Локальные")
        self.assertEqual(self.model.index(1, COL_SOURCE).data(Qt.ItemDataRole.DisplayRole), "Provider")


class ColumnSpecsTests(unittest.TestCase):
    """AC7: generous maximum widths; "name" stays the single flex column."""

    def test_maximum_widths_match_flex_layout_spec(self) -> None:
        expected = {
            "type": 200,
            "address": 360,
            "group": 800,
            "tags": 1000,
            "ping": 160,
            "speed": 200,
            "last_used": 480,
            "source": 1000,
        }
        for key, maximum in expected.items():
            self.assertEqual(
                COLUMN_BY_KEY[key].maximum_width, maximum, f"maximum_width of {key}"
            )

    def test_name_is_the_single_flex_column(self) -> None:
        flex = [spec.key for spec in COLUMN_SPECS if spec.stretch]
        self.assertEqual(flex, [])


if __name__ == "__main__":
    unittest.main()
