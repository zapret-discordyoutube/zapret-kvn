"""Фильтры и сортировка таблицы серверов (бывший NodesFilterProxy).

Фильтр и сортировку теперь считает сама ``NodesTableModel`` в ``_relayout``;
порядок проверяется без группировки (``group_mode == "none"``), чтобы строка
N была N-м сервером. Сохранение выделения при смене фильтра (reset модели)
восстанавливает вид по ключам строк — это проверяется в
tests/test_app_nodes_interaction.py.
"""

import unittest

from PyQt6.QtCore import QCoreApplication, QItemSelectionModel
from PyQt6.QtTest import QTest

from xray_fluent.profiles.models import Node
from xray_fluent.ui.nodes_table_model import (
    DEFAULT_SORT_KEY,
    NODE_ID_ROLE,
    SORT_KEYS,
    NodesTableModel,
)

_APP = QCoreApplication.instance() or QCoreApplication([])

# Окно троттлинга пересортировки по метрикам (300 мс) плюс запас.
_AFTER_RELAYOUT_WINDOW_MS = 400


def _make(nodes: list[Node]) -> NodesTableModel:
    model = NodesTableModel()
    model.set_group_mode("none")
    model.set_nodes(nodes)
    return model


def _order(model: NodesTableModel) -> list[str]:
    return [model.index(row, 0).data(NODE_ID_ROLE) for row in range(model.rowCount())]


class NodesModelFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.nodes = [
            Node(id="a", name="Alpha", scheme="vless", server="alpha.example", group="EU", tags=["fast"], sort_order=0),
            Node(id="b", name="Bravo", scheme="trojan", server="bravo.example", group="US", tags=["slow"], sort_order=1),
            Node(
                id="c",
                name="Charlie",
                scheme="ss",
                server="charlie.example",
                group="EU",
                tags=["fast", "premium"],
                sort_order=2,
                subscription_id="sub-1",
            ),
        ]
        self.model = _make(self.nodes)
        self.model.set_source_names({"sub-1": "Provider"})

    def test_no_filters_accepts_all_rows(self) -> None:
        self.assertEqual(self.model.rowCount(), 3)
        self.assertEqual(self.model.visible_node_count(), 3)

    def test_group_filter(self) -> None:
        self.model.set_group_filter("EU")
        self.assertEqual(set(_order(self.model)), {"a", "c"})
        self.assertEqual(self.model.visible_node_count(), 2)
        self.model.set_group_filter("")
        self.assertEqual(self.model.rowCount(), 3)

    def test_tag_filter(self) -> None:
        self.model.set_tag_filter("premium")
        self.assertEqual(_order(self.model), ["c"])

    def test_source_filter(self) -> None:
        # Фильтр источника — по имени источника: подписка по её названию,
        # локальные ноды — по «Локальные».
        self.model.set_source_filter("Provider")
        self.assertEqual(_order(self.model), ["c"])
        self.model.set_source_filter("Локальные")
        self.assertEqual(set(_order(self.model)), {"a", "b"})
        self.model.set_source_filter("")
        self.assertEqual(self.model.rowCount(), 3)

    def test_source_filter_follows_subscription_rename(self) -> None:
        self.model.set_source_filter("Renamed")
        self.assertEqual(_order(self.model), [])
        self.model.set_source_names({"sub-1": "Renamed"})
        self.assertEqual(_order(self.model), ["c"])

    def test_query_filter_matches_substring_case_insensitively(self) -> None:
        # Стог поиска: имя, тип, сервер, группа, источник, теги.
        self.model.set_query("bravo.EX")
        self.assertEqual(_order(self.model), ["b"])
        self.model.set_query("provider")
        self.assertEqual(_order(self.model), ["c"])
        self.model.set_query("TROJAN")
        self.assertEqual(_order(self.model), ["b"])
        self.model.set_query("premium")
        self.assertEqual(_order(self.model), ["c"])
        self.model.set_query("  us  ")
        self.assertEqual(_order(self.model), ["b"])
        self.model.set_query("")
        self.assertEqual(self.model.rowCount(), 3)

    def test_query_haystack_follows_edited_node_and_source_rename(self) -> None:
        self.model.set_query("delta")
        self.assertEqual(_order(self.model), [])
        edited = Node(id="b", name="Delta", scheme="trojan", server="bravo.example", group="US", sort_order=1)
        self.model.set_nodes([self.nodes[0], edited, self.nodes[2]])
        self.assertEqual(_order(self.model), ["b"])

        self.model.set_query("acme")
        self.assertEqual(_order(self.model), [])
        self.model.set_source_names({"sub-1": "ACME"})
        self.assertEqual(_order(self.model), ["c"])

    def test_favorites_only(self) -> None:
        self.nodes[1].is_favorite = True
        self.model.set_nodes(list(self.nodes))
        self.model.set_favorites_only(True)
        self.assertEqual(_order(self.model), ["b"])
        self.model.set_favorites_only(False)
        self.assertEqual(self.model.rowCount(), 3)

    def test_combined_filters(self) -> None:
        self.model.set_group_filter("EU")
        self.model.set_tag_filter("fast")
        self.model.set_query("charlie")
        self.assertEqual(_order(self.model), ["c"])

    def test_filtered_out_node_is_not_reported_as_collapsed(self) -> None:
        model = NodesTableModel()
        model.set_nodes(self.nodes)
        model.set_collapsed_groups({"source:local"})
        model.set_group_filter("US")
        self.assertEqual(model.collapsed_group_of("b"), "source:local")
        self.assertIsNone(model.collapsed_group_of("a"))


class NodesModelSortTests(unittest.TestCase):
    def test_sort_keys_are_stable_english_identifiers(self) -> None:
        self.assertEqual(
            SORT_KEYS,
            ("manual", "name", "group", "type", "ping", "speed", "last_used"),
        )
        self.assertEqual(DEFAULT_SORT_KEY, "manual")

    def test_unknown_sort_key_falls_back_to_manual(self) -> None:
        model = _make([Node(id="a", name="B", sort_order=1), Node(id="b", name="A", sort_order=0)])
        model.set_sort("bogus", False)
        self.assertEqual(model.sort_key(), "manual")
        self.assertEqual(_order(model), ["b", "a"])

    def test_manual_sort_uses_sort_order(self) -> None:
        nodes = [
            Node(id="a", name="Z", sort_order=2),
            Node(id="b", name="A", sort_order=0),
            Node(id="c", name="M", sort_order=1),
        ]
        model = _make(nodes)
        model.set_sort("manual", False)
        self.assertEqual(_order(model), ["b", "c", "a"])
        model.set_sort("manual", True)
        self.assertEqual(_order(model), ["a", "c", "b"])

    def test_equal_keys_keep_catalog_order(self) -> None:
        nodes = [Node(id=f"n{i}", name="Same", sort_order=0) for i in range(5)]
        model = _make(nodes)
        for key in ("manual", "name"):
            model.set_sort(key, False)
            self.assertEqual(_order(model), ["n0", "n1", "n2", "n3", "n4"], key)
            model.set_sort(key, True)
            self.assertEqual(_order(model), ["n0", "n1", "n2", "n3", "n4"], key)

    def test_name_sort(self) -> None:
        nodes = [
            Node(id="a", name="zeta", sort_order=0),
            Node(id="b", name="Alpha", sort_order=1),
            Node(id="c", name="miDDle", sort_order=2),
        ]
        model = _make(nodes)
        model.set_sort("name", False)
        self.assertEqual(_order(model), ["b", "c", "a"])

    def test_group_sort(self) -> None:
        nodes = [
            Node(id="a", name="A", group="zz", sort_order=0),
            Node(id="b", name="B", group="aa", sort_order=1),
        ]
        model = _make(nodes)
        model.set_sort("group", False)
        self.assertEqual(_order(model), ["b", "a"])

    def test_type_sort(self) -> None:
        nodes = [
            Node(id="a", name="A", scheme="vless", sort_order=0),
            Node(id="b", name="B", scheme="ss", sort_order=1),
            Node(id="c", name="C", scheme="trojan", sort_order=2),
        ]
        model = _make(nodes)
        model.set_sort("type", False)
        self.assertEqual(_order(model), ["b", "c", "a"])

    def test_last_used_sort(self) -> None:
        nodes = [
            Node(id="a", name="A", last_used_at="2026-02-01T00:00:00+00:00", sort_order=0),
            Node(id="b", name="B", last_used_at="2026-01-01T00:00:00+00:00", sort_order=1),
            Node(id="c", name="C", last_used_at=None, sort_order=2),
        ]
        model = _make(nodes)
        model.set_sort("last_used", False)
        self.assertEqual(_order(model), ["c", "b", "a"])

    def test_ping_sort_keeps_none_last_in_both_directions(self) -> None:
        nodes = [
            Node(id="slow", name="S", ping_ms=200, sort_order=0),
            Node(id="none", name="N", ping_ms=None, sort_order=1),
            Node(id="fast", name="F", ping_ms=20, sort_order=2),
        ]
        model = _make(nodes)

        model.set_sort("ping", False)
        self.assertEqual(_order(model), ["fast", "slow", "none"])

        model.set_sort("ping", True)
        self.assertEqual(_order(model), ["slow", "fast", "none"])

    def test_speed_sort_keeps_none_last_in_both_directions(self) -> None:
        nodes = [
            Node(id="fast", name="F", speed_mbps=50.0, sort_order=0),
            Node(id="none", name="N", speed_mbps=None, sort_order=1),
            Node(id="slow", name="S", speed_mbps=1.5, sort_order=2),
        ]
        model = _make(nodes)

        model.set_sort("speed", False)
        self.assertEqual(_order(model), ["slow", "fast", "none"])

        model.set_sort("speed", True)
        self.assertEqual(_order(model), ["fast", "slow", "none"])

    def test_sort_applies_inside_each_group(self) -> None:
        nodes = [
            Node(id="a", name="A", ping_ms=300, sort_order=0),
            Node(id="b", name="B", ping_ms=100, sort_order=1, subscription_id="s"),
            Node(id="c", name="C", ping_ms=200, sort_order=2),
            Node(id="d", name="D", ping_ms=50, sort_order=3, subscription_id="s"),
        ]
        model = NodesTableModel()
        model.set_source_names({"s": "Sub"})
        model.set_nodes(nodes)
        model.set_sort("ping", False)
        rows = [model.index(row, 0).data(NODE_ID_ROLE) for row in range(model.rowCount())]
        # Группы по названию: «Sub» < «Локальные» (casefold); строки-заголовки — None.
        self.assertEqual(rows, [None, "d", "b", None, "c", "a"])
        self.assertEqual(model.visible_node_ids(), ["d", "b", "c", "a"])

    def test_dynamic_resort_after_ping_result(self) -> None:
        first = Node(id="first", name="First", ping_ms=100, sort_order=0)
        second = Node(id="second", name="Second", ping_ms=50, sort_order=1)
        model = _make([first, second])
        model.set_sort("ping", False)
        self.assertEqual(_order(model), ["second", "first"])

        first.ping_ms = 10
        model.finish_ping_batch({"first"})
        QTest.qWait(_AFTER_RELAYOUT_WINDOW_MS)

        self.assertEqual(_order(model), ["first", "second"])


class NodesModelSelectionTests(unittest.TestCase):
    def test_selection_follows_row_through_resort(self) -> None:
        nodes = [
            Node(id="a", name="Alpha", group="EU", ping_ms=30, sort_order=0),
            Node(id="b", name="Bravo", group="US", ping_ms=10, sort_order=1),
            Node(id="c", name="Charlie", group="EU", ping_ms=20, sort_order=2),
        ]
        model = _make(nodes)
        selection = QItemSelectionModel(model)
        selection.select(
            model.index(_order(model).index("c"), 0),
            QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
        )

        def selected_ids() -> set[str]:
            return {index.data(NODE_ID_ROLE) for index in selection.selectedRows()}

        self.assertEqual(selected_ids(), {"c"})

        # Пересортировка без смены состава — layoutChanged с переносом
        # индексов: строка переезжает, выделение едет вместе с ней.
        resets = []
        model.modelReset.connect(lambda: resets.append(True))
        model.set_sort("ping", False)
        self.assertEqual(_order(model), ["b", "c", "a"])
        self.assertEqual(selected_ids(), {"c"})
        model.set_sort("ping", True)
        self.assertEqual(_order(model), ["a", "c", "b"])
        self.assertEqual(selected_ids(), {"c"})
        self.assertEqual(resets, [])


if __name__ == "__main__":
    unittest.main()
