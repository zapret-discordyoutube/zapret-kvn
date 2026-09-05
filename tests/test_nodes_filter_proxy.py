import unittest

from PyQt6.QtCore import QItemSelectionModel, Qt

from xray_fluent.profiles.models import Node
from xray_fluent.ui.nodes_filter_proxy import SORT_KEYS, NodesFilterProxy
from xray_fluent.ui.nodes_table_model import NODE_ID_ROLE, NodesTableModel


def _make(nodes: list[Node]) -> tuple[NodesTableModel, NodesFilterProxy]:
    model = NodesTableModel()
    model.set_nodes(nodes)
    proxy = NodesFilterProxy()
    proxy.setSourceModel(model)
    proxy.sort(0, Qt.SortOrder.AscendingOrder)
    return model, proxy


def _order(proxy: NodesFilterProxy) -> list[str]:
    return [proxy.index(row, 0).data(NODE_ID_ROLE) for row in range(proxy.rowCount())]


class NodesFilterProxyFilterTests(unittest.TestCase):
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
        self.model, self.proxy = _make(self.nodes)
        self.proxy.set_source_names({"sub-1": "Provider"})

    def test_no_filters_accepts_all_rows(self) -> None:
        self.assertEqual(self.proxy.rowCount(), 3)

    def test_group_filter(self) -> None:
        self.proxy.set_group("EU")
        self.assertEqual(set(_order(self.proxy)), {"a", "c"})
        self.proxy.set_group("")
        self.assertEqual(self.proxy.rowCount(), 3)

    def test_tag_filter(self) -> None:
        self.proxy.set_tag("premium")
        self.assertEqual(_order(self.proxy), ["c"])

    def test_source_filter(self) -> None:
        self.proxy.set_source("Provider")
        self.assertEqual(_order(self.proxy), ["c"])
        self.proxy.set_source("Локальные")
        self.assertEqual(set(_order(self.proxy)), {"a", "b"})

    def test_query_filter_matches_substring_lazily(self) -> None:
        self.proxy.set_query("bravo.EX")
        self.assertEqual(_order(self.proxy), ["b"])
        self.proxy.set_query("provider")
        self.assertEqual(_order(self.proxy), ["c"])
        self.proxy.set_query("")
        self.assertEqual(self.proxy.rowCount(), 3)

    def test_combined_filters(self) -> None:
        self.proxy.set_group("EU")
        self.proxy.set_tag("fast")
        self.proxy.set_query("charlie")
        self.assertEqual(_order(self.proxy), ["c"])


class NodesFilterProxySortTests(unittest.TestCase):
    def test_sort_keys_are_stable_english_identifiers(self) -> None:
        self.assertEqual(
            SORT_KEYS,
            ("manual", "name", "group", "type", "ping", "speed", "last_used"),
        )

    def test_manual_sort_uses_sort_order(self) -> None:
        nodes = [
            Node(id="a", name="Z", sort_order=2),
            Node(id="b", name="A", sort_order=0),
            Node(id="c", name="M", sort_order=1),
        ]
        _, proxy = _make(nodes)
        proxy.set_sort_key("manual")
        self.assertEqual(_order(proxy), ["b", "c", "a"])
        proxy.sort(0, Qt.SortOrder.DescendingOrder)
        self.assertEqual(_order(proxy), ["a", "c", "b"])

    def test_name_sort(self) -> None:
        nodes = [
            Node(id="a", name="zeta", sort_order=0),
            Node(id="b", name="Alpha", sort_order=1),
            Node(id="c", name="miDDle", sort_order=2),
        ]
        _, proxy = _make(nodes)
        proxy.set_sort_key("name")
        self.assertEqual(_order(proxy), ["b", "c", "a"])

    def test_group_sort(self) -> None:
        nodes = [
            Node(id="a", name="A", group="zz", sort_order=0),
            Node(id="b", name="B", group="aa", sort_order=1),
        ]
        _, proxy = _make(nodes)
        proxy.set_sort_key("group")
        self.assertEqual(_order(proxy), ["b", "a"])

    def test_type_sort(self) -> None:
        nodes = [
            Node(id="a", name="A", scheme="vless", sort_order=0),
            Node(id="b", name="B", scheme="ss", sort_order=1),
            Node(id="c", name="C", scheme="trojan", sort_order=2),
        ]
        _, proxy = _make(nodes)
        proxy.set_sort_key("type")
        self.assertEqual(_order(proxy), ["b", "c", "a"])

    def test_last_used_sort(self) -> None:
        nodes = [
            Node(id="a", name="A", last_used_at="2026-02-01T00:00:00+00:00", sort_order=0),
            Node(id="b", name="B", last_used_at="2026-01-01T00:00:00+00:00", sort_order=1),
            Node(id="c", name="C", last_used_at=None, sort_order=2),
        ]
        _, proxy = _make(nodes)
        proxy.set_sort_key("last_used")
        self.assertEqual(_order(proxy), ["c", "b", "a"])

    def test_ping_sort_keeps_none_last_in_both_directions(self) -> None:
        nodes = [
            Node(id="slow", name="S", ping_ms=200, sort_order=0),
            Node(id="none", name="N", ping_ms=None, sort_order=1),
            Node(id="fast", name="F", ping_ms=20, sort_order=2),
        ]
        _, proxy = _make(nodes)
        proxy.set_sort_key("ping")

        proxy.sort(0, Qt.SortOrder.AscendingOrder)
        self.assertEqual(_order(proxy), ["fast", "slow", "none"])

        proxy.sort(0, Qt.SortOrder.DescendingOrder)
        self.assertEqual(_order(proxy), ["slow", "fast", "none"])

    def test_speed_sort_keeps_none_last_in_both_directions(self) -> None:
        nodes = [
            Node(id="fast", name="F", speed_mbps=50.0, sort_order=0),
            Node(id="none", name="N", speed_mbps=None, sort_order=1),
            Node(id="slow", name="S", speed_mbps=1.5, sort_order=2),
        ]
        _, proxy = _make(nodes)
        proxy.set_sort_key("speed")

        proxy.sort(0, Qt.SortOrder.AscendingOrder)
        self.assertEqual(_order(proxy), ["slow", "fast", "none"])

        proxy.sort(0, Qt.SortOrder.DescendingOrder)
        self.assertEqual(_order(proxy), ["fast", "slow", "none"])

    def test_dynamic_resort_after_ping_data_changed(self) -> None:
        first = Node(id="first", name="First", ping_ms=100, sort_order=0)
        second = Node(id="second", name="Second", ping_ms=50, sort_order=1)
        model, proxy = _make([first, second])
        proxy.set_sort_key("ping")
        proxy.sort(0, Qt.SortOrder.AscendingOrder)
        self.assertEqual(_order(proxy), ["second", "first"])

        first.ping_ms = 10
        model.finish_ping_batch({"first"})

        self.assertEqual(_order(proxy), ["first", "second"])


class NodesFilterProxySelectionTests(unittest.TestCase):
    def test_selection_survives_filter_invalidation_and_resort(self) -> None:
        nodes = [
            Node(id="a", name="Alpha", group="EU", ping_ms=30, sort_order=0),
            Node(id="b", name="Bravo", group="US", ping_ms=10, sort_order=1),
            Node(id="c", name="Charlie", group="EU", ping_ms=20, sort_order=2),
        ]
        _, proxy = _make(nodes)
        selection = QItemSelectionModel(proxy)

        # Select "c" (row 2 with manual ascending order).
        proxy_row = _order(proxy).index("c")
        selection.select(
            proxy.index(proxy_row, 0),
            QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
        )

        def selected_ids() -> set[str]:
            return {index.data(NODE_ID_ROLE) for index in selection.selectedRows()}

        self.assertEqual(selected_ids(), {"c"})

        # Filter out an unrelated row → selection persists.
        proxy.set_group("EU")
        self.assertEqual(selected_ids(), {"c"})

        # Remove the filter again → selection persists.
        proxy.set_group("")
        self.assertEqual(selected_ids(), {"c"})

        # Re-sort by ping → the row moves, selection follows the node.
        proxy.set_sort_key("ping")
        proxy.sort(0, Qt.SortOrder.AscendingOrder)
        self.assertEqual(_order(proxy), ["b", "c", "a"])
        self.assertEqual(selected_ids(), {"c"})


if __name__ == "__main__":
    unittest.main()
