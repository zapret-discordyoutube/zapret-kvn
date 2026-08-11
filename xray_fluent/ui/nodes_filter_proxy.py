from __future__ import annotations

from PyQt6.QtCore import QModelIndex, QSortFilterProxyModel, Qt

from ..models import Node
from .nodes_table_model import NodesTableModel

# Stable english sort keys (persisted in AppSettings.nodes_sort_key).
SORT_KEYS = ("manual", "name", "group", "type", "ping", "speed", "last_used")

DEFAULT_SORT_KEY = "manual"


class NodesFilterProxy(QSortFilterProxyModel):
    """Filtering + sorting proxy over NodesTableModel.

    The source model keeps all nodes in stable insertion order; this proxy
    applies group/tag/source/search filters and the active sort key.
    ``setDynamicSortFilter(True)`` keeps the view live-sorted as ping/speed
    results arrive via ``dataChanged``.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._query = ""
        self._group = ""
        self._tag = ""
        self._source = ""
        self._sort_key = DEFAULT_SORT_KEY
        self._source_names: dict[str, str] = {}
        self._haystacks: dict[str, str] = {}
        self.setDynamicSortFilter(True)

    # ── Filter setters ──

    def set_query(self, query: str) -> None:
        query = (query or "").strip().lower()
        if query == self._query:
            return
        self._query = query
        self.invalidateFilter()

    def set_group(self, group: str) -> None:
        group = group or ""
        if group == self._group:
            return
        self._group = group
        self.invalidateFilter()

    def set_tag(self, tag: str) -> None:
        tag = tag or ""
        if tag == self._tag:
            return
        self._tag = tag
        self.invalidateFilter()

    def set_source(self, source: str) -> None:
        source = source or ""
        if source == self._source:
            return
        self._source = source
        self.invalidateFilter()

    def set_source_names(self, names: dict[str, str]) -> None:
        self._source_names = dict(names)
        self._haystacks.clear()
        self.invalidateFilter()

    def invalidate_haystacks(self) -> None:
        """Drop the lazy search cache (node fields may have changed)."""
        self._haystacks.clear()

    # ── Sort key ──

    def sort_key(self) -> str:
        return self._sort_key

    def set_sort_key(self, key: str) -> None:
        if key not in SORT_KEYS:
            key = DEFAULT_SORT_KEY
        if key == self._sort_key:
            return
        self._sort_key = key
        self.invalidate()
        column = self.sortColumn()
        self.sort(0 if column < 0 else column, self.sortOrder())

    # ── QSortFilterProxyModel overrides ──

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model = self.sourceModel()
        if not isinstance(model, NodesTableModel):
            return True
        node = model.node_at_row(source_row)
        if node is None:
            return True
        if self._group and node.group != self._group:
            return False
        if self._tag and self._tag not in node.tags:
            return False
        if self._source or self._query:
            source_name = self._source_names.get(node.subscription_id or "", "Локальные")
            if self._source and source_name != self._source:
                return False
            if self._query:
                haystack = self._haystacks.get(node.id)
                if haystack is None:
                    haystack = " ".join(
                        [
                            node.name,
                            node.scheme,
                            node.server,
                            node.group,
                            source_name,
                            " ".join(node.tags),
                        ]
                    ).lower()
                    self._haystacks[node.id] = haystack
                if self._query not in haystack:
                    return False
        return True

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        model = self.sourceModel()
        if not isinstance(model, NodesTableModel):
            return super().lessThan(left, right)
        a = model.node_at_row(left.row())
        b = model.node_at_row(right.row())
        if a is None or b is None:
            return super().lessThan(left, right)

        key = self._sort_key
        if key == "manual":
            return a.sort_order < b.sort_order
        if key == "name":
            return a.name.lower() < b.name.lower()
        if key == "group":
            return a.group.lower() < b.group.lower()
        if key == "type":
            return a.scheme.lower() < b.scheme.lower()
        if key == "ping":
            return self._less_optional(a.ping_ms, b.ping_ms)
        if key == "speed":
            return self._less_optional(a.speed_mbps, b.speed_mbps)
        if key == "last_used":
            return (a.last_used_at or "") < (b.last_used_at or "")
        return a.sort_order < b.sort_order

    def _less_optional(self, a_value, b_value) -> bool:
        """Compare optional metrics keeping None at the visual end for both orders.

        Equivalent to sorting by the tuple ``(value is None, value)`` in the
        on-screen order: for descending display Qt inverts lessThan, so the
        None branch is inverted here to keep missing values last either way.
        """
        if a_value is None and b_value is None:
            return False
        descending = self.sortOrder() == Qt.SortOrder.DescendingOrder
        if a_value is None:
            return descending
        if b_value is None:
            return not descending
        return a_value < b_value
