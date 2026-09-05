from __future__ import annotations

from PyQt6.QtCore import QModelIndex, QSortFilterProxyModel, Qt

from ..profiles.models import Node
from .nodes_table_model import NodesTableModel, node_type_text, COLUMN_SPECS, FILTER_FIELDS_ROLE

# Stable english sort keys (persisted in AppSettings.nodes_sort_key).
SORT_KEYS = ("manual", "name", "group", "type", "ping", "speed", "last_used")

DEFAULT_SORT_KEY = "manual"


class NodesFilterProxy(QSortFilterProxyModel):
    """Filtering + sorting proxy over NodesTableModel.

    The source model keeps all nodes in stable insertion order; this proxy
    applies group/tag/source/search filters and the active sort key.
    Metric batches explicitly invalidate sorting only when their column
    participates in the current sort; visual changes only repaint cells.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._favorites_only = False
        self._query = ""
        self._group = ""
        self._tag = ""
        self._source = ""
        self._sort_key = DEFAULT_SORT_KEY
        self._source_names: dict[str, str] = {}
        self._haystacks: dict[str, str] = {}
        self._sort_values = []
        self._descending = False
        self.setDynamicSortFilter(False)
        self.setFilterRole(FILTER_FIELDS_ROLE)

    def sort(self, column, order=Qt.SortOrder.AscendingOrder):
        # Qt must watch the actual metric column; a ping update must not sort
        # by name/type, nor should painting a busy indicator filter every row.
        column = next((i for i, spec in enumerate(COLUMN_SPECS) if spec.sort_key == self._sort_key), 0)
        self._descending = order == Qt.SortOrder.DescendingOrder
        super().sort(column, order)

    # ── Filter setters ──

    def set_favorites_only(self, enabled: bool) -> None:
        self._favorites_only = enabled
        self.invalidateFilter()

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
        self._refresh_sort_values()
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
        if self._favorites_only and not node.is_favorite:
            return False
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
                            node_type_text(node),
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

    def setSourceModel(self, model):
        self._key_source = model
        # Refresh keys before Qt's own slots begin comparing changed rows.
        model.modelReset.connect(self._refresh_sort_values)
        model.rowsInserted.connect(self._refresh_sort_values)
        model.rowsRemoved.connect(self._refresh_sort_values)
        model.dataChanged.connect(self._refresh_sort_values)
        self._refresh_sort_values()
        super().setSourceModel(model)
        model.dataChanged.connect(self._source_data_changed)

    def _source_data_changed(self, top, bottom, roles):
        if not roles or FILTER_FIELDS_ROLE in roles:
            self.invalidate_haystacks()
            self.invalidate()
        elif self._sort_values_changed and Qt.ItemDataRole.DisplayRole in roles and top.column() <= self.sortColumn() <= bottom.column():
            self.invalidate()

    def _refresh_sort_values(self, *args):
        self._sort_values_changed = False
        model = getattr(self, '_key_source', None)
        if model is None:
            return
        if len(args) == 3 and isinstance(args[2], list):
            top, bottom, roles = args
            if roles and Qt.ItemDataRole.DisplayRole not in roles:
                return
            column = next((i for i, spec in enumerate(COLUMN_SPECS) if spec.sort_key == self._sort_key), 0)
            if not top.column() <= column <= bottom.column():
                return
        key = self._sort_key
        previous = self._sort_values
        if key == 'type':
            self._sort_values = [node_type_text(node).casefold() for node in model._nodes]
        else:
            attribute = {'manual': 'sort_order', 'name': 'name', 'group': 'group',
                         'ping': 'ping_ms', 'speed': 'speed_mbps', 'last_used': 'last_used_at'}[key]
            values = [getattr(node, attribute) for node in model._nodes]
            self._sort_values = [(value or '').casefold() for value in values] if key in {'name','group','last_used'} else values

        self._sort_values_changed = self._sort_values != previous

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        a, b = self._sort_values[left.row()], self._sort_values[right.row()]
        if self._sort_key in {'ping', 'speed'}:
            return self._less_optional(a, b)
        return a < b

    def _less_optional(self, a_value, b_value) -> bool:
        """Compare optional metrics keeping None at the visual end for both orders.

        Equivalent to sorting by the tuple ``(value is None, value)`` in the
        on-screen order: for descending display Qt inverts lessThan, so the
        None branch is inverted here to keep missing values last either way.
        """
        if a_value is None and b_value is None:
            return False
        descending = self._descending
        if a_value is None:
            return descending
        if b_value is None:
            return not descending
        return a_value < b_value
