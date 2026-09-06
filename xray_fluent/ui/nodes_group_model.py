"""Flat grouped rows for a virtualized table; node objects are never copied."""
from __future__ import annotations

from dataclasses import dataclass, field
from PyQt6.QtCore import QAbstractProxyModel, QModelIndex, Qt, QSize
from PyQt6.QtGui import QFont
from .nodes_table_model import NODE_ID_ROLE, ACTIVE_ROLE, NODE_ROW_HEIGHT, node_type_text
from ..profiles.node_presentation import node_country

GROUP_KEY_ROLE = int(Qt.ItemDataRole.UserRole) + 20
GROUP_MODES = {"source": "Подписки", "group": "Группы", "country": "Страны", "type": "Протоколы", "none": "Без группировки"}


@dataclass(eq=False)
class Entry:
    key: str
    title: str = ""
    parent: Entry | None = None
    children: list = field(default_factory=list)
    row: int = 0
    node_id: str = ""


class NodesGroupModel(QAbstractProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.mode = "source"
        self._roots = []
        self._rows = []
        self._entries = {}
        self._sources = {}
        self._source_entries = []
        self._nodes = {}
        self._rebuilding = False
        self.collapsed_groups = set()
        self._display_cache = {}
        self.modelAboutToBeReset.connect(self.clear_display_cache)
        self.layoutAboutToBeChanged.connect(self.clear_display_cache)
        self.dataChanged.connect(self._invalidate_display_range)

    def clear_display_cache(self, *_args):
        self._display_cache.clear()

    def _invalidate_display_range(self, top, bottom, _roles):
        self._invalidate_display_rows(set(range(top.row(), bottom.row()+1)))

    def _invalidate_display_rows(self, rows):
        for key in list(self._display_cache):
            if key[0] in rows:
                del self._display_cache[key]

    def setSourceModel(self, source):
        super().setSourceModel(source)
        source.modelReset.connect(self.rebuild)
        source.layoutChanged.connect(self.rebuild)
        source.rowsInserted.connect(self.rebuild)
        source.rowsRemoved.connect(self.rebuild)
        source.dataChanged.connect(self._data_changed)
        self.rebuild()

    def set_group_mode(self, mode):
        mode = mode if mode in GROUP_MODES else "source"
        if self.mode != mode:
            self.mode = mode
            self.rebuild()

    def _group(self, node):
        if self.mode == "source":
            key = node.subscription_id or "local"
            return "source:" + key, self.sourceModel()._source_names.get(key, "Локальные" if key == "local" else "Подписка")
        if self.mode == "group":
            return "group:" + node.group, node.group or "Без группы"
        if self.mode == "country":
            code = node_country(node)
            return "country:" + code, code or "Страна не определена"
        value = node_type_text(node)
        return "type:" + value, value

    def rebuild(self, *_):
        if self._rebuilding or self.sourceModel() is None:
            return
        self._rebuilding = True
        try:
            source = self.sourceModel()
            base = source.sourceModel()
            records = []
            keys = set()
            for row in range(source.rowCount()):
                node = base.node_at_row(source.mapToSource(source.index(row, 0)).row())
                if node is None:
                    continue
                group_key, title = self._group(node) if self.mode != "none" else ("", "")
                records.append((row, node, group_key, title))
                keys.add("node:" + node.id)
                if group_key:
                    keys.add(group_key)
            # Layout notifications preserve persistent indexes for sorting.
            # Membership changes require a reset under the Qt model contract.
            structural = keys != self._entries.keys()
            if structural:
                self.beginResetModel()
                persistent, identities = [], []
            else:
                self.layoutAboutToBeChanged.emit()
                persistent = self.persistentIndexList()
                identities = [(i.internalPointer().key, i.column()) for i in persistent]
            old = self._entries
            entries, groups, sources, nodes, leaves = {}, {}, {}, {}, []
            for row, node, group_key, title in records:
                key = "node:" + node.id
                item = old.get(key) or Entry(key, node_id=node.id)
                entries[key] = item
                sources[node.id] = row
                nodes[node.id] = node
                if group_key:
                    if group_key not in groups:
                        group = old.get(group_key) or Entry(group_key)
                        group.children = []
                        group.title = title
                        groups[group_key] = group
                        entries[group_key] = group
                    item.parent = groups[group_key]
                    item.parent.children.append(item)
                else:
                    item.parent = None
                    leaves.append(item)
            roots = sorted(groups.values(), key=lambda e: (e.title.casefold(), e.key)) if self.mode != "none" else leaves
            rows = []
            for item in roots:
                rows.append(item)
                if not item.node_id:
                    rows.extend(item.children)
            for row, item in enumerate(rows):
                item.row = row
            self._rows = rows
            self._roots, self._entries, self._sources, self._nodes = roots, entries, sources, nodes
            self._source_entries = [entries['node:' + nid] for nid in sources]
            replacements = [self._index_for(entries[key], column) if key in entries else QModelIndex() for key, column in identities]
            self.changePersistentIndexList(persistent, replacements)
            if structural:
                self.endResetModel()
            else:
                self.layoutChanged.emit()
        finally:
            self._rebuilding = False

    def _data_changed(self, top, bottom, roles):
        # Invalidate changed nodes even while collapsed, but retain cached
        # values for every other row across metric updates and tab switches.
        self._invalidate_display_rows({entry.row for entry in self._source_entries[top.row():bottom.row()+1]})
        changed = {}
        grouping_may_change = not roles or (self.mode == 'country' and Qt.ItemDataRole.DecorationRole in roles)
        for row in range(top.row(), bottom.row() + 1):
            if row >= len(self._source_entries):
                self.rebuild()
                return
            item = self._source_entries[row]
            if self.mode != "none" and grouping_may_change:
                base = self.sourceModel().sourceModel()
                node = base.node_at_row(base.row_for_node(item.node_id))
                self._nodes[item.node_id] = node
                if self._group(node)[0] != item.parent.key:
                    self.rebuild()
                    return
            if item.parent is not None and item.parent.key in self.collapsed_groups:
                continue
            bounds = changed.setdefault(item.parent, [item, item])
            if item.row < bounds[0].row:
                bounds[0] = item
            if item.row > bounds[1].row:
                bounds[1] = item
        # One update per parent range, rather than thousands of Qt signals.
        for first, last in changed.values():
            self.dataChanged.emit(self._index_for(first, top.column()), self._index_for(last, bottom.column()), roles)

    def _index_for(self, entry, column=0):
        return self.createIndex(entry.row, column, entry)

    def group_indexes(self):
        return [self._index_for(entry) for entry in self._roots if not entry.node_id]

    def index(self, row, column, parent=QModelIndex()):
        if parent.isValid() or row < 0 or column < 0 or column >= self.columnCount():
            return QModelIndex()
        return self._index_for(self._rows[row], column) if row < len(self._rows) else QModelIndex()

    def parent(self, index):
        return QModelIndex()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()):
        return self.sourceModel().columnCount() if not parent.isValid() and self.sourceModel() else 0

    def mapToSource(self, index):
        if not index.isValid():
            return QModelIndex()
        row = self._sources.get(index.internalPointer().node_id)
        return self.sourceModel().index(row, index.column()) if row is not None else QModelIndex()

    def mapFromSource(self, index):
        if not index.isValid():
            return QModelIndex()
        item = self._entries.get("node:" + str(index.data(NODE_ID_ROLE)))
        return self._index_for(item, index.column()) if item else QModelIndex()

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        key = (index.row(), index.column(), int(role))
        if key not in self._display_cache:
            # Cache only cells requested by the view, never all server rows.
            if len(self._display_cache) >= 8192:
                self._display_cache.clear()
            self._display_cache[key] = self._cell_data(index, role)
        return self._display_cache[key]

    def _cell_data(self, index, role):
        if not index.isValid():
            return None
        item = index.internalPointer()
        if role == NODE_ID_ROLE:
            return item.node_id or None
        if role == Qt.ItemDataRole.SizeHintRole:
            return QSize(0, NODE_ROW_HEIGHT)
        if item.node_id:
            source = self.mapToSource(index)
            if role == Qt.ItemDataRole.FontRole and source.data(ACTIVE_ROLE):
                font = QFont()
                font.setBold(True)
                return font
            return source.data(role)
        if role == GROUP_KEY_ROLE:
            return item.key
        if role == Qt.ItemDataRole.DisplayRole and index.column() == 0:
            return f"    {item.title} · {len(item.children)}"
        if role == Qt.ItemDataRole.FontRole:
            font = QFont()
            font.setBold(True)
            return font
        return None

    def flags(self, index):
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        if index.internalPointer().node_id:
            return self.sourceModel().flags(self.mapToSource(index))
        return Qt.ItemFlag.ItemIsEnabled

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        return self.sourceModel().headerData(section, orientation, role)
