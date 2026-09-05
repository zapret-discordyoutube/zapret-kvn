"""Hierarchical presentation of the filtered server model, without copying nodes."""
from __future__ import annotations

from dataclasses import dataclass, field
from PyQt6.QtCore import QAbstractProxyModel, QModelIndex, Qt, QSize
from PyQt6.QtGui import QFont
from .nodes_table_model import NODE_ID_ROLE, ACTIVE_ROLE, node_type_text

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
        self._entries = {}
        self._sources = {}
        self._nodes = {}
        self._rebuilding = False

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
            code = node.country_override or node.country_code
            return "country:" + code, code or "Страна не определена"
        value = node_type_text(node)
        return "type:" + value, value

    def rebuild(self, *_):
        if self._rebuilding or self.sourceModel() is None:
            return
        self._rebuilding = True
        try:
            self.layoutAboutToBeChanged.emit()
            persistent = self.persistentIndexList()
            identities = [(i.internalPointer().key, i.column()) for i in persistent]
            source = self.sourceModel()
            base = source.sourceModel()
            old = self._entries
            entries, groups, sources, nodes, leaves = {}, {}, {}, {}, []
            for row in range(source.rowCount()):
                index = source.index(row, 0)
                node = base.node_at_row(source.mapToSource(index).row())
                if node is None:
                    continue
                key = "node:" + node.id
                item = old.get(key) or Entry(key, node_id=node.id)
                entries[key] = item
                sources[node.id] = row
                nodes[node.id] = node
                if self.mode != "none":
                    group_key, title = self._group(node)
                    if group_key not in groups:
                        group = old.get(group_key) or Entry(group_key)
                        group.children = []
                        group.title = title
                        groups[group_key] = group
                        entries[group_key] = group
                    item.parent = groups[group_key]
                    item.row = len(item.parent.children)
                    item.parent.children.append(item)
                else:
                    item.parent = None
                    item.row = len(leaves)
                    leaves.append(item)
            roots = sorted(groups.values(), key=lambda e: (e.title.casefold(), e.key)) if self.mode != "none" else leaves
            for row, item in enumerate(roots):
                item.row = row
            self._roots, self._entries, self._sources, self._nodes = roots, entries, sources, nodes
            replacements = [self._index_for(entries[key], column) if key in entries else QModelIndex() for key, column in identities]
            self.changePersistentIndexList(persistent, replacements)
            self.layoutChanged.emit()
        finally:
            self._rebuilding = False

    def _data_changed(self, top, bottom, roles):
        source = self.sourceModel()
        for row in range(top.row(), bottom.row() + 1):
            idx = source.index(row, 0)
            nid = idx.data(NODE_ID_ROLE)
            item = self._entries.get("node:" + str(nid))
            if item is None:
                self.rebuild()
                return
            if self.mode != "none":
                node = source.sourceModel().node_at_row(source.mapToSource(idx).row())
                if self._group(node)[0] != item.parent.key:
                    self.rebuild()
                    return
            self.dataChanged.emit(self._index_for(item, top.column()), self._index_for(item, bottom.column()), roles)

    def _index_for(self, entry, column=0):
        return self.createIndex(entry.row, column, entry)

    def index(self, row, column, parent=QModelIndex()):
        if row < 0 or column < 0 or column >= self.columnCount() or (parent.isValid() and parent.column() != 0):
            return QModelIndex()
        children = parent.internalPointer().children if parent.isValid() else self._roots
        return self._index_for(children[row], column) if row < len(children) else QModelIndex()

    def parent(self, index):
        if not index.isValid():
            return QModelIndex()
        parent = index.internalPointer().parent
        return self._index_for(parent) if parent else QModelIndex()

    def rowCount(self, parent=QModelIndex()):
        if parent.isValid():
            return len(parent.internalPointer().children) if parent.column() == 0 else 0
        return len(self._roots)

    def columnCount(self, parent=QModelIndex()):
        return self.sourceModel().columnCount() if self.sourceModel() else 0

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
        item = index.internalPointer()
        if role == Qt.ItemDataRole.SizeHintRole:
            return QSize(0, 36)
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
            return f"{item.title} · {len(item.children)}"
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
