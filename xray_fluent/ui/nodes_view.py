"""Interactive virtual table with fixed rows and inexpensive group headers."""
from PyQt6.QtCore import QItemSelectionModel, Qt, pyqtSignal, QRect, QPoint, QSignalBlocker
from PyQt6.QtGui import QColor, QPainter, QPolygon
from PyQt6.QtWidgets import QHeaderView
from qfluentwidgets import TableView, themeColor, isDarkTheme

from .nodes_table_delegate import NodesActivityDelegate
from .nodes_table_model import ACTIVE_ROLE, NODE_ID_ROLE
from .nodes_group_model import GROUP_KEY_ROLE


class NodesDelegate(NodesActivityDelegate):
    def _row_fill_span(self, index):
        edges = getattr(self.parent(), "_row_edges", None)
        if edges is not None:
            return index.column() == edges[0], index.column() == edges[1]
        return super()._row_fill_span(index)

    def row_fill_color(self, index):
        if index.data(ACTIVE_ROLE) or index.row() in self.selectedRows:
            color = themeColor()
            color.setAlpha(95 if isDarkTheme() else 60)
            return color
        if index.data(NODE_ID_ROLE):
            return QColor(255, 255, 255, 6) if isDarkTheme() else QColor(0, 0, 0, 6)
        return None

    def paint(self, painter, option, index):
        super().paint(painter, option, index)
        if index.column() == 0 and index.data(GROUP_KEY_ROLE):
            painter.save()
            painter.setPen(QColor(210, 210, 210) if isDarkTheme() else QColor(75, 75, 75))
            x, y = option.rect.left() + 8, option.rect.center().y()
            points = [(x, y-3), (x+4, y), (x, y+3)] if not self.parent().isExpanded(index) else [(x-2,y-2),(x+1,y+2),(x+4,y-2)]
            painter.drawPolyline(QPolygon([QPoint(*point) for point in points]))
            painter.restore()


class NodesHeader(QHeaderView):
    def paintSection(self, painter, rect, logical_index):
        super().paintSection(painter, rect, logical_index)
        painter.save()
        painter.setPen(QColor(255, 255, 255, 28) if isDarkTheme() else QColor(0, 0, 0, 28))
        painter.drawLine(rect.right(), rect.top()+4, rect.right(), rect.bottom()-4)
        painter.restore()


class NodesView(TableView):
    collapsed = pyqtSignal(object)
    expanded = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHorizontalHeader(NodesHeader(Qt.Orientation.Horizontal, self))
        self.setShowGrid(False)
        self._collapsed_groups = set()
        self._hidden_rows = set()

    def setModel(self, model):
        super().setModel(model)
        model.modelAboutToBeReset.connect(self._remember_selection)
        model.modelReset.connect(self._restore_selection)

    def _remember_selection(self):
        # Read identities directly: the source may already have removed rows.
        self._saved_selection = [
            self.model().index(row, 0).internalPointer().key
            for selected_range in self.selectionModel().selection()
            for row in range(selected_range.top(), selected_range.bottom() + 1)
        ]
        current = self.currentIndex()
        self._saved_current = current.internalPointer().key if current.isValid() else None

    def _restore_selection(self):
        self._hidden_rows.clear()
        selection = self.selectionModel()
        with QSignalBlocker(selection):
            for key in self._saved_selection:
                entry = self.model()._entries.get(key)
                if entry is not None:
                    selection.select(self.model().index(entry.row, 0),
                                     QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows)
            entry = self.model()._entries.get(self._saved_current)
            if entry is not None:
                selection.setCurrentIndex(self.model().index(entry.row, 0), QItemSelectionModel.SelectionFlag.NoUpdate)
        self.apply_collapsed_groups(self._collapsed_groups)
        self.updateSelectedRows()

    def header(self):
        return self.horizontalHeader()

    def apply_collapsed_groups(self, keys):
        self._collapsed_groups = set(keys)
        hidden = set()
        hidden_ids = set()
        self.model().collapsed_groups = self._collapsed_groups
        for index in self.model().group_indexes():
            if index.data(GROUP_KEY_ROLE) in self._collapsed_groups:
                hidden.update(child.row for child in index.internalPointer().children)
                hidden_ids.update(child.node_id for child in index.internalPointer().children)
        for row in self._hidden_rows - hidden:
            self.setRowHidden(row, False)
        for row in hidden - self._hidden_rows:
            self.setRowHidden(row, True)
        self._hidden_rows = hidden
        self.model().sourceModel().set_deferred_nodes(hidden_ids)
        self.viewport().update()

    def isExpanded(self, index):
        return index.data(GROUP_KEY_ROLE) not in self._collapsed_groups

    def setExpanded(self, index, expanded):
        key = index.data(GROUP_KEY_ROLE)
        if not key or expanded == self.isExpanded(index):
            return
        keys = self._collapsed_groups - {key} if expanded else self._collapsed_groups | {key}
        self.apply_collapsed_groups(keys)
        (self.expanded if expanded else self.collapsed).emit(index)

    def expand(self, index):
        self.setExpanded(index, True)

    def collapse(self, index):
        self.setExpanded(index, False)

    def _set_all_expanded(self, expanded):
        groups = self.model().group_indexes()
        changed = [index for index in groups if self.isExpanded(index) != expanded]
        keys = set() if expanded else {index.data(GROUP_KEY_ROLE) for index in groups}
        self.apply_collapsed_groups(keys)
        signal = self.expanded if expanded else self.collapsed
        for index in changed:
            signal.emit(index)

    def expandAll(self):
        self._set_all_expanded(True)

    def collapseAll(self):
        self._set_all_expanded(False)

    def mousePressEvent(self, event):
        index = self.indexAt(event.pos())
        if event.button() == Qt.MouseButton.LeftButton and index.data(GROUP_KEY_ROLE):
            self.selectionModel().setCurrentIndex(index, QItemSelectionModel.SelectionFlag.NoUpdate)
            self.setExpanded(index, not self.isExpanded(index))
            return
        super().mousePressEvent(event)

    def keyPressEvent(self, event):
        index = self.currentIndex()
        key = event.key()
        if index.isValid() and not event.modifiers():
            group = index if index.data(GROUP_KEY_ROLE) else None
            if group is None and key == Qt.Key.Key_Left:
                parent = index.internalPointer().parent
                if parent is not None:
                    group = self.model().index(parent.row, 0)
                    self.selectionModel().setCurrentIndex(group, QItemSelectionModel.SelectionFlag.NoUpdate)
                    self.scrollTo(group)
                    return
            if group is not None and key in (Qt.Key.Key_Left, Qt.Key.Key_Right, Qt.Key.Key_Space):
                expanded = not self.isExpanded(group) if key == Qt.Key.Key_Space else key == Qt.Key.Key_Right
                self.setExpanded(group, expanded)
                return
        super().keyPressEvent(event)

    def select_index(self, index):
        if not index.isValid():
            return
        group = index.internalPointer().parent
        if group is not None:
            self.expand(self.model().index(group.row, 0))
        self.selectionModel().setCurrentIndex(index, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)
        self.updateSelectedRows()

    def paintEvent(self, event):
        header = self.header()
        columns = [header.logicalIndex(i) for i in range(header.count()) if not header.isSectionHidden(header.logicalIndex(i))]
        self._row_edges = (columns[0], columns[-1]) if columns else None
        super().paintEvent(event)
        painter = QPainter(self.viewport())
        base = 255 if isDarkTheme() else 0
        painter.setPen(QColor(base, base, base, 20))
        for col in columns[:-1]:
            x = header.sectionViewportPosition(col) + header.sectionSize(col) - 1
            painter.drawLine(x, 0, x, self.viewport().height())
        # Paint borders only for visible rows, never scan the server catalogue.
        y = 0
        while y < self.viewport().height():
            row = self.rowAt(y)
            if row < 0:
                break
            top, height = self.rowViewportPosition(row), self.rowHeight(row)
            if self.model().index(row, 0).data(NODE_ID_ROLE):
                painter.drawRoundedRect(QRect(3, top+1, self.viewport().width()-7, height-2), 3, 3)
            y = max(y+1, top+height)
        painter.end()
