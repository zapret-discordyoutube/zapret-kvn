"""Stock Fluent tree with the existing activity indicators."""
from PyQt6.QtCore import QItemSelectionModel
from PyQt6.QtWidgets import QStyle
from qfluentwidgets import TreeView, TreeItemDelegate, themeColor, isDarkTheme
from .nodes_table_delegate import NodesActivityDelegate
from .nodes_table_model import PING_BUSY_ROLE, SPEED_PROGRESS_ROLE, ACTIVE_ROLE


class NodesTreeDelegate(TreeItemDelegate):
    def paint(self, painter, option, index):
        super().paint(painter, option, index)
        if index.data(PING_BUSY_ROLE):
            NodesActivityDelegate._paint_spinner(self, painter, option)
        elif index.data(SPEED_PROGRESS_ROLE) is not None:
            NodesActivityDelegate._paint_progress(painter, option, int(index.data(SPEED_PROGRESS_ROLE)))

    def _drawIndicator(self, painter, option, index):
        # One row indicator is painted by the view, including the tree indent.
        pass


class NodesTreeView(TreeView):
    def drawRow(self, painter, option, index):
        highlighted = bool(index.data(ACTIVE_ROLE)) or bool(option.state & QStyle.StateFlag.State_Selected)
        if highlighted:
            painter.save()
            tint = themeColor()
            tint.setAlpha(95 if isDarkTheme() else 60)
            row = option.rect.adjusted(0, 0, 0, 0)
            row.setLeft(0)
            row.setRight(self.viewport().width())
            painter.fillRect(row, tint)
            painter.restore()
        super().drawRow(painter, option, index)
        if highlighted:
            painter.save()
            stripe = option.rect.adjusted(0, 3, 0, -3)
            stripe.setLeft(4)
            stripe.setWidth(3)
            painter.fillRect(stripe, themeColor())
            painter.restore()

    def horizontalHeader(self):
        return self.header()

    def select_index(self, index):
        if not index.isValid():
            return
        if index.parent().isValid():
            self.expand(index.parent())
        self.selectionModel().setCurrentIndex(index, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)

    def updateSelectedRows(self):
        self.viewport().update()
