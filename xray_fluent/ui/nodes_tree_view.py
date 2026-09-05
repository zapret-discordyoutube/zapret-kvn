"""Stock Fluent tree with the existing activity indicators."""
from PyQt6.QtCore import QItemSelectionModel
from qfluentwidgets import TreeView, TreeItemDelegate
from .nodes_table_delegate import NodesActivityDelegate
from .nodes_table_model import PING_BUSY_ROLE, SPEED_PROGRESS_ROLE


class NodesTreeDelegate(TreeItemDelegate):
    def paint(self, painter, option, index):
        super().paint(painter, option, index)
        if index.data(PING_BUSY_ROLE):
            NodesActivityDelegate._paint_spinner(self, painter, option)
        elif index.data(SPEED_PROGRESS_ROLE) is not None:
            NodesActivityDelegate._paint_progress(painter, option, int(index.data(SPEED_PROGRESS_ROLE)))


class NodesTreeView(TreeView):
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
