from __future__ import annotations

from PyQt6.QtCore import QPoint, QRect, QTimer, Qt
from PyQt6.QtGui import QPainter, QPalette, QPen
from PyQt6.QtWidgets import QAbstractItemView, QStyle
from qfluentwidgets import TableItemDelegate

from .nodes_table_model import PING_BUSY_ROLE, SPEED_PROGRESS_ROLE


class NodesActivityDelegate(TableItemDelegate):
    """Paint table activity without creating a QWidget for every active row."""

    def __init__(self, view: QAbstractItemView):
        super().__init__(view)
        self._view = view
        self._spinner_angle = 0
        self._animation_timer = QTimer(self)
        self._animation_timer.setInterval(90)
        self._animation_timer.timeout.connect(self._advance_spinner)

    def set_ping_animation_active(self, active: bool) -> None:
        if active == self._animation_timer.isActive():
            return
        if active:
            self._animation_timer.start()
        else:
            self._animation_timer.stop()
        self._update_visible_ping_cells()

    def paint(self, painter: QPainter, option, index) -> None:
        ping_busy = bool(index.data(PING_BUSY_ROLE))
        speed_progress = index.data(SPEED_PROGRESS_ROLE)

        super().paint(painter, option, index)

        if ping_busy:
            self._paint_spinner(painter, option)
        elif speed_progress is not None:
            self._paint_progress(painter, option, int(speed_progress))

    def _paint_spinner(self, painter: QPainter, option) -> None:
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        color_role = QPalette.ColorRole.HighlightedText if selected else QPalette.ColorRole.Highlight
        pen = QPen(option.palette.color(color_role), 2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)

        size = min(16, option.rect.height() - 8, option.rect.width() - 8)
        size = max(8, size)
        spinner_rect = QRect(0, 0, size, size)
        spinner_rect.moveCenter(option.rect.center())
        painter.drawArc(spinner_rect, self._spinner_angle * 16, 250 * 16)
        painter.restore()

    @staticmethod
    def _paint_progress(painter: QPainter, option, percent: int) -> None:
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        bar_width = max(0, option.rect.width() - 16)
        track = QRect(0, 0, bar_width, 6)
        track.moveCenter(option.rect.center())

        track_color = option.palette.color(QPalette.ColorRole.Mid)
        track_color.setAlpha(80)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(track_color)
        painter.drawRoundedRect(track, 3, 3)

        fill_width = round(track.width() * max(0, min(100, percent)) / 100)
        if fill_width > 0:
            fill = QRect(track)
            fill.setWidth(fill_width)
            painter.setBrush(option.palette.color(QPalette.ColorRole.Highlight))
            painter.drawRoundedRect(fill, 3, 3)
        painter.restore()

    def _advance_spinner(self) -> None:
        self._spinner_angle = (self._spinner_angle - 30) % 360
        self._update_visible_ping_cells()

    def _update_visible_ping_cells(self) -> None:
        if not self._view.isVisible():
            return
        model = self._view.model()
        viewport = self._view.viewport()
        if model is None or viewport is None or model.rowCount() == 0:
            return

        first_row = self._view.indexAt(QPoint(0, 0)).row()
        last_row = self._view.indexAt(QPoint(0, max(0, viewport.height() - 1))).row()
        if first_row < 0:
            first_row = 0
        if last_row < 0:
            last_row = min(model.rowCount() - 1, first_row + 50)

        dirty_rect = QRect()
        for row in range(first_row, min(last_row + 1, model.rowCount())):
            cell_rect = self._view.visualRect(model.index(row, 6))
            dirty_rect = cell_rect if dirty_rect.isNull() else dirty_rect.united(cell_rect)
        if not dirty_rect.isNull():
            viewport.update(dirty_rect)
