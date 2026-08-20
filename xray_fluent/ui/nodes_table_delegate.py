from __future__ import annotations

from PyQt6.QtCore import QRect, Qt
from PyQt6.QtGui import QColor, QPainter, QPalette, QPen
from PyQt6.QtWidgets import QAbstractItemView
from qfluentwidgets import TableItemDelegate, themeColor

from .nodes_table_model import ACTIVE_ROLE, COL_NAME, PING_BUSY_ROLE, SPEED_PROGRESS_ROLE
from .theme import accent_soft_bg, text_muted_color

_ACTIVE_STRIPE_WIDTH = 3
_ACTIVE_FILL_RADIUS = 5


class NodesActivityDelegate(TableItemDelegate):
    """Paint table activity without creating a QWidget for every active row."""

    def __init__(self, view: QAbstractItemView):
        super().__init__(view)

    def paint(self, painter: QPainter, option, index) -> None:
        ping_busy = bool(index.data(PING_BUSY_ROLE))
        speed_progress = index.data(SPEED_PROGRESS_ROLE)

        fill_color = self.row_fill_color(index)
        if fill_color is not None:
            self._paint_active_row_fill(painter, option, index, fill_color)

        super().paint(painter, option, index)

        if (
            index.column() == COL_NAME
            and bool(index.data(ACTIVE_ROLE))
            and not self._selection_indicator_visible(index)
        ):
            self._paint_active_stripe(painter, option)

        if ping_busy:
            self._paint_spinner(painter, option)
        elif speed_progress is not None:
            self._paint_progress(painter, option, int(speed_progress))

    @staticmethod
    def row_fill_color(index) -> QColor | None:
        """Soft accent fill for the active node row; None for other rows (AC5).

        Resolved lazily on every call so it always matches the current accent.
        """
        if bool(index.data(ACTIVE_ROLE)):
            return accent_soft_bg()
        return None

    def _row_fill_span(self, index) -> tuple[bool, bool]:
        """(is_first_visible, is_last_visible) for the cell's column."""
        header = self.parent().horizontalHeader()
        visual = header.visualIndex(index.column())
        first = last = True
        for logical in range(header.count()):
            if header.isSectionHidden(logical):
                continue
            other = header.visualIndex(logical)
            if other < visual:
                first = False
            elif other > visual:
                last = False
        return first, last

    def _paint_active_row_fill(self, painter: QPainter, option, index, color: QColor) -> None:
        """Soft accent fill under the whole active row, rounded at row edges (D5)."""
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(color)
        radius = _ACTIVE_FILL_RADIUS
        first, last = self._row_fill_span(index)
        rect = option.rect
        # Edge insets follow qfluentwidgets' TableItemDelegate._drawBackground
        # so the fill lines up with the stock selection/hover background.
        if first and last:
            painter.drawRoundedRect(rect.adjusted(4, 0, -4, 0), radius, radius)
        elif first:
            painter.drawRoundedRect(rect.adjusted(4, 0, radius + 1, 0), radius, radius)
        elif last:
            painter.drawRoundedRect(rect.adjusted(-radius - 1, 0, -4, 0), radius, radius)
        else:
            painter.drawRect(rect.adjusted(-1, 0, 1, 0))
        painter.restore()

    def _selection_indicator_visible(self, index) -> bool:
        # qfluentwidgets' TableItemDelegate draws its own selection pill on
        # column 0 of selected rows (only while hscroll is at 0); painting the
        # active stripe on top of it doubles the marker.
        return (
            index.row() in self.selectedRows
            and self.parent().horizontalScrollBar().value() == 0
        )

    @staticmethod
    def _paint_active_stripe(painter: QPainter, option) -> None:
        """Accent bar at the left edge of the active node row."""
        painter.save()
        try:
            color = themeColor()
        except Exception:
            color = option.palette.color(QPalette.ColorRole.Highlight)
        # x offset 4 matches the qfluentwidgets selection pill, so the marker
        # keeps its position when the active row gets selected/deselected.
        stripe = QRect(
            option.rect.left() + 4,
            option.rect.top() + 6,
            _ACTIVE_STRIPE_WIDTH,
            option.rect.height() - 12,
        )
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(color)
        painter.drawRoundedRect(stripe, 1.5, 1.5)
        painter.restore()

    def _paint_spinner(self, painter: QPainter, option) -> None:
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        # option.palette is not synchronized with the fluent theme — use the
        # accent color from qfluentwidgets instead of QPalette.Highlight.
        try:
            color = themeColor()
        except Exception:
            color = option.palette.color(QPalette.ColorRole.Highlight)
        pen = QPen(color, 2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)

        size = min(16, option.rect.height() - 8, option.rect.width() - 8)
        size = max(8, size)
        spinner_rect = QRect(0, 0, size, size)
        spinner_rect.moveCenter(option.rect.center())
        painter.drawArc(spinner_rect, 35 * 16, 250 * 16)
        painter.restore()

    @staticmethod
    def _paint_progress(painter: QPainter, option, percent: int) -> None:
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        bar_width = max(0, option.rect.width() - 16)
        track = QRect(0, 0, bar_width, 6)
        track.moveCenter(option.rect.center())

        track_color = QColor(text_muted_color())
        track_color.setAlpha(80)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(track_color)
        painter.drawRoundedRect(track, 3, 3)

        fill_width = round(track.width() * max(0, min(100, percent)) / 100)
        if fill_width > 0:
            fill = QRect(track)
            fill.setWidth(fill_width)
            try:
                fill_color = themeColor()
            except Exception:
                fill_color = option.palette.color(QPalette.ColorRole.Highlight)
            painter.setBrush(fill_color)
            painter.drawRoundedRect(fill, 3, 3)
        painter.restore()
