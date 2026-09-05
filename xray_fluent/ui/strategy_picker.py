"""Compact strategy picker for the winws2 catalog (~390 TCP / ~66 UDP entries).

A combo box cannot present a catalog this size: it hides the label, the author
and the arguments, and filtering it silently moves the selection.  This widget
follows the zapret-gui shape instead — a dense one-line-per-strategy list with
a live search, a label filter and a colored badge per entry.
"""

from __future__ import annotations

from PyQt6.QtCore import QModelIndex, QRect, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QPainter
from PyQt6.QtWidgets import QHBoxLayout, QListWidgetItem, QStyleOptionViewItem, QVBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    ComboBox,
    ListWidget,
    SearchLineEdit,
    StrongBodyLabel,
)
from qfluentwidgets.components.widgets.list_view import ListItemDelegate

from ..engines.zapret.target import STRATEGY_LABELS, STRATEGY_LABEL_TITLES, ZapretStrategyEntry
from .theme import (
    accent_color,
    error_color,
    info_color,
    success_color,
    text_muted_color,
    warning_color,
)

CUSTOM_STRATEGY_ID = "custom"

_ROW_HEIGHT = 30
_VISIBLE_ROWS = 12
_BADGE_HEIGHT = 18
_BADGE_PADDING = 8
_SEARCH_DEBOUNCE_MS = 180

_ID_ROLE = Qt.ItemDataRole.UserRole
_BADGE_ROLE = Qt.ItemDataRole.UserRole + 1
_AUTHOR_ROLE = Qt.ItemDataRole.UserRole + 2
_LABEL_ROLE = Qt.ItemDataRole.UserRole + 3


def label_color(label: str) -> QColor:
    """Semantic color for a catalog label, resolved through the theme tokens."""

    if label == "recommended":
        return success_color()
    if label == "caution":
        return error_color()
    if label == "experimental":
        return warning_color()
    if label == "game":
        return info_color()
    if label == "stable":
        return accent_color()
    return text_muted_color()


class StrategyItemDelegate(ListItemDelegate):
    """Draws the stock row, then a label badge and the author on its right."""

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex) -> QSize:
        size = super().sizeHint(option, index)
        return QSize(size.width(), _ROW_HEIGHT)

    def _badge_font(self, option: QStyleOptionViewItem) -> QFont:
        font = QFont(option.font)
        font.setPointSizeF(max(7.5, option.font.pointSizeF() - 1.5))
        return font

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex) -> None:
        badge = index.data(_BADGE_ROLE) or ""
        author = index.data(_AUTHOR_ROLE) or ""
        reserved = 0
        badge_width = 0
        if badge:
            badge_font = self._badge_font(option)
            painter.save()
            painter.setFont(badge_font)
            badge_width = painter.fontMetrics().horizontalAdvance(badge) + 2 * _BADGE_PADDING
            painter.restore()
            reserved += badge_width + 8
        author_width = 0
        if author:
            painter.save()
            painter.setFont(self._badge_font(option))
            author_width = min(140, painter.fontMetrics().horizontalAdvance(author) + 10)
            painter.restore()
            reserved += author_width

        text_option = QStyleOptionViewItem(option)
        if reserved:
            text_option.rect = option.rect.adjusted(0, 0, -reserved, 0)
        super().paint(painter, text_option, index)

        if not (badge or author):
            return
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setFont(self._badge_font(option))
        right = option.rect.right() - 10
        if badge:
            color = label_color(str(index.data(_LABEL_ROLE) or ""))
            rect = QRect(
                right - badge_width,
                option.rect.center().y() - _BADGE_HEIGHT // 2,
                badge_width,
                _BADGE_HEIGHT,
            )
            fill = QColor(color)
            fill.setAlpha(38)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(fill)
            painter.drawRoundedRect(rect, 9, 9)
            painter.setPen(color)
            painter.drawText(rect, int(Qt.AlignmentFlag.AlignCenter), badge)
            right -= badge_width + 8
        if author:
            rect = QRect(right - author_width, option.rect.y(), author_width, option.rect.height())
            painter.setPen(text_muted_color())
            painter.drawText(
                rect,
                int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
                painter.fontMetrics().elidedText(author, Qt.TextElideMode.ElideRight, author_width - 8),
            )
        painter.restore()


class StrategyPicker(QWidget):
    """Search + label filter + dense list, rebuilt per transport."""

    selection_changed = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._entries: dict[str, ZapretStrategyEntry] = {}
        self._selected_id = ""
        self._visible_ids: list[str] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        header = QHBoxLayout()
        header.setSpacing(8)
        self.title_label = StrongBodyLabel("Стратегия", self)
        self.count_label = CaptionLabel("", self)
        header.addWidget(self.title_label)
        header.addWidget(self.count_label)
        header.addStretch(1)
        self.label_filter = ComboBox(self)
        self.label_filter.setFixedWidth(150)
        self.label_filter.addItem("Все метки", userData="")
        for label in STRATEGY_LABELS:
            self.label_filter.addItem(STRATEGY_LABEL_TITLES[label], userData=label)
        header.addWidget(self.label_filter)
        self.search = SearchLineEdit(self)
        self.search.setPlaceholderText("Поиск по каталогу")
        self.search.setFixedWidth(280)
        header.addWidget(self.search)
        layout.addLayout(header)

        self.list = ListWidget(self)
        self.list.setItemDelegate(StrategyItemDelegate(self.list))
        self.list.setUniformItemSizes(True)
        # Pixel scrolling parks the view mid-row; per-item scrolling keeps every
        # visible row whole.
        self.list.setVerticalScrollMode(ListWidget.ScrollMode.ScrollPerItem)
        # A height that is not a whole number of rows leaves a sliced row at the
        # bottom edge, which reads as a rendering glitch.
        self.list.setFixedHeight(_VISIBLE_ROWS * _ROW_HEIGHT)
        layout.addWidget(self.list)

        self.hidden_hint = CaptionLabel("", self)
        self.hidden_hint.hide()
        layout.addWidget(self.hidden_hint)

        self.description_label = BodyLabel("", self)
        self.description_label.setWordWrap(True)
        layout.addWidget(self.description_label)

        self.args_label = CaptionLabel("", self)
        self.args_label.setWordWrap(True)
        self.args_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        mono.setPointSizeF(max(8.0, self.args_label.font().pointSizeF() - 0.5))
        self.args_label.setFont(mono)
        layout.addWidget(self.args_label)

        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(_SEARCH_DEBOUNCE_MS)
        self._debounce.timeout.connect(self._rebuild)
        self.search.textChanged.connect(lambda _text: self._debounce.start())
        self.label_filter.currentIndexChanged.connect(lambda _index: self._rebuild())
        self.list.currentRowChanged.connect(self._on_row_changed)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._fit_list_height()

    def _fit_list_height(self) -> None:
        """Keep the viewport an exact number of rows, whatever the frame costs."""

        overhead = self.list.height() - self.list.viewport().height()
        wanted = _VISIBLE_ROWS * _ROW_HEIGHT + max(0, overhead)
        if self.list.height() != wanted:
            self.list.setFixedHeight(wanted)

    # ── public API ──

    def set_entries(self, title: str, entries: dict[str, ZapretStrategyEntry]) -> None:
        """Load one transport's catalog; the previous selection is kept if present."""

        self.title_label.setText(title)
        self._entries = dict(entries)
        self._rebuild()

    def set_selected(self, strategy_id: str) -> None:
        self._selected_id = str(strategy_id or "")
        self._sync_selection()
        self._show_details()

    def selected_id(self) -> str:
        return self._selected_id

    def selected_entry(self) -> ZapretStrategyEntry | None:
        return self._entries.get(self._selected_id)

    def entries(self) -> dict[str, ZapretStrategyEntry]:
        return self._entries

    # ── internals ──

    def _matches(self, entry: ZapretStrategyEntry, query: str, label: str) -> bool:
        if label and entry.label != label:
            return False
        return not query or query in entry.search_haystack

    def _rebuild(self) -> None:
        query = self.search.text().strip().casefold()
        label = str(self.label_filter.currentData() or "")
        ordered = sorted(
            self._entries.values(),
            key=lambda item: (
                STRATEGY_LABELS.index(item.label) if item.label in STRATEGY_LABELS else len(STRATEGY_LABELS),
                item.name.casefold(),
            ),
        )
        self.list.blockSignals(True)
        self.list.clear()
        self._visible_ids = []
        custom = QListWidgetItem("Своя стратегия")
        custom.setData(_ID_ROLE, CUSTOM_STRATEGY_ID)
        custom.setSizeHint(QSize(0, _ROW_HEIGHT))
        self.list.addItem(custom)
        self._visible_ids.append(CUSTOM_STRATEGY_ID)
        for entry in ordered:
            if not self._matches(entry, query, label):
                continue
            item = QListWidgetItem(entry.name)
            item.setData(_ID_ROLE, entry.strategy_id)
            item.setData(_BADGE_ROLE, entry.label_title)
            item.setData(_AUTHOR_ROLE, entry.author)
            item.setData(_LABEL_ROLE, entry.label)
            item.setSizeHint(QSize(0, _ROW_HEIGHT))
            item.setToolTip("\n".join(entry.args))
            self.list.addItem(item)
            self._visible_ids.append(entry.strategy_id)
        self.list.blockSignals(False)
        shown = len(self._visible_ids) - 1
        self.count_label.setText(f"{shown} из {len(self._entries)}")
        self._sync_selection()
        self._show_details()

    def _sync_selection(self) -> None:
        """Restore the selection without letting a filter reassign it."""

        self.list.blockSignals(True)
        if self._selected_id in self._visible_ids:
            row = self._visible_ids.index(self._selected_id)
            self.list.setCurrentRow(row)
            item = self.list.item(row)
            if item is not None:
                self.list.scrollToItem(item, self.list.ScrollHint.PositionAtCenter)
            self.hidden_hint.hide()
        else:
            self.list.setCurrentRow(-1)
            entry = self._entries.get(self._selected_id)
            if entry is not None:
                self.hidden_hint.setText(f"Выбрана «{entry.name}» — скрыта текущим фильтром")
                self.hidden_hint.show()
            elif self._selected_id:
                self.hidden_hint.setText(f"Выбрана «{self._selected_id}» — нет в каталоге")
                self.hidden_hint.show()
            else:
                self.hidden_hint.hide()
        self.list.blockSignals(False)

    def _on_row_changed(self, row: int) -> None:
        if not (0 <= row < len(self._visible_ids)):
            return
        self._selected_id = self._visible_ids[row]
        self.hidden_hint.hide()
        self._show_details()
        self.selection_changed.emit(self._selected_id)

    def _show_details(self) -> None:
        if self._selected_id == CUSTOM_STRATEGY_ID:
            self.description_label.setText("")
            self.args_label.setText("")
            return
        entry = self._entries.get(self._selected_id)
        if entry is None:
            self.description_label.setText("Стратегия не выбрана")
            self.args_label.setText("")
            return
        parts = [entry.description or "Без описания"]
        if entry.blob_dependencies:
            parts.append("Блобы: " + ", ".join(entry.blob_dependencies))
        self.description_label.setText(" · ".join(parts))
        self.args_label.setText("\n".join(entry.args))

