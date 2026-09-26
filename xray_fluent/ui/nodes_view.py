"""Таблица серверов: лёгкий вид и делегат поверх ``NodesTableModel``.

Цена кадра определяется только видимыми ячейками:

* наведение/нажатие перерисовывают две строки, а не весь viewport
  (у ``qfluentwidgets.TableView`` любое движение мыши — полный repaint);
* делегат рисует ячейку сам: строка берётся из модели напрямую
  (``row_at``), цвета/шрифты/метрики — из палитры, которая пересобирается
  только при смене темы или акцента; ``QStyle`` и ``data()`` не участвуют.
"""

from __future__ import annotations

from PyQt6.QtCore import QItemSelectionModel, QModelIndex, QPointF, QRect, QRectF, QSize, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QFontMetrics, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import QAbstractItemView, QHeaderView, QStyle, QStyledItemDelegate, QTableView
from qfluentwidgets import FluentStyleSheet, SmoothScrollDelegate, isDarkTheme
from qfluentwidgets.common.font import getFont

from ..profiles.country_flags import get_flag_icon
from ..profiles.node_presentation import node_country
from .nodes_table_model import (
    CENTERED_COLUMNS,
    COL_NAME,
    COL_PING,
    COL_SPEED,
    COL_TYPE,
    NodesTableModel,
)
from .theme import (
    accent_color,
    accent_soft_bg,
    accent_soft_bg_hover,
    on_theme_or_accent_changed,
    text_color,
    text_muted_color,
)

FLAG_SIZE = QSize(18, 13)
_ROW_MARGIN = 2          # вертикальный зазор между «карточками» строк
_EDGE_INSET = 4          # отступ скруглённых краёв строки от краёв viewport
_RADIUS = 5.0
_PILL_WIDTH = 3
_TEXT_PAD = 10


class _Palette:
    """Всё, что нужно для отрисовки, собранное один раз на тему/акцент."""

    def __init__(self, font: QFont) -> None:
        dark = isDarkTheme()
        base = 255 if dark else 0
        self.card = QColor(base, base, base, 6)
        self.hover = QColor(base, base, base, 14)
        self.pressed = QColor(base, base, base, 9 if dark else 6)
        self.selected = QColor(base, base, base, 20 if dark else 14)
        self.selected_hover = QColor(base, base, base, 28 if dark else 20)
        self.active = accent_soft_bg()
        self.active_hover = accent_soft_bg_hover()
        self.accent = accent_color()
        self.text = text_color()
        self.muted = text_muted_color()
        self.chevron = QColor(210, 210, 210) if dark else QColor(75, 75, 75)
        self.track = QColor(self.muted)
        self.track.setAlpha(80)
        self.font = QFont(font)
        self.bold = QFont(font)
        self.bold.setBold(True)
        self.metrics = QFontMetrics(self.font)
        self.bold_metrics = QFontMetrics(self.bold)
        self.badge_font = QFont(font)
        if font.pixelSize() > 0:  # getFont() задаёт размер в пикселях
            self.badge_font.setPixelSize(max(9, font.pixelSize() - 2))
        else:
            self.badge_font.setPointSizeF(max(7.0, font.pointSizeF() - 1.5))
        self.badge_font.setWeight(QFont.Weight.DemiBold)
        self.badge_font.setLetterSpacing(QFont.SpacingType.PercentageSpacing, 104)
        self.badge_metrics = QFontMetrics(self.badge_font)
        self.badge_fill = QColor(base, base, base, 10)
        self.badge_border = QColor(base, base, base, 40 if dark else 34)
        self.spinner_pen = QPen(self.accent, 2)
        self.spinner_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        self.chevron_pen = QPen(self.chevron, 1.3)
        self.chevron_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        self.chevron_pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)


class NodesDelegate(QStyledItemDelegate):
    def __init__(self, view: NodesView):
        super().__init__(view)
        self._view = view
        self._palette: _Palette | None = None
        self._flags: dict[tuple[str, float], object] = {}
        on_theme_or_accent_changed(self.invalidate)

    def invalidate(self, *_args) -> None:
        self._palette = None
        self._flags.clear()

    def palette(self) -> _Palette:
        if self._palette is None:
            self._palette = _Palette(getFont(13))
        return self._palette

    def sizeHint(self, option, index) -> QSize:
        return QSize(0, self._view.verticalHeader().defaultSectionSize())

    def paint(self, painter: QPainter, option, index: QModelIndex) -> None:
        view = self._view
        model: NodesTableModel = view.model()
        r = index.row()
        item = model.row_at(r)
        if item is None:
            return
        col = index.column()
        pal = self.palette()
        rect = option.rect
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        hovered = r == view.hover_row
        first = col == view.first_column
        last = col == view.last_column

        if item.is_group:
            if hovered:
                self._fill(painter, rect, pal.hover, first, last)
            if first:
                self._paint_group_title(painter, rect, item, pal)
            return

        node = item.node
        active = node.id == model.active_node_id()
        if active:
            fill = pal.active_hover if hovered else pal.active
        elif selected:
            fill = pal.selected_hover if hovered else pal.selected
        elif r == view.pressed_row:
            fill = pal.pressed
        elif hovered:
            fill = pal.hover
        else:
            fill = pal.card
        self._fill(painter, rect, fill, first, last)

        if first and (active or selected) and view.horizontalScrollBar().value() == 0:
            self._paint_pill(painter, rect, pal, pressed=r == view.pressed_row)

        if col == COL_PING and model.is_ping_busy(node.id):
            self._paint_spinner(painter, rect, pal)
            return
        if col == COL_SPEED:
            progress = model.speed_progress(node.id)
            if progress is not None:
                self._paint_progress(painter, rect, pal, progress)
                return

        text = model.display_text(item, col)
        color = model.status_color(item, col) or pal.text
        text_rect = rect.adjusted(_TEXT_PAD, 0, -_TEXT_PAD, 0)
        if col == COL_NAME:
            text_rect.setLeft(text_rect.left() + _PILL_WIDTH + 2)
            pixmap = self._flag(node_country(node), painter)
            if pixmap is not None:
                y = rect.top() + (rect.height() - FLAG_SIZE.height()) // 2
                painter.drawPixmap(text_rect.left(), y, pixmap)
                text_rect.setLeft(text_rect.left() + FLAG_SIZE.width() + 8)
        if not text:
            return
        if col == COL_TYPE:
            self._paint_badge(painter, rect, pal, text, color)
            return
        painter.setFont(pal.font)
        painter.setPen(color)
        align = Qt.AlignmentFlag.AlignCenter if col in CENTERED_COLUMNS else (
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        painter.drawText(text_rect, align, pal.metrics.elidedText(text, Qt.TextElideMode.ElideRight, text_rect.width()))

    # ── Примитивы ──────────────────────────────────────────

    @staticmethod
    def _fill(painter: QPainter, rect: QRect, color: QColor, first: bool, last: bool) -> None:
        if not color.alpha():
            return
        body = rect.adjusted(0, _ROW_MARGIN, 0, -_ROW_MARGIN)
        if not (first or last):
            painter.fillRect(body, color)
            return
        # Скругление только у крайних видимых колонок; сегмент строго внутри
        # своей ячейки, чтобы полупрозрачные куски не перекрывались.
        left = body.left() + _EDGE_INSET if first else body.left() - int(_RADIUS) - 1
        right = body.right() - _EDGE_INSET if last else body.right() + int(_RADIUS) + 1
        painter.save()
        painter.setClipRect(body)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(color)
        painter.drawRoundedRect(QRectF(left, body.top(), right - left + 1, body.height()), _RADIUS, _RADIUS)
        painter.restore()

    @staticmethod
    def _paint_pill(painter: QPainter, rect: QRect, pal: _Palette, *, pressed: bool) -> None:
        inset = round(rect.height() * (0.35 if pressed else 0.27))
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(pal.accent)
        painter.drawRoundedRect(QRectF(rect.left() + _EDGE_INSET + 3, rect.top() + inset, _PILL_WIDTH,
                                       rect.height() - 2 * inset), 1.5, 1.5)
        painter.restore()

    def _paint_group_title(self, painter: QPainter, rect: QRect, item, pal: _Palette) -> None:
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(pal.chevron_pen)
        x, y = rect.left() + 14.0, float(rect.center().y()) + 0.5
        if item.collapsed:
            points = (QPointF(x - 1.5, y - 4), QPointF(x + 2.5, y), QPointF(x - 1.5, y + 4))
        else:
            points = (QPointF(x - 4, y - 2), QPointF(x, y + 2), QPointF(x + 4, y - 2))
        path = QPainterPath(points[0])
        path.lineTo(points[1])
        path.lineTo(points[2])
        painter.drawPath(path)
        painter.setFont(pal.bold)
        painter.setPen(pal.text)
        text_rect = rect.adjusted(30, 0, -_TEXT_PAD, 0)
        painter.drawText(text_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                         pal.bold_metrics.elidedText(item.label, Qt.TextElideMode.ElideRight, text_rect.width()))
        painter.restore()

    @staticmethod
    def _paint_badge(painter: QPainter, rect: QRect, pal: _Palette, text: str, color: QColor) -> None:
        """Протокол — компактная «пилюля» с обводкой, а не голый капслок."""
        metrics = pal.badge_metrics
        width = min(metrics.horizontalAdvance(text) + 16, rect.width() - 8)
        height = min(18, rect.height() - 8)
        badge = QRectF(0, 0, width, height)
        badge.moveCenter(QRectF(rect).center())
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(pal.badge_border, 1))
        painter.setBrush(pal.badge_fill)
        painter.drawRoundedRect(badge, height / 2, height / 2)
        painter.setFont(pal.badge_font)
        painter.setPen(color)
        painter.drawText(badge, Qt.AlignmentFlag.AlignCenter,
                         metrics.elidedText(text, Qt.TextElideMode.ElideRight, int(badge.width()) - 8))
        painter.restore()

    @staticmethod
    def _paint_spinner(painter: QPainter, rect: QRect, pal: _Palette) -> None:
        size = max(8, min(16, rect.height() - 8, rect.width() - 8))
        spinner = QRect(0, 0, size, size)
        spinner.moveCenter(rect.center())
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(pal.spinner_pen)
        painter.drawArc(spinner, 35 * 16, 250 * 16)
        painter.restore()

    @staticmethod
    def _paint_progress(painter: QPainter, rect: QRect, pal: _Palette, percent: int) -> None:
        track = QRect(0, 0, max(0, rect.width() - 16), 6)
        track.moveCenter(rect.center())
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(pal.track)
        painter.drawRoundedRect(track, 3, 3)
        width = round(track.width() * max(0, min(100, percent)) / 100)
        if width > 0:
            fill = QRect(track)
            fill.setWidth(width)
            painter.setBrush(pal.accent)
            painter.drawRoundedRect(fill, 3, 3)
        painter.restore()

    def _flag(self, code: str, painter: QPainter):
        if not code:
            return None
        ratio = painter.device().devicePixelRatioF() if painter.device() is not None else 1.0
        key = (code, ratio)
        if key not in self._flags:
            icon = get_flag_icon(code)
            self._flags[key] = icon.pixmap(FLAG_SIZE, ratio) if icon is not None else None
        return self._flags[key]


class NodesHeader(QHeaderView):
    def paintSection(self, painter, rect, logical_index):
        super().paintSection(painter, rect, logical_index)
        painter.save()
        painter.setPen(QColor(255, 255, 255, 28) if isDarkTheme() else QColor(0, 0, 0, 28))
        painter.drawLine(rect.right(), rect.top() + 4, rect.right(), rect.bottom() - 4)
        painter.restore()


class NodesView(QTableView):
    """Плоская таблица с группами-заголовками; свёртка — через модель."""

    group_toggled = pyqtSignal(str, bool)  # ключ группы, развёрнута
    # Явная активация сервера (двойной клик или Enter по строке-серверу).
    # Простое выделение строк её не вызывает.
    node_activated = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHorizontalHeader(NodesHeader(Qt.Orientation.Horizontal, self))
        # Имя поля — как у qfluentwidgets.TableView (страница его настраивает).
        self.scrollDelagate = SmoothScrollDelegate(self)
        FluentStyleSheet.TABLE_VIEW.apply(self)
        self.setShowGrid(False)
        self.setMouseTracking(True)
        self.setWordWrap(False)
        self.horizontalHeader().setHighlightSections(False)
        self.verticalHeader().setHighlightSections(False)
        self.hover_row = -1
        self.pressed_row = -1
        self.first_column = 0
        self.last_column = 0
        self._saved_keys: list[str] = []
        self._saved_current: str | None = None
        self._saved_top: str | None = None
        # Выделенные серверы, спрятанные свёрткой группы: строк в модели нет,
        # но выделение не должно теряться (свернул/развернул — оно на месте).
        self._parked_keys: set[str] = set()
        self.setItemDelegate(NodesDelegate(self))
        header = self.horizontalHeader()
        header.sectionMoved.connect(lambda *_: self.update_edge_columns())
        header.sectionCountChanged.connect(lambda *_: self.update_edge_columns())
        self.doubleClicked.connect(self._on_double_clicked)

    # ── Модель и выделение через reset ─────────────────────

    def setModel(self, model: NodesTableModel) -> None:
        super().setModel(model)
        model.modelAboutToBeReset.connect(self._remember_view_state)
        model.modelReset.connect(self._restore_view_state)
        self.update_edge_columns()

    def _remember_view_state(self) -> None:
        model: NodesTableModel = self.model()
        self._saved_keys = [model.row_at(index.row()).key for index in self.selectionModel().selectedRows()]
        self._saved_keys.extend(key for key in self._parked_keys if key not in self._saved_keys)
        current = self.currentIndex()
        self._saved_current = model.row_at(current.row()).key if current.isValid() else None
        top = self.rowAt(0)
        self._saved_top = model.row_at(top).key if top >= 0 else None
        self.hover_row = self.pressed_row = -1

    def _restore_view_state(self) -> None:
        model: NodesTableModel = self.model()
        selection = self.selectionModel()
        flags = QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows
        parked: set[str] = set()
        selection.blockSignals(True)
        try:
            for key in self._saved_keys:
                row = model.row_of_key(key)
                if row is not None:
                    selection.select(model.index(row, 0), flags)
                elif self._hidden_by_collapse(key):
                    parked.add(key)  # отфильтрованные/удалённые — забываются
            self._parked_keys = parked
            row = model.row_of_key(self._saved_current) if self._saved_current else None
            if row is not None:
                selection.setCurrentIndex(model.index(row, 0), QItemSelectionModel.SelectionFlag.NoUpdate)
        finally:
            selection.blockSignals(False)
        top = model.row_of_key(self._saved_top) if self._saved_top else None
        if top is not None:
            self.verticalScrollBar().setValue(top)

    def _hidden_by_collapse(self, key: str) -> bool:
        return key.startswith("node:") and self.model().collapsed_group_of(key[5:]) is not None

    def parked_node_ids(self) -> set[str]:
        """Выделенные серверы внутри свёрнутых групп (проверка — по живой модели)."""
        return {key[5:] for key in self._parked_keys if self._hidden_by_collapse(key)}

    def selectionCommand(self, index, event=None):
        flags = super().selectionCommand(index, event)
        if flags & QItemSelectionModel.SelectionFlag.Clear:
            # Обычный клик/стрелки заменяют выделение целиком — вместе со
            # спрятанной частью; Ctrl+клик её не трогает.
            self._parked_keys.clear()
        return flags

    def clearSelection(self) -> None:
        self._parked_keys.clear()
        super().clearSelection()

    # ── Колонки ────────────────────────────────────────────

    def update_edge_columns(self) -> None:
        header = self.horizontalHeader()
        visible = [header.logicalIndex(v) for v in range(header.count())
                   if not header.isSectionHidden(header.logicalIndex(v))]
        edges = (visible[0], visible[-1]) if visible else (0, 0)
        if edges != (self.first_column, self.last_column):
            self.first_column, self.last_column = edges
            self.viewport().update()

    def setColumnHidden(self, column: int, hide: bool) -> None:
        super().setColumnHidden(column, hide)
        self.update_edge_columns()

    # ── Наведение/нажатие: перерисовка только затронутых строк ──

    def _update_row(self, row: int) -> None:
        if row >= 0:
            self.viewport().update(QRect(0, self.rowViewportPosition(row), self.viewport().width(), self.rowHeight(row)))

    def _set_hover_row(self, row: int) -> None:
        if row != self.hover_row:
            previous, self.hover_row = self.hover_row, row
            self._update_row(previous)
            self._update_row(row)

    def _set_pressed_row(self, row: int) -> None:
        if row != self.pressed_row:
            previous, self.pressed_row = self.pressed_row, row
            self._update_row(previous)
            self._update_row(row)

    def mouseMoveEvent(self, event) -> None:
        self._set_hover_row(self.rowAt(event.position().toPoint().y()))
        super().mouseMoveEvent(event)

    def leaveEvent(self, event) -> None:
        self._set_hover_row(-1)
        super().leaveEvent(event)

    def wheelEvent(self, event) -> None:
        super().wheelEvent(event)
        self._set_hover_row(self.rowAt(self.viewport().mapFromGlobal(event.globalPosition().toPoint()).y()))

    def mousePressEvent(self, event) -> None:
        index = self.indexAt(event.position().toPoint())
        if event.button() == Qt.MouseButton.LeftButton:
            if not index.isValid():
                return  # клик по пустому месту не снимает выделение
            item = self.model().row_at(index.row())
            if item is not None and item.is_group:
                self.selectionModel().setCurrentIndex(index, QItemSelectionModel.SelectionFlag.NoUpdate)
                self.toggle_group(item.key)
                return
        if index.isValid():
            self._set_pressed_row(index.row())
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        super().mouseReleaseEvent(event)
        self._set_pressed_row(-1)

    def mouseDoubleClickEvent(self, event) -> None:
        item = self.model().row_at(self.rowAt(event.position().toPoint().y()))
        if item is not None and item.is_group and event.button() == Qt.MouseButton.LeftButton:
            # Первое нажатие уже свернуло/развернуло группу; второе нажатие
            # двойного клика не должно откатывать это обратно.
            return
        super().mouseDoubleClickEvent(event)

    def _on_double_clicked(self, index: QModelIndex) -> None:
        node = self.model().node_at_row(index.row()) if index.isValid() else None
        if node is not None:
            self.node_activated.emit(node.id)

    # ── Группы ─────────────────────────────────────────────

    def is_group_expanded(self, key: str) -> bool:
        return key not in self.model().collapsed_groups()

    def set_group_expanded(self, key: str, expanded: bool) -> None:
        model: NodesTableModel = self.model()
        collapsed = model.collapsed_groups()
        if (key not in collapsed) == expanded:
            return
        model.set_collapsed_groups(collapsed - {key} if expanded else collapsed | {key})
        self.group_toggled.emit(key, expanded)

    def toggle_group(self, key: str) -> None:
        self.set_group_expanded(key, not self.is_group_expanded(key))

    def set_all_groups_expanded(self, expanded: bool) -> None:
        model: NodesTableModel = self.model()
        keys = model.group_keys()
        changed = [key for key in keys if self.is_group_expanded(key) != expanded]
        model.set_collapsed_groups(set() if expanded else set(keys))
        for key in changed:
            self.group_toggled.emit(key, expanded)

    def expandAll(self) -> None:
        self.set_all_groups_expanded(True)

    def collapseAll(self) -> None:
        self.set_all_groups_expanded(False)

    def keyPressEvent(self, event) -> None:
        index = self.currentIndex()
        key = event.key()
        model: NodesTableModel = self.model()
        item = model.row_at(index.row()) if index.isValid() else None
        if (item is not None and key in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
                and not event.modifiers() & ~Qt.KeyboardModifier.KeypadModifier):
            # Enter: заголовок группы — свернуть/развернуть, сервер — подключить.
            if item.is_group:
                self.toggle_group(item.key)
            else:
                self.node_activated.emit(item.node.id)
            return
        if item is not None and not event.modifiers():
            if item.is_group and key in (Qt.Key.Key_Left, Qt.Key.Key_Right, Qt.Key.Key_Space):
                expanded = not self.is_group_expanded(item.key) if key == Qt.Key.Key_Space else key == Qt.Key.Key_Right
                self.set_group_expanded(item.key, expanded)
                return
            if not item.is_group and key == Qt.Key.Key_Left:
                # Влево с сервера — на заголовок его группы.
                for row in range(index.row() - 1, -1, -1):
                    if model.row_at(row).is_group:
                        group_index = model.index(row, 0)
                        self.selectionModel().setCurrentIndex(group_index, QItemSelectionModel.SelectionFlag.NoUpdate)
                        self.scrollTo(group_index)
                        return
        super().keyPressEvent(event)

    def select_row(self, row: int) -> None:
        index = self.model().index(row, 0)
        if not index.isValid():
            return
        self._parked_keys.clear()
        self.selectionModel().setCurrentIndex(
            index, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows
        )
        self.scrollTo(index)
