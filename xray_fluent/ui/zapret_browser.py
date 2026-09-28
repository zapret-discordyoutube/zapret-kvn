"""List ↔ card browsers of the Zapret section: strategies and presets.

Both catalogs are too long for a combo box (≈470 strategies, ≈30 presets), so
they share one shape: a searchable list of two-line rows on the left and a card
describing the highlighted item on the right, with the action button in the
card.  Highlighting only shows an item; the button makes it the one in use,
marked by a check in the list.  On a narrow window the card goes under the list.
"""

from __future__ import annotations

from typing import Mapping

from PyQt6.QtCore import QModelIndex, QPointF, QRect, QRectF, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QPainter
from PyQt6.QtWidgets import (
    QBoxLayout,
    QHBoxLayout,
    QListWidgetItem,
    QSizePolicy,
    QStyleOptionViewItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    CardWidget,
    ComboBox,
    FluentIcon as FIF,
    ListWidget,
    PlainTextEdit,
    PrimaryPushButton,
    SearchLineEdit,
    StrongBodyLabel,
    SubtitleLabel,
    TransparentPushButton,
)
from qfluentwidgets.components.widgets.list_view import ListItemDelegate

from ..engines.zapret.presets import PresetInfo
from ..engines.zapret.strategies import (
    CUSTOM_STRATEGY_ID,
    STRATEGY_LABEL_TITLES,
    STRATEGY_LABELS,
    Strategy,
    validate_custom_strategy,
)
from .singbox.art import draw_icon
from .theme import (
    accent_color,
    error_color,
    info_color,
    positive_color,
    text_color,
    text_muted_color,
    warning_color,
)

ROW_HEIGHT = 50
#: Below this width the card moves under the list.
STACK_WIDTH = 820
_SEARCH_DEBOUNCE_MS = 150

ID_ROLE = Qt.ItemDataRole.UserRole
SUBTITLE_ROLE = Qt.ItemDataRole.UserRole + 1
CHIP_ROLE = Qt.ItemDataRole.UserRole + 2
TONE_ROLE = Qt.ItemDataRole.UserRole + 3
MARK_ROLE = Qt.ItemDataRole.UserRole + 4

_UNLABELED = "-"
_CUSTOM_TITLE = "Своя стратегия"


def tone_color(tone: str) -> QColor:
    """Colour of a chip: catalog labels and the «Работает» state."""

    if tone == "running":
        return accent_color()
    if tone == "recommended":
        return positive_color()
    if tone == "caution":
        return error_color()
    if tone == "experimental":
        return warning_color()
    if tone == "game":
        return info_color()
    if tone == "stable":
        return accent_color()
    return text_muted_color()


class TwoLineDelegate(ListItemDelegate):
    """Check mark · title over a muted subtitle · optional chip on the right."""

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex) -> QSize:
        return QSize(super().sizeHint(option, index).width(), ROW_HEIGHT)

    def initStyleOption(self, option: QStyleOptionViewItem, index: QModelIndex) -> None:
        super().initStyleOption(option, index)
        option.text = ""  # drawn below in two lines

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex) -> None:
        super().paint(painter, option, index)
        title = str(index.data(Qt.ItemDataRole.DisplayRole) or "")
        subtitle = str(index.data(SUBTITLE_ROLE) or "")
        chip = str(index.data(CHIP_ROLE) or "")
        tone = str(index.data(TONE_ROLE) or "")
        marked = bool(index.data(MARK_ROLE))

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = option.rect
        small = QFont(option.font)
        small.setPointSizeF(max(7.5, option.font.pointSizeF() - 1.5))

        if marked:
            draw_icon(painter, FIF.ACCEPT, QPointF(rect.left() + 22, rect.center().y()), 14, accent_color())
        right = rect.right() - 12
        if chip:
            painter.setFont(small)
            width = painter.fontMetrics().horizontalAdvance(chip) + 16
            chip_rect = QRect(right - width, rect.center().y() - 9, width, 18)
            color = tone_color(tone)
            fill = QColor(color)
            fill.setAlpha(40)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(fill)
            painter.drawRoundedRect(QRectF(chip_rect), 9, 9)
            painter.setPen(color)
            painter.drawText(chip_rect, int(Qt.AlignmentFlag.AlignCenter), chip)
            right -= width + 10

        left = rect.left() + 40
        width = max(40, right - left)
        top_half = QRect(left, rect.top() + 6, width, rect.height() // 2 - 4)
        bottom_half = QRect(left, rect.center().y() + 1, width, rect.height() // 2 - 6)
        title_font = QFont(option.font)
        title_font.setBold(marked)
        painter.setFont(title_font)
        painter.setPen(accent_color() if marked else text_color())
        painter.drawText(
            top_half if subtitle else rect.adjusted(left - rect.left(), 0, 0, 0),
            int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
            painter.fontMetrics().elidedText(title, Qt.TextElideMode.ElideRight, width),
        )
        if subtitle:
            painter.setFont(small)
            painter.setPen(text_muted_color())
            painter.drawText(
                bottom_half,
                int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
                painter.fontMetrics().elidedText(subtitle, Qt.TextElideMode.ElideRight, width),
            )
        painter.restore()


def new_list(parent: QWidget) -> ListWidget:
    view = ListWidget(parent)
    view.setItemDelegate(TwoLineDelegate(view))
    view.setUniformItemSizes(True)
    # Pixel scrolling parks the view mid-row; whole rows read as intended.
    view.setVerticalScrollMode(ListWidget.ScrollMode.ScrollPerItem)
    view.setMinimumHeight(ROW_HEIGHT * 5)
    view.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
    return view


class SplitView(QWidget):
    """List on the left, card on the right; stacked when the window is narrow."""

    def __init__(self, master: QWidget, detail: QWidget, parent: QWidget | None = None):
        super().__init__(parent)
        self.master = master
        self.detail = detail
        self._layout = QBoxLayout(QBoxLayout.Direction.LeftToRight, self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(12)
        self._layout.addWidget(master, 3)
        self._layout.addWidget(detail, 2)
        detail.setMinimumWidth(280)

    @property
    def stacked(self) -> bool:
        return self._layout.direction() == QBoxLayout.Direction.TopToBottom

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        stacked = self.width() < STACK_WIDTH
        if stacked != self.stacked:
            self._layout.setDirection(
                QBoxLayout.Direction.TopToBottom if stacked else QBoxLayout.Direction.LeftToRight
            )
            # Under the list the card takes only the height it needs.
            self._layout.setStretchFactor(self.detail, 0 if stacked else 2)
            self.detail.setSizePolicy(
                QSizePolicy.Policy.Preferred,
                QSizePolicy.Policy.Maximum if stacked else QSizePolicy.Policy.Preferred,
            )


def _card(parent: QWidget) -> tuple[CardWidget, QVBoxLayout]:
    card = CardWidget(parent)
    layout = QVBoxLayout(card)
    layout.setContentsMargins(18, 16, 18, 16)
    layout.setSpacing(8)
    return card, layout


def readable_arguments(args: tuple[str, ...]) -> str:
    """One parameter per line: ``--lua-desync=fake`` then ``    blob=tls_google``…

    A desync line is one long token that a label cannot wrap; split at its
    ``:`` parameters it fits the card and reads as a recipe.
    """

    lines: list[str] = []
    for arg in args:
        head, _, params = arg.partition(":")
        lines.append(head)
        lines.extend(f"    {param}" for param in params.split(":") if params)
    return "\n".join(lines)


def _wrapped(label: QWidget) -> QWidget:
    label.setWordWrap(True)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


# ── strategies ───────────────────────────────────────────────────────────────


class StrategyBrowser(QWidget):
    """Pick the strategy a server kind uses; the button in the card applies it."""

    chosen = pyqtSignal(str, str)  # strategy id, own strategy text

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._entries: dict[str, Strategy] = {}
        self._chosen_id = ""
        self._custom_text = ""
        self._highlight = ""
        self._ids: list[str] = []

        master = QWidget(self)
        column = QVBoxLayout(master)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(8)
        tools = QHBoxLayout()
        tools.setSpacing(8)
        self.search = SearchLineEdit(master)
        self.search.setPlaceholderText("Поиск по названию, описанию, аргументам")
        self.search.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        tools.addWidget(self.search, 1)
        self.group = ComboBox(master)
        self.group.setMinimumWidth(190)
        tools.addWidget(self.group)
        column.addLayout(tools)
        self.count_label = CaptionLabel("", master)
        column.addWidget(self.count_label)
        self.list = new_list(master)
        column.addWidget(self.list, 1)

        detail, card = _card(self)
        self.title_label = SubtitleLabel("", detail)
        self.title_label.setWordWrap(True)
        card.addWidget(self.title_label)
        self.meta_label = CaptionLabel("", detail)
        card.addWidget(self.meta_label)
        self.description_label = _wrapped(BodyLabel("", detail))
        card.addWidget(self.description_label)
        self.args_title = StrongBodyLabel("Аргументы winws2", detail)
        card.addWidget(self.args_title)
        self.args_label = _wrapped(CaptionLabel("", detail))
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        mono.setPointSizeF(max(8.0, self.args_label.font().pointSizeF() - 0.5))
        self.args_label.setFont(mono)
        card.addWidget(self.args_label)
        self.custom_edit = PlainTextEdit(detail)
        self.custom_edit.setPlaceholderText("# комментарий\n--payload=tls_client_hello\n--lua-desync=...")
        self.custom_edit.setFont(mono)
        self.custom_edit.setMinimumHeight(140)
        card.addWidget(self.custom_edit, 1)
        self.error_label = _wrapped(CaptionLabel("", detail))
        card.addWidget(self.error_label)
        card.addStretch(1)
        self.use_btn = PrimaryPushButton(FIF.ACCEPT, "Использовать", detail)
        self.use_btn.clicked.connect(self._use)
        card.addWidget(self.use_btn)

        self.split = SplitView(master, detail, self)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self.split)

        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(_SEARCH_DEBOUNCE_MS)
        self._debounce.timeout.connect(self._rebuild)
        self.search.textChanged.connect(lambda _text: self._debounce.start())
        self.group.currentIndexChanged.connect(lambda _index: self._rebuild())
        self.list.currentRowChanged.connect(self._on_row)
        self.custom_edit.textChanged.connect(self._sync_button)

    # ── public API ──

    def set_entries(self, entries: Mapping[str, Strategy]) -> None:
        """Load a catalog; the group filter lists every label with its count."""

        self._entries = dict(entries)
        counts: dict[str, int] = {}
        for entry in self._entries.values():
            key = entry.label if entry.label in STRATEGY_LABELS else _UNLABELED
            counts[key] = counts.get(key, 0) + 1
        self.group.blockSignals(True)
        self.group.clear()
        self.group.addItem(f"Все · {len(self._entries)}", userData="")
        for label in (*STRATEGY_LABELS, _UNLABELED):
            if counts.get(label):
                title = STRATEGY_LABEL_TITLES.get(label, "Без метки")
                self.group.addItem(f"{title} · {counts[label]}", userData=label)
        self.group.setCurrentIndex(0)
        self.group.blockSignals(False)
        self.search.blockSignals(True)
        self.search.clear()
        self.search.blockSignals(False)
        self._rebuild()

    def set_chosen(self, strategy_id: str, custom_text: str) -> None:
        """The strategy in use; the list opens on it."""

        self._chosen_id = strategy_id
        self._custom_text = custom_text
        self.custom_edit.blockSignals(True)
        self.custom_edit.setPlainText(custom_text)
        self.custom_edit.blockSignals(False)
        self._highlight = strategy_id
        self._rebuild()

    def chosen_id(self) -> str:
        return self._chosen_id

    def highlighted_id(self) -> str:
        return self._highlight

    def highlight(self, strategy_id: str) -> None:
        self._highlight = strategy_id
        self._sync_list()
        self._show()

    # ── list ──

    def _visible(self) -> list[Strategy]:
        query = self.search.text().strip().casefold()
        group = str(self.group.currentData() or "")
        rank = {label: index for index, label in enumerate(STRATEGY_LABELS)}
        result = [
            entry for entry in self._entries.values()
            if (not group or (entry.label if entry.label in rank else _UNLABELED) == group)
            and (not query or query in entry.search_haystack)
        ]
        result.sort(key=lambda entry: (rank.get(entry.label, len(rank)), entry.name.casefold()))
        return result

    def _rebuild(self) -> None:
        entries = self._visible()
        query = self.search.text().strip().casefold()
        self.list.blockSignals(True)
        self.list.clear()
        self._ids = []
        if not query or query in _CUSTOM_TITLE.casefold():
            item = QListWidgetItem(_CUSTOM_TITLE)
            item.setData(SUBTITLE_ROLE, "Свои строки --lua-desync из инструкций к zapret")
            self._add(item, CUSTOM_STRATEGY_ID)
        for entry in entries:
            item = QListWidgetItem(entry.name)
            item.setData(SUBTITLE_ROLE, entry.description or " ".join(entry.args))
            if entry.label in STRATEGY_LABEL_TITLES:
                item.setData(CHIP_ROLE, entry.label_title)
                item.setData(TONE_ROLE, entry.label)
            self._add(item, entry.strategy_id)
        self.list.blockSignals(False)
        self.count_label.setText(f"Показано {len(entries)} из {len(self._entries)}")
        self._sync_list()
        self._show()

    def _add(self, item: QListWidgetItem, strategy_id: str) -> None:
        item.setData(ID_ROLE, strategy_id)
        item.setData(MARK_ROLE, strategy_id == self._chosen_id)
        item.setSizeHint(QSize(0, ROW_HEIGHT))
        self.list.addItem(item)
        self._ids.append(strategy_id)

    def _sync_list(self) -> None:
        """Keep the highlight on its row without letting a filter move it."""

        self.list.blockSignals(True)
        for row, strategy_id in enumerate(self._ids):
            self.list.item(row).setData(MARK_ROLE, strategy_id == self._chosen_id)
        if self._highlight in self._ids:
            row = self._ids.index(self._highlight)
            self.list.setCurrentRow(row)
            self.list.scrollToItem(self.list.item(row), ListWidget.ScrollHint.PositionAtCenter)
        else:
            self.list.setCurrentRow(-1)
        self.list.blockSignals(False)

    def _on_row(self, row: int) -> None:
        if 0 <= row < len(self._ids):
            self._highlight = self._ids[row]
            self._show()

    # ── card ──

    def _show(self) -> None:
        strategy_id = self._highlight
        custom = strategy_id == CUSTOM_STRATEGY_ID
        entry = self._entries.get(strategy_id)
        self.error_label.setText("")
        self.custom_edit.setVisible(custom)
        self.args_title.setVisible(entry is not None)
        self.args_label.setVisible(entry is not None)
        if custom:
            self.title_label.setText(_CUSTOM_TITLE)
            self.meta_label.setText("")
            self.description_label.setText(
                "Строки --lua-desync=…, --payload=…, --out-range=… и комментарии #. "
                "Порты, адрес сервера и нужные блобы приложение добавит само."
            )
        elif entry is not None:
            self.title_label.setText(entry.name)
            meta = [entry.label_title] if entry.label_title else []
            if entry.author:
                meta.append(f"автор {entry.author}")
            self.meta_label.setText(" · ".join(meta))
            parts = [entry.description or "Описания нет."]
            if entry.blob_dependencies:
                parts.append("Блобы: " + ", ".join(entry.blob_dependencies))
            self.description_label.setText("\n".join(parts))
            self.args_label.setText(readable_arguments(entry.args))
        else:
            self.title_label.setText("Стратегия не выбрана")
            self.meta_label.setText("")
            self.description_label.setText(
                f"«{strategy_id}» нет в каталоге." if strategy_id else "Выберите стратегию в списке."
            )
        self.meta_label.setVisible(bool(self.meta_label.text()))
        self._sync_button()

    def _sync_button(self) -> None:
        strategy_id = self._highlight
        custom = strategy_id == CUSTOM_STRATEGY_ID
        known = custom or strategy_id in self._entries
        in_use = strategy_id == self._chosen_id and (
            not custom or self.custom_edit.toPlainText() == self._custom_text
        )
        self.use_btn.setEnabled(known and not in_use)
        self.use_btn.setText("Используется" if in_use else "Использовать")

    def _use(self) -> None:
        strategy_id = self._highlight
        text = self.custom_edit.toPlainText()
        if strategy_id == CUSTOM_STRATEGY_ID:
            try:
                validate_custom_strategy(text)
            except ValueError as exc:
                self.error_label.setText(str(exc))
                return
        else:
            text = self._custom_text  # a catalog choice keeps the saved own text
        self._chosen_id = strategy_id
        self._custom_text = text
        self._sync_list()
        self._sync_button()
        self.chosen.emit(strategy_id, text)


# ── presets ──────────────────────────────────────────────────────────────────


class PresetBrowser(QWidget):
    """Pick the preset winws2 runs; edit, delete or start it from the card."""

    chosen = pyqtSignal(str)
    edit_requested = pyqtSignal(str)
    delete_requested = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._presets: list[PresetInfo] = []
        self._chosen = ""
        self._running = ""
        self._highlight = ""
        self._ids: list[str] = []

        master = QWidget(self)
        column = QVBoxLayout(master)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(8)
        self.search = SearchLineEdit(master)
        self.search.setPlaceholderText("Поиск по названию и целям")
        column.addWidget(self.search)
        self.count_label = CaptionLabel("", master)
        column.addWidget(self.count_label)
        self.list = new_list(master)
        column.addWidget(self.list, 1)

        detail, card = _card(self)
        self.title_label = SubtitleLabel("", detail)
        self.title_label.setWordWrap(True)
        card.addWidget(self.title_label)
        self.meta_label = CaptionLabel("", detail)
        card.addWidget(self.meta_label)
        self.description_label = _wrapped(BodyLabel("", detail))
        card.addWidget(self.description_label)
        card.addWidget(StrongBodyLabel("Что обходит", detail))
        self.targets_label = _wrapped(BodyLabel("", detail))
        card.addWidget(self.targets_label)
        card.addWidget(StrongBodyLabel("Перехват", detail))
        self.ports_label = _wrapped(CaptionLabel("", detail))
        card.addWidget(self.ports_label)
        card.addStretch(1)
        self.choose_btn = PrimaryPushButton(FIF.ACCEPT, "Выбрать", detail)
        self.choose_btn.clicked.connect(lambda: self.chosen.emit(self._highlight))
        card.addWidget(self.choose_btn)
        actions = QHBoxLayout()
        self.edit_btn = TransparentPushButton(FIF.EDIT, "Изменить", detail)
        self.edit_btn.clicked.connect(lambda: self.edit_requested.emit(self._highlight))
        self.delete_btn = TransparentPushButton(FIF.DELETE, "Удалить", detail)
        self.delete_btn.clicked.connect(lambda: self.delete_requested.emit(self._highlight))
        actions.addWidget(self.edit_btn)
        actions.addWidget(self.delete_btn)
        actions.addStretch(1)
        card.addLayout(actions)

        self.split = SplitView(master, detail, self)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self.split)

        self.search.textChanged.connect(lambda _text: self._rebuild())
        self.list.currentRowChanged.connect(self._on_row)

    def set_presets(self, presets: list[PresetInfo], chosen: str, running: str) -> None:
        self._presets = list(presets)
        self._chosen = chosen
        self._running = running
        if not self._highlight or self._highlight not in {preset.name for preset in presets}:
            self._highlight = chosen
        self._rebuild()

    def highlight(self, name: str) -> None:
        self._highlight = name
        self._sync_list()
        self._show()

    def highlighted(self) -> str:
        return self._highlight

    def _rebuild(self) -> None:
        query = self.search.text().strip().casefold()
        shown = [
            preset for preset in self._presets
            if not query
            or query in preset.name.casefold()
            or query in " ".join(preset.summary.targets).casefold()
        ]
        self.list.blockSignals(True)
        self.list.clear()
        self._ids = []
        for preset in shown:
            item = QListWidgetItem(preset.name)
            item.setData(SUBTITLE_ROLE, preset.description or preset.summary.short())
            item.setData(ID_ROLE, preset.name)
            if preset.name == self._running:
                item.setData(CHIP_ROLE, "Работает")
                item.setData(TONE_ROLE, "running")
            item.setSizeHint(QSize(0, ROW_HEIGHT))
            self.list.addItem(item)
            self._ids.append(preset.name)
        self.list.blockSignals(False)
        self.count_label.setText(f"Показано {len(shown)} из {len(self._presets)}")
        self._sync_list()
        self._show()

    def _sync_list(self) -> None:
        self.list.blockSignals(True)
        for row, name in enumerate(self._ids):
            self.list.item(row).setData(MARK_ROLE, name == self._chosen)
        if self._highlight in self._ids:
            row = self._ids.index(self._highlight)
            self.list.setCurrentRow(row)
            self.list.scrollToItem(self.list.item(row), ListWidget.ScrollHint.PositionAtCenter)
        else:
            self.list.setCurrentRow(-1)
        self.list.blockSignals(False)

    def _on_row(self, row: int) -> None:
        if 0 <= row < len(self._ids):
            self._highlight = self._ids[row]
            self._show()

    def _show(self) -> None:
        preset = next((item for item in self._presets if item.name == self._highlight), None)
        for widget in (self.choose_btn, self.edit_btn, self.delete_btn):
            widget.setEnabled(preset is not None)
        if preset is None:
            self.title_label.setText("Пресет не выбран")
            for label in (self.meta_label, self.description_label, self.targets_label, self.ports_label):
                label.setText("")
            self.choose_btn.setText("Выбрать")
            return
        summary = preset.summary
        self.title_label.setText(preset.name)
        state = []
        if preset.name == self._running:
            state.append("работает сейчас")
        elif preset.name == self._chosen:
            state.append("выбран")
        state.append(f"профилей: {summary.profiles}")
        self.meta_label.setText(" · ".join(state))
        self.description_label.setText(preset.description)
        self.description_label.setVisible(bool(preset.description))
        targets = list(summary.targets)
        if summary.catch_all:
            targets.append("весь остальной трафик на перехваченных портах")
        self.targets_label.setText(", ".join(targets) or "Целей нет")
        ports = []
        if summary.tcp_ports:
            ports.append(f"TCP {summary.tcp_ports}")
        if summary.udp_ports:
            ports.append(f"UDP {summary.udp_ports}")
        self.ports_label.setText("\n".join(ports) or "Порты не заданы")
        chosen = preset.name == self._chosen
        self.choose_btn.setEnabled(not chosen)
        self.choose_btn.setText("Выбран" if chosen else "Выбрать")
