"""«Сервисы»: own servers for YouTube, AI and Telegram (docs/SERVICE_SLOTS.md, "The «Сервисы» page").

Owner 2026-11-17: the slots get their own page with a full-page server picker. The old main-page card held three
ComboBoxes refilled with every server on each runtime change; with 30+ servers their pop-ups overflowed the window,
scrolled slowly and lagged. Here the overview is three light rows, and the server list is built only when the picker
opens, for one service, inside a list view that fills the page and has a search field.

A switch makes the app write the slot into the active sing-box config itself; the slot then picks its server on its
own («Авто»), or uses the pinned one while it is good (owner 2026-11-17: a bad pinned server gives way to the best one).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QAbstractItemView, QHBoxLayout, QHeaderView, QStackedWidget, QVBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    CardWidget,
    ComboBox,
    FluentIcon,
    PrimaryPushButton,
    PushButton,
    SearchLineEdit,
    SmoothMode,
    StrongBodyLabel,
    SubtitleLabel,
    SwitchButton,
    TransparentToolButton,
)

from ..profiles.models import Node
from ..slots.catalog import BUILT_IN
from .nodes_table_model import COLUMN_SPECS, GROUP_MODES, NODE_ROW_HEIGHT, NodesTableModel
from .nodes_view import FLAG_SIZE, NodesView
from .privacy import node_name_text

AUTO = "Авто"
AUTO_DETAIL = "лучший свободный сервер, сам меняется, если сервер стал плохим"

_PAGE_MARGINS = (24, 20, 24, 20)
# The picker shows the same table as «Серверы», with only the columns that help to choose a server.
_PICKER_COLUMNS = ("name", "type", "ping", "speed")
# Header click -> model sort key; a second click on the same column flips the order.
_SORTABLE = {index: spec.sort_key for index, spec in enumerate(COLUMN_SPECS) if spec.key in _PICKER_COLUMNS}
_DEFAULT_SORT = ("ping", False)


class _ServiceRow(CardWidget):
    def __init__(self, title: str, parent: QWidget | None = None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 12, 18, 12)
        layout.setSpacing(14)
        self.switch = SwitchButton(self)
        self.switch.setOnText("")
        self.switch.setOffText("")
        layout.addWidget(self.switch)
        texts = QVBoxLayout()
        texts.setSpacing(2)
        texts.addWidget(StrongBodyLabel(title, self))
        self.server = BodyLabel("", self)
        self.state = CaptionLabel("", self)
        texts.addWidget(self.server)
        texts.addWidget(self.state)
        layout.addLayout(texts, 1)
        self.choose = PushButton(FluentIcon.EDIT, "Выбрать сервер", self)
        layout.addWidget(self.choose)


class ServicesPage(QWidget):
    """Signals carry the whole wanted set / one pin; the controller writes the config and moves the slot."""

    slots_changed = pyqtSignal(object)  # set[str] of ticked slot ids
    pin_changed = pyqtSignal(str, str)  # slot id, server id ("" = «Авто»)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("services_page_body")
        self._updating = False
        self._available = False
        self._enabled: set[str] = set()
        self._pins: dict[str, str] = {}
        self._nodes: list[Node] = []
        self._source_names: dict[str, str] = {}
        self._picking: str | None = None
        self._sort = _DEFAULT_SORT
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self._stack = QStackedWidget(self)
        outer.addWidget(self._stack)
        self._stack.addWidget(self._build_overview())
        self._stack.addWidget(self._build_picker())

    # ── overview ──

    def _build_overview(self) -> QWidget:
        page = QWidget(self)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(*_PAGE_MARGINS)
        layout.setSpacing(12)
        layout.addWidget(SubtitleLabel("Сервисы", page))
        hint = CaptionLabel(
            "Включённый сервис идёт через свой сервер, все остальные программы — через основной. Сервер выбирается "
            "сам; можно закрепить свой, но если он станет плохим, программа временно возьмёт лучший.",
            page,
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self._rows: dict[str, _ServiceRow] = {}
        for spec in BUILT_IN:
            row = _ServiceRow(spec.title, page)
            row.switch.checkedChanged.connect(self._on_switch)
            row.choose.clicked.connect(lambda _checked=False, slot=spec.id: self.open_picker(slot))
            layout.addWidget(row)
            self._rows[spec.id] = row
        self._note = CaptionLabel("", page)
        self._note.setWordWrap(True)
        layout.addWidget(self._note)
        layout.addStretch(1)
        return page

    # ── picker: the same server table as «Серверы» ──

    def _build_picker(self) -> QWidget:
        page = QWidget(self)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(*_PAGE_MARGINS)
        layout.setSpacing(10)

        header = QHBoxLayout()
        header.setSpacing(8)
        self._back = TransparentToolButton(FluentIcon.RETURN, page)
        self._back.setToolTip("Назад к сервисам (Esc)")
        self._back.clicked.connect(self.close_picker)
        header.addWidget(self._back)
        self._picker_title = SubtitleLabel("", page)
        header.addWidget(self._picker_title, 1)
        self._auto_button = PushButton(FluentIcon.SYNC, AUTO, page)
        self._auto_button.setToolTip(f"{AUTO}: {AUTO_DETAIL}")
        self._auto_button.clicked.connect(self._pick_auto)
        header.addWidget(self._auto_button)
        self._pin_button = PrimaryPushButton(FluentIcon.PIN, "Закрепить выбранный", page)
        self._pin_button.clicked.connect(self._pin_selected)
        header.addWidget(self._pin_button)
        layout.addLayout(header)

        self._current = CaptionLabel("", page)
        self._current.setWordWrap(True)
        layout.addWidget(self._current)

        tools = QHBoxLayout()
        tools.setSpacing(8)
        self._search = SearchLineEdit(page)
        self._search.setPlaceholderText("Поиск: имя, протокол, подписка")
        self._search.textChanged.connect(self._filter)
        tools.addWidget(self._search, 1)
        tools.addWidget(CaptionLabel("Группировка", page))
        self._grouping = ComboBox(page)
        for mode, title in GROUP_MODES.items():
            self._grouping.addItem(title, userData=mode)
        self._grouping.currentIndexChanged.connect(self._on_grouping)
        tools.addWidget(self._grouping)
        layout.addLayout(tools)

        self._model = NodesTableModel(page)
        self._table = NodesView(page)
        self._table.setModel(self._model)
        vertical = self._table.verticalHeader()
        vertical.setDefaultSectionSize(NODE_ROW_HEIGHT)
        vertical.setMinimumSectionSize(NODE_ROW_HEIGHT)
        vertical.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        vertical.hide()
        horizontal = self._table.horizontalHeader()
        horizontal.setStretchLastSection(False)
        horizontal.setSectionsClickable(True)
        horizontal.setSectionsMovable(False)
        horizontal.setSortIndicatorShown(True)
        horizontal.sectionClicked.connect(self._on_header_clicked)
        for index, spec in enumerate(COLUMN_SPECS):
            visible = spec.key in _PICKER_COLUMNS
            self._table.setColumnHidden(index, not visible)
            if spec.key == "name":
                horizontal.setSectionResizeMode(index, QHeaderView.ResizeMode.Stretch)
            elif visible:
                horizontal.setSectionResizeMode(index, QHeaderView.ResizeMode.Fixed)
                horizontal.resizeSection(index, spec.default_width + 20)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setIconSize(FLAG_SIZE)
        self._table.scrollDelagate.verticalSmoothScroll.setSmoothMode(SmoothMode.NO_SMOOTH)
        self._table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerItem)
        self._table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._table.node_activated.connect(lambda node_id, _source: self._pin(node_id))
        self._table.selectionModel().selectionChanged.connect(self._update_pin_button)
        self._model.modelReset.connect(self._update_pin_button)
        self._model.set_group_mode("source")
        self._apply_sort()
        layout.addWidget(self._table, 1)
        return page

    def open_picker(self, slot_id: str) -> None:
        """Full-page server table for one service; the pinned server is shown like the active one on «Серверы»."""
        title = next((spec.title for spec in BUILT_IN if spec.id == slot_id), slot_id)
        self._picking = slot_id
        self._picker_title.setText(f"Сервер для «{title}»")
        self._search.blockSignals(True)
        self._search.clear()
        self._search.blockSignals(False)
        self._model.set_query("")
        self._fill_table()
        self._table.clearSelection()
        self._stack.setCurrentIndex(1)
        pin = self._pins.get(slot_id, "")
        row = self._model.row_of_node(pin) if pin else None
        if row is not None:
            self._table.scrollTo(self._model.index(row, 0), QAbstractItemView.ScrollHint.PositionAtCenter)
        else:
            self._table.scrollToTop()
        self._update_pin_button()
        self._search.setFocus()

    def close_picker(self) -> None:
        self._picking = None
        self._stack.setCurrentIndex(0)

    def picker_open(self) -> bool:
        return self._stack.currentIndex() == 1

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key.Key_Escape and self.picker_open():
            self.close_picker()
            return
        super().keyPressEvent(event)

    def _fill_table(self) -> None:
        pin = self._pins.get(self._picking or "", "")
        self._model.set_source_names(self._source_names)
        self._model.set_nodes(self._nodes)
        self._model.set_active_node_id(pin or None)
        names = {node.id: node_name_text(node) for node in self._nodes}
        if pin in names:
            self._current.setText(f"Сейчас закреплён «{names[pin]}» (выделен). Если он станет плохим, программа "
                                  f"временно возьмёт лучший. Кнопка «{AUTO}» снимает закрепление.")
        else:
            self._current.setText(f"Сейчас: {AUTO} — {AUTO_DETAIL}. Выберите сервер в таблице и нажмите "
                                  "«Закрепить выбранный» (или дважды щёлкните по строке).")
        self._auto_button.setEnabled(bool(pin))

    def _filter(self, text: str) -> None:
        self._model.set_query(text)

    def _on_grouping(self, _index: int) -> None:
        self._model.set_group_mode(self._grouping.currentData() or "source")

    def _on_header_clicked(self, index: int) -> None:
        key = _SORTABLE.get(index)
        if key is None:
            return
        descending = not self._sort[1] if self._sort[0] == key else key == "speed"
        self._sort = (key, descending)
        self._apply_sort()

    def _apply_sort(self) -> None:
        key, descending = self._sort
        self._model.set_sort(key, descending)
        column = next(index for index, sort_key in _SORTABLE.items() if sort_key == key)
        order = Qt.SortOrder.DescendingOrder if descending else Qt.SortOrder.AscendingOrder
        self._table.horizontalHeader().setSortIndicator(column, order)

    def _selected_node_id(self) -> str | None:
        rows = self._table.selectionModel().selectedRows()
        node = self._model.node_at_row(rows[0].row()) if rows else None
        return node.id if node is not None else None

    def _update_pin_button(self, *_args) -> None:
        selected = self._selected_node_id()
        self._pin_button.setEnabled(selected is not None and selected != self._pins.get(self._picking or "", ""))

    def _pin_selected(self) -> None:
        node_id = self._selected_node_id()
        if node_id:
            self._pin(node_id)

    def _pick_auto(self) -> None:
        self._pin("")

    def _pin(self, node_id: str) -> None:
        slot_id = self._picking
        if slot_id is None:
            return
        self.close_picker()
        self.pin_changed.emit(slot_id, node_id)

    # ── state ──

    def set_state(
        self,
        *,
        available: bool,
        enabled: Iterable[str],
        pins: Mapping[str, str],
        nodes: list[Node],
        live: Mapping[str, Node | None],
        connected: bool = False,
        note: str = "",
        source_names: Mapping[str, str] | None = None,
    ) -> None:
        """[live]: slot id -> the server the running slot uses now (None = it follows the main server). Cheap: the
        table model is not touched until the picker opens (an open picker updates only the changed rows)."""
        self._updating = True
        try:
            self._available = available
            self._enabled = set(enabled)
            self._pins = dict(pins)
            self._nodes = list(nodes)
            if source_names is not None:
                self._source_names = dict(source_names)
            names = {node.id: node_name_text(node) for node in self._nodes}
            for spec in BUILT_IN:
                row = self._rows[spec.id]
                on = spec.id in self._enabled
                row.switch.setEnabled(available)
                row.switch.setChecked(on)
                row.choose.setEnabled(available and on)
                pin = self._pins.get(spec.id, "")
                row.server.setText(f"Закреплён: {names[pin]}" if pin in names else f"Сервер: {AUTO}")
                row.state.setText(_live_text(spec.id, live) if connected and on else ("" if on else "выключен"))
            self._note.setText(note)
            self._note.setVisible(bool(note))
            if self.picker_open() and self._picking is not None:
                self._fill_table()
                self._update_pin_button()
        finally:
            self._updating = False

    def _on_switch(self, _checked: bool) -> None:
        if self._updating:
            return
        wanted = {slot for slot, row in self._rows.items() if row.switch.isChecked()}
        for slot, row in self._rows.items():
            row.choose.setEnabled(self._available and slot in wanted)
        self.slots_changed.emit(wanted)


def _live_text(slot_id: str, live: Mapping[str, Node | None]) -> str:
    if slot_id not in live:
        return "запустится при подключении"
    node = live[slot_id]
    return f"сейчас: {node_name_text(node)}" if node is not None else "сейчас: как основной"
