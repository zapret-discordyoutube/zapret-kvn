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
from PyQt6.QtWidgets import QHBoxLayout, QListWidgetItem, QStackedWidget, QVBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    CardWidget,
    FluentIcon,
    ListWidget,
    PushButton,
    SearchLineEdit,
    StrongBodyLabel,
    SubtitleLabel,
    SwitchButton,
    TransparentToolButton,
)

from ..profiles.models import Node
from ..slots.catalog import BUILT_IN
from .privacy import node_name_text

AUTO = "Авто"
AUTO_DETAIL = "Авто — лучший свободный сервер, сам меняется, если сервер стал плохим"

_PAGE_MARGINS = (24, 20, 24, 20)


def rank_key(node: Node) -> tuple:
    """Best first, as the slot assigner ranks servers: answered, then faster speed test, then lower ping."""
    alive = 0 if node.is_alive is True else (2 if node.is_alive is False else 1)
    ping = node.ping_ms if node.ping_ms is not None and node.ping_ms > 0 else 1_000_000
    return (alive, -(node.speed_mbps or 0.0), ping, (node.name or "").lower())


def node_detail(node: Node) -> str:
    """One line under a server's name: protocol and the last check, never the address."""
    protocol = str((node.outbound or {}).get("protocol") or (node.outbound or {}).get("type") or node.scheme or "")
    parts = [protocol.upper() if protocol else ""]
    if node.is_alive is False:
        parts.append("не отвечал")
    else:
        if node.ping_ms is not None and node.ping_ms > 0:
            parts.append(f"{node.ping_ms} мс")
        if node.speed_mbps:
            parts.append(f"{node.speed_mbps:.0f} Мбит/с")
    return " · ".join(part for part in parts if part)


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
        self._picking: str | None = None
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

    # ── picker ──

    def _build_picker(self) -> QWidget:
        page = QWidget(self)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(*_PAGE_MARGINS)
        layout.setSpacing(10)
        header = QHBoxLayout()
        self._back = TransparentToolButton(FluentIcon.RETURN, page)
        self._back.setToolTip("Назад к сервисам")
        self._back.clicked.connect(self.close_picker)
        header.addWidget(self._back)
        self._picker_title = SubtitleLabel("", page)
        header.addWidget(self._picker_title, 1)
        layout.addLayout(header)
        self._search = SearchLineEdit(page)
        self._search.setPlaceholderText("Поиск сервера")
        self._search.textChanged.connect(self._filter)
        layout.addWidget(self._search)
        self._list = ListWidget(page)
        self._list.setUniformItemSizes(True)
        self._list.itemClicked.connect(self._on_pick)
        layout.addWidget(self._list, 1)
        return page

    def open_picker(self, slot_id: str) -> None:
        """Full-page list for one service: «Авто» first, then servers best first; the current choice is marked."""
        title = next((spec.title for spec in BUILT_IN if spec.id == slot_id), slot_id)
        self._picking = slot_id
        self._picker_title.setText(f"Сервер для «{title}»")
        self._search.blockSignals(True)
        self._search.clear()
        self._search.blockSignals(False)
        self._fill_list()
        self._stack.setCurrentIndex(1)
        self._search.setFocus()

    def close_picker(self) -> None:
        self._picking = None
        self._list.clear()  # nothing to keep: the list is rebuilt for the next service
        self._stack.setCurrentIndex(0)

    def picker_open(self) -> bool:
        return self._stack.currentIndex() == 1

    def _fill_list(self) -> None:
        pin = self._pins.get(self._picking or "", "")
        self._list.setUpdatesEnabled(False)
        try:
            self._list.clear()
            auto = QListWidgetItem(("✓  " if not pin else "") + AUTO_DETAIL)
            auto.setData(Qt.ItemDataRole.UserRole, "")
            self._list.addItem(auto)
            for node in sorted(self._nodes, key=rank_key):
                mark = "✓  " if node.id == pin else ""
                item = QListWidgetItem(f"{mark}{node_name_text(node)}    {node_detail(node)}")
                item.setData(Qt.ItemDataRole.UserRole, node.id)
                item.setData(Qt.ItemDataRole.UserRole + 1, node_name_text(node).lower())
                self._list.addItem(item)
        finally:
            self._list.setUpdatesEnabled(True)

    def _filter(self, text: str) -> None:
        needle = text.strip().lower()
        for index in range(self._list.count()):
            item = self._list.item(index)
            name = item.data(Qt.ItemDataRole.UserRole + 1)
            item.setHidden(bool(needle) and (name is None or needle not in name))

    def _on_pick(self, item: QListWidgetItem) -> None:
        slot_id = self._picking
        if slot_id is None:
            return
        node_id = str(item.data(Qt.ItemDataRole.UserRole) or "")
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
    ) -> None:
        """[live]: slot id -> the server the running slot uses now (None = it follows the main server). Cheap: the
        server list is not touched until the picker opens (an open picker is refreshed in place)."""
        self._updating = True
        try:
            self._available = available
            self._enabled = set(enabled)
            self._pins = dict(pins)
            self._nodes = list(nodes)
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
                scroll = self._list.verticalScrollBar().value()
                self._fill_list()
                self._filter(self._search.text())
                self._list.verticalScrollBar().setValue(scroll)
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
