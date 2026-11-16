"""«Серверы по сервисам» on the main page (docs/SERVICE_SLOTS.md, phase 5; owner 2026-11-16: «for beginners»).

One switch per service and «Авто» or a pinned server. A switch makes the app write the slot into the active sing-box
config itself; the slot then picks its server on its own.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QGridLayout, QVBoxLayout, QWidget
from qfluentwidgets import BodyLabel, CaptionLabel, CardWidget, ComboBox, StrongBodyLabel, SwitchButton

from ..profiles.models import Node
from ..slots.catalog import BUILT_IN
from .privacy import node_name_text

AUTO = "Авто"


class ServiceSlotsCard(CardWidget):
    """Signals carry the whole wanted set / one pin; the controller writes the config and moves the slot."""

    slots_changed = pyqtSignal(object)  # set[str] of ticked slot ids
    pin_changed = pyqtSignal(str, str)  # slot id, server id ("" = «Авто»)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._updating = False
        self._enabled: set[str] = set()
        self._node_ids: list[str] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 16)
        layout.setSpacing(8)
        layout.addWidget(StrongBodyLabel("Серверы по сервисам", self))
        hint = CaptionLabel(
            "YouTube, ИИ-сервисы и Telegram идут через свой сервер, остальные программы — через основной. "
            "Сервер выбирается сам; можно закрепить свой.",
            self,
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(6)
        self._switches: dict[str, SwitchButton] = {}
        self._combos: dict[str, ComboBox] = {}
        self._states: dict[str, CaptionLabel] = {}
        for row, spec in enumerate(BUILT_IN):
            switch = SwitchButton(self)
            switch.setOnText("")
            switch.setOffText("")
            switch.checkedChanged.connect(self._on_switch)
            combo = ComboBox(self)
            combo.setMinimumWidth(200)
            combo.currentIndexChanged.connect(lambda _index, slot=spec.id: self._on_pin(slot))
            state = CaptionLabel("", self)
            grid.addWidget(switch, row, 0)
            grid.addWidget(BodyLabel(spec.title, self), row, 1)
            grid.addWidget(combo, row, 2)
            grid.addWidget(state, row, 3)
            self._switches[spec.id] = switch
            self._combos[spec.id] = combo
            self._states[spec.id] = state
        grid.setColumnStretch(3, 1)
        layout.addLayout(grid)
        self._note = CaptionLabel("", self)
        self._note.setWordWrap(True)
        layout.addWidget(self._note)

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
        """[live]: slot id -> the server the running slot uses now (None = it follows the main server)."""
        self._updating = True
        try:
            self._enabled = set(enabled)
            self._node_ids = [node.id for node in nodes]
            for spec in BUILT_IN:
                switch = self._switches[spec.id]
                switch.setEnabled(available)
                switch.setChecked(spec.id in self._enabled)
                combo = self._combos[spec.id]
                combo.clear()
                combo.addItem(AUTO)
                for node in nodes:
                    combo.addItem(node_name_text(node))
                pin = pins.get(spec.id, "")
                combo.setCurrentIndex(self._node_ids.index(pin) + 1 if pin in self._node_ids else 0)
                combo.setEnabled(available and spec.id in self._enabled)
                self._states[spec.id].setText(_live_text(spec.id, live) if connected and spec.id in self._enabled else "")
            self._note.setText(note)
            self._note.setVisible(bool(note))
        finally:
            self._updating = False

    def _on_switch(self, _checked: bool) -> None:
        if self._updating:
            return
        wanted = {slot for slot, switch in self._switches.items() if switch.isChecked()}
        for slot, combo in self._combos.items():
            combo.setEnabled(slot in wanted)
        self.slots_changed.emit(wanted)

    def _on_pin(self, slot_id: str) -> None:
        if self._updating:
            return
        index = self._combos[slot_id].currentIndex()
        node_id = self._node_ids[index - 1] if 0 < index <= len(self._node_ids) else ""
        self.pin_changed.emit(slot_id, node_id)


def _live_text(slot_id: str, live: Mapping[str, Node | None]) -> str:
    if slot_id not in live:
        return "запустится при подключении"
    node = live[slot_id]
    return f"сейчас: {node_name_text(node)}" if node is not None else "сейчас: как основной"
