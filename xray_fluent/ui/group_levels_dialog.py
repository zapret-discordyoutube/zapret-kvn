"""«Свой порядок» of the server list: the user picks up to three levels of folders, in the order he wants.

Owner request 2026-11-27: "the user chooses how to group the servers themselves, which lets everyone customize the app".
The result is a mode string (the levels joined by «+»), saved with the other view settings.
"""

from __future__ import annotations

from PyQt6.QtWidgets import QVBoxLayout, QWidget
from qfluentwidgets import BodyLabel, CaptionLabel, ComboBox, MessageBoxBase, SubtitleLabel

from .nodes_table_model import GROUP_LEVELS, MAX_GROUP_LEVELS, group_levels

_NONE = "—"


def levels_title(levels: tuple[str, ...]) -> str:
    return " › ".join(GROUP_LEVELS[level] for level in levels) or "Без группировки"


def mode_from_choices(choices: list[str]) -> str:
    """Levels picked in the combos (empty strings = «—») to a mode string; a repeated level counts once."""
    levels: list[str] = []
    for choice in choices:
        if choice and choice in GROUP_LEVELS and choice not in levels:
            levels.append(choice)
    return "+".join(levels) if levels else "none"


class GroupLevelsDialog(MessageBoxBase):
    def __init__(self, current_mode: str, parent=None):
        super().__init__(parent)
        self.viewLayout.addWidget(SubtitleLabel("Свой порядок группировки", self))
        hint = CaptionLabel(
            "Выберите, какими папками разбить список и в каком порядке: например, «Страна › Сервер › Протокол». "
            "Внутри последней папки лежат ключи.",
            self,
        )
        hint.setWordWrap(True)
        self.viewLayout.addWidget(hint)
        holder = QWidget(self)
        rows = QVBoxLayout(holder)
        rows.setContentsMargins(0, 0, 0, 0)
        self._combos: list[ComboBox] = []
        current = list(group_levels(current_mode))
        for position in range(MAX_GROUP_LEVELS):
            rows.addWidget(BodyLabel(f"Уровень {position + 1}", self))
            combo = ComboBox(self)
            combo.addItem(_NONE, userData="")
            for level, title in GROUP_LEVELS.items():
                combo.addItem(title, userData=level)
            wanted = current[position] if position < len(current) else ""
            for index in range(combo.count()):
                if combo.itemData(index) == wanted:
                    combo.setCurrentIndex(index)
            rows.addWidget(combo)
            self._combos.append(combo)
        self.viewLayout.addWidget(holder)
        self.yesButton.setText("Применить")
        self.cancelButton.setText("Отмена")
        self.widget.setMinimumWidth(420)

    def mode(self) -> str:
        return mode_from_choices([str(combo.currentData() or "") for combo in self._combos])
