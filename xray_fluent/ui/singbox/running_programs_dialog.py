"""«Найти запущенные»: running programs grouped by install folder, the user ticks the games.

Owner request 2026-11-27: "WoW has a lot of processes, need to gather them all". A game is not one program, so the
list shows FOLDERS (with how many processes run from each) and one tick puts the whole folder into the rule.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QListWidget, QListWidgetItem
from qfluentwidgets import CaptionLabel, MessageBoxBase, SubtitleLabel

from ...platform.windows.running_programs import ProgramGroup


def group_caption(group: ProgramGroup) -> str:
    """One list line: ``World of Warcraft — 3 процесса``; the full folder is in the tooltip."""
    count = group.processes
    tail = 10 <= count % 100 <= 19 or count % 10 == 0 or count % 10 >= 5
    word = "процессов" if tail else ("процесс" if count % 10 == 1 else "процесса")
    return f"{group.name} — {count} {word}"


class RunningProgramsDialog(MessageBoxBase):
    def __init__(self, groups: list[ProgramGroup], parent=None):
        super().__init__(parent)
        self.viewLayout.addWidget(SubtitleLabel("Запущенные программы", self))
        hint = CaptionLabel(
            "Отмечайте папки, а не процессы: правило на папку подхватит всё, что запускается из неё, "
            "в том числе лаунчер и обновлялку. Запустите игру и нажмите «Найти запущенные» ещё раз, если её нет в списке.",
            self,
        )
        hint.setWordWrap(True)
        self.viewLayout.addWidget(hint)
        self.list = QListWidget(self)
        self.list.setMinimumHeight(280)
        for group in groups:
            item = QListWidgetItem(group_caption(group))
            item.setToolTip(group.root)
            item.setData(Qt.ItemDataRole.UserRole, group.root)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Unchecked)
            self.list.addItem(item)
        self.viewLayout.addWidget(self.list)
        self.yesButton.setText("Добавить в правило")
        self.cancelButton.setText("Отмена")
        self.widget.setMinimumWidth(460)

    def chosen_folders(self) -> list[str]:
        folders = []
        for index in range(self.list.count()):
            item = self.list.item(index)
            if item.checkState() == Qt.CheckState.Checked:
                folders.append(str(item.data(Qt.ItemDataRole.UserRole)))
        return folders
