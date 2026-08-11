"""Bulk server editing as an in-page breadcrumb sub-page (was BulkEditDialog)."""

from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QFormLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CardWidget,
    CaptionLabel,
    EditableComboBox,
    FluentIcon as FIF,
    LineEdit,
    PrimaryPushButton,
    PushButton,
)

from .detail_page import DetailPage


class BulkEditPage(DetailPage):
    """Apply a group move and tag add/remove to a selection of servers."""

    apply_requested = pyqtSignal(object, dict)  # set[str] node_ids, operations

    def __init__(self, parent: QWidget | None = None):
        super().__init__(
            "Серверы",
            "Массовое редактирование",
            parent,
            root_key="nodes",
            page_key="bulk-edit",
        )
        self._node_ids: set[str] = set()

        self.cancel_btn = PushButton("Отмена", self)
        self.cancel_btn.clicked.connect(self.request_back)
        self.add_header_action(self.cancel_btn)
        self.apply_btn = PrimaryPushButton(FIF.ACCEPT, "Применить", self)
        self.apply_btn.clicked.connect(self._emit_apply)
        self.add_header_action(self.apply_btn)

        card = CardWidget(self.body)
        form = QFormLayout(card)
        form.setContentsMargins(20, 18, 20, 18)
        form.setSpacing(10)

        self.count_label = BodyLabel("", card)
        form.addRow(BodyLabel("Выбрано", card), self.count_label)

        self.group_combo = EditableComboBox(card)
        form.addRow(BodyLabel("Переместить в группу", card), self.group_combo)

        self.add_tags_edit = LineEdit(card)
        self.add_tags_edit.setPlaceholderText("тег1, тег2")
        form.addRow(BodyLabel("Добавить теги", card), self.add_tags_edit)

        self.remove_tags_edit = LineEdit(card)
        self.remove_tags_edit.setPlaceholderText("тег1, тег2")
        form.addRow(BodyLabel("Удалить теги", card), self.remove_tags_edit)

        form.addRow("", CaptionLabel("Пустое поле — операция пропускается", card))

        self.content_layout.addWidget(card)
        self.content_layout.addStretch(1)

    # ── Public API ──

    def set_targets(self, node_ids: set[str], existing_groups: list[str]) -> None:
        self._node_ids = set(node_ids)
        self.count_label.setText(f"{len(self._node_ids)} серверов")

        self.group_combo.clear()
        for group in existing_groups:
            self.group_combo.addItem(group)
        self.group_combo.setText("")
        self.add_tags_edit.clear()
        self.remove_tags_edit.clear()

    def get_operations(self) -> dict:
        return {
            "group": self.group_combo.text().strip(),
            "add_tags": _split_tags(self.add_tags_edit.text()),
            "remove_tags": _split_tags(self.remove_tags_edit.text()),
        }

    def is_dirty(self) -> bool:
        operations = self.get_operations()
        return bool(operations["group"] or operations["add_tags"] or operations["remove_tags"])

    # ── Internals ──

    def _emit_apply(self) -> None:
        if not self._node_ids:
            return
        self.apply_requested.emit(set(self._node_ids), self.get_operations())


def _split_tags(raw: str) -> list[str]:
    value = raw.strip()
    return [tag.strip() for tag in value.split(",") if tag.strip()] if value else []
