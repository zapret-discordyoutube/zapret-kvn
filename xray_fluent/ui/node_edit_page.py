"""Server editing as an in-page breadcrumb sub-page (was NodeEditDialog)."""

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
    StrongBodyLabel,
)

from ..models import Node
from .detail_page import DetailPage
from .privacy import masked_endpoint


class NodeEditPage(DetailPage):
    """Edit one server's name, group and tags."""

    save_requested = pyqtSignal(str, dict)  # node_id, updated fields

    def __init__(self, parent: QWidget | None = None):
        super().__init__(
            "Серверы",
            "Редактирование сервера",
            parent,
            root_key="nodes",
            page_key="node-edit",
        )
        self._node_id = ""
        self._original: dict = {}

        self.cancel_btn = PushButton("Отмена", self)
        self.cancel_btn.clicked.connect(self.request_back)
        self.add_header_action(self.cancel_btn)
        self.save_btn = PrimaryPushButton(FIF.SAVE, "Сохранить", self)
        self.save_btn.clicked.connect(self._emit_save)
        self.add_header_action(self.save_btn)

        card = CardWidget(self.body)
        form = QFormLayout(card)
        form.setContentsMargins(20, 18, 20, 18)
        form.setSpacing(10)

        self.endpoint_label = StrongBodyLabel("", card)
        form.addRow(BodyLabel("Адрес", card), self.endpoint_label)

        self.name_edit = LineEdit(card)
        self.name_edit.setPlaceholderText("Имя сервера")
        self.name_edit.returnPressed.connect(self._emit_save)
        form.addRow(BodyLabel("Название", card), self.name_edit)

        self.group_combo = EditableComboBox(card)
        form.addRow(BodyLabel("Группа", card), self.group_combo)

        self.tags_edit = LineEdit(card)
        self.tags_edit.setPlaceholderText("tag1, tag2, tag3")
        form.addRow(BodyLabel("Теги", card), self.tags_edit)
        form.addRow("", CaptionLabel("Перечислите теги через запятую", card))

        self.content_layout.addWidget(card)
        self.content_layout.addStretch(1)

    # ── Public API ──

    def set_node(self, node: Node, existing_groups: list[str]) -> None:
        self._node_id = node.id
        scheme = node.scheme.upper() if node.scheme else "?"
        self.endpoint_label.setText(f"{masked_endpoint()}  ({scheme})")

        self.group_combo.clear()
        for group in existing_groups:
            self.group_combo.addItem(group)

        self.name_edit.setText(node.name)
        self.group_combo.setText(node.group)
        self.tags_edit.setText(", ".join(node.tags))

        self.set_page_label(node.name or "Без имени")
        self._original = self.get_updated_fields()

    def get_updated_fields(self) -> dict:
        raw_tags = self.tags_edit.text().strip()
        tags = [t.strip() for t in raw_tags.split(",") if t.strip()] if raw_tags else []
        return {
            "name": self.name_edit.text().strip(),
            "group": self.group_combo.text().strip() or "Default",
            "tags": tags,
        }

    def mark_clean(self) -> None:
        self._original = self.get_updated_fields()

    def is_dirty(self) -> bool:
        return bool(self._original) and self.get_updated_fields() != self._original

    # ── Internals ──

    def _emit_save(self) -> None:
        if not self._node_id:
            return
        self.save_requested.emit(self._node_id, self.get_updated_fields())
