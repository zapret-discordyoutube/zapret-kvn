from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    CardWidget,
    FluentIcon as FIF,
    LineEdit,
    PlainTextEdit,
    PrimaryPushButton,
)

from .detail_page import DetailPage


class PresetEditWidget(DetailPage):
    #: original name ("" for a new preset), name, description, content
    save_requested = pyqtSignal(str, str, str, str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(
            "Zapret",
            "Редактирование пресета",
            parent,
            root_key="zapret",
            page_key="preset-edit",
        )
        self._original_content = ""
        self._original_name = ""
        self._original_description = ""

        root = self.content_layout

        self.error_label = CaptionLabel("", self)
        self.add_header_action(self.error_label)
        self.save_btn = PrimaryPushButton(FIF.SAVE, "Сохранить", self)
        self.save_btn.clicked.connect(self._on_save)
        self.add_header_action(self.save_btn)

        # Metadata card
        meta_card = CardWidget(self)
        meta_layout = QVBoxLayout(meta_card)
        meta_layout.setContentsMargins(16, 12, 16, 12)
        meta_layout.setSpacing(8)

        name_row = QHBoxLayout()
        name_row.addWidget(BodyLabel("Название:", meta_card))
        self.name_edit = LineEdit(meta_card)
        self.name_edit.setPlaceholderText("Имя пресета")
        name_row.addWidget(self.name_edit, 1)
        meta_layout.addLayout(name_row)

        desc_row = QHBoxLayout()
        desc_row.addWidget(BodyLabel("Описание:", meta_card))
        self.desc_edit = LineEdit(meta_card)
        self.desc_edit.setPlaceholderText("Краткое описание (необязательно)")
        desc_row.addWidget(self.desc_edit, 1)
        meta_layout.addLayout(desc_row)

        self.meta_label = CaptionLabel("", meta_card)
        meta_layout.addWidget(self.meta_label)
        root.addWidget(meta_card)

        # Content editor
        self.editor = PlainTextEdit(self)
        self.editor.setPlaceholderText("Аргументы winws2, по одному на строку.\nСтроки с # — комментарии.")
        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.editor.setFont(font)
        root.addWidget(self.editor, 1)

    def set_preset(self, name: str, description: str, content: str,
                   created: str = "", modified: str = "") -> None:
        """Load a preset into the editor."""
        self._original_name = name
        self._original_description = description
        self._original_content = content

        self.error_label.setText("")
        self.name_edit.setText(name)
        self.desc_edit.setText(description)
        self.editor.setPlainText(content)
        self.set_page_label(name or "Новый пресет")

        # Meta info
        parts = []
        if created:
            parts.append(f"Создан: {created}")
        if modified:
            parts.append(f"Изменён: {modified}")
        self.meta_label.setText("  |  ".join(parts) if parts else "")

    def is_dirty(self) -> bool:
        """Check if content was modified."""
        return (self.editor.toPlainText() != self._original_content
                or self.name_edit.text() != self._original_name
                or self.desc_edit.text() != self._original_description)

    def _on_save(self) -> None:
        name = self.name_edit.text().strip()
        if not name:
            self.error_label.setText("Введите название")
            return
        if any(char in '\\/:*?"<>|' for char in name) or name.startswith("_"):
            self.error_label.setText("Название не может содержать \\ / : * ? \" < > | и начинаться с _")
            return
        self.error_label.setText("")
        desc = self.desc_edit.text().strip()
        content = self.editor.toPlainText()
        self.save_requested.emit(self._original_name, name, desc, content)

    def mark_saved(self, name: str, description: str, content: str) -> None:
        """The file is written: this is the new clean state."""
        self._original_name = name
        self._original_description = description
        self._original_content = content

    def show_error(self, message: str) -> None:
        self.error_label.setText(message)
