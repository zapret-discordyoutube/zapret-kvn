"""Value editors for one native sing-box field.

Every editor reads ``owner[name]`` and writes the edited value back into the
same dict, then emits ``changed``. The editor kind is chosen from the core
schema :class:`~xray_fluent.singbox_config.schema.Shape`, never from a list
of known option names.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any, Callable

from PyQt6.QtCore import QEvent, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QHBoxLayout, QSizePolicy, QVBoxLayout, QWidget
from qfluentwidgets import (
    CaptionLabel,
    CheckBox,
    ComboBox,
    FlowLayout,
    FluentIcon as FIF,
    LineEdit,
    PlainTextEdit,
    PushButton,
    SwitchButton,
    TransparentToolButton,
)

from ...singbox_config import catalog
from ..qt_lifecycle import dispose_later
from .visuals import enum_icon, tag_icon
from ...singbox_config.document import as_list, store_list, tags
from ...singbox_config.schema import Shape, SingboxSchema

_DURATION = re.compile(r"^[-+]?(((\d+(\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h|d))+|0)$")
_MONO = QFont("Consolas", 10)
_MONO.setStyleHint(QFont.StyleHint.Monospace)


@dataclass
class FormContext:
    """What editors need beyond their own field."""

    schema: SingboxSchema
    document: dict
    #: Open a nested list of rule objects as a sub-page:
    #: ``open_list(title, items, item_node, context)``.
    open_list: Callable[[str, list, dict, str], None] | None = None
    extra: dict = field(default_factory=dict)


class FieldEditor(QWidget):
    changed = pyqtSignal()

    def __init__(self, ctx: FormContext, owner: dict, name: str, shape: Shape, parent: QWidget | None = None):
        super().__init__(parent)
        self.ctx = ctx
        self.owner = owner
        self.name = name
        self.shape = shape
        self.layout_ = QHBoxLayout(self)
        self.layout_.setContentsMargins(0, 0, 0, 0)
        self.layout_.setSpacing(8)

    @property
    def value(self) -> Any:
        return self.owner.get(self.name)

    def flush(self) -> None:
        """Commit input that is still waiting for a debounce or focus-out."""

    def write(self, value: Any) -> None:
        if value is None:
            if self.name not in self.owner:
                return
            self.owner.pop(self.name, None)
        else:
            if self.owner.get(self.name, _SENTINEL) == value:
                return
            self.owner[self.name] = value
        self.changed.emit()


_SENTINEL = object()


def _stretch(widget: QWidget) -> None:
    policy = widget.sizePolicy()
    policy.setHorizontalPolicy(QSizePolicy.Policy.Expanding)
    widget.setSizePolicy(policy)


def _convert_scalar(text: str, shape: Shape) -> Any:
    """Parse editor text into the JSON value the shape expects."""

    text = text.strip()
    if shape.kind == "int":
        return int(text)
    if shape.kind == "union":
        kinds = {alt.kind for alt in shape.alternatives}
        if "int" in kinds and re.fullmatch(r"-?\d+", text):
            return int(text)
        if "bool" in kinds and text in ("true", "false"):
            return text == "true"
        return text
    if shape.kind == "enum" and shape.enum and all(isinstance(item, int) for item in shape.enum):
        return int(text)
    if shape.kind == "duration" and not _DURATION.fullmatch(text):
        raise ValueError("длительность вида 300ms, 5s, 1m, 1h, 1d")
    return text


class _Debounced:
    """Commit a text editor after a pause, on focus-out and on :meth:`flush`."""

    def _init_debounce(self, edit: QWidget, interval: int) -> None:
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(interval)
        self._timer.timeout.connect(self._commit)
        edit.installEventFilter(self)

    def eventFilter(self, obj, event) -> bool:  # noqa: N802 - Qt API
        if event.type() == QEvent.Type.FocusOut:
            self.flush()
        return False

    def flush(self) -> None:
        if self._timer.isActive():
            self._timer.stop()
            self._commit()


class BoolEditor(FieldEditor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.switch = SwitchButton(self)
        self.switch.setChecked(bool(self.value))
        self.switch.checkedChanged.connect(lambda checked: self.write(bool(checked)))
        self.layout_.addWidget(self.switch)
        self.layout_.addStretch(1)


class EnumEditor(FieldEditor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.combo = ComboBox(self)
        values = list(self.shape.enum)
        current = self.value
        if current is not None and current not in values:
            values.append(current)
        for item in values:
            self.combo.addItem(catalog.enum_label(self.name, item), icon=enum_icon(self.name, item), userData=item)
        if current in values:
            self.combo.setCurrentIndex(values.index(current))
        else:
            self.combo.setCurrentIndex(-1)
            self.combo.setPlaceholderText("по умолчанию")
        self.combo.currentIndexChanged.connect(lambda _index: self.write(self.combo.currentData()))
        self.combo.setMinimumWidth(200)
        self.layout_.addWidget(self.combo)
        self.layout_.addStretch(1)


class TagEditor(FieldEditor):
    """One tag of an existing outbound / DNS server / rule-set."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.combo = ComboBox(self)
        choices = tags(self.ctx.document, self.shape.tag_ref or "")
        current = self.value
        if isinstance(current, str) and current and current not in choices:
            choices.append(current)
        for tag in choices:
            label = catalog.outbound_label(tag) if self.shape.tag_ref == "outbound" else tag
            if tag == current and tag not in tags(self.ctx.document, self.shape.tag_ref or ""):
                label = f"{tag} — нет такого тега"
            self.combo.addItem(label, icon=tag_icon(self.shape.tag_ref, tag), userData=tag)
        if current in choices:
            self.combo.setCurrentIndex(choices.index(current))
        else:
            self.combo.setCurrentIndex(-1)
            self.combo.setPlaceholderText("не выбрано")
        self.combo.currentIndexChanged.connect(lambda _index: self.write(self.combo.currentData()))
        self.combo.setMinimumWidth(240)
        self.layout_.addWidget(self.combo)
        self.layout_.addStretch(1)


class TextEditor(FieldEditor):
    """Single string / number / duration."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.edit = LineEdit(self)
        current = self.value
        if current is not None:
            self.edit.setText(current if isinstance(current, str) else json.dumps(current))
        placeholder = {
            "duration": "например 300ms, 5s, 1m",
            "int": "число",
        }.get(self.shape.kind, "")
        self.edit.setPlaceholderText(placeholder)
        self.edit.setClearButtonEnabled(True)
        _stretch(self.edit)
        self.error = CaptionLabel("", self)
        self.error.setVisible(False)
        column = QVBoxLayout()
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(2)
        column.addWidget(self.edit)
        column.addWidget(self.error)
        self.layout_.addLayout(column, 1)
        self.edit.editingFinished.connect(self._commit)

    def flush(self) -> None:
        if self.edit.isModified():
            self._commit()

    def _commit(self) -> None:
        self.edit.setModified(False)
        text = self.edit.text()
        if not text.strip():
            self.error.setVisible(False)
            self.write(None)
            return
        try:
            value = _convert_scalar(text, self.shape)
        except ValueError as exc:
            self.error.setText(f"Нужно: {exc}" if "длительность" in str(exc) else "Нужно целое число")
            self.error.setVisible(True)
            return
        self.error.setVisible(False)
        self.write(value)


class ListEditor(_Debounced, FieldEditor):
    """Values of a listable field, one per line."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.edit = PlainTextEdit(self)
        self.edit.setFont(_MONO)
        values = as_list(self.value)
        self.edit.setPlainText("\n".join(v if isinstance(v, str) else json.dumps(v) for v in values))
        self.edit.setPlaceholderText("по одному значению на строку")
        _stretch(self.edit)
        self._fit_height()
        self.error = CaptionLabel("", self)
        self.error.setVisible(False)
        column = QVBoxLayout()
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(2)
        column.addWidget(self.edit)
        column.addWidget(self.error)
        self.layout_.addLayout(column, 1)
        self._init_debounce(self.edit, 500)
        self.edit.textChanged.connect(self._timer.start)
        self.edit.textChanged.connect(self._fit_height)

    def _fit_height(self) -> None:
        lines = max(2, min(10, self.edit.toPlainText().count("\n") + 1))
        self.edit.setFixedHeight(18 * lines + 18)

    def _commit(self) -> None:
        item_shape = self.shape.item or self.shape
        items: list = []
        for line in self.edit.toPlainText().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(_convert_scalar(line, item_shape))
            except ValueError:
                self.error.setText(f"Не подходит значение: {line}")
                self.error.setVisible(True)
                return
        self.error.setVisible(False)
        before = json.dumps(self.owner.get(self.name), ensure_ascii=False)
        store_list(self.owner, self.name, items, self.shape)
        if json.dumps(self.owner.get(self.name), ensure_ascii=False) != before:
            self.changed.emit()


class ChoiceListEditor(FieldEditor):
    """Listable enum or list of tags: a flow of check boxes."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        item = self.shape.item or self.shape
        if item.tag_ref:
            choices = list(tags(self.ctx.document, item.tag_ref))
        else:
            choices = list(item.enum)
        current = as_list(self.value)
        for value in current:
            if value not in choices:
                choices.append(value)
        host = QWidget(self)
        flow = FlowLayout(host, needAni=False)
        flow.setContentsMargins(0, 0, 0, 0)
        flow.setHorizontalSpacing(14)
        flow.setVerticalSpacing(6)
        self._boxes: list[tuple[CheckBox, Any]] = []
        for value in choices:
            label = (
                catalog.outbound_label(value)
                if item.tag_ref == "outbound"
                else catalog.enum_label(self.name, value)
            )
            box = CheckBox(label, host)
            box.setChecked(value in current)
            box.stateChanged.connect(lambda _state: self._commit())
            flow.addWidget(box)
            self._boxes.append((box, value))
        if not choices:
            flow.addWidget(CaptionLabel("Нет доступных значений", host))
        _stretch(host)
        self.layout_.addWidget(host, 1)

    def _commit(self) -> None:
        items = [value for box, value in self._boxes if box.isChecked()]
        store_list(self.owner, self.name, items, self.shape)
        self.changed.emit()


class JsonEditor(_Debounced, FieldEditor):
    """Raw native JSON for maps, arrays of objects and untyped fields."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.edit = PlainTextEdit(self)
        self.edit.setFont(_MONO)
        current = self.value
        if current is not None:
            self.edit.setPlainText(json.dumps(current, ensure_ascii=False, indent=2))
        self.edit.setPlaceholderText("значение в формате JSON")
        lines = max(2, min(12, self.edit.toPlainText().count("\n") + 1))
        self.edit.setFixedHeight(18 * lines + 18)
        _stretch(self.edit)
        self.error = CaptionLabel("", self)
        self.error.setVisible(False)
        column = QVBoxLayout()
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(2)
        column.addWidget(self.edit)
        column.addWidget(self.error)
        self.layout_.addLayout(column, 1)
        self._init_debounce(self.edit, 600)
        self.edit.textChanged.connect(self._timer.start)

    def _commit(self) -> None:
        text = self.edit.toPlainText().strip()
        if not text:
            self.error.setVisible(False)
            self.write(None)
            return
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            self.error.setText(f"JSON: {exc.msg} (строка {exc.lineno})")
            self.error.setVisible(True)
            return
        self.error.setVisible(False)
        self.write(value)


class NestedListEditor(FieldEditor):
    """Array of rule objects (logical rule, inline rule-set) edited on a sub-page."""

    def __init__(self, *args, item_context: str = "rule", **kwargs):
        super().__init__(*args, **kwargs)
        self._item_context = item_context
        self.caption = CaptionLabel("", self)
        self.open_btn = PushButton(FIF.EDIT, "Изменить", self)
        self.open_btn.clicked.connect(self._open)
        self.layout_.addWidget(self.caption, 1)
        self.layout_.addWidget(self.open_btn)
        self._refresh()

    def _refresh(self) -> None:
        count = len(self.owner.get(self.name) or [])
        self.caption.setText(f"Вложенных правил: {count}")

    def _open(self) -> None:
        if self.ctx.open_list is None:
            return
        items = self.owner.get(self.name)
        if not isinstance(items, list):
            items = []
            self.owner[self.name] = items
            self.changed.emit()
        item_node = (self.shape.item.node if self.shape.item is not None else None) or {}
        self.ctx.open_list(catalog.field_label(self.name), items, item_node, self._item_context)


class ObjectEditor(FieldEditor):
    """Nested object rendered as an indented sub-form."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from .form import SchemaForm  # circular: forms contain object editors

        current = self.value
        if not isinstance(current, dict):
            # Detached until the first real edit: showing an empty pinned
            # object must not add ``{}`` to the user's JSON.
            current = {}
        self._current = current
        self.form = SchemaForm(self.ctx, self.shape.node or {}, current, self.name, self)
        self.form.changed.connect(self._on_changed)
        self.layout_.addWidget(self.form, 1)

    def _on_changed(self) -> None:
        if self.owner.get(self.name) is not self._current:
            self.owner[self.name] = self._current
        self.changed.emit()


class UnionEditor(FieldEditor):
    """``string | object`` style fields such as ``domain_resolver``.

    The short form is edited by default; «Подробно» switches to the object form
    and carries the value over when the object has a single required field.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._object_alt = next((alt for alt in self.shape.alternatives if alt.kind == "object"), None)
        self._scalar_alt = next((alt for alt in self.shape.alternatives if alt.kind != "object"), None)
        self._body: QWidget | None = None
        self.toggle = TransparentToolButton(FIF.MORE, self)
        self.toggle.setToolTip("Кратко / подробно")
        self.toggle.clicked.connect(self._switch)
        self.toggle.setVisible(self._object_alt is not None and self._scalar_alt is not None)
        self._build()

    def _build(self) -> None:
        if self._body is not None:
            self.layout_.removeWidget(self._body)
            dispose_later(self._body)
        use_object = isinstance(self.value, dict) or self._scalar_alt is None
        alt = self._object_alt if use_object else self._scalar_alt
        if alt is None:
            self._body = JsonEditor(self.ctx, self.owner, self.name, self.shape, self)
        elif alt.kind == "object":
            self._body = ObjectEditor(self.ctx, self.owner, self.name, alt, self)
        else:
            merged = alt if alt.kind != "string" or alt.tag_ref else self.shape
            self._body = create_editor(self.ctx, self.owner, self.name, merged, self)
        self._body.changed.connect(self.changed)
        self.layout_.insertWidget(0, self._body, 1)
        self.layout_.addWidget(self.toggle, 0, Qt.AlignmentFlag.AlignTop)

    def _switch(self) -> None:
        current = self.value
        required = []
        if self._object_alt is not None and self._object_alt.node:
            required = list(self._object_alt.node.get("required", ()))
        if isinstance(current, dict):
            key = required[0] if len(required) == 1 else None
            self.owner[self.name] = current.get(key) if key and current.get(key) is not None else ""
            if not self.owner[self.name]:
                self.owner.pop(self.name, None)
        else:
            key = required[0] if len(required) == 1 else None
            self.owner[self.name] = {key: current} if key and current is not None else {}
        self.changed.emit()
        # Triggered by a button inside the body being replaced: defer.
        QTimer.singleShot(0, self._build)


def create_editor(ctx: FormContext, owner: dict, name: str, shape: Shape, parent: QWidget | None = None) -> FieldEditor:
    kind = shape.kind
    if shape.listable:
        if kind == "enum" or (kind == "string" and shape.tag_ref):
            return ChoiceListEditor(ctx, owner, name, shape, parent)
        if kind in ("string", "int", "duration", "union"):
            return ListEditor(ctx, owner, name, shape, parent)
        return JsonEditor(ctx, owner, name, shape, parent)
    if kind == "bool":
        return BoolEditor(ctx, owner, name, shape, parent)
    if kind == "enum":
        return EnumEditor(ctx, owner, name, shape, parent)
    if kind == "string" and shape.tag_ref:
        return TagEditor(ctx, owner, name, shape, parent)
    if kind in ("string", "int", "duration"):
        return TextEditor(ctx, owner, name, shape, parent)
    if kind == "union":
        if any(alt.kind == "object" for alt in shape.alternatives):
            return UnionEditor(ctx, owner, name, shape, parent)
        if all(alt.scalar for alt in shape.alternatives):
            return TextEditor(ctx, owner, name, shape, parent)
        return JsonEditor(ctx, owner, name, shape, parent)
    if kind == "array":
        item = shape.item
        if item is not None and item.kind == "string" and item.tag_ref:
            return ChoiceListEditor(ctx, owner, name, Shape("string", listable=True, item=item), parent)
        if item is not None and item.scalar:
            return ListEditor(ctx, owner, name, Shape(item.kind, listable=True, item=item), parent)
        if item is not None and item.kind == "object" and name == "rules" and ctx.open_list is not None:
            return NestedListEditor(ctx, owner, name, shape, parent, item_context=ctx.extra.get("rules_context", "rule"))
        return JsonEditor(ctx, owner, name, shape, parent)
    if kind == "object" and shape.node:
        return ObjectEditor(ctx, owner, name, shape, parent)
    return JsonEditor(ctx, owner, name, shape, parent)
