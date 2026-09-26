"""Schema-driven form for one native sing-box object.

The form shows the object's discriminators (``type`` / ``action``) as choices,
then only the fields that matter right now: fields already set in the JSON,
fields the core requires and a few pinned by the catalog. Every other field
the core accepts is one click away in «Добавить». The result: a short form for
the common case and the complete option set of the core when needed.
"""

from __future__ import annotations

from dataclasses import replace

from PyQt6.QtCore import QTimer, Qt, pyqtSignal
from PyQt6.QtWidgets import QFormLayout, QHBoxLayout, QVBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    ComboBox,
    FluentIcon as FIF,
    IconWidget,
    StrongBodyLabel,
    TransparentToolButton,
)

from ...singbox_config import catalog
from ...singbox_config.schema import Field, FieldGroup
from .fields import FieldEditor, FormContext, JsonEditor, create_editor
from ..qt_lifecycle import dispose_later
from .lists import menu_button
from .visuals import FIELD_ICONS, variant_icon

GROUP_TITLES = {
    ("rule", 0): "Условия",
    ("rule", 1): "Действие",
    ("dns_rule", 0): "Условия",
    ("dns_rule", 1): "Действие",
}

_EMPTY_DEFAULTS = {"bool": True}


def _default_value(item: Field):
    shape = item.shape
    if shape.kind == "bool":
        return True
    if shape.kind == "enum" and shape.enum and not shape.listable:
        return shape.enum[0]
    if shape.kind == "object" and not shape.listable:
        return {}
    if shape.kind == "array" and shape.item is not None and shape.item.kind == "object":
        return []
    return None


class SchemaForm(QWidget):
    changed = pyqtSignal()
    #: Emitted after a discriminator switch rebuilt the form.
    structure_changed = pyqtSignal()

    def __init__(
        self,
        ctx: FormContext,
        node: dict,
        value: dict,
        context: str,
        parent: QWidget | None = None,
        *,
        hidden: tuple[str, ...] = (),
        locked: bool = False,
    ):
        super().__init__(parent)
        self.ctx = ctx
        self.node = node
        self.value = value
        self.context = context
        self.hidden = set(hidden)
        self.locked = locked
        self._shown_extra: set[str] = set()
        self._outer = QVBoxLayout(self)
        self._outer.setContentsMargins(0, 0, 0, 0)
        self._body: QWidget | None = None
        self.rebuild()

    # -- building -------------------------------------------------------------

    def flush(self) -> None:
        """Commit pending input of every editor in this form (nested included)."""
        if self._body is None:
            return
        for editor in self._body.findChildren(FieldEditor):
            editor.flush()

    def rebuild(self) -> None:
        # Replace one container instead of taking layouts apart: the old
        # subtree is deleted as a whole, nothing is left half-owned.
        self.flush()
        if self._body is not None:
            self._outer.removeWidget(self._body)
            dispose_later(self._body)
        self._body = QWidget(self)
        self._root = QVBoxLayout(self._body)
        self._root.setContentsMargins(0, 0, 0, 0)
        self._root.setSpacing(10)
        self._outer.addWidget(self._body)
        groups = self.ctx.schema.groups(self.node, self.value)
        if not groups:
            self._build_unknown()
            return
        discriminators = {
            group.discriminator: str(self.value.get(group.discriminator) or group.default_variant or "")
            for group in groups
            if group.discriminator
        }
        pinned = catalog.pinned_fields(self.context, discriminators)
        known: set[str] = set()
        for index, group in enumerate(groups):
            known |= {item.name for item in group.fields}
            self._build_group(index, group, pinned, len(groups) > 1)
        unknown = [key for key in self.value if key not in known]
        if unknown:
            self._build_unknown_fields(unknown)

    def _build_group(self, index: int, group: FieldGroup, pinned: tuple[str, ...], titled: bool) -> None:
        title = GROUP_TITLES.get((self.context, index))
        if titled and title:
            self._root.addWidget(StrongBodyLabel(title, self._body))
        form = QFormLayout()
        form.setContentsMargins(0, 0, 0, 0)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self._root.addLayout(form)

        if group.discriminator and group.discriminator not in self.hidden:
            form.addRow(self._label(group.discriminator), self._variant_combo(group))

        order = {name: position for position, name in enumerate(pinned)}
        visible: list[Field] = []
        hidden: list[Field] = []
        for item in group.fields:
            if item.name == group.discriminator or item.name in self.hidden or item.shape.kind == "const":
                continue
            if (
                item.name in self.value
                or item.required
                or item.name in order
                or item.name in self._shown_extra
            ):
                visible.append(item)
            else:
                hidden.append(item)
        visible.sort(key=lambda item: (order.get(item.name, len(order)), 0))
        for item in visible:
            self._add_row(form, item)
        if hidden and not self.locked:
            holder = QWidget(self._body)
            line = QHBoxLayout(holder)
            line.setContentsMargins(0, 0, 0, 0)
            line.addWidget(self._add_button(index, hidden))
            line.addStretch(1)
            form.addRow("", holder)

    def _label(self, name: str) -> QWidget:
        host = QWidget(self._body)
        row = QHBoxLayout(host)
        row.setContentsMargins(0, 2, 0, 0)
        row.setSpacing(8)
        icon = FIELD_ICONS.get(name)
        glyph = IconWidget(icon if icon is not None else FIF.TAG, host)
        glyph.setFixedSize(14, 14)
        glyph.setVisible(icon is not None)
        row.addWidget(glyph, 0, Qt.AlignmentFlag.AlignTop)
        text = BodyLabel(catalog.field_label(name), host)
        text.setToolTip(name)
        row.addWidget(text)
        row.addStretch(1)
        # One label column width for every group of the form.
        host.setMinimumWidth(190)
        host.text = text
        host.setToolTip(name)
        return host

    def _variant_combo(self, group: FieldGroup) -> QWidget:
        key = group.discriminator or ""
        combo = ComboBox(self._body)
        values = list(group.variants)
        current = self.value.get(key) or group.default_variant
        if current is not None and current not in values:
            values.append(current)
        for value in values:
            combo.addItem(catalog.enum_label(key, value), icon=variant_icon(self.context, key, value), userData=value)
        if current in values:
            combo.setCurrentIndex(values.index(current))
        combo.setMinimumWidth(240)
        combo.setEnabled(not self.locked)
        combo.currentIndexChanged.connect(lambda _index: self._switch_variant(key, combo.currentData()))
        return combo

    def _switch_variant(self, key: str, value) -> None:
        if value is None or self.value.get(key) == value:
            return
        self.value[key] = value
        accepted = set(self.ctx.schema.fields(self.node, self.value))
        for name in list(self.value):
            if name not in accepted:
                self.value.pop(name, None)
        self._shown_extra.clear()
        self.changed.emit()
        # The choice comes from the combo's own popup: rebuilding (and so
        # deleting that combo) must wait until its signal has returned.
        QTimer.singleShot(0, self._rebuild_after_switch)

    def _rebuild_after_switch(self) -> None:
        self.rebuild()
        self.structure_changed.emit()

    def _add_row(self, form: QFormLayout, item: Field) -> None:
        ctx = self.ctx
        if item.name == "rules":
            rules_context = "headless" if self.context.startswith("rule_set") else self.context
            ctx = replace(ctx, extra={**ctx.extra, "rules_context": rules_context})
        editor = create_editor(ctx, self.value, item.name, item.shape, self._body)
        editor.setEnabled(not self.locked)
        editor.changed.connect(self.changed)
        label = self._label(item.name)
        if item.shape.deprecated:
            label.text.setText(label.text.text() + " (устарело)")
        if item.required or self.locked:
            form.addRow(label, editor)
            return
        row = QWidget(self._body)
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        layout.addWidget(editor, 1)
        remove = TransparentToolButton(FIF.CLOSE, row)
        remove.setToolTip("Убрать параметр")
        remove.clicked.connect(lambda _checked=False, name=item.name: self._remove(name))
        layout.addWidget(remove, 0, Qt.AlignmentFlag.AlignTop)
        form.addRow(label, row)

    def _remove(self, name: str) -> None:
        self._shown_extra.discard(name)
        existed = name in self.value
        self.value.pop(name, None)
        self.rebuild()
        if existed:
            self.changed.emit()

    def _add_button(self, index: int, fields: list[Field]) -> QWidget:
        text = "Добавить условие" if (self.context in ("rule", "dns_rule", "headless") and index == 0) else "Добавить параметр"
        return menu_button(text, self._body, lambda: self._add_entries(fields))

    def _add_entries(self, fields: list[Field]) -> list:
        by_name = {item.name: item for item in fields}
        common = [name for name in catalog.COMMON_MATCH_FIELDS if name in by_name]
        rest = sorted(
            (name for name in by_name if name not in common and name not in catalog.FOREIGN_PLATFORM_FIELDS),
            key=lambda name: catalog.field_label(name).lower(),
        )
        foreign = sorted(name for name in by_name if name in catalog.FOREIGN_PLATFORM_FIELDS)
        entries = []
        for name in common + rest + foreign:
            item = by_name[name]
            if item.shape.deprecated and name not in foreign:
                continue
            label = catalog.field_label(name)
            text = label if label == name else f"{label}  ·  {name}"
            submenu = "Другие платформы" if name in foreign else ""
            entries.append((text, lambda field=item: self._add_field(field), submenu))
        return entries

    def _add_field(self, item: Field) -> None:
        default = _default_value(item)
        if default is not None:
            self.value[item.name] = default
        self._shown_extra.add(item.name)
        self.rebuild()
        if default is not None:
            self.changed.emit()

    def _build_unknown(self) -> None:
        self._root.addWidget(
            CaptionLabel(
                "Этот тип ядро не знает — объект показан как JSON. "
                "Проверьте тип или исправьте его в JSON.",
                self._body,
            )
        )
        self._build_unknown_fields(list(self.value))

    def _build_unknown_fields(self, names: list[str]) -> None:
        form = QFormLayout()
        form.setContentsMargins(0, 0, 0, 0)
        self._root.addLayout(form)
        from ...singbox_config.schema import Shape

        for name in names:
            editor = JsonEditor(self.ctx, self.value, name, Shape("any"), self._body)
            editor.changed.connect(self.changed)
            label = BodyLabel(f"{name} — неизвестное поле", self._body)
            label.setToolTip("Ядро sing-box не знает это поле и не запустит такой конфиг.")
            row = QWidget(self._body)
            layout = QHBoxLayout(row)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(editor, 1)
            remove = TransparentToolButton(FIF.DELETE, row)
            remove.setToolTip("Удалить поле")
            remove.clicked.connect(lambda _checked=False, key=name: self._remove(key))
            layout.addWidget(remove, 0, Qt.AlignmentFlag.AlignTop)
            form.addRow(label, row)

