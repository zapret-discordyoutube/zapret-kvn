"""Ordered lists of native objects and nested sub-page navigation."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Callable

from PyQt6.QtCore import QPoint, Qt, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QStackedWidget, QVBoxLayout, QWidget
from qfluentwidgets import (
    Action,
    BodyLabel,
    CaptionLabel,
    CardWidget,
    FluentIcon as FIF,
    RoundMenu,
    StrongBodyLabel,
    TransparentPushButton,
    TransparentToolButton,
)

from ..detail_page import DetailPage
from ..qt_lifecycle import dispose_later


def popup_menu(anchor: QWidget, entries: list[tuple[str, Callable[[], None], str]]) -> None:
    """Show a menu under ``anchor``; entries are ``(text, callback, submenu)``.

    Built on click and owned by the window, like the other context menus of
    the app: a ``RoundMenu`` must never be destroyed together with a form that
    is being rebuilt. After closing it is disposed with cyclic GC paused.
    """

    owner = anchor.window()
    menu = RoundMenu(parent=owner)
    submenus: dict[str, RoundMenu] = {}
    for text, callback, submenu in entries:
        target = menu
        if submenu:
            target = submenus.get(submenu)
            if target is None:
                target = RoundMenu(submenu, menu)
                submenus[submenu] = target
        action = Action(text, menu)
        action.triggered.connect(lambda _checked=False, cb=callback: cb())
        target.addAction(action)
    for submenu in submenus.values():
        menu.addMenu(submenu)
    menu.closedSignal.connect(lambda: dispose_later(menu))
    menu.exec(anchor.mapToGlobal(QPoint(0, anchor.height())))


def menu_button(text: str, parent: QWidget, entries: Callable[[], list[tuple[str, Callable[[], None], str]]]) -> TransparentPushButton:
    button = TransparentPushButton(FIF.ADD, text, parent)
    button.clicked.connect(lambda: popup_menu(button, entries()))
    return button


@dataclass(frozen=True)
class RowInfo:
    title: str
    subtitle: str = ""
    note: str = ""
    removable: bool = True


@dataclass(frozen=True)
class AddOption:
    label: str
    factory: Callable[[], dict]
    submenu: str = ""


class _Row(CardWidget):
    """One list row; updated in place so reordering creates no widgets."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.index = 0
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 8, 8, 8)
        layout.setSpacing(10)
        self.number = CaptionLabel("", self)
        self.number.setFixedWidth(22)
        layout.addWidget(self.number)
        column = QVBoxLayout()
        column.setSpacing(2)
        self.title = BodyLabel("", self)
        self.title.setWordWrap(True)
        column.addWidget(self.title)
        self.subtitle = CaptionLabel("", self)
        self.subtitle.setWordWrap(True)
        column.addWidget(self.subtitle)
        self.note = CaptionLabel("", self)
        self.note.setWordWrap(True)
        column.addWidget(self.note)
        layout.addLayout(column, 1)
        self.up = TransparentToolButton(FIF.UP, self)
        self.up.setToolTip("Выше")
        self.down = TransparentToolButton(FIF.DOWN, self)
        self.down.setToolTip("Ниже")
        self.copy = TransparentToolButton(FIF.COPY, self)
        self.copy.setToolTip("Дублировать")
        self.remove = TransparentToolButton(FIF.DELETE, self)
        self.remove.setToolTip("Удалить")
        for button in (self.up, self.down, self.copy, self.remove):
            layout.addWidget(button, 0, Qt.AlignmentFlag.AlignVCenter)

    def show_info(self, index: int, info: RowInfo, count: int) -> None:
        self.index = index
        self.number.setText(str(index + 1))
        self.title.setText(info.title)
        for label, text in ((self.subtitle, info.subtitle), (self.note, info.note)):
            label.setText(text)
            label.setVisible(bool(text))
        self.up.setEnabled(index > 0)
        self.down.setEnabled(index < count - 1)
        self.remove.setEnabled(info.removable)


class ObjectList(QWidget):
    """Editable ordered list of dicts that lives inside the native document."""

    changed = pyqtSignal()
    open_requested = pyqtSignal(int)

    def __init__(
        self,
        items: Callable[[], list],
        ensure_items: Callable[[], list],
        describe: Callable[[dict, int], RowInfo],
        add_options: list[AddOption],
        parent: QWidget | None = None,
        *,
        add_text: str = "Добавить",
        empty_text: str = "Пока пусто.",
        can_remove: Callable[[dict], str] | None = None,
    ):
        super().__init__(parent)
        self._items = items
        self._ensure_items = ensure_items
        self._describe = describe
        self._can_remove = can_remove
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(6)
        self._rows_host = QWidget(self)
        self._rows = QVBoxLayout(self._rows_host)
        self._rows.setContentsMargins(0, 0, 0, 0)
        self._rows.setSpacing(6)
        self._layout.addWidget(self._rows_host)
        self._row_widgets: list[_Row] = []
        self._empty = CaptionLabel(empty_text, self)
        self._layout.addWidget(self._empty)
        self.add_button = self._make_add_button(add_text, add_options)
        self._layout.addWidget(self.add_button, 0, Qt.AlignmentFlag.AlignLeft)
        self.refresh()

    def _make_add_button(self, text: str, options: list[AddOption]) -> QWidget:
        self.options = list(options)
        if len(options) == 1:
            button = TransparentPushButton(FIF.ADD, text, self)
            button.clicked.connect(lambda: self._add(options[0]))
            return button
        return menu_button(
            text,
            self,
            lambda: [(option.label, lambda item=option: self._add(item), option.submenu) for option in options],
        )

    def refresh(self) -> None:
        items = self._items()
        while len(self._row_widgets) > len(items):
            row = self._row_widgets.pop()
            self._rows.removeWidget(row)
            dispose_later(row)
        while len(self._row_widgets) < len(items):
            row = _Row(self._rows_host)
            row.clicked.connect(lambda r=row: self.open_requested.emit(r.index))
            row.up.clicked.connect(lambda _c=False, r=row: self._move(r.index, -1))
            row.down.clicked.connect(lambda _c=False, r=row: self._move(r.index, 1))
            row.copy.clicked.connect(lambda _c=False, r=row: self._duplicate(r.index))
            row.remove.clicked.connect(lambda _c=False, r=row: self._remove(r.index))
            self._rows.addWidget(row)
            self._row_widgets.append(row)
        for index, (row, item) in enumerate(zip(self._row_widgets, items)):
            row.show_info(index, self._describe(item if isinstance(item, dict) else {}, index), len(items))
        self._empty.setVisible(not items)

    def _add(self, option: AddOption) -> None:
        items = self._ensure_items()
        items.append(option.factory())
        self.refresh()
        self.changed.emit()
        self.open_requested.emit(len(items) - 1)

    def _move(self, index: int, delta: int) -> None:
        items = self._items()
        target = index + delta
        if not 0 <= target < len(items):
            return
        items[index], items[target] = items[target], items[index]
        self.refresh()
        self.changed.emit()

    def _duplicate(self, index: int) -> None:
        items = self._items()
        copy = json.loads(json.dumps(items[index]))
        if isinstance(copy, dict) and isinstance(copy.get("tag"), str):
            copy["tag"] = _unique_tag(copy["tag"], items)
        items.insert(index + 1, copy)
        self.refresh()
        self.changed.emit()

    def _remove(self, index: int) -> None:
        items = self._items()
        if self._can_remove is not None:
            problem = self._can_remove(items[index])
            if problem:
                from qfluentwidgets import MessageBox

                box = MessageBox("Удалить?", problem, self.window())
                box.yesButton.setText("Удалить")
                box.cancelButton.setText("Отмена")
                if not box.exec():
                    return
        del items[index]
        self.refresh()
        self.changed.emit()


def _unique_tag(tag: str, items: list) -> str:
    existing = {item.get("tag") for item in items if isinstance(item, dict)}
    index = 2
    while f"{tag}-{index}" in existing:
        index += 1
    return f"{tag}-{index}"


def unique_tag(base: str, items: list) -> str:
    existing = {item.get("tag") for item in items if isinstance(item, dict)}
    if base not in existing:
        return base
    return _unique_tag(base, items)


class NavStack(QStackedWidget):
    """Root view plus a stack of :class:`DetailPage` sub-pages."""

    popped = pyqtSignal()

    def __init__(self, root: QWidget, parent: QWidget | None = None):
        super().__init__(parent)
        self.root = root
        self.addWidget(root)
        self._pages: list[DetailPage] = []

    def push(self, page: DetailPage) -> None:
        page.back_requested.connect(self.pop)
        self._pages.append(page)
        self.addWidget(page)
        self.setCurrentWidget(page)

    def pop(self) -> None:
        if not self._pages:
            return
        page = self._pages.pop()
        self.setCurrentWidget(self._pages[-1] if self._pages else self.root)
        self.removeWidget(page)
        dispose_later(page)
        self.popped.emit()

    def pop_all(self) -> None:
        while self._pages:
            self.pop()

    @property
    def depth(self) -> int:
        return len(self._pages)


def section_header(title: str, hint: str, parent: QWidget) -> QWidget:
    host = QWidget(parent)
    layout = QVBoxLayout(host)
    layout.setContentsMargins(0, 6, 0, 0)
    layout.setSpacing(2)
    layout.addWidget(StrongBodyLabel(title, host))
    if hint:
        label = CaptionLabel(hint, host)
        label.setWordWrap(True)
        layout.addWidget(label)
    return host
