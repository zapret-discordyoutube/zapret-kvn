"""In-page navigation scaffolding: breadcrumb sub-pages instead of modals.

Large forms used to open as modal ``FluentDialog`` windows on top of the app.
They now live *inside* their section as a sub-page reached through a
``BreadcrumbBar``, the same way the zapret preset editor and the server detail
view already worked.  Two pieces make that uniform:

``StackedSection``
    A section page (the thing registered in the ``FluentWindow`` navigation)
    that owns a ``QStackedWidget``: index 0 is the root view, every other index
    is a sub-page.

``DetailPage``
    A sub-page: breadcrumb + back button + title + header actions on top, and a
    scrollable, Mica-transparent content area below.  Subclasses fill
    ``content_layout`` and drop their primary buttons into ``add_header_action``.

Leaving a sub-page goes through :meth:`DetailPage.request_back`, which asks
:meth:`DetailPage.is_dirty` first — so unsaved edits still get a confirmation
instead of being silently dropped.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QStackedWidget, QVBoxLayout, QWidget
from qfluentwidgets import (
    BreadcrumbBar,
    FluentIcon as FIF,
    MessageBox,
    SubtitleLabel,
    TransparentToolButton,
)

from .base_page import BODY_MARGINS, PageScrollArea

_TRANSPARENT_SCROLL_QSS = "QScrollArea { background: transparent; border: none; }"
_TRANSPARENT_BODY_QSS = "QWidget { background: transparent; }"


class DetailPage(QWidget):
    """Sub-page shown inside a section instead of a modal dialog."""

    back_requested = pyqtSignal()

    def __init__(
        self,
        root_label: str,
        page_label: str,
        parent: QWidget | None = None,
        *,
        root_key: str = "root",
        page_key: str = "page",
    ):
        super().__init__(parent)
        self._root_key = root_key
        self._page_key = page_key
        self._root_label = root_label
        self._page_label = page_label

        left, top, right, bottom = BODY_MARGINS
        outer = QVBoxLayout(self)
        # The header stays pinned; the bottom padding belongs to the scrolled
        # content so it does not double up with the scrollbar.
        outer.setContentsMargins(left, top, right, 0)
        outer.setSpacing(12)

        self.breadcrumb = BreadcrumbBar(self)
        self.breadcrumb.currentItemChanged.connect(self._on_breadcrumb)
        outer.addWidget(self.breadcrumb)

        header = QHBoxLayout()
        header.setSpacing(8)
        self.back_btn = TransparentToolButton(FIF.RETURN, self)
        self.back_btn.setToolTip("Назад")
        self.back_btn.clicked.connect(self.request_back)
        header.addWidget(self.back_btn)
        self.title_label = SubtitleLabel(page_label, self)
        header.addWidget(self.title_label)
        header.addStretch(1)
        self.header_actions = QHBoxLayout()
        self.header_actions.setSpacing(8)
        header.addLayout(self.header_actions)
        outer.addLayout(header)

        self.scroll_area = PageScrollArea(self)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.scroll_area.setStyleSheet(_TRANSPARENT_SCROLL_QSS)
        outer.addWidget(self.scroll_area, 1)

        self.body = QWidget()
        self.body.setStyleSheet(_TRANSPARENT_BODY_QSS)
        self.scroll_area.setWidget(self.body)

        self.content_layout = QVBoxLayout(self.body)
        self.content_layout.setContentsMargins(0, 0, 0, bottom)
        self.content_layout.setSpacing(12)

        self.reset_breadcrumb()

    # ── Header ──

    def add_header_action(self, widget: QWidget) -> None:
        """Add a button to the right side of the title row."""
        self.header_actions.addWidget(widget)

    def set_page_label(self, label: str) -> None:
        """Rename the trailing breadcrumb crumb and the title."""
        self._page_label = label
        self.title_label.setText(label)
        self.reset_breadcrumb()

    # ── Breadcrumb ──

    def reset_breadcrumb(self) -> None:
        """Restore the two-item trail (BreadcrumbBar pops the tail on click)."""
        self.breadcrumb.blockSignals(True)
        self.breadcrumb.clear()
        self.breadcrumb.addItem(self._root_key, self._root_label)
        self.breadcrumb.addItem(self._page_key, self._page_label)
        self.breadcrumb.blockSignals(False)

    def _on_breadcrumb(self, routeKey: str) -> None:
        if routeKey == self._root_key:
            self.request_back()

    # ── Leaving the page ──

    def request_back(self) -> None:
        """Leave the sub-page, asking about unsaved edits first."""
        if self.confirm_back():
            self.back_requested.emit()
            return
        # The user clicked the root crumb and then cancelled: the trail already
        # lost its tail, so rebuild it once the signal has been delivered.
        QTimer.singleShot(0, self.reset_breadcrumb)

    def confirm_back(self) -> bool:
        if not self.is_dirty():
            return True
        box = MessageBox("Несохранённые изменения", "Выйти без сохранения?", self.window())
        box.yesButton.setText("Выйти")
        box.cancelButton.setText("Остаться")
        return bool(box.exec())

    def is_dirty(self) -> bool:
        """Override in subclasses that hold editable state."""
        return False


class StackedSection(QWidget):
    """Section page hosting a root view plus :class:`DetailPage` sub-pages."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._root_page: QWidget | None = None

        self._stack = QStackedWidget(self)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._stack)

    def set_root_page(self, page: QWidget) -> None:
        self._root_page = page
        self._stack.insertWidget(0, page)
        self._stack.setCurrentIndex(0)

    def add_sub_page(self, page: DetailPage) -> DetailPage:
        page.back_requested.connect(self.show_root)
        self._stack.addWidget(page)
        return page

    def show_sub_page(self, page: QWidget) -> None:
        if isinstance(page, DetailPage):
            page.reset_breadcrumb()
        self._stack.setCurrentWidget(page)

    def show_root(self) -> None:
        if self._root_page is not None:
            self._stack.setCurrentWidget(self._root_page)

    def is_root_visible(self) -> bool:
        return self._stack.currentWidget() is self._root_page
