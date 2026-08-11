"""Base scrollable page (AC7).

``ScrollablePage`` is the common base for content pages: a vertical
``SmoothScrollArea`` whose horizontal scrollbar policy is ``ScrollBarAsNeeded``
(content wider than the viewport scrolls instead of being clipped), fully
transparent surfaces so the Windows 11 Mica effect shows through, and a
``body`` container with the standard page paddings.

Subclasses add their content to ``self.body_layout`` (children parented to
``self.body``).
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QVBoxLayout, QWidget
from qfluentwidgets import SmoothScrollArea

#: Standard content paddings (left, top, right, bottom) for pages.
BODY_MARGINS = (24, 20, 24, 20)

_TRANSPARENT_SCROLL_QSS = "QScrollArea { background: transparent; border: none; }"
_TRANSPARENT_BODY_QSS = "QWidget { background: transparent; }"


class PageScrollArea(SmoothScrollArea):
    """SmoothScrollArea that reports the *logical* scrollbar policies.

    qfluentwidgets' SmoothScrollDelegate replaces the native scrollbars with
    floating ones: it monkey-patches the policy setters on the instance, always
    forces the native policy to AlwaysOff and expresses the requested policy
    via ``setForceHidden`` on the floating bars. That makes the stock
    ``horizontalScrollBarPolicy()`` getter lie about the effective behaviour.
    This subclass records the requested policies and returns them from the
    getters so the effective policy is inspectable (AC7).
    """

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._logical_h_policy = Qt.ScrollBarPolicy.ScrollBarAsNeeded
        self._logical_v_policy = Qt.ScrollBarPolicy.ScrollBarAsNeeded

        # The delegate installed bound methods as *instance* attributes, which
        # shadow any subclass override — wrap them instead.
        delegate_set_h = self.setHorizontalScrollBarPolicy
        delegate_set_v = self.setVerticalScrollBarPolicy

        def _set_h(policy: Qt.ScrollBarPolicy) -> None:
            self._logical_h_policy = policy
            delegate_set_h(policy)

        def _set_v(policy: Qt.ScrollBarPolicy) -> None:
            self._logical_v_policy = policy
            delegate_set_v(policy)

        self.setHorizontalScrollBarPolicy = _set_h
        self.setVerticalScrollBarPolicy = _set_v

    def horizontalScrollBarPolicy(self) -> Qt.ScrollBarPolicy:
        return self._logical_h_policy

    def verticalScrollBarPolicy(self) -> Qt.ScrollBarPolicy:
        return self._logical_v_policy


class ScrollablePage(QWidget):
    """Vertically scrollable, Mica-transparent page with a padded body."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.scroll_area = PageScrollArea(self)
        self.scroll_area.setWidgetResizable(True)
        # ScrollBarAsNeeded (NOT AlwaysOff): overly wide content must remain
        # reachable instead of being cut off at the viewport edge.
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.scroll_area.setStyleSheet(_TRANSPARENT_SCROLL_QSS)
        outer.addWidget(self.scroll_area)

        self.body = QWidget()
        self.body.setStyleSheet(_TRANSPARENT_BODY_QSS)
        self.scroll_area.setWidget(self.body)

        self.body_layout = QVBoxLayout(self.body)
        self.body_layout.setContentsMargins(*BODY_MARGINS)
        self.body_layout.setSpacing(12)
