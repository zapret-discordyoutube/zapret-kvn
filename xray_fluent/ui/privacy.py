"""Display-only helpers and controls for sensitive endpoint values.

Server addresses are never persisted as visible UI state.  Every surface uses
the same press-and-hold control, so releasing the mouse/key, leaving the
button, hiding it, or moving focus away immediately restores the mask.
"""

from __future__ import annotations

from PyQt6.QtCore import QEvent, Qt, pyqtSignal
from PyQt6.QtGui import QFocusEvent, QHideEvent, QKeyEvent, QMouseEvent
from PyQt6.QtWidgets import QWidget
from qfluentwidgets import FluentIcon as FIF, TransparentToolButton


MASKED_VALUE = "********"


def masked_endpoint() -> str:
    """Return the common placeholder used instead of a server endpoint."""
    return MASKED_VALUE


def format_endpoint(server: str, port: int) -> str:
    """Format a host and port for display, including bracketed IPv6 hosts."""
    host = (server or "").strip()
    if not host:
        return "—"
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        host = f"[{host}]"
    return f"{host}:{int(port)}" if int(port or 0) > 0 else host


def endpoint_text(server: str, port: int, revealed: bool) -> str:
    """Return an endpoint only while an explicit reveal gesture is active."""
    return format_endpoint(server, port) if revealed else masked_endpoint()


def node_name_text(node, *, revealed: bool = False) -> str:
    """Generated WG/AWG names can contain the endpoint itself."""
    name = node.name or "Без имени"
    host = (node.server or "").strip()
    if host and not revealed:
        name = name.replace(format_endpoint(host, node.port), MASKED_VALUE)
        name = name.replace(host, MASKED_VALUE)
    return name


class HoldToRevealButton(TransparentToolButton):
    """A non-toggle button that reveals sensitive text only while held."""

    revealChanged = pyqtSignal(bool)

    _REVEAL_KEYS = (Qt.Key.Key_Space, Qt.Key.Key_Return, Qt.Key.Key_Enter)

    def __init__(self, parent: QWidget | None = None, *, plural: bool = False):
        # qfluentwidgets' icon overload delegates through ``self.__init__``;
        # subclasses must use the parent-only overload to avoid recursion.
        super().__init__(parent)
        self.setIcon(FIF.VIEW)
        self._revealed = False
        target = "адреса" if plural else "адрес"
        self.setToolTip(f"Удерживайте, чтобы показать {target} (Space/Enter)")
        self.setAccessibleName(f"Показать {target} при удержании")
        self.setAutoRepeat(False)
        self.pressed.connect(lambda: self._set_revealed(True))
        self.released.connect(self.reset_reveal)

    def is_revealed(self) -> bool:
        return self._revealed

    def reset_reveal(self) -> None:
        self.setDown(False)
        self._set_revealed(False)

    def _set_revealed(self, revealed: bool) -> None:
        revealed = bool(revealed)
        if revealed == self._revealed:
            return
        self._revealed = revealed
        self.setIcon(FIF.HIDE if revealed else FIF.VIEW)
        self.revealChanged.emit(revealed)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() in self._REVEAL_KEYS:
            if not event.isAutoRepeat():
                self.setDown(True)
                self._set_revealed(True)
            event.accept()
            return
        super().keyPressEvent(event)

    def keyReleaseEvent(self, event: QKeyEvent) -> None:
        if event.key() in self._REVEAL_KEYS:
            if not event.isAutoRepeat():
                self.reset_reveal()
            event.accept()
            return
        super().keyReleaseEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        super().mouseReleaseEvent(event)
        self.reset_reveal()

    def leaveEvent(self, event: QEvent) -> None:
        self.reset_reveal()
        super().leaveEvent(event)

    def focusOutEvent(self, event: QFocusEvent) -> None:
        self.reset_reveal()
        super().focusOutEvent(event)

    def hideEvent(self, event: QHideEvent) -> None:
        self.reset_reveal()
        super().hideEvent(event)

    def event(self, event: QEvent) -> bool:
        if event.type() == QEvent.Type.WindowDeactivate:
            self.reset_reveal()
        return super().event(event)

    def changeEvent(self, event: QEvent) -> None:
        if event.type() == QEvent.Type.EnabledChange and not self.isEnabled():
            self.reset_reveal()
        super().changeEvent(event)
