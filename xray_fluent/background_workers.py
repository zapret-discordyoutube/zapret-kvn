from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from PyQt6.QtCore import QThread, pyqtSignal

if TYPE_CHECKING:
    from .models import AppState
    from .storage import StateStorage


class ProxyProtectionResolver(QThread):
    """Resolve one proxy endpoint without blocking the Qt event loop."""

    resolved = pyqtSignal(int, str, object, object)

    def __init__(
        self,
        generation: int,
        server: str,
        resolver: Callable[[str], set[str]],
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._generation = generation
        self._server = server
        self._resolver = resolver

    def run(self) -> None:
        try:
            addresses = self._resolver(self._server)
            error: Exception | None = None
        except Exception as exc:  # DNS errors are reported back on the GUI thread
            addresses = set()
            error = exc
        self.resolved.emit(self._generation, self._server, addresses, error)


class StateSaveWorker(QThread):
    """Serialize, encrypt and write a large state away from the GUI thread."""

    failed = pyqtSignal(str)

    def __init__(self, storage: StateStorage, state: AppState, parent=None) -> None:
        super().__init__(parent)
        self._storage = storage
        self._state = state

    def run(self) -> None:
        try:
            self._storage.save(self._state)
        except Exception as exc:
            self.failed.emit(str(exc))
