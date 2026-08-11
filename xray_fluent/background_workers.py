from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from PyQt6.QtCore import QThread, pyqtSignal

from .subscription_http import fetch_subscription
from .subscription_parser import parse_subscription_payload

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


class SubscriptionUpdateWorker(QThread):
    """Fetch and parse a subscription without mutating application state."""

    completed = pyqtSignal(object, object, object)  # Subscription, fetch result, parsed result | None
    failed = pyqtSignal(object, str)                # Subscription, sanitized message
    progress = pyqtSignal(str, str)                 # subscription id, phase

    def __init__(self, subscription, *, mode: str, proxy_port: int | None, parent=None) -> None:
        super().__init__(parent)
        self._subscription = subscription
        self._mode = mode
        self._proxy_port = proxy_port

    def run(self) -> None:
        try:
            self.progress.emit(self._subscription.id, "download")
            fetched = fetch_subscription(
                self._subscription,
                mode=self._mode,
                proxy_port=self._proxy_port,
            )
            if fetched.not_modified:
                self.completed.emit(self._subscription, fetched, None)
                return
            self.progress.emit(self._subscription.id, "parse")
            parsed = parse_subscription_payload(
                fetched.data,
                headers=fetched.headers,
                source_url=self._subscription.url,
                include_pattern=self._subscription.include_pattern,
                exclude_pattern=self._subscription.exclude_pattern,
                hidden_source_keys=set(self._subscription.hidden_source_keys),
            )
            self.completed.emit(self._subscription, fetched, parsed)
        except Exception as exc:
            from .subscription_http import sanitize_fetch_error

            self.failed.emit(self._subscription, sanitize_fetch_error(exc))
