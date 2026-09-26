from __future__ import annotations

import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from ..importer.subscription_http import fetch_subscription
from ..importer.subscription_parser import parse_subscription_payload

if TYPE_CHECKING:
    from ..profiles.models import AppState
    from ..profiles.storage import StateStorage


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


class TargetProfileResolver(QThread):
    """Resolve every host in one immutable selected-server endpoint spec."""

    resolved = pyqtSignal(int, object, object, object)

    def __init__(self, generation: int, spec, resolver: Callable, parent=None) -> None:
        super().__init__(parent)
        self._generation = generation
        self._spec = spec
        self._resolver = resolver

    def run(self) -> None:
        try:
            endpoint = self._resolver(self._spec)
            error: Exception | None = None
        except Exception as exc:
            endpoint = None
            error = exc
        self.resolved.emit(self._generation, self._spec, endpoint, error)


class StateWriter(QObject):
    """Единственный поток записи состояния на диск; побеждает последний снимок.

    GUI-поток отдаёт готовый текст (``StateStorage.serialize_state``) и сразу
    возвращается; шифрование и запись идут здесь. Промежуточные снимки,
    пришедшие во время записи, схлопываются в последний.
    """

    failed = pyqtSignal(str)

    def __init__(self, storage: StateStorage, parent=None) -> None:
        super().__init__(parent)
        self._storage = storage
        self._cond = threading.Condition()
        self._pending: tuple[str, str] | None = None
        self._busy = False
        self._closed = False
        self._thread = threading.Thread(target=self._run, name="state-writer", daemon=True)
        self._thread.start()

    def submit(self, payload: str, passphrase: str) -> None:
        with self._cond:
            if self._closed:
                return
            self._pending = (payload, passphrase)
            self._cond.notify_all()

    def flush(self, timeout: float = 15.0) -> bool:
        """Дождаться записи всего отданного. Только для выхода из приложения."""
        with self._cond:
            return self._cond.wait_for(lambda: self._pending is None and not self._busy, timeout)

    def close(self, timeout: float = 15.0) -> bool:
        done = self.flush(timeout)
        with self._cond:
            self._closed = True
            self._cond.notify_all()
        self._thread.join(timeout=1.0)
        return done

    def _run(self) -> None:
        while True:
            with self._cond:
                self._cond.wait_for(lambda: self._pending is not None or self._closed)
                if self._pending is None:
                    return
                payload, passphrase = self._pending
                self._pending = None
                self._busy = True
            try:
                self._storage.write_serialized(payload, passphrase)
            except Exception as exc:
                self.failed.emit(str(exc))
            finally:
                with self._cond:
                    self._busy = False
                    self._cond.notify_all()


class SubscriptionUpdateWorker(QThread):
    """Fetch and parse a subscription without mutating application state."""

    completed = pyqtSignal(object, object, object)  # Subscription, fetch result, parsed result | None
    failed = pyqtSignal(object, str)                # Subscription, sanitized message
    progress = pyqtSignal(str, str)                 # subscription id, phase

    def __init__(
        self,
        subscription,
        *,
        mode: str,
        proxy_port: int | None,
        force_refresh: bool = False,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._subscription = subscription
        self._mode = mode
        self._proxy_port = proxy_port
        self._force_refresh = bool(force_refresh)

    def run(self) -> None:
        try:
            self.progress.emit(self._subscription.id, "download")
            fetched = fetch_subscription(
                self._subscription,
                mode=self._mode,
                proxy_port=self._proxy_port,
                force_refresh=self._force_refresh,
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
            from ..importer.subscription_http import sanitize_fetch_error

            self.failed.emit(self._subscription, sanitize_fetch_error(exc))
