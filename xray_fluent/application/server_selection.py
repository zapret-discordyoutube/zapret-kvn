"""Server selection transaction: the requested server vs the server that serves.

Before this module the app had three different selection protocols, chosen by
protocol and transition kind. A native pool switch wrote ``selected_node_id``
first and then hot-switched. Hysteria wrote it before the replacement sidecar
proved readiness. Amnezia kept the choice pending until the replacement was
ready. After a failed Hysteria switch (31.10.2026, 0.8.51: UDP to the new server
never arrived) the previous runtime kept serving, yet the failed server stayed
selected and saved, and the next start went to it.

One rule now holds for every protocol and every transition:

- ``committed`` (``state.selected_node_id``) names the server serving the live
  connection. While connected it changes only in :meth:`commit`, called by the
  hot switch, the sidecar replacement or the reconnect once the new runtime is
  ready.
- A choice made while connected is only the pending *target*. A failed
  transition drops it (:meth:`settle`): the failed server was never selected,
  so there is nothing to roll back.
- Without a live connection nothing serves, so the choice is committed at once
  and decides the next start. A transition that ended with nothing serving
  keeps the user's choice the same way, except for an automatic replacement.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Callable


class SelectionRequest(Enum):
    # The server is already the committed or requested one.
    UNCHANGED = "unchanged"
    # Nothing serves: the choice is the selection now.
    COMMITTED = "committed"
    # Connected: target of the next transition, committed once it is ready.
    PENDING = "pending"
    # Connected: the serving server again; the in-flight target is dropped.
    BACK_TO_SERVING = "back_to_serving"


class ServerSelection:
    """The only writer of the selected server outside subscription maintenance."""

    def __init__(
        self,
        state: Callable[[], Any],
        *,
        find_node: Callable[[str | None], Any],
        on_changed: Callable[[Any], None],
        save: Callable[[], None],
        log: Callable[[str], None],
    ) -> None:
        self._state = state
        self._find_node = find_node
        self._on_changed = on_changed
        self._save = save
        self._log = log
        self._pending_id: str | None = None

    # ── reading ──────────────────────────────────────────────────────────
    @property
    def committed_id(self) -> str | None:
        return self._state().selected_node_id

    @property
    def pending_id(self) -> str | None:
        return self._pending_id

    @pending_id.setter
    def pending_id(self, node_id: str | None) -> None:
        # Automatic Hysteria recovery requests its replacement directly.
        self._pending_id = node_id if isinstance(node_id, str) and node_id else None

    @property
    def target_id(self) -> str | None:
        return self._pending_id or self.committed_id

    def target(self):
        """The server the next runtime must serve."""
        if self._pending_id:
            node = self._find_node(self._pending_id)
            if node is not None:
                return node
            # The requested server left the list (subscription update).
            self._pending_id = None
        return self.committed()

    def committed(self):
        return self._find_node(self.committed_id) if self.committed_id else None

    # ── transaction ──────────────────────────────────────────────────────
    def request(self, node_id: str, *, serving: bool) -> SelectionRequest:
        if node_id == self.target_id:
            return SelectionRequest.UNCHANGED
        if serving:
            if node_id == self.committed_id:
                self._pending_id = None
                return SelectionRequest.BACK_TO_SERVING
            self._pending_id = node_id
            return SelectionRequest.PENDING
        self._pending_id = None
        self._write(node_id)
        return SelectionRequest.COMMITTED

    def commit(self, node) -> bool:
        """A runtime serving ``node`` is ready: it becomes the selection."""
        pending = self._pending_id
        if pending and (node is None or node.id != pending):
            self._log("[transport-transition] ready runtime does not match pending selection")
            return False
        self._pending_id = None
        if node is not None:
            self._write(node.id, node)
        return True

    def drop(self) -> None:
        self._pending_id = None

    def settle(self, *, serving: bool, keep_intent: bool) -> None:
        """A transition ended without committing its target."""
        pending, self._pending_id = self._pending_id, None
        if pending and not serving and keep_intent:
            self._write(pending)

    def _write(self, node_id: str, node=None) -> None:
        state = self._state()
        if state.selected_node_id == node_id:
            return
        state.selected_node_id = node_id
        self._on_changed(node if node is not None else self._find_node(node_id))
        self._save()
