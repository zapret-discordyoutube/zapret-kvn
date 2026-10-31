"""Attach the real selection transaction to fake controllers (not a test module)."""

from __future__ import annotations

from typing import Any
from unittest.mock import Mock

from xray_fluent.application.controller import AppController
from xray_fluent.application.server_selection import ServerSelection


class SelectionMock(Mock):
    """``Mock`` whose ``_pending_transport_node_id`` is the real selection's target."""

    @property
    def _pending_transport_node_id(self):
        return self.selection.pending_id

    @_pending_transport_node_id.setter
    def _pending_transport_node_id(self, node_id):
        self.selection.pending_id = node_id


def attach_selection(controller: Any, *, bind_methods: bool = False) -> Any:
    """Give a fake controller the production ServerSelection over its state."""

    def find(node_id):
        return next((node for node in controller.state.nodes if node.id == node_id), None)

    controller.selection = ServerSelection(
        lambda: controller.state,
        find_node=find,
        on_changed=lambda node: controller.selection_changed.emit(node),
        save=lambda: controller.schedule_save(),
        log=lambda line: controller._log(line),
    )
    if bind_methods:
        for name in (
            "_commit_pending_transport_selection",
            "_clear_pending_transport_selection",
            "_settle_pending_transport_selection",
        ):
            method = getattr(AppController, name)
            setattr(controller, name, Mock(side_effect=lambda *a, _m=method, **k: _m(controller, *a, **k)))
    return controller
