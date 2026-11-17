"""Runs the service-slot helpers next to sing-box (docs/SERVICE_SLOTS.md, "Phase 3 plan").

Isolation is the rule: a slot never fails the main connection. The helpers start after sing-box is up, each from its
own executable copy with its own config; a helper that does not start leaves its slot on the main server (`proxy`)
and says so in the log. The helpers stop when sing-box stops.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from dataclasses import replace
from typing import Any

from PyQt6.QtCore import QObject, pyqtSignal

from ..constants import PROXY_HOST, slot_helper_config, slot_helper_exe
from ..diagnostics.runtime_logging import RuntimeNodeIdentity
from ..engines.hysteria.config_adapter import build_uri_client_config
from ..engines.hysteria.manager import HysteriaManager
from ..engines.singbox.selector_api import select_outbound
from ..engines.xray.manager import XrayManager
from ..network.speed_test_worker import prepare_speed_test_xray
from ..slots.config_writer import PROXY_TAG, SELECTOR_PREFIX
from ..slots.runtime_plan import SlotHelper, SlotRuntimePlan, xray_helper_config
from . import masking_runtime
from .async_steps import TransitionRunner, TransitionSteps, run_in_worker
from .outbound_pool_service import build_xray_outbound_pool
from .protocol_core import ProtocolCore, protocol_core
from ..masking.model import MaskingSettings
from ..profiles.models import Node

#: Connect-log note: a slot's own Xray gets mux, XHTTP connection rotation and fragmentation, not packet tricks.
SLOT_DESYNC_NOTE = "пакеты-обманки маскировки у сервера слота не применяются"


def helper_config(
    helper: SlotHelper,
    masking: MaskingSettings | None = None,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    """The native core's own config for a slot helper (pure).

    «Маскировка» shapes a slot's Xray server like the main one (mux, XHTTP connection rotation, fragmentation: all
    native Xray settings of the outbound). Packet tricks are a sing-box route option of the main path's server
    socket, so a slot helper drops the carried plan; `notes` gets what masking said.
    """
    node = helper.node
    if helper.core is ProtocolCore.HYSTERIA:
        return build_uri_client_config(
            str(node.link or "").strip(),
            node.outbound if isinstance(node.outbound, dict) else {},
            relay_host=PROXY_HOST,
            relay_port=helper.relay_port,
            relay_username=helper.username,
            relay_password=helper.password,
        )
    if helper.core is ProtocolCore.XRAY:
        pool = build_xray_outbound_pool([node])
        if not pool.contains(node.id):
            reason = pool.excluded.get(node.id) or "сервер не подходит для Xray"
            raise ValueError(reason)
        outbounds = pool.outbounds()
        if masking is not None:
            outbounds, _changed, masking_notes = masking_runtime.mask_pool_outbounds(outbounds, pool.tags, masking)
            if notes is not None:
                notes.extend(masking_notes)
        outbound = dict(outbounds[0])
        if masking_runtime.strip_desync([outbound]) and notes is not None:
            notes.append(SLOT_DESYNC_NOTE)
        return xray_helper_config(helper, outbound)
    raise ValueError(f"no slot helper for {helper.core.value}")


class SlotRuntimeService(QObject):
    # Where the slots are now changed (started, moved, stopped): the main-page card refreshes.
    changed = pyqtSignal()

    def __init__(
        self,
        parent: QObject | None,
        *,
        log: Callable[[str], None],
        hysteria_source: Callable[[], Path],
        xray_source: Callable[[], Path],
        on_helper_failed: Callable[[str, str], None] | None = None,
        masking: Callable[[], MaskingSettings] | None = None,
    ):
        super().__init__(parent)
        self._log = log
        self._hysteria_source = hysteria_source
        self._xray_source = xray_source
        self._on_helper_failed = on_helper_failed
        self._masking = masking
        self._helpers: dict[str, HysteriaManager | XrayManager] = {}
        self._runner: TransitionRunner | None = None
        self._generation = 0
        # The live launch: slot plans, Clash API port, provider members and the main server (for hot moves).
        self._plans: dict[str, SlotRuntimePlan] = {}
        self._clash_api_port = 0
        self._provider_tags: dict[str, str] = {}
        self._main_node_id: str | None = None

    @property
    def running_slots(self) -> list[str]:
        return sorted(slot for slot, manager in self._helpers.items() if getattr(manager, "is_running", False))

    @property
    def main_node_id(self) -> str | None:
        return self._main_node_id

    @property
    def active_slots(self) -> list[str]:
        return list(self._plans)

    def server_of(self, slot_id: str) -> str | None:
        plan = self._plans.get(slot_id)
        return plan.server_id if plan is not None and plan.member_tag != PROXY_TAG else None

    def servers_in_use(self) -> dict[str, str]:
        return {slot: plan.server_id for slot, plan in self._plans.items() if plan.server_id and plan.member_tag != PROXY_TAG}

    def can_move_hot(self, node: Node) -> bool:
        """A move without a sing-box restart: a server with its own native core behind the slot's relay, or a
        sing-box-core server of the launch provider."""
        core = protocol_core(node)
        if core in (ProtocolCore.HYSTERIA, ProtocolCore.XRAY):
            return True
        return core is ProtocolCore.SINGBOX and node.id in self._provider_tags

    def move(self, slot_id: str, node: Node | None) -> bool:
        """Move one slot to [node] (None = follow the main server) without touching the main path."""
        plan = self._plans.get(slot_id)
        if plan is None or plan.relay is None or (node is not None and not self.can_move_hot(node)):
            return False
        self._generation += 1
        generation = self._generation
        self._cancel_runner()
        runner = TransitionRunner(
            self._move_steps(slot_id, node, generation),
            is_current=lambda: generation == self._generation,
            parent=self,
        )
        self._runner = runner
        runner.start()
        return True

    def _move_steps(self, slot_id: str, node: Node | None, generation: int) -> TransitionSteps:
        current = lambda: generation == self._generation  # noqa: E731
        plan = self._plans[slot_id]
        old = self._helpers.pop(slot_id, None)
        if old is not None:
            yield from old.stop_steps()
            old.deleteLater()
        member, helper = PROXY_TAG, None
        if node is not None and node.id != self._main_node_id:
            core = protocol_core(node)
            if core is ProtocolCore.SINGBOX:
                member = self._provider_tags[node.id]
            else:
                helper = plan.relay.helper(core, node)
                if (yield from self._start_helper_steps(slot_id, helper, current)):
                    member = plan.relay.tag
                else:
                    helper = None
                    if self._on_helper_failed is not None and current():
                        self._on_helper_failed(slot_id, node.id)
        if not current():
            return False
        selector = f"{SELECTOR_PREFIX}{slot_id}"
        ok, output = yield run_in_worker(lambda: select_outbound(self._clash_api_port, selector, member))
        self._log(f"[slots] {slot_id}: moved, {selector} -> {member} " + ("ok" if ok else f"rejected: {output}"))
        self._plans[slot_id] = replace(plan, member_tag=member, helper=helper, server_id=node.id if node else None, note="")
        self.changed.emit()
        return bool(ok)

    def start(
        self,
        plans: list[SlotRuntimePlan],
        clash_api_port: int,
        *,
        provider_tags: dict[str, str] | None = None,
        main_node_id: str | None = None,
    ) -> None:
        """sing-box is up with these slot plans: start the helpers and pin every slot selector."""
        self._plans = {plan.slot_id: plan for plan in plans}
        self._clash_api_port = clash_api_port
        self._provider_tags = dict(provider_tags or {})
        self._main_node_id = main_node_id
        self._generation += 1
        generation = self._generation
        self._cancel_runner()
        if not plans:
            self._stop_helpers()
            return
        runner = TransitionRunner(
            self._start_steps(plans, clash_api_port, generation),
            is_current=lambda: generation == self._generation,
            parent=self,
        )
        self._runner = runner
        runner.start()

    def stop(self) -> None:
        """sing-box stopped: the helpers have nothing to serve."""
        self._plans = {}
        self._generation += 1
        self._cancel_runner()
        self._stop_helpers()
        self.changed.emit()

    def _cancel_runner(self) -> None:
        if self._runner is not None and not self._runner.done:
            self._runner.cancel()
        self._runner = None

    def _stop_helpers(self) -> None:
        helpers, self._helpers = self._helpers, {}
        if not helpers:
            return

        def steps() -> TransitionSteps:
            for slot_id, manager in helpers.items():
                yield from manager.stop_steps()
                self._log(f"[slots] {slot_id}: helper stopped")
                manager.deleteLater()

        TransitionRunner(steps(), parent=self).start()

    def _start_steps(self, plans: list[SlotRuntimePlan], clash_api_port: int, generation: int) -> TransitionSteps:
        current = lambda: generation == self._generation  # noqa: E731
        old, self._helpers = self._helpers, {}
        for slot_id, manager in old.items():
            yield from manager.stop_steps()
            manager.deleteLater()
        for plan in plans:
            if not current():
                return False
            member = plan.member_tag
            if plan.note:
                self._log(f"[slots] {plan.slot_id}: {plan.note}")
            if plan.helper is not None:
                started = yield from self._start_helper_steps(plan.slot_id, plan.helper, current)
                if not started:
                    member = PROXY_TAG
                    if self._on_helper_failed is not None and current():
                        self._on_helper_failed(plan.slot_id, plan.helper.node.id)
                    self._log(f"[slots] {plan.slot_id}: helper did not start, the slot follows the main server")
            selector = f"{SELECTOR_PREFIX}{plan.slot_id}"
            ok, output = yield run_in_worker(lambda s=selector, m=member: select_outbound(clash_api_port, s, m))
            self._log(f"[slots] {plan.slot_id}: {selector} -> {member} " + ("ok" if ok else f"rejected: {output}"))
            if member != plan.member_tag and plan.slot_id in self._plans:
                self._plans[plan.slot_id] = replace(plan, member_tag=member, helper=None)
        self.changed.emit()
        return True

    def _start_helper_steps(self, slot_id: str, helper: SlotHelper, current: Callable[[], bool]) -> TransitionSteps:
        core = helper.core.value
        notes: list[str] = []
        try:
            config = helper_config(helper, self._masking() if self._masking is not None else None, notes)
        except ValueError as error:
            self._log(f"[slots] {slot_id}: no {core} config ({error})")
            return False
        if notes:
            self._log(f"[slots] {slot_id}: маскировка: {'; '.join(dict.fromkeys(notes))}")
        source = self._hysteria_source() if helper.core is ProtocolCore.HYSTERIA else self._xray_source()
        target = slot_helper_exe(core, slot_id)
        exe = yield run_in_worker(lambda: prepare_speed_test_xray(source, target))
        if Path(exe) != target:
            # Without its own copy the helper would share the main sidecar's orphan cleanup: do not run it.
            self._log(f"[slots] {slot_id}: could not prepare {target.name}")
            return False
        self._log(f"[slots] {slot_id}: starting {core} helper relay=127.0.0.1:{helper.relay_port} "
                  f"{RuntimeNodeIdentity.from_node(helper.node).fields()}")
        if helper.core is ProtocolCore.HYSTERIA:
            manager: HysteriaManager | XrayManager = HysteriaManager(
                self, exe_path=target, config_file=slot_helper_config(core, slot_id),
            )
            self._helpers[slot_id] = manager
            ok = yield from manager.start_steps(
                config,
                helper.relay_port,
                context=RuntimeNodeIdentity.from_node(helper.node),
                should_continue=current,
            )
        else:
            manager = XrayManager(self, config_file=slot_helper_config(core, slot_id))
            self._helpers[slot_id] = manager
            ok = yield from manager.start_steps(str(target), config)
        return bool(ok) and current()
