"""Zapret rule for the selected VPN server, kept in step with the connection.

The connection coordinator asks three things before a VPN core may start:

* :meth:`ServerBypass.prepare` — bring winws2 to the rule this server needs
  (fresh DNS in a worker, then a manager ``apply``); ``True`` means "wait, the
  transition is resumed by :meth:`_on_plan_applied` or cancelled";
* :meth:`ServerBypass.ready_for` — is the running winws2 exactly that rule;
* :meth:`ServerBypass.allows_core_start` — the last fence before a process start.

What the rule is comes from :func:`server_strategy`: the chosen strategy when
bypass is on for the server's kind; ``pass`` for a UDP server with bypass off
(preset fakes must not hit the tunnel); nothing for a TCP server with bypass
off (the preset decides).  Zapret that is not running is never started just to
say ``pass``.

The server's name is resolved before every connection even when Zapret has no
work: that lookup also teaches log redaction the server's IPs
(``register_server_aliases``) before a core can print them.  After a
connection the other pool servers are learned in the background, so a hot
switch to them is masked too.

Safety rules kept from the previous implementation:

* DNS never runs on the GUI thread; a previous answer is never readiness proof.
* A connected tunnel is stopped before its rule changes (except during Hysteria
  recovery, whose coordinator already closed admission), so no retry loop can
  reach the server unprotected.
* If winws2 dies while a session depends on it, the VPN is stopped (fail
  closed).
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

from PyQt6.QtCore import QObject

from ..engines.zapret import presets
from ..engines.zapret.command import ServerRule
from ..engines.zapret.endpoint import ServerEndpoint, endpoint_for_node, resolve_endpoint, resolve_host
from ..engines.zapret.manager import ZapretPlan
from ..engines.zapret.strategies import server_strategy
from ..network.background_workers import EndpointResolver
from ..profiles.models import ZapretTargetSettings
from .transition_engine import transition_request_delay_ms

if TYPE_CHECKING:
    from ..profiles.models import Node
    from .controller import AppController

#: Background lookups of pool servers: one thread, never the transition pool.
_POOL_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="xray_fluent_pool_dns")
_POOL_THROTTLE_SEC = 0.05


class ServerBypass(QObject):
    def __init__(self, controller: AppController):
        super().__init__(controller if isinstance(controller, QObject) else None)
        self._controller = controller
        self._zapret = controller.zapret
        self._workers: set[EndpointResolver] = set()
        # The connection transition waiting for us: its generation and the
        # lowest manager revision whose outcome answers it (None during DNS).
        self._wait_generation = 0
        self._wait_revision: int | None = None
        # Manual start: the last click wins; "busy" is released by the process
        # outcome (started / error), not by the click.
        self._manual_generation = 0
        self._manual_busy = False
        self._learned_hosts: set[str] = set()

        self._zapret.plan_applied.connect(self._on_plan_applied)
        self._zapret.plan_failed.connect(self._on_plan_failed)
        self._zapret.stopped.connect(self._on_zapret_stopped)
        self._zapret.started.connect(self._settle_manual_busy)
        self._zapret.error.connect(self._settle_manual_busy)

    # ── questions ────────────────────────────────────────────────────────

    @property
    def settings(self) -> ZapretTargetSettings:
        return self._controller.state.settings.zapret_target

    def required(self, node: Node | None) -> bool:
        """The server's kind has bypass on: the VPN must not start without it."""

        endpoint = endpoint_for_node(node)
        return endpoint is not None and self.settings.enabled(endpoint.kind)

    def ready_for(self, node: Node | None) -> bool:
        """winws2 is in the state this node needs, proven by a started process."""

        endpoint = endpoint_for_node(node)
        if endpoint is None:
            return True
        if self._zapret.pending:
            return False
        try:
            strategy = server_strategy(self.settings, endpoint)
        except ValueError:
            return False
        if strategy is None:
            return True
        if not self.settings.enabled(endpoint.kind) and not self._zapret.active:
            return True  # "pass" with no winws2 at all: nothing touches the server
        rule = self._zapret.rule
        return (
            self._zapret.is_applied()
            and rule is not None
            and rule.target.endpoint == endpoint
            and rule.strategy == strategy
        )

    @property
    def waiting(self) -> bool:
        return bool(self._wait_generation)

    def waiting_for(self, generation: int) -> bool:
        return bool(self._wait_generation) and self._wait_generation == generation

    def hold(self, generation: int) -> None:
        """The coordinator is stopping the tunnel for us: keep the queue shut."""
        self._wait_generation = generation
        self._wait_revision = None

    def cancel_wait(self) -> None:
        self._wait_generation = 0
        self._wait_revision = None

    @property
    def manual_start_pending(self) -> bool:
        """A manual start is resolving the server or waiting for winws2."""
        return self._manual_busy

    def workers(self) -> list[EndpointResolver]:
        """DNS threads still alive — joined on application shutdown."""
        return list(self._workers)

    # ── connection transition ────────────────────────────────────────────

    def prepare(self, generation: int) -> bool:
        """Start bringing winws2 to this generation's rule; True = wait for it."""

        c = self._controller
        self.cancel_wait()
        node = c._runtime_selected_node()
        endpoint = endpoint_for_node(node) if c._active_config_uses_selected_node(node) else None
        if endpoint is None:
            self._drop_rule()
            return False
        try:
            server_strategy(self.settings, endpoint)
        except ValueError as exc:
            c._cancel_target_transition(f"Zapret: {exc}")
            return True
        if self.settings.enabled(endpoint.kind) and not self._ensure_preset():
            return True

        if c.connected and not self.ready_for(node):
            # Stop the old tunnel before DNS: its retries must not reach the
            # server while the rule is being replaced, and in TUN mode the
            # lookup must not go through the tunnel being torn down.
            c.transition_state_changed.emit(True, "Остановка VPN перед DNS...")
            c._run_prestop(
                generation,
                lambda: self._resolve(generation, endpoint),
                failure_message="Не удалось остановить VPN перед обновлением правила Zapret",
            )
            return True
        self._resolve(generation, endpoint)
        return True

    def allows_core_start(self, node: Node | None, *, used_selected_node: bool = True) -> bool:
        if not used_selected_node:
            self._drop_rule()
            return True
        if self.ready_for(node):
            return True
        self._controller._set_connection_status(
            "error",
            "Запуск VPN заблокирован: правило Zapret для выбранного сервера не готово",
            level="warning",
        )
        return False

    def _ensure_preset(self) -> bool:
        """A required rule needs a preset to ride on; fall back to the default."""

        c = self._controller
        chosen = c.state.settings.zapret_preset
        if chosen and presets.preset_path(chosen).is_file():
            return True
        fallback = presets.default_preset()
        if not fallback:
            c._cancel_target_transition("Для обхода выбранного сервера сначала выберите пресет Zapret")
            return False
        c._logger.info("Zapret preset %r is missing, falling back to %r", chosen, fallback)
        c.state.settings.zapret_preset = fallback
        c.schedule_save()
        c.transition_state_changed.emit(True, f"Zapret: пресет по умолчанию «{fallback}»")
        return True

    def _drop_rule(self) -> None:
        """A running winws2 keeps its preset but loses a stale server rule."""

        plan = self._zapret.plan
        if plan is not None and plan.rule is not None:
            self._zapret.apply(ZapretPlan(plan.preset))

    def _resolve(self, generation: int, endpoint: ServerEndpoint) -> None:
        self._wait_generation = generation
        self._wait_revision = None
        self._controller.transition_state_changed.emit(True, "DNS выбранного VPN-сервера...")
        self._start_worker(generation, endpoint, self._on_resolved)

    def _start_worker(self, generation: int, endpoint: ServerEndpoint, slot) -> None:
        worker = EndpointResolver(generation, endpoint, resolve_endpoint, parent=self)
        self._workers.add(worker)
        worker.resolved.connect(slot)
        worker.finished.connect(lambda: self._forget_worker(worker))
        worker.start()

    def _forget_worker(self, worker: EndpointResolver) -> None:
        self._workers.discard(worker)
        worker.deleteLater()

    def _on_resolved(self, generation: int, endpoint: ServerEndpoint, resolved, error) -> None:
        c = self._controller
        if generation != c._transition_generation:
            return  # superseded: the newer request prepares for itself
        self.cancel_wait()
        if not c._desired_connected:
            c.transition_state_changed.emit(False, "")
            return
        node = c._runtime_selected_node()
        if endpoint != endpoint_for_node(node):
            return
        required = self.settings.enabled(endpoint.kind)
        if error is not None:
            c._log(
                f"[zapret] DNS выбранного сервера host={', '.join(endpoint.hosts)} "
                f"завершился ошибкой: {error}"
            )
            if required or self._zapret.active:
                c._cancel_target_transition(
                    "Подключение отменено: не удалось определить IP выбранного сервера"
                )
            else:
                c._schedule_transition_drain(0)
            return

        from .node_runtime_service import remember_country_addresses
        remember_country_addresses(c, node, resolved.ips)

        try:
            strategy = server_strategy(self.settings, endpoint)
        except ValueError as exc:
            c._cancel_target_transition(f"Zapret: {exc}")
            return
        if strategy is None or (not required and not self._zapret.active):
            # TCP with bypass off (the preset decides) or "pass" with no winws2.
            self._drop_rule()
            self._resume(transition_request_delay_ms(c._transition_reason))
            return
        if not self._ensure_preset():
            return
        # The chosen preset is what runs: a restart on another one goes
        # through here, so a protected tunnel is stopped first.
        plan = ZapretPlan(c.state.settings.zapret_preset, ServerRule(resolved, strategy))
        if self._zapret.is_applied(plan):
            self._resume(transition_request_delay_ms(c._transition_reason))
            return
        if c.connected:
            if c._hysteria_recovery_active:
                # Admission is already closed by the Hysteria failure
                # coordinator; the old sidecar generation retires only after
                # the replacement is ready.
                c._log(
                    "[hysteria-recovery] preparing Zapret target without "
                    "stopping the old Hysteria generation"
                )
            else:
                c.transition_state_changed.emit(True, "Остановка VPN перед Zapret...")
                c._run_prestop(generation, lambda: self._apply(generation, plan), failure_message=None)
                return
        self._apply(generation, plan)

    def _apply(self, generation: int, plan: ZapretPlan) -> None:
        c = self._controller
        # Wait before asking: a synchronous outcome must still find the waiter.
        self._wait_generation = generation
        self._wait_revision = self._zapret.revision
        c.transition_state_changed.emit(True, "Запуск Zapret для выбранного сервера...")
        revision = self._zapret.apply(plan)
        if not self._wait_generation:
            return  # answered synchronously
        if self._zapret.is_applied(plan):
            self.cancel_wait()
            self._resume(transition_request_delay_ms(c._transition_reason))
            return
        self._wait_revision = revision

    def _resume(self, delay_ms: int) -> None:
        if not self._controller._transition_active:
            self._controller._schedule_transition_drain(delay_ms)

    def _answers_wait(self, revision: int) -> bool:
        return (
            bool(self._wait_generation)
            and self._wait_revision is not None
            and revision >= self._wait_revision
            and self._wait_generation == self._controller._transition_generation
        )

    def _on_plan_applied(self, revision: int) -> None:
        c = self._controller
        if not self._answers_wait(revision):
            return
        if not c._desired_connected:
            self.cancel_wait()
            c.transition_state_changed.emit(False, "")
            return
        if not self.ready_for(c._runtime_selected_node()):
            if self._zapret.pending:
                return  # a newer request is starting; its outcome answers
            self._fail("applied rule does not match the selected server")
            return
        self.cancel_wait()
        self._resume(transition_request_delay_ms(c._transition_reason))

    def _on_plan_failed(self, revision: int, reason: str) -> None:
        if self._answers_wait(revision):
            self._fail(reason)
        elif reason == "timeout":
            # A restart outside a transition never came up.  Crashes and
            # launch errors end in ``stopped``; a timeout does not.
            self._on_zapret_stopped()

    def _fail(self, reason: str) -> None:
        c = self._controller
        self.cancel_wait()
        c._transition_pending = False
        c._blocked_transition_signature = c._transition_signature(c._runtime_selected_node())
        if c._hysteria_recovery_active:
            c._clear_pending_transport_selection()
            c._hysteria_recovery_active = False
        c._desired_connected = False
        if c.connected or c._has_residual_processes():
            c._request_stop("zapret profile failed", quiet=True)
        c._log(f"[zapret] правило выбранного сервера не подтверждено: {reason}; подключение отменено")
        c._set_connection_status(
            "error",
            "Zapret не подтвердил правило выбранного сервера; подключение отменено",
            level="warning",
        )
        c.transition_state_changed.emit(False, "")

    def _on_zapret_stopped(self) -> None:
        """Fail closed: a session that needs winws2 must not outlive it."""

        c = self._controller
        if not c.connected or not self.required(c.selected_node):
            return
        c._log("[zapret] процесс остановлен во время защищённой VPN-сессии")
        c._desired_connected = False
        c._request_stop("zapret stopped", quiet=True)
        c._set_connection_status(
            "error",
            "VPN остановлен: Zapret больше не защищает выбранный сервер",
            level="error",
        )

    # ── log redaction of pool servers ────────────────────────────────────

    def learn_pool_addresses(self, *, submit=None) -> bool:
        """Resolve the pool's server names in the background (redaction only).

        Nothing waits for it and winws2 is never touched; failures are ignored.
        Returns whether a job was queued.
        """

        c = self._controller
        try:
            nodes = list(c.xray_outbound_pool().nodes) or list(c.state.nodes)
        except Exception:
            nodes = list(c.state.nodes)
        hosts: list[str] = []
        for node in nodes:
            endpoint = endpoint_for_node(node)
            for host in endpoint.hosts if endpoint is not None else ():
                if host not in self._learned_hosts:
                    self._learned_hosts.add(host)
                    hosts.append(host)
        if not hosts:
            return False

        def job() -> None:
            for host in hosts:
                try:
                    resolve_host(host)
                except (OSError, UnicodeError):
                    pass
                time.sleep(_POOL_THROTTLE_SEC)

        (submit or _POOL_EXECUTOR.submit)(job)
        return True

    # ── manual start / stop ──────────────────────────────────────────────

    def start_manual(self, preset: str) -> None:
        """Start (or restart) winws2 on ``preset`` with the selected server's rule."""

        c = self._controller
        c.state.settings.zapret_preset = preset
        c.schedule_save()
        self._manual_generation += 1
        node = c.selected_node
        if (c.connected or c._desired_connected) and self.required(node):
            # winws2 carries this session: restarting it under a live tunnel
            # would leave a window without bypass.  The coordinator stops the
            # tunnel, restarts winws2 on the new preset and reconnects.
            self._settle_manual_busy()
            c._desired_connected = True
            c._request_transition("Zapret preset changed")
            return
        endpoint = endpoint_for_node(node) if c._active_config_uses_selected_node(node) else None
        try:
            strategy = server_strategy(self.settings, endpoint) if endpoint is not None else None
        except ValueError as exc:
            self._settle_manual_busy()
            c._set_connection_status("error", f"Zapret не запущен: {exc}", level="warning")
            return
        if endpoint is None or strategy is None:
            self._settle_manual_busy()
            self._zapret.apply(ZapretPlan(preset))
            return
        generation = self._manual_generation
        self._manual_busy = True
        c.transition_state_changed.emit(True, "DNS выбранного VPN-сервера...")

        def on_resolved(result_generation, result_endpoint, resolved, error) -> None:
            if result_generation != self._manual_generation:
                return  # stopped or re-clicked meanwhile
            if error is not None or result_endpoint != endpoint_for_node(c.selected_node):
                self._settle_manual_busy()
                c._set_connection_status(
                    "error",
                    "Zapret не запущен: не удалось определить IP выбранного сервера",
                    level="warning",
                )
                return
            c.transition_state_changed.emit(True, "Запуск Zapret...")
            # "Busy" is released by the process outcome: started or error.
            self._zapret.apply(ZapretPlan(preset, ServerRule(resolved, strategy)))

        self._start_worker(generation, endpoint, on_resolved)

    def stop_manual(self) -> None:
        """Stop winws2 and cancel a pending manual start (its DNS callback)."""

        self._manual_generation += 1
        self._zapret.stop()
        self._settle_manual_busy()

    def _settle_manual_busy(self, *_args) -> None:
        if not self._manual_busy:
            return
        self._manual_busy = False
        c = self._controller
        if (
            c._transition_active
            or c._transition_scheduled
            or c._transition_pending
            or self.waiting
        ):
            return  # the connection transition owns the indicator
        c.transition_state_changed.emit(False, "")
