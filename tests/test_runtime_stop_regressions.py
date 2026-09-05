"""Regressions from the repeated transport-switch/stop diagnostic logs."""
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from xray_fluent.application.async_steps import TransitionRunner
from xray_fluent.application.controller import AppController
from xray_fluent.application.connection_service import connect_selected, disconnect_current
from xray_fluent.application.node_service import set_selected_node
from xray_fluent.profiles.models import Node


class RuntimeStopTests(TestCase):
    def test_initial_start_cancellation_is_shared_by_native_hysteria_and_xray(self):
        for kind in ('native', 'hysteria', 'xray'):
            for stage in ('sidecar', 'front', 'selector'):
                if kind == 'native' and stage == 'sidecar':
                    continue
                with self.subTest(kind=kind, stage=stage):
                    controller = Mock()
                    controller._transition_generation = 1
                    controller._desired_connected = True
                    controller._active_singbox_plan = None
                    sidecar = SimpleNamespace(config={}, relay_port=11809, context=None,
                                              protect_port=11810, protect_password='', api_port=0)
                    plan = SimpleNamespace(amnezia_sidecar=None, provider_payload=None,
                        hysteria_sidecar=sidecar if kind == 'hysteria' else None,
                        xray_sidecar=sidecar if kind == 'xray' else None,
                        used_selected_node=True, clash_api_port=0, is_hybrid=kind == 'xray',
                        selected_outbound_tag='proxy', hybrid_relay_selected_tag='proxy', singbox_config={})
                    def cancel(*_args, **_kwargs):
                        controller._desired_connected = False
                        controller._transition_generation += 1
                        return True
                    if stage == 'sidecar':
                        getattr(controller, kind).start.side_effect = cancel
                    elif stage == 'front':
                        controller.singbox.start.side_effect = cancel
                    else:
                        def select(core, *_a, **_k):
                            return cancel() if core == 'singbox' else True
                        controller._apply_core_outbound_tag.side_effect = select
                    self.assertFalse(AppController._start_singbox_runtime_plan(controller, plan))
                    self.assertIsNone(controller._active_singbox_plan)
                    if stage == 'sidecar':
                        controller.singbox.start.assert_not_called()
                    if kind != 'native':
                        getattr(controller, kind).stop.assert_called()

    def test_stop_inside_synchronous_step_cancels_its_result(self):
        current = [True]
        def steps():
            yield from ()
            current[0] = False  # Stop delivered by a readiness event pump.
            return True
        runner = TransitionRunner(steps(), is_current=lambda: current[0])
        runner.start()
        self.assertTrue(runner.done)
        self.assertTrue(runner.cancelled)

    def test_stop_reconciles_connected_even_when_recovery_suppressed_signals(self):
        controller = Mock()
        controller.connected = True
        controller._switching = True
        controller._active_session = SimpleNamespace(tun_mode=True)
        controller._stop_active_connection_processes.return_value = True
        def refresh():
            old, controller.connected = controller.connected, False
            return old, False
        controller._refresh_connected_state.side_effect = refresh
        self.assertTrue(disconnect_current(controller))
        self.assertFalse(controller.connected)
        controller._clear_active_session.assert_called_once()

    def test_repeated_current_or_pending_selection_does_not_request_restart(self):
        for pending in (None, 'new'):
            controller = Mock()
            controller.state.nodes = [Node(id='old', scheme='awg'), Node(id='new', scheme='awg')]
            controller.state.selected_node_id = 'old'
            controller._pending_transport_node_id = pending
            set_selected_node(controller, pending or 'old')
            controller._request_transition.assert_not_called()

    def test_cold_reconnect_uses_and_commits_the_requested_node_for_every_protocol(self):
        for scheme in ('awg', 'wireguard', 'hysteria2', 'vless', 'vmess', 'trojan', 'ss'):
            with self.subTest(scheme=scheme):
                node = Node(id='new', name='New', scheme=scheme)
                controller = Mock()
                controller._connecting = controller._reconnecting = controller.locked = False
                controller._transition_generation = 3
                controller._desired_connected = True
                controller.state.settings.tun_mode = False
                controller.selected_node = Node(id='old')
                controller.state.selected_node_id = 'old'
                controller._runtime_selected_node.return_value = node
                controller._pending_transport_node_id = 'new'
                controller._clear_pending_transport_selection.side_effect = lambda: setattr(controller, '_pending_transport_node_id', None)
                controller._commit_pending_transport_selection.side_effect = lambda n: AppController._commit_pending_transport_selection(controller, n)
                controller._infer_singbox_ping_target.return_value = ('', 0)
                plan = SimpleNamespace(used_selected_node=True, selector_tags={}, is_hybrid=False,
                    is_hysteria_sidecar=False, sidecar_kind=scheme, socks_port=1390, http_port=1391,
                    xray_sidecar=None, hysteria_sidecar=None, amnezia_sidecar=None,
                    singbox_config={}, hybrid_relay_selector_tags=(), hybrid_relay_selected_tag='')
                with patch('xray_fluent.application.connection_service.start_singbox_proxy', return_value=SimpleNamespace(plan=plan, session_label='New')) as start:
                    self.assertTrue(connect_selected(controller))
                self.assertIs(start.call_args.args[1], node)
                self.assertIs(controller._capture_active_session.call_args.args[0], node)
                self.assertEqual(controller.state.selected_node_id, 'new')
                self.assertIsNone(controller._pending_transport_node_id)

    def test_stop_clears_pending_recovery_before_requesting_disconnect(self):
        controller = Mock()
        controller._transition_active = True
        controller._desired_connected = True
        controller._hysteria_recovery_active = True
        AppController.toggle_connection(controller)
        self.assertFalse(controller._desired_connected)
        self.assertFalse(controller._hysteria_recovery_active)
        controller._clear_pending_transport_selection.assert_called_once()

    def test_late_network_event_cannot_override_stop(self):
        controller = Mock()
        controller.state.settings.tun_mode = False
        controller.connected = True
        controller._desired_connected = False
        AppController._on_network_changed(controller, 'old', 'new')
        controller._request_transition.assert_not_called()
