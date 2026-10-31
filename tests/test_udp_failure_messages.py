"""A failed UDP server is named by its cause; a failed switch keeps the serving server selected.

Diagnostics of 31.10.2026 (0.8.51): switching Hipse → 4stok (Hysteria2) got no
reply over UDP. The old runtime kept serving traffic, yet the app showed
«Ошибка подключения — Новый Hysteria sidecar не доказал readiness», kept 4stok
selected, and a later start superseded by the user's own click blamed sing-box
(«Не удалось запустить sing-box proxy runtime»).
"""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock

import tests.test_singbox_proxy_runtime as proxy_runtime
from tests.step_fakes import bridge_controller
from xray_fluent.application.controller import AppController
from xray_fluent.diagnostics.connection_message import connection_message
from xray_fluent.diagnostics.transport_failure import (
    UDP_ONLY_ADVICE,
    amnezia_failure_message,
    hysteria_failure_message,
    udp_unanswered_message,
)
from xray_fluent.engines.hysteria.runtime_contract import HysteriaFailureCode
from xray_fluent.engines.singbox.operations import restart_proxy_runtime, restart_runtime, start_proxy, start_tun
from xray_fluent.importer.link_parser import parse_single

# Lines as the official Hysteria CLI printed them in the user's log (redacted).
NO_REPLY_LINE = (
    '[hysteria][attempt=1 stage=remote_handshake node="4stok"] WARN SOCKS5 TCP error '
    '{"reqAddr": "www.google.com:443", "error": "connect error: timeout: no recent network activity"}'
)
NO_ROUTE_LINE = (
    '[hysteria][attempt=1 stage=runtime node="Hipse"] WARN SOCKS5 TCP error {"error": "connect error: '
    'write udp [::]:63722-><сервер>:443: wsasendto: A socket operation was attempted to an unreachable network."}'
)


class UdpFailureMessageTests(unittest.TestCase):
    def test_unanswered_hysteria_names_udp_and_a_tcp_alternative(self) -> None:
        message = hysteria_failure_message(
            "🇸🇪 4stok",
            code=HysteriaFailureCode.TARGET_NETWORK_TIMEOUT,
            remote_authenticated=False,
            output_lines=(NO_REPLY_LINE,),
        )
        self.assertEqual(message, udp_unanswered_message("🇸🇪 4stok", "Hysteria2"))
        self.assertIn("«🇸🇪 4stok» не ответил по UDP", message)
        self.assertIn("VLESS", message)
        self.assertIn(UDP_ONLY_ADVICE, message)

    def test_no_route_is_reported_as_missing_network_not_as_server(self) -> None:
        message = hysteria_failure_message(
            "Hipse",
            code=HysteriaFailureCode.TARGET_NETWORK_TIMEOUT,
            remote_authenticated=False,
            output_lines=(NO_ROUTE_LINE,),
        )
        self.assertTrue(message.startswith("Нет сети"))
        self.assertNotIn("Hipse", message)

    def test_authenticated_server_is_not_blamed_for_udp(self) -> None:
        message = hysteria_failure_message(
            "Spaice",
            code=HysteriaFailureCode.TARGET_NETWORK_TIMEOUT,
            remote_authenticated=True,
            output_lines=(NO_REPLY_LINE,),
        )
        self.assertNotIn("UDP", message)
        self.assertIn("проверка HTTPS не прошла", message)

    def test_server_rejections_name_what_was_rejected(self) -> None:
        cases = {
            HysteriaFailureCode.TARGET_AUTH_REJECTED: "пароль",
            HysteriaFailureCode.TARGET_OBFS_REJECTED: "obfs",
            HysteriaFailureCode.TARGET_TLS_UNKNOWN_AUTHORITY: "Сертификат",
            HysteriaFailureCode.TARGET_CONNECTION_REFUSED: "порт закрыт",
        }
        for code, expected in cases.items():
            with self.subTest(code=code):
                message = hysteria_failure_message("X", code=code, remote_authenticated=False)
                self.assertIn(expected, message)

    def test_unknown_evidence_keeps_the_original_core_message(self) -> None:
        self.assertIsNone(hysteria_failure_message(
            "X", code=HysteriaFailureCode.CORE_UNCLASSIFIED, remote_authenticated=False,
        ))
        self.assertIsNone(amnezia_failure_message("X", stage="process", message="exited with code 1"))

    def test_awg_without_handshake_is_a_udp_failure(self) -> None:
        message = amnezia_failure_message(
            "AWG-1", stage="handshake_readiness", message="No authenticated handshake observed; a: timed out",
        )
        self.assertEqual(message, udp_unanswered_message("AWG-1", "AmneziaWG/WireGuard"))

    def test_dashboard_shows_the_cause_verbatim(self) -> None:
        for message in (
            udp_unanswered_message("4stok", "Hysteria2"),
            amnezia_failure_message("AWG", stage="handshake_readiness", message="x"),
            hysteria_failure_message("Hipse", code=None, remote_authenticated=False, output_lines=(NO_ROUTE_LINE,)),
        ):
            self.assertEqual(connection_message(message), message)

    def test_controller_reads_evidence_from_failed_sidecars(self) -> None:
        node = SimpleNamespace(name="4stok")
        hysteria = SimpleNamespace(
            last_failure_code=HysteriaFailureCode.TARGET_NETWORK_TIMEOUT,
            remote_authenticated=False,
            recent_output_lines=(NO_REPLY_LINE,),
        )
        self.assertEqual(
            AppController._sidecar_failure_message(hysteria, node),
            udp_unanswered_message("4stok", "Hysteria2"),
        )
        amnezia = SimpleNamespace(last_failure=("handshake_readiness", "No authenticated handshake observed"))
        self.assertIn("AmneziaWG/WireGuard", AppController._sidecar_failure_message(amnezia, node))
        self.assertIsNone(AppController._sidecar_failure_message(SimpleNamespace(last_failure=None), node))
        # Loose mocks must not turn into a message.
        self.assertIsNone(AppController._sidecar_failure_message(Mock(spec=[]), node))


class FailedSwitchKeepsServingSelectionTests(unittest.TestCase):
    def _switch_controller(self, *, tun: bool):
        controller, _ = proxy_runtime.SingboxProxyRuntimeTests._restart_controller(self, tun=tun)
        serving = parse_single("hy2://old@hipse.example:443/#Hipse")
        target = parse_single("hy2://new@4stok.example:443/#4stok")
        controller._runtime_selected_node.return_value = target
        # A Hysteria switch stores the new selection before readiness.
        controller.state.selected_node_id = target.id
        controller._active_session = SimpleNamespace(node_id=serving.id)
        nodes = {serving.id: serving, target.id: target}
        controller._get_node_by_id.side_effect = nodes.get
        controller.state.nodes = [serving, target]
        plan = controller._plan_runtime_singbox.return_value if tun else controller._plan_proxy_runtime_singbox.return_value
        plan.hysteria_sidecar = SimpleNamespace(relay_port=11810)
        plan.is_hysteria_sidecar = True
        plan.sidecar_kind = "hysteria"
        controller._hysteria_contract.session.session_generation = 3
        controller._hysteria_recovery_active = False
        controller.singbox.is_running = True
        controller.hysteria.is_running = True
        return controller, serving, target

    def test_failed_hysteria_switch_selects_the_serving_server_and_names_the_cause(self) -> None:
        for tun in (False, True):
            with self.subTest(tun=tun):
                controller, serving, target = self._switch_controller(tun=tun)
                cause = udp_unanswered_message(target.name, "Hysteria2")

                def fail(_plan):
                    controller._last_sidecar_failure_message = cause
                    return None

                controller._prepare_hysteria_replacement.side_effect = fail
                restart = restart_runtime if tun else restart_proxy_runtime
                self.assertFalse(restart(controller, "node switched"))

                self.assertEqual(controller.state.selected_node_id, serving.id)
                controller.selection_changed.emit.assert_called_once_with(serving)
                controller.schedule_save.assert_called()
                logged = [call.args[0] for call in controller._log.call_args_list]
                self.assertTrue(
                    any(line.startswith("[select] source=switch-failed") and "4stok" in line and "Hipse" in line
                        for line in logged),
                    logged,
                )
                phase, message = controller._set_connection_status.call_args.args
                self.assertEqual(phase, "running")
                self.assertEqual(message, f"{cause} Соединение осталось на «Hipse».")
                self.assertEqual(controller._set_connection_status.call_args.kwargs, {"level": "warning-long"})
                controller.singbox.stop.assert_not_called()
                controller._handle_unexpected_disconnect.assert_not_called()

    def test_failed_switch_without_evidence_still_says_the_old_server_serves(self) -> None:
        controller, serving, _ = self._switch_controller(tun=False)
        controller._prepare_hysteria_replacement.return_value = None

        self.assertFalse(restart_proxy_runtime(controller, "node switched"))

        self.assertEqual(controller.state.selected_node_id, serving.id)
        _, message = controller._set_connection_status.call_args.args
        self.assertIn("не прошёл проверку", message)
        self.assertIn("осталось на «Hipse»", message)
        self.assertNotIn("readiness", message)

    def test_superseded_switch_neither_rolls_back_nor_reports(self) -> None:
        controller, _, target = self._switch_controller(tun=False)

        def superseded(_plan):
            controller._transition_generation += 1
            controller._last_sidecar_failure_message = "should not be shown"
            return None

        controller._prepare_hysteria_replacement.side_effect = superseded
        self.assertFalse(restart_proxy_runtime(controller, "node switched"))

        self.assertEqual(controller.state.selected_node_id, target.id)
        controller.selection_changed.emit.assert_not_called()
        for call in controller._set_connection_status.call_args_list:
            self.assertNotIn(call.args[0], {"error", "running"})


class StartFailureMessageTests(unittest.TestCase):
    def _start_controller(self):
        node = parse_single("hy2://secret@4stok.example:443/#4stok")
        plan = SimpleNamespace(
            used_selected_node=True, source_path=proxy_runtime.TEMPLATE_PATH, is_hybrid=False,
            is_hysteria_sidecar=True, sidecar_kind="hysteria", amnezia_sidecar=None,
            proxy_ports_changed=False, outcome="hysteria_sidecar",
        )
        controller = Mock()
        controller._transition_generation = 5
        controller._desired_connected = True
        controller._plan_proxy_runtime_singbox.return_value = plan
        controller._plan_runtime_singbox.return_value = plan
        controller._last_sidecar_failure_message = None
        return bridge_controller(controller), node

    def _statuses(self, controller):
        return [call.args for call in controller._set_connection_status.call_args_list]

    def test_sidecar_cause_replaces_the_generic_singbox_message(self) -> None:
        for start in (start_proxy, start_tun):
            with self.subTest(start=start.__name__):
                controller, node = self._start_controller()
                cause = udp_unanswered_message("4stok", "Hysteria2")

                def fail(_plan, **_kwargs):
                    controller._last_sidecar_failure_message = cause
                    return False

                controller._start_singbox_runtime_plan.side_effect = fail
                self.assertIsNone(start(controller, node, prev_active_core="xray"))
                self.assertEqual(self._statuses(controller)[-1], ("error", cause))
                self.assertEqual(controller._active_core, "xray")

    def test_start_superseded_by_a_newer_click_publishes_no_error(self) -> None:
        for change in ("selection", "disconnect"):
            with self.subTest(change=change):
                controller, node = self._start_controller()

                def superseded(_plan, **_kwargs):
                    if change == "selection":
                        controller._transition_generation += 1
                    else:
                        controller._desired_connected = False
                    return False

                controller._start_singbox_runtime_plan.side_effect = superseded
                self.assertIsNone(start_proxy(controller, node, prev_active_core="singbox"))
                self.assertNotIn("error", [phase for phase, _ in self._statuses(controller)])

    def test_failure_without_cause_keeps_the_generic_message(self) -> None:
        controller, node = self._start_controller()
        controller._start_singbox_runtime_plan.return_value = False
        start_proxy(controller, node, prev_active_core="singbox")
        phase, message = self._statuses(controller)[-1]
        self.assertEqual(phase, "error")
        self.assertIn("sing-box proxy runtime", message)


if __name__ == "__main__":
    unittest.main()
