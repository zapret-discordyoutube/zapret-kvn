"""A failed UDP server is named by its cause; a failed switch never selects the failed server.

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
from xray_fluent.application.server_selection import SelectionRequest, ServerSelection
from xray_fluent.application.transition_outcome import (
    GENERIC_FAILURE,
    FailureRank,
    TransitionFailure,
    TransitionOutcome,
    failure_status,
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


class FailedSwitchNeverSelectsTheFailedServerTests(unittest.TestCase):
    def _switch_controller(self, *, tun: bool):
        controller, _ = proxy_runtime.SingboxProxyRuntimeTests._restart_controller(self, tun=tun)
        serving = parse_single("hy2://old@hipse.example:443/#Hipse")
        target = parse_single("hy2://new@4stok.example:443/#4stok")
        controller._runtime_selected_node.return_value = target
        # Selection transaction: the target is pending, the serving server committed.
        controller.state.selected_node_id = serving.id
        controller._pending_transport_node_id = target.id
        plan = controller._plan_runtime_singbox.return_value if tun else controller._plan_proxy_runtime_singbox.return_value
        plan.hysteria_sidecar = SimpleNamespace(relay_port=11810)
        plan.is_hysteria_sidecar = True
        plan.sidecar_kind = "hysteria"
        controller._hysteria_contract.session.session_generation = 3
        controller._hysteria_recovery_active = False
        controller.singbox.is_running = True
        controller.hysteria.is_running = True
        return controller, serving, target

    def test_failed_hysteria_switch_reports_a_cause_and_keeps_the_old_runtime(self) -> None:
        for tun in (False, True):
            with self.subTest(tun=tun):
                controller, serving, _ = self._switch_controller(tun=tun)
                controller._prepare_hysteria_replacement.return_value = None
                restart = restart_runtime if tun else restart_proxy_runtime
                self.assertFalse(restart(controller, "node switched"))

                self.assertEqual(controller.state.selected_node_id, serving.id)
                controller.selection_changed.emit.assert_not_called()
                controller._fail_transition.assert_called_once_with("Новый сервер Hysteria2 не прошёл проверку.")
                # Steps never publish a failure themselves.
                self.assertNotIn("error", [c.args[0] for c in controller._set_connection_status.call_args_list])
                controller.singbox.stop.assert_not_called()
                controller._handle_unexpected_disconnect.assert_not_called()
                controller._settle_pending_transport_selection.assert_called_once_with()


class ServerSelectionTests(unittest.TestCase):
    def _selection(self, *ids):
        nodes = {node_id: SimpleNamespace(id=node_id, name=node_id) for node_id in ids}
        state = SimpleNamespace(selected_node_id=ids[0])
        events: list[str] = []
        selection = ServerSelection(
            lambda: state,
            find_node=lambda node_id: nodes.get(node_id),
            on_changed=lambda node: events.append(f"changed:{node.id}"),
            save=lambda: events.append("save"),
            log=lambda line: events.append(line),
        )
        return selection, state, nodes, events

    def test_connected_choice_is_pending_until_its_runtime_is_ready(self) -> None:
        selection, state, nodes, events = self._selection("hipse", "4stok")
        self.assertIs(selection.request("4stok", serving=True), SelectionRequest.PENDING)
        self.assertEqual(state.selected_node_id, "hipse")
        self.assertEqual(selection.target().id, "4stok")
        self.assertTrue(selection.commit(nodes["4stok"]))
        self.assertEqual(state.selected_node_id, "4stok")
        self.assertEqual(events, ["changed:4stok", "save"])

    def test_failed_switch_while_serving_never_selected_the_failed_server(self) -> None:
        selection, state, _, events = self._selection("hipse", "4stok")
        selection.request("4stok", serving=True)
        selection.settle(serving=True, keep_intent=True)
        self.assertEqual(state.selected_node_id, "hipse")
        self.assertIsNone(selection.pending_id)
        self.assertEqual(events, [])

    def test_failed_transition_with_nothing_serving_keeps_the_users_choice(self) -> None:
        selection, state, _, _ = self._selection("hipse", "4stok")
        selection.request("4stok", serving=True)
        selection.settle(serving=False, keep_intent=True)
        self.assertEqual(state.selected_node_id, "4stok")

    def test_automatic_replacement_is_never_kept(self) -> None:
        selection, state, _, _ = self._selection("hipse", "backup")
        selection.pending_id = "backup"
        selection.settle(serving=False, keep_intent=False)
        self.assertEqual(state.selected_node_id, "hipse")

    def test_back_to_serving_and_idempotent_requests(self) -> None:
        selection, state, _, events = self._selection("hipse", "4stok")
        self.assertIs(selection.request("hipse", serving=True), SelectionRequest.UNCHANGED)
        selection.request("4stok", serving=True)
        self.assertIs(selection.request("4stok", serving=True), SelectionRequest.UNCHANGED)
        self.assertIs(selection.request("hipse", serving=True), SelectionRequest.BACK_TO_SERVING)
        self.assertIsNone(selection.pending_id)
        self.assertEqual(events, [])

    def test_disconnected_choice_commits_at_once(self) -> None:
        selection, state, _, events = self._selection("hipse", "4stok")
        self.assertIs(selection.request("4stok", serving=False), SelectionRequest.COMMITTED)
        self.assertEqual(state.selected_node_id, "4stok")
        self.assertEqual(events, ["changed:4stok", "save"])

    def test_commit_rejects_a_runtime_for_another_target(self) -> None:
        selection, state, nodes, _ = self._selection("hipse", "4stok", "tinul")
        selection.request("tinul", serving=True)
        self.assertFalse(selection.commit(nodes["4stok"]))
        self.assertEqual(state.selected_node_id, "hipse")
        self.assertEqual(selection.pending_id, "tinul")

    def test_removed_target_falls_back_to_the_serving_server(self) -> None:
        selection, _, nodes, _ = self._selection("hipse", "4stok")
        selection.request("4stok", serving=True)
        del nodes["4stok"]
        self.assertEqual(selection.target().id, "hipse")
        self.assertIsNone(selection.pending_id)


class SignatureFollowsTheSwitchTargetTests(unittest.TestCase):
    def test_desired_runtime_signature_uses_the_pending_target(self) -> None:
        # E2E (31.10.2026): with the committed server in the signature a
        # pending Hysteria switch looked unchanged, the coordinator chose a
        # full reconnect and stopped the serving connection first.
        from xray_fluent.application import signature_service

        serving = SimpleNamespace(id="hipse")
        target = SimpleNamespace(id="4stok")
        controller = SimpleNamespace(selected_node=serving, _runtime_selected_node=lambda: target)
        self.assertIs(signature_service._target_node(controller), target)
        controller._runtime_selected_node = lambda: None
        self.assertIs(signature_service._target_node(controller), serving)


class TransitionOutcomeTests(unittest.TestCase):
    def test_most_specific_cause_wins_and_ties_keep_the_first(self) -> None:
        outcome = TransitionOutcome()
        outcome.fail("Не удалось запустить sing-box proxy runtime.")
        outcome.fail("второй общий текст")
        self.assertEqual(outcome.failure.message, "Не удалось запустить sing-box proxy runtime.")
        outcome.fail("hysteria core text", FailureRank.CORE)
        cause = udp_unanswered_message("4stok", "Hysteria2")
        outcome.fail(cause, FailureRank.CAUSE)
        outcome.fail("generic after the cause")
        self.assertEqual(outcome.take().message, cause)
        self.assertIsNone(outcome.failure)

    def test_security_outranks_every_other_cause(self) -> None:
        outcome = TransitionOutcome()
        outcome.fail(udp_unanswered_message("x", "Hysteria2"), FailureRank.CAUSE)
        outcome.fail("pin mismatch", FailureRank.SECURITY)
        self.assertEqual(outcome.failure.message, "pin mismatch")

    def test_status_is_derived_from_what_still_runs(self) -> None:
        cause = TransitionFailure("Сервер «4stok» не ответил по UDP.", FailureRank.CAUSE)
        self.assertEqual(
            failure_status(cause, connected=True, serving_name="Hipse"),
            ("running", "Сервер «4stok» не ответил по UDP. Соединение осталось на «Hipse».", "warning-long"),
        )
        self.assertEqual(failure_status(cause, connected=False), ("error", cause.message, "error"))
        self.assertEqual(failure_status(None, connected=False)[1], GENERIC_FAILURE)


class StartFailureReportsThroughTheOutcomeTests(unittest.TestCase):
    def _start_controller(self):
        node = parse_single("hy2://secret@4stok.example:443/#4stok")
        plan = SimpleNamespace(
            used_selected_node=True, source_path=proxy_runtime.TEMPLATE_PATH, is_hybrid=False,
            is_hysteria_sidecar=True, sidecar_kind="hysteria", amnezia_sidecar=None,
            proxy_ports_changed=False, outcome="hysteria_sidecar",
        )
        controller = Mock()
        controller._plan_proxy_runtime_singbox.return_value = plan
        controller._plan_runtime_singbox.return_value = plan
        controller._start_singbox_runtime_plan.return_value = False
        return bridge_controller(controller), node

    def test_failed_start_reports_a_step_message_and_publishes_nothing(self) -> None:
        for start, text in ((start_proxy, "sing-box proxy runtime"), (start_tun, "sing-box sidecar runtime")):
            with self.subTest(start=start.__name__):
                controller, node = self._start_controller()
                self.assertIsNone(start(controller, node, prev_active_core="xray"))
                (message,), _ = controller._fail_transition.call_args
                self.assertIn(text, message)
                self.assertEqual(controller._active_core, "xray")
                self.assertNotIn("error", [c.args[0] for c in controller._set_connection_status.call_args_list])


if __name__ == "__main__":
    unittest.main()
