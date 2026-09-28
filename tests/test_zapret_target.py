"""Selected-server bypass: endpoint kinds, the rule choice and the connection gate."""

from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from PyQt6.QtCore import QCoreApplication

from xray_fluent.application.server_bypass import ServerBypass
from xray_fluent.engines.zapret.command import ServerRule
from xray_fluent.engines.zapret.endpoint import ResolvedEndpoint, ServerEndpoint, endpoint_for_node
from xray_fluent.engines.zapret.manager import ZapretManager, ZapretPlan
from xray_fluent.engines.zapret.strategies import (
    load_strategy_catalog,
    server_strategy,
    validate_custom_strategy,
)
from xray_fluent.importer.link_parser import parse_single
from xray_fluent.profiles.models import AppSettings, Node, ZapretTargetSettings

_APP = QCoreApplication.instance() or QCoreApplication([])

_HY2 = "hy2://secret@203.0.113.7:443/?insecure=1&pinSHA256=" + "a" * 64


def _vless(server: str = "one.example") -> Node:
    return Node(
        name="vless", scheme="vless", server=server, port=443,
        outbound={"protocol": "vless", "streamSettings": {"network": "tcp"}},
    )


class EndpointTests(unittest.TestCase):
    def test_tcp_proxy(self) -> None:
        endpoint = endpoint_for_node(parse_single("vless://00000000-0000-4000-8000-000000000001@example.com:443"))
        self.assertEqual((endpoint.kind, endpoint.transport, endpoint.ports), ("tcp", "tcp", ("443",)))

    def test_vless_over_quic_and_kcp_is_a_quic_server(self) -> None:
        for network in ("quic", "kcp"):
            node = parse_single(f"vless://00000000-0000-4000-8000-000000000001@example.com:443?type={network}")
            with self.subTest(network=network):
                endpoint = endpoint_for_node(node)
                self.assertEqual((endpoint.kind, endpoint.transport), ("quic", "udp"))

    def test_hysteria_port_hopping_becomes_a_winws_range(self) -> None:
        node = parse_single("hy2://secret@one.example:443,5000-5010/?insecure=1&pinSHA256=" + "a" * 64)
        self.assertEqual(endpoint_for_node(node).ports, ("443", "5000-5010"))

    def test_wireguard_uses_every_peer(self) -> None:
        node = Node(
            name="wg", scheme="wireguard",
            outbound={"type": "wireguard", "peers": [
                {"address": "one.example", "port": 51820},
                {"address": "2001:db8::7", "port": 51821},
            ]},
        )
        endpoint = endpoint_for_node(node)
        self.assertEqual(endpoint.kind, "wireguard")
        self.assertEqual(endpoint.hosts, ("one.example", "2001:db8::7"))
        self.assertEqual(endpoint.ports, ("51820", "51821"))

    def test_unknown_outbound_is_not_targeted(self) -> None:
        self.assertIsNone(endpoint_for_node(Node(outbound={"type": "ssh"})))
        self.assertIsNone(endpoint_for_node(None))


class RuleChoiceTests(unittest.TestCase):
    def test_alt9_is_the_exact_tcp_default(self) -> None:
        strategy = server_strategy(ZapretTargetSettings(), ServerEndpoint("tcp", ("one.example",), ("443",)))
        self.assertEqual(strategy.args, ("--lua-desync=hostfakesplit:host=ozon.ru:tcp_ts=-1000:tcp_md5:repeats=4",))

    def test_tcp_off_means_the_preset_decides(self) -> None:
        settings = ZapretTargetSettings(tcp_proxy_enabled=False)
        self.assertIsNone(server_strategy(settings, ServerEndpoint("tcp", ("one.example",), ("443",))))

    def test_udp_off_means_hands_off(self) -> None:
        for kind in ("quic", "wireguard"):
            with self.subTest(kind=kind):
                strategy = server_strategy(ZapretTargetSettings(), ServerEndpoint(kind, ("one.example",), ("443",)))
                self.assertTrue(strategy.is_pass)

    def test_quic_and_wireguard_have_their_own_strategies(self) -> None:
        settings = ZapretTargetSettings(
            quic_proxy_enabled=True, wireguard_enabled=True,
            quic_strategy_id="fake_default_quic", wireguard_strategy_id="fake_zero",
        )
        quic = server_strategy(settings, ServerEndpoint("quic", ("a",), ("443",)))
        wireguard = server_strategy(settings, ServerEndpoint("wireguard", ("a",), ("51820",)))
        self.assertEqual((quic.strategy_id, wireguard.strategy_id), ("fake_default_quic", "fake_zero"))

    def test_missing_strategy_is_an_error_not_a_silent_default(self) -> None:
        settings = ZapretTargetSettings(quic_proxy_enabled=True, quic_strategy_id="no_such_strategy")
        with self.assertRaisesRegex(ValueError, "no_such_strategy"):
            server_strategy(settings, ServerEndpoint("quic", ("a",), ("443",)))

    def test_own_strategy_is_profile_scoped(self) -> None:
        self.assertEqual(
            validate_custom_strategy("# note\n--payload=tls_client_hello\n--lua-desync=fake:repeats=2"),
            ("--payload=tls_client_hello", "--lua-desync=fake:repeats=2"),
        )
        for forbidden in ("--new", "--filter-tcp=443", "--wf-tcp-out=443", "--blob=x:y", "--payload=all"):
            with self.subTest(forbidden=forbidden), self.assertRaises(ValueError):
                validate_custom_strategy(forbidden)

    def test_composite_catalog_strategies_are_loaded(self) -> None:
        entry = load_strategy_catalog("tcp")["general_alt_all_sites"]
        self.assertEqual(entry.args[0], "--payload=tls_client_hello")


class SettingsTests(unittest.TestCase):
    def test_fresh_state_defaults(self) -> None:
        settings = AppSettings.from_dict({"zapret_preset": "Default"}).zapret_target
        self.assertTrue(settings.tcp_proxy_enabled)
        self.assertFalse(settings.quic_proxy_enabled)
        self.assertEqual(settings.strategy_id("tcp"), "alt9")
        self.assertEqual(settings.strategy_id("wireguard"), "general_bf_32")

    def test_shared_udp_strategy_seeds_both_udp_kinds(self) -> None:
        settings = ZapretTargetSettings.from_dict({
            "wireguard_enabled": True, "udp_strategy_id": "fake_zero", "udp_custom_args": "--lua-desync=pass",
        })
        self.assertEqual(settings.quic_strategy_id, "fake_zero")
        self.assertEqual(settings.wireguard_strategy_id, "fake_zero")
        self.assertEqual(settings.wireguard_custom_args, "--lua-desync=pass")

    def test_older_builds_still_read_a_udp_strategy(self) -> None:
        data = ZapretTargetSettings(quic_strategy_id="fake_zero", wireguard_strategy_id="fake_default_quic").to_dict()
        self.assertEqual(data["udp_strategy_id"], "fake_zero")
        self.assertEqual(ZapretTargetSettings.from_dict(data).wireguard_strategy_id, "fake_default_quic")

    def test_with_kind_changes_only_that_kind(self) -> None:
        settings = ZapretTargetSettings().with_kind(
            "wireguard", enabled=True, strategy_id="fake_zero", custom_args="",
        )
        self.assertTrue(settings.wireguard_enabled)
        self.assertEqual(settings.wireguard_strategy_id, "fake_zero")
        self.assertEqual(settings.quic_strategy_id, "general_bf_32")
        self.assertTrue(settings.tcp_proxy_enabled)


# ── the connection gate ──────────────────────────────────────────────────


class FakeZapret(ZapretManager):
    """Real revision bookkeeping, no process: tests start it by hand."""

    def __init__(self) -> None:
        super().__init__()
        self.fake_running = False
        self.launches: list[tuple[ZapretPlan, int]] = []

    @property
    def running(self) -> bool:  # type: ignore[override]
        return self.fake_running

    @property
    def starting(self) -> bool:  # type: ignore[override]
        return False

    def _start_runner(self, plan: ZapretPlan, revision: int) -> None:
        self.fake_running = False
        self.launches.append((plan, revision))

    def process_started(self) -> None:
        plan, revision = self.launches[-1]
        self._process_plan = plan
        self.fake_running = True
        self._on_started(revision)


def _controller(node: Node, **overrides) -> Mock:
    controller = Mock()
    controller.zapret = FakeZapret()
    controller.state.settings.zapret_target = overrides.pop("settings", ZapretTargetSettings())
    controller.state.settings.zapret_preset = overrides.pop("preset", "Default")
    controller._runtime_selected_node.return_value = node
    controller.selected_node = node
    controller._active_config_uses_selected_node.return_value = True
    controller.connected = False
    controller._transition_generation = 5
    controller._desired_connected = True
    controller._hysteria_recovery_active = False
    controller._transition_active = False
    controller._transition_scheduled = False
    controller._transition_pending = False
    controller._transition_reason = "connect"
    for key, value in overrides.items():
        setattr(controller, key, value)
    return controller


def _resolved(node: Node, *ips: str) -> ResolvedEndpoint:
    return ResolvedEndpoint(endpoint_for_node(node), ips or ("203.0.113.1",))


class GateTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = patch("xray_fluent.application.server_bypass.EndpointResolver")
        self.resolver = patcher.start()
        self.addCleanup(patcher.stop)
        remember = patch("xray_fluent.application.node_runtime_service.remember_country_addresses")
        remember.start()
        self.addCleanup(remember.stop)

    def _bypass(self, controller: Mock) -> ServerBypass:
        return ServerBypass(controller)

    def test_uninvolved_zapret_still_resolves_but_starts_nothing(self) -> None:
        """The lookup teaches log redaction the server IPs before a core starts."""

        for node, settings in (
            (_vless(), ZapretTargetSettings(tcp_proxy_enabled=False)),
            (parse_single(_HY2), ZapretTargetSettings()),
        ):
            with self.subTest(kind=endpoint_for_node(node).kind):
                self.resolver.reset_mock()
                controller = _controller(node, settings=settings)
                bypass = self._bypass(controller)
                self.assertTrue(bypass.prepare(5))
                self.resolver.assert_called_once()
                bypass._on_resolved(5, endpoint_for_node(node), _resolved(node), None)
                self.assertEqual(controller.zapret.launches, [])
                self.assertFalse(bypass.waiting)
                controller._schedule_transition_drain.assert_called_once()
                self.assertTrue(bypass.ready_for(node))

    def test_dns_failure_is_harmless_when_zapret_is_uninvolved(self) -> None:
        node = _vless()
        controller = _controller(node, settings=ZapretTargetSettings(tcp_proxy_enabled=False))
        bypass = self._bypass(controller)
        bypass.prepare(5)
        bypass._on_resolved(5, endpoint_for_node(node), None, OSError("offline"))
        controller._cancel_target_transition.assert_not_called()
        controller._schedule_transition_drain.assert_called_once_with(0)

    def test_missing_preset_file_falls_back_to_default(self) -> None:
        controller = _controller(_vless(), preset="Renamed away")
        bypass = self._bypass(controller)
        with patch("xray_fluent.application.server_bypass.presets.default_preset", return_value="Default"):
            self.assertTrue(bypass.prepare(5))
        self.assertEqual(controller.state.settings.zapret_preset, "Default")
        controller._cancel_target_transition.assert_not_called()

    def test_restart_timeout_outside_a_transition_fails_closed(self) -> None:
        controller = _controller(_vless(), connected=True)
        bypass = self._bypass(controller)
        revision = controller.zapret.apply(ZapretPlan("Default"))
        controller.zapret._on_apply_timeout(revision)
        controller._request_stop.assert_called_once_with("zapret stopped", quiet=True)

    def test_manual_start_under_a_protected_session_goes_through_the_coordinator(self) -> None:
        controller = _controller(_vless(), connected=True)
        bypass = self._bypass(controller)
        bypass.start_manual("Other")
        self.assertEqual(controller.state.settings.zapret_preset, "Other")
        controller._request_transition.assert_called_once_with("Zapret preset changed")
        self.assertEqual(controller.zapret.launches, [])
        self.resolver.assert_not_called()

    def test_manual_start_without_a_session_restarts_directly(self) -> None:
        controller = _controller(_vless(), _desired_connected=False)
        bypass = self._bypass(controller)
        bypass.start_manual("Other")
        controller._request_transition.assert_not_called()
        self.resolver.assert_called_once()

    def test_pool_addresses_are_learned_once_in_the_background(self) -> None:
        controller = _controller(_vless())
        controller.xray_outbound_pool.return_value.nodes = [_vless("one.example"), _vless("two.example")]
        bypass = self._bypass(controller)
        jobs = []
        self.assertTrue(bypass.learn_pool_addresses(submit=jobs.append))
        self.assertFalse(bypass.learn_pool_addresses(submit=jobs.append))
        with (
            patch("xray_fluent.application.server_bypass.resolve_host") as resolve,
            patch("xray_fluent.application.server_bypass.time.sleep"),
        ):
            resolve.side_effect = [OSError("offline"), {"203.0.113.2"}]
            jobs[0]()
        self.assertEqual([c.args[0] for c in resolve.call_args_list], ["one.example", "two.example"])
        self.assertEqual(controller.zapret.launches, [])

    def test_required_rule_resolves_then_waits_for_its_process(self) -> None:
        node = _vless()
        controller = _controller(node)
        bypass = self._bypass(controller)

        self.assertTrue(bypass.prepare(5))
        self.resolver.assert_called_once()
        self.assertTrue(bypass.waiting_for(5))
        self.assertFalse(bypass.ready_for(node))

        with patch("xray_fluent.application.node_runtime_service.remember_country_addresses") as remember:
            bypass._on_resolved(5, endpoint_for_node(node), _resolved(node), None)
        remember.assert_called_once()
        plan, _revision = controller.zapret.launches[-1]
        self.assertEqual(plan.preset, "Default")
        self.assertEqual(plan.rule.strategy.strategy_id, "alt9")
        self.assertTrue(bypass.waiting_for(5))
        controller._schedule_transition_drain.assert_not_called()

        controller.zapret.process_started()

        self.assertFalse(bypass.waiting)
        self.assertTrue(bypass.ready_for(node))
        controller._schedule_transition_drain.assert_called_once()

    def test_udp_off_with_zapret_running_gets_a_pass_rule(self) -> None:
        node = parse_single(_HY2)
        controller = _controller(node)
        controller.zapret.apply(ZapretPlan("Default"))
        controller.zapret.process_started()
        bypass = self._bypass(controller)

        self.assertTrue(bypass.prepare(5))
        bypass._on_resolved(5, endpoint_for_node(node), _resolved(node, "203.0.113.7"), None)
        plan, _ = controller.zapret.launches[-1]
        self.assertTrue(plan.rule.strategy.is_pass)
        controller.zapret.process_started()
        self.assertTrue(bypass.ready_for(node))

    def test_dns_answer_of_an_old_generation_is_discarded(self) -> None:
        node = _vless()
        controller = _controller(node)
        bypass = self._bypass(controller)
        bypass.prepare(5)
        controller._transition_generation = 6
        bypass._on_resolved(5, endpoint_for_node(node), _resolved(node), None)
        self.assertEqual(controller.zapret.launches, [])

    def test_plan_outcome_during_dns_does_not_resume(self) -> None:
        node = _vless()
        controller = _controller(node)
        bypass = self._bypass(controller)
        bypass.prepare(5)
        controller.zapret.plan_applied.emit(99)
        controller.zapret.plan_failed.emit(99, "timeout")
        controller._schedule_transition_drain.assert_not_called()
        controller._set_connection_status.assert_not_called()
        self.assertTrue(bypass.waiting_for(5))

    def test_dns_failure_cancels_a_required_rule_and_names_every_host(self) -> None:
        node = Node(
            name="wg", scheme="wireguard",
            outbound={"type": "wireguard", "peers": [
                {"address": "one.example", "port": 51820}, {"address": "two.example", "port": 51820},
            ]},
        )
        controller = _controller(node, settings=ZapretTargetSettings(wireguard_enabled=True))
        bypass = self._bypass(controller)
        bypass.prepare(5)
        bypass._on_resolved(5, endpoint_for_node(node), None, OSError(11001, "getaddrinfo failed"))
        controller._log.assert_called_once_with(
            "[zapret] DNS выбранного сервера host=one.example, two.example "
            "завершился ошибкой: [Errno 11001] getaddrinfo failed"
        )
        controller._cancel_target_transition.assert_called_once()

    def test_connected_server_change_stops_the_old_tunnel_before_dns(self) -> None:
        node = _vless("new.example")
        controller = _controller(node, connected=True)
        bypass = self._bypass(controller)

        self.assertTrue(bypass.prepare(12))

        controller._run_prestop.assert_called_once()
        args, _kwargs = controller._run_prestop.call_args
        self.assertEqual(args[0], 12)
        self.resolver.assert_not_called()
        args[1]()  # the coordinator finished stopping
        self.resolver.assert_called_once()

    def test_hysteria_recovery_does_not_stop_the_old_generation(self) -> None:
        node = parse_single(_HY2)
        controller = _controller(
            node, settings=ZapretTargetSettings(quic_proxy_enabled=True), _hysteria_recovery_active=True,
        )
        bypass = self._bypass(controller)
        bypass.prepare(5)
        controller.connected = True
        bypass._on_resolved(5, endpoint_for_node(node), _resolved(node, "203.0.113.7"), None)
        controller._run_prestop.assert_not_called()
        self.assertEqual(len(controller.zapret.launches), 1)

    def test_empty_preset_falls_back_to_default(self) -> None:
        controller = _controller(_vless(), preset="")
        bypass = self._bypass(controller)
        with patch("xray_fluent.application.server_bypass.presets.default_preset", return_value="Default"):
            self.assertTrue(bypass.prepare(21))
        controller._cancel_target_transition.assert_not_called()
        self.assertEqual(controller.state.settings.zapret_preset, "Default")
        controller.schedule_save.assert_called_once()
        self.resolver.assert_called_once()

    def test_no_presets_at_all_cancel_with_a_message(self) -> None:
        controller = _controller(_vless(), preset="")
        bypass = self._bypass(controller)
        with patch("xray_fluent.application.server_bypass.presets.default_preset", return_value=""):
            self.assertTrue(bypass.prepare(22))
        controller._cancel_target_transition.assert_called_once()
        self.resolver.assert_not_called()

    def test_failed_rule_cancels_the_connection(self) -> None:
        node = _vless()
        controller = _controller(node)
        controller._has_residual_processes.return_value = False
        bypass = self._bypass(controller)
        bypass.prepare(5)
        bypass._on_resolved(5, endpoint_for_node(node), _resolved(node), None)
        _plan, revision = controller.zapret.launches[-1]

        controller.zapret._on_apply_timeout(revision)

        self.assertFalse(controller._desired_connected)
        self.assertFalse(bypass.waiting)
        controller._set_connection_status.assert_called_once()
        controller._schedule_transition_drain.assert_not_called()

    def test_core_start_fence_rejects_an_unready_rule(self) -> None:
        controller = _controller(_vless())
        bypass = self._bypass(controller)
        self.assertFalse(bypass.allows_core_start(controller.selected_node))
        controller._set_connection_status.assert_called_once()

    def test_core_start_fence_ignores_a_node_the_config_does_not_use(self) -> None:
        controller = _controller(_vless())
        bypass = self._bypass(controller)
        self.assertTrue(bypass.allows_core_start(controller.selected_node, used_selected_node=False))

    def test_losing_zapret_stops_a_session_that_needs_it(self) -> None:
        controller = _controller(_vless(), connected=True)
        bypass = self._bypass(controller)
        controller.zapret.stopped.emit()
        self.assertFalse(controller._desired_connected)
        controller._request_stop.assert_called_once_with("zapret stopped", quiet=True)
        controller.disconnect_current.assert_not_called()

    def test_losing_zapret_leaves_a_session_that_does_not_need_it(self) -> None:
        controller = _controller(_vless(), connected=True, settings=ZapretTargetSettings(tcp_proxy_enabled=False))
        self._bypass(controller)
        controller.zapret.stopped.emit()
        controller._request_stop.assert_not_called()

    def test_a_different_rule_is_not_ready(self) -> None:
        node = _vless()
        controller = _controller(node)
        other = ResolvedEndpoint(endpoint_for_node(_vless("other.example")), ("203.0.113.9",))
        controller.zapret.apply(ZapretPlan("Default", ServerRule(other, load_strategy_catalog("tcp")["alt9"])))
        controller.zapret.process_started()
        self.assertFalse(self._bypass(controller).ready_for(node))



class ApplyTargetSettingsTests(unittest.TestCase):
    """The page's «Применить» reaches the connection or winws2, never both."""

    def _controller(self, *, connected: bool, desired: bool, plan: ZapretPlan | None) -> Mock:
        controller = Mock()
        controller.connected = connected
        controller._desired_connected = desired
        controller.zapret.plan = plan
        controller.state.settings.zapret_preset = "Default"
        return controller

    def test_live_session_is_reconnected(self) -> None:
        from xray_fluent.application.controller import AppController

        controller = self._controller(connected=True, desired=True, plan=ZapretPlan("Default"))
        settings = ZapretTargetSettings(quic_proxy_enabled=True)
        AppController.apply_zapret_target_settings(controller, settings)
        self.assertIs(controller.state.settings.zapret_target, settings)
        controller._request_transition.assert_called_once_with("Zapret target strategy changed")
        controller.start_zapret.assert_not_called()

    def test_running_zapret_without_a_session_restarts(self) -> None:
        from xray_fluent.application.controller import AppController

        controller = self._controller(connected=False, desired=False, plan=ZapretPlan("Default"))
        AppController.apply_zapret_target_settings(controller, ZapretTargetSettings())
        controller.start_zapret.assert_called_once_with("Default")
        controller._request_transition.assert_not_called()

    def test_idle_only_saves(self) -> None:
        from xray_fluent.application.controller import AppController

        controller = self._controller(connected=False, desired=False, plan=None)
        AppController.apply_zapret_target_settings(controller, ZapretTargetSettings())
        controller.schedule_save.assert_called_once_with()
        controller.start_zapret.assert_not_called()
        controller._request_transition.assert_not_called()


if __name__ == "__main__":
    unittest.main()
