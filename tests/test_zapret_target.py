from __future__ import annotations

import unittest
from unittest.mock import patch
from unittest.mock import Mock

from xray_fluent.app_controller import AppController
from xray_fluent.link_parser import parse_single
from xray_fluent.models import AppSettings, Node, ZapretTargetSettings
from xray_fluent.zapret_manager import ZapretManager
from xray_fluent.zapret_blobs import lua_init_arguments
from xray_fluent.zapret_target import (
    ResolvedZapretEndpoint,
    ZapretEndpointSpec,
    endpoint_spec_for_node,
    load_strategy_catalog,
    strategy_for_target,
    validate_custom_strategy,
)


class ZapretTargetClassificationTests(unittest.TestCase):
    def test_tcp_proxy_is_enabled_by_default(self) -> None:
        node = parse_single(
            "vless://00000000-0000-4000-8000-000000000001@example.com:443"
        )
        spec = endpoint_spec_for_node(node)
        self.assertEqual((spec.group, spec.transport, spec.ports), ("tcp_proxy", "tcp", ("443",)))

    def test_vless_quic_and_kcp_use_udp_group(self) -> None:
        for network in ("quic", "kcp"):
            node = parse_single(
                "vless://00000000-0000-4000-8000-000000000001@example.com:443"
                f"?type={network}"
            )
            with self.subTest(network=network):
                spec = endpoint_spec_for_node(node)
                self.assertEqual((spec.group, spec.transport), ("quic_proxy", "udp"))

    def test_hysteria_port_hopping_becomes_winws_range(self) -> None:
        node = parse_single("hy2://secret@one.example:443,5000-5010/?insecure=1#one")
        spec = endpoint_spec_for_node(node)
        self.assertEqual(spec.ports, ("443", "5000-5010"))

    def test_wireguard_uses_all_peer_endpoints(self) -> None:
        node = Node(
            name="wg",
            scheme="wireguard",
            outbound={
                "type": "wireguard",
                "peers": [
                    {"address": "one.example", "port": 51820},
                    {"address": "2001:db8::7", "port": 51821},
                ],
            },
        )
        spec = endpoint_spec_for_node(node)
        self.assertEqual(spec.group, "wireguard")
        self.assertEqual(spec.hosts, ("one.example", "2001:db8::7"))
        self.assertEqual(spec.ports, ("51820", "51821"))

    def test_unknown_native_outbound_is_not_targeted(self) -> None:
        self.assertIsNone(endpoint_spec_for_node(Node(outbound={"type": "ssh"})))


class ZapretTargetStrategyTests(unittest.TestCase):
    def test_alt9_is_exact_default(self) -> None:
        entry = load_strategy_catalog("tcp")["alt9"]
        self.assertEqual(
            entry.args,
            ("--lua-desync=hostfakesplit:host=ozon.ru:tcp_ts=-1000:tcp_md5:repeats=4",),
        )

    def test_disabled_udp_gets_exact_pass_profile(self) -> None:
        spec = ZapretEndpointSpec("quic_proxy", "udp", ("one.example",), ("443",))
        entry = strategy_for_target(ZapretTargetSettings(), spec)
        self.assertEqual(entry.args, ("--lua-desync=pass",))

    def test_enabled_udp_without_strategy_is_rejected(self) -> None:
        settings = ZapretTargetSettings(quic_proxy_enabled=True)
        spec = ZapretEndpointSpec("quic_proxy", "udp", ("one.example",), ("443",))
        with self.assertRaisesRegex(ValueError, "UDP"):
            strategy_for_target(settings, spec)

    def test_custom_strategy_is_profile_scoped(self) -> None:
        self.assertEqual(
            validate_custom_strategy("# note\n--lua-desync=fake:repeats=2"),
            ("--lua-desync=fake:repeats=2",),
        )
        for forbidden in ("--new", "--filter-tcp=443", "--wf-tcp-out=443", "--blob=x:y"):
            with self.subTest(forbidden=forbidden), self.assertRaises(ValueError):
                validate_custom_strategy(forbidden)

    def test_old_settings_load_nested_defaults(self) -> None:
        settings = AppSettings.from_dict({"zapret_preset": "Default"})
        self.assertTrue(settings.zapret_target.tcp_proxy_enabled)
        self.assertFalse(settings.zapret_target.quic_proxy_enabled)
        self.assertEqual(settings.zapret_target.tcp_strategy_id, "alt9")


class ZapretTargetArgumentTests(unittest.TestCase):
    def test_target_profile_is_first_and_does_not_mutate_preset(self) -> None:
        original = [
            "--wf-tcp-out=80",
            "--filter-udp=443",
            "--lua-desync=pass",
        ]
        spec = ZapretEndpointSpec("tcp_proxy", "tcp", ("one.example",), ("443",), "one")
        target = ResolvedZapretEndpoint(spec, ("2001:0db8::7", "203.0.113.7", "203.0.113.7"))
        strategy = load_strategy_catalog("tcp")["alt9"]

        updated = ZapretManager._with_target_profile(original, target, strategy)

        self.assertEqual(original, ["--wf-tcp-out=80", "--filter-udp=443", "--lua-desync=pass"])
        self.assertIn("--wf-tcp-out=80,443", updated)
        name_index = updated.index("--name=ZapretKVN: выбранный сервер")
        self.assertLess(name_index, updated.index("--filter-udp=443"))
        self.assertEqual(updated[name_index + 1], "--filter-tcp=443")
        self.assertEqual(updated[name_index + 2], "--ipset-ip=203.0.113.7,2001:db8::7")

    def test_tcp_and_udp_capture_filters_are_not_mixed(self) -> None:
        args = ["--wf-tcp-out=443", "--filter-tcp=443", "--lua-desync=pass"]
        spec = ZapretEndpointSpec("quic_proxy", "udp", ("one.example",), ("8443",))
        target = ResolvedZapretEndpoint(spec, ("203.0.113.8",))
        strategy = load_strategy_catalog("udp")["general_bf_32"]
        updated = ZapretManager._with_target_profile(args, target, strategy)
        self.assertIn("--wf-tcp-out=443", updated)
        self.assertIn("--wf-udp-out=8443", updated)
        self.assertIn("--filter-udp=8443", updated)
        self.assertIn("--blob=quic_google:@bin/quic_initial_www_google_com.bin", updated)

    def test_repeated_global_capture_filters_keep_every_original_port(self) -> None:
        args = [
            "--wf-tcp-out=80",
            "--wf-tcp-out=443,8080",
            "--filter-tcp=80",
            "--lua-desync=pass",
        ]
        spec = ZapretEndpointSpec("tcp_proxy", "tcp", ("one.example",), ("8443",))
        target = ResolvedZapretEndpoint(spec, ("203.0.113.8",))
        updated = ZapretManager._with_target_profile(
            args,
            target,
            load_strategy_catalog("tcp")["alt9"],
        )
        captures = [arg for arg in updated if arg.startswith("--wf-tcp-out=")]
        self.assertEqual(captures, ["--wf-tcp-out=80,443,8080,8443"])

    def test_extension_lua_is_injected_after_the_core_libraries(self) -> None:
        """Extension lua defines functions on top of the core API, so order matters."""

        spec = ZapretEndpointSpec("tcp_proxy", "tcp", ("one.example",), ("443",))
        target = ResolvedZapretEndpoint(spec, ("203.0.113.8",))
        entry = load_strategy_catalog("tcp")["fakemultisplit_google_ultra"]
        updated = ZapretManager._with_target_profile([], target, entry)
        lua = [arg for arg in updated if arg.startswith("--lua-init=")]
        self.assertEqual(
            lua,
            [
                "--lua-init=@lua/zapret-lib.lua",
                "--lua-init=@lua/zapret-antidpi.lua",
                "--lua-init=@lua/fakemultisplit.lua",
            ],
        )

    def test_core_only_strategy_gets_no_extension_lua(self) -> None:
        spec = ZapretEndpointSpec("tcp_proxy", "tcp", ("one.example",), ("443",))
        target = ResolvedZapretEndpoint(spec, ("203.0.113.8",))
        updated = ZapretManager._with_target_profile(
            [], target, load_strategy_catalog("tcp")["multisplit_pos1"]
        )
        lua = [arg for arg in updated if arg.startswith("--lua-init=")]
        self.assertEqual(len(lua), 2)

    def test_every_catalog_strategy_gets_the_lua_it_needs(self) -> None:
        """Whole-catalog sweep: any extension function implies its lua-init."""

        for transport in ("tcp", "udp"):
            spec = ZapretEndpointSpec(
                "tcp_proxy" if transport == "tcp" else "quic_proxy",
                transport, ("one.example",), ("443",),
            )
            target = ResolvedZapretEndpoint(spec, ("203.0.113.8",))
            for entry in load_strategy_catalog(transport).values():
                required = lua_init_arguments(entry.args)
                if not required:
                    continue
                with self.subTest(transport=transport, strategy=entry.strategy_id):
                    updated = ZapretManager._with_target_profile([], target, entry)
                    core = updated.index("--lua-init=@lua/zapret-antidpi.lua")
                    for extension in required:
                        self.assertIn(extension, updated)
                        self.assertGreater(updated.index(extension), core)

    def test_every_catalog_blob_dependency_is_injected(self) -> None:
        for transport in ("tcp", "udp"):
            for entry in load_strategy_catalog(transport).values():
                with self.subTest(transport=transport, strategy=entry.strategy_id):
                    spec = ZapretEndpointSpec(
                        "tcp_proxy" if transport == "tcp" else "quic_proxy",
                        transport,
                        ("one.example",),
                        ("443",),
                    )
                    updated = ZapretManager._with_target_profile(
                        [],
                        ResolvedZapretEndpoint(spec, ("203.0.113.8",)),
                        entry,
                    )
                    for dependency in entry.blob_dependencies:
                        self.assertTrue(
                            any(arg.startswith(f"--blob={dependency}:") for arg in updated),
                            dependency,
                        )

    def test_fresh_resolution_resolves_every_host(self) -> None:
        spec = ZapretEndpointSpec(
            "wireguard", "udp", ("one.example", "two.example"), ("51820",),
        )
        with patch.object(
            ZapretManager,
            "_resolve_server_ips",
            side_effect=({"203.0.113.1"}, {"2001:db8::2", "203.0.113.1"}),
        ) as resolver:
            result = ZapretManager.resolve_target(spec)
        self.assertEqual(resolver.call_count, 2)
        self.assertEqual(result.ips, ("203.0.113.1", "2001:db8::2"))


class ZapretTargetBarrierTests(unittest.TestCase):
    def test_stale_dns_generation_is_discarded(self) -> None:
        controller = Mock()
        controller._transition_generation = 8
        spec = ZapretEndpointSpec("tcp_proxy", "tcp", ("one.example",), ("443",))
        endpoint = ResolvedZapretEndpoint(spec, ("203.0.113.1",))

        AppController._on_proxy_protection_resolved(controller, 7, spec, endpoint, None)

        controller.zapret.apply_resolved_target.assert_not_called()

    def test_core_start_fence_rejects_unready_profile(self) -> None:
        controller = Mock()
        controller.zapret.target_profile_is_ready.return_value = False
        node = Node(name="one", scheme="vless", server="one.example", port=443)

        allowed = AppController.target_profile_allows_core_start(controller, node)

        self.assertFalse(allowed)
        controller._set_connection_status.assert_called_once()

    def test_zapret_loss_disables_reconnect_and_stops_vpn(self) -> None:
        controller = Mock()
        controller.connected = True
        controller._transition_generation = 5
        controller.zapret.target_requires_zapret.return_value = True

        AppController._on_zapret_stopped_safety(controller)

        self.assertFalse(controller._desired_connected)
        self.assertFalse(controller._transition_pending)
        self.assertEqual(controller._transition_generation, 6)
        controller.disconnect_current.assert_called_once_with(
            disable_proxy=True,
            emit_status=False,
        )

    def test_server_change_stops_old_vpn_before_dns_worker(self) -> None:
        controller = Mock()
        controller.selected_node = Node(
            name="new",
            scheme="vless",
            server="new.example",
            port=443,
            outbound={"protocol": "vless", "streamSettings": {"network": "tcp"}},
        )
        spec = endpoint_spec_for_node(controller.selected_node)
        controller.state.settings.zapret_target = ZapretTargetSettings()
        controller.state.settings.zapret_preset = "Default"
        controller._active_config_uses_selected_node.return_value = True
        controller.zapret.target_spec.return_value = spec
        controller.zapret.target_requires_zapret.return_value = True
        controller.zapret.target_profile_is_ready.return_value = False
        controller.connected = True
        controller.disconnect_current.return_value = True
        controller._proxy_protection_workers = {}
        controller._proxy_protection_wait_generation = 0
        controller._proxy_protection_wait_token = 0
        worker = Mock()

        with patch("xray_fluent.app_controller.TargetProfileResolver", return_value=worker):
            waiting = AppController._prepare_proxy_protection(controller, 12)

        self.assertTrue(waiting)
        controller.disconnect_current.assert_called_once_with(
            disable_proxy=False,
            emit_status=False,
        )
        self.assertTrue(controller._desired_connected)
        worker.start.assert_called_once()

    def test_empty_preset_falls_back_instead_of_cancelling(self) -> None:
        """A fresh install must connect on the default preset, not be refused."""

        controller = Mock()
        controller.selected_node = Node(
            name="new",
            scheme="vless",
            server="new.example",
            port=443,
            outbound={"protocol": "vless", "streamSettings": {"network": "tcp"}},
        )
        spec = endpoint_spec_for_node(controller.selected_node)
        controller.state.settings.zapret_target = ZapretTargetSettings()
        controller.state.settings.zapret_preset = ""
        controller._active_config_uses_selected_node.return_value = True
        controller.zapret.target_spec.return_value = spec
        controller.zapret.target_requires_zapret.return_value = True
        controller.zapret.target_profile_is_ready.return_value = True
        controller.zapret.default_preset.return_value = "Default"
        controller.connected = False
        controller._proxy_protection_workers = {}
        controller._proxy_protection_wait_generation = 0
        controller._proxy_protection_wait_token = 0
        worker = Mock()

        with patch("xray_fluent.app_controller.TargetProfileResolver", return_value=worker):
            waiting = AppController._prepare_proxy_protection(controller, 21)

        self.assertTrue(waiting)
        controller._cancel_target_transition.assert_not_called()
        self.assertEqual(controller.state.settings.zapret_preset, "Default")
        controller.schedule_save.assert_called_once()
        worker.start.assert_called_once()

    def test_missing_presets_still_cancel_with_a_message(self) -> None:
        controller = Mock()
        controller.selected_node = Node(
            name="new",
            scheme="vless",
            server="new.example",
            port=443,
            outbound={"protocol": "vless", "streamSettings": {"network": "tcp"}},
        )
        spec = endpoint_spec_for_node(controller.selected_node)
        controller.state.settings.zapret_target = ZapretTargetSettings()
        controller.state.settings.zapret_preset = ""
        controller._active_config_uses_selected_node.return_value = True
        controller.zapret.target_spec.return_value = spec
        controller.zapret.target_requires_zapret.return_value = True
        controller.zapret.target_profile_is_ready.return_value = True
        controller.zapret.default_preset.return_value = ""
        controller.connected = False

        handled = AppController._prepare_proxy_protection(controller, 22)

        self.assertTrue(handled)
        controller._cancel_target_transition.assert_called_once()

    def test_manual_stop_fails_pending_profile_instead_of_marking_ready(self) -> None:
        manager = ZapretManager()
        manager._proxy_protection_pending_generation = 4
        ready: list[int] = []
        failed: list[tuple[int, str]] = []
        manager.target_profile_ready.connect(ready.append)
        manager.target_profile_failed.connect(lambda generation, reason: failed.append((generation, reason)))

        manager.stop()

        self.assertEqual(ready, [])
        self.assertEqual(failed, [(4, "stopped")])


if __name__ == "__main__":
    unittest.main()
