"""Masking reaches the native cores' runtime config on Windows, as copies; stored nodes stay as imported."""

import unittest

from xray_fluent.application import masking_runtime
from xray_fluent.engines.singbox.runtime_planner import parse_singbox_document, plan_singbox_runtime
from xray_fluent.importer.link_parser import parse_single
from xray_fluent.masking import codec
from xray_fluent.masking.apply import apply_server
from xray_fluent.masking.model import OFF, Masking, MaskingSettings, MuxCool, XrayFragment, XrayShaping
from xray_fluent.masking import presets
from xray_fluent.profiles.models import AppSettings
from tests.test_singbox_proxy_runtime import TEMPLATE_PATH

REALITY = (
    "vless://11111111-1111-1111-1111-111111111111@reality.example:8443"
    "?type=tcp&encryption=none&security=reality"
    "&pbk=Ie4ld0x7PvMRA2idLXq58rXRhefsved2eKgqtBtS2Hg"
    "&fp=edge&sni=www.example.com&sid=0123456789abcdef&spx=%2F#Reality"
)
SETTINGS = MaskingSettings(True, Masking(xray=XrayShaping(mux=MuxCool(), fragment=XrayFragment())))


class MaskingRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = parse_singbox_document(TEMPLATE_PATH, TEMPLATE_PATH.read_text(encoding="utf-8"))
        self.node = parse_single(REALITY)

    def sidecar_proxy(self, node) -> dict:
        plan = plan_singbox_runtime(self.document, node, pool_nodes=[node])
        return plan.xray_sidecar.config["outbounds"][0]

    def test_masked_node_reaches_the_xray_sidecar_and_the_stored_node_is_untouched(self) -> None:
        proxy = self.sidecar_proxy(masking_runtime.masked_node(self.node, SETTINGS))
        self.assertEqual({"enabled": True, "concurrency": 8, "xudpConcurrency": 16, "xudpProxyUDP443": "reject"}, proxy["mux"])
        self.assertEqual("fragment", proxy["streamSettings"]["finalmask"]["tcp"][0]["type"])
        # The app-owned socket boundary is still added on top of the masked copy.
        self.assertIn("dialerProxy", proxy["streamSettings"]["sockopt"])
        self.assertNotIn("mux", self.node.outbound)
        self.assertNotIn("finalmask", self.node.outbound["streamSettings"])

    def test_off_and_per_server_off_leave_the_sidecar_as_before(self) -> None:
        self.assertNotIn("mux", self.sidecar_proxy(masking_runtime.masked_node(self.node, MaskingSettings())))
        per_server_off = MaskingSettings(True, SETTINGS.global_masking, {self.node.id: OFF})
        self.assertIs(self.node, masking_runtime.masked_node(self.node, per_server_off))

    def test_pool_outbounds_are_masked_by_node_id(self) -> None:
        outbounds = [{"tag": "pool-a", "protocol": "vless", "streamSettings": {"network": "tcp", "security": "reality"}},
                     {"tag": "pool-b", "protocol": "vless", "streamSettings": {"network": "tcp", "security": "reality"}}]
        settings = MaskingSettings(True, SETTINGS.global_masking, {"b": OFF})
        masked, changed, _ = masking_runtime.mask_pool_outbounds(outbounds, {"a": "pool-a", "b": "pool-b"}, settings)
        self.assertEqual(1, changed)
        self.assertIn("mux", masked[0])
        self.assertIs(outbounds[1], masked[1])

    def test_settings_come_from_the_state_file_document(self) -> None:
        app = AppSettings.from_dict({"masking": codec.encode(SETTINGS)})
        self.assertEqual(SETTINGS, masking_runtime.settings_of(app))
        self.assertEqual(codec.encode(SETTINGS), AppSettings.from_dict(app.to_dict()).masking)
        self.assertFalse(masking_runtime.settings_of(AppSettings()).enabled)

    def test_wireguard_endpoint_gets_junk_and_keeps_its_headers(self) -> None:
        settings = MaskingSettings(True, presets.wireguard_dns().masking)
        endpoint = {"type": "wireguard", "tag": "wg", "amnezia": {"h1": "5"}}
        masked, _ = apply_server(endpoint, settings, "n")
        self.assertEqual("5", masked["amnezia"]["h1"])
        self.assertEqual(3, masked["amnezia"]["jc"])
        self.assertTrue(masked["amnezia"]["i1"].startswith("<r 2>"))
        self.assertEqual({"h1": "5"}, endpoint["amnezia"])


class DesyncRuntimeTests(unittest.TestCase):
    """«Пакеты-обманки» on Windows: a sing-box route option of the server socket, never Xray."""

    def setUp(self) -> None:
        self.document = parse_singbox_document(TEMPLATE_PATH, TEMPLATE_PATH.read_text(encoding="utf-8"))
        self.node = parse_single(REALITY)

    def plan(self, masking):
        node = masking_runtime.masked_node(self.node, MaskingSettings(True, masking))
        return plan_singbox_runtime(self.document, node, pool_nodes=[node])

    def protect_rules(self, plan) -> list[dict]:
        return [rule for rule in plan.singbox_config["route"]["rules"]
                if isinstance(rule, dict) and rule.get("inbound") == ["__app_hybrid_protect_in"]]

    def test_fake_becomes_tls_spoof_for_that_server_and_xray_never_sees_it(self) -> None:
        from xray_fluent.masking import desync

        plan = self.plan(presets.DESYNC_FAKE.masking)
        rules = self.protect_rules(plan)
        spoof = [rule for rule in rules if rule.get("action") == "route-options"]
        self.assertEqual(1, len(spoof))
        self.assertEqual(["reality.example"], spoof[0]["domain"])
        self.assertEqual("vk.com", spoof[0]["tls_spoof"])
        self.assertEqual("wrong-sequence", spoof[0]["tls_spoof_method"])
        # Before the protect route itself, so the options apply to its connections.
        self.assertEqual("direct", rules[-1].get("outbound"))
        self.assertLess(rules.index(spoof[0]), rules.index(rules[-1]))
        for outbound in plan.xray_sidecar.config["outbounds"]:
            self.assertNotIn(desync.CARRY_KEY, outbound)
        self.assertTrue(desync.uses_windivert(plan.singbox_config))
        self.assertNotIn(desync.CARRY_KEY, self.node.outbound)

    def test_disorder_becomes_kvn_desync_without_windivert(self) -> None:
        from xray_fluent.masking import desync

        plan = self.plan(presets.DESYNC_DISORDER.masking)
        options = [rule for rule in self.protect_rules(plan) if rule.get("action") == "route-options"]
        self.assertEqual("disorder:sni", options[0]["kvn_desync"])
        self.assertFalse(desync.uses_windivert(plan.singbox_config))

    def test_no_tricks_no_rule_and_a_replan_does_not_pile_rules_up(self) -> None:
        plan = self.plan(SETTINGS.global_masking)
        self.assertFalse([rule for rule in self.protect_rules(plan) if rule.get("action") == "route-options"])
        from xray_fluent.engines.singbox.runtime_planner import _ensure_hybrid_desync_routes

        config = {"route": {"rules": [{"inbound": ["__app_hybrid_protect_in"], "outbound": "direct"}]}}
        targets = [(["a.example"], {"method": "split", "split_at": "sni"})]
        _ensure_hybrid_desync_routes(config, targets)
        _ensure_hybrid_desync_routes(config, targets)
        self.assertEqual(2, len(config["route"]["rules"]))

    def test_raw_xray_config_gets_no_carried_plan(self) -> None:
        from xray_fluent.masking import desync

        masked = masking_runtime.masked_node(self.node, MaskingSettings(True, presets.DESYNC_FAKE.masking))
        self.assertTrue(masking_runtime.carries_desync(masked))
        outbounds = [dict(masked.outbound)]
        self.assertEqual(1, masking_runtime.strip_desync(outbounds))
        self.assertNotIn(desync.CARRY_KEY, outbounds[0])

    def test_desync_of_names_the_servers_whose_socket_gets_tricks(self) -> None:
        on = MaskingSettings(True, presets.DESYNC_FAKE.masking)
        self.assertEqual("fake", masking_runtime.desync_of(self.node, on).method)
        self.assertIsNone(masking_runtime.desync_of(self.node, MaskingSettings(True, presets.DESYNC_FAKE.masking, {self.node.id: OFF})))
        self.assertIsNone(masking_runtime.desync_of(self.node, MaskingSettings(False, presets.DESYNC_FAKE.masking)))


class ControllerOverrideTests(unittest.TestCase):
    def test_set_masking_override_writes_the_document_and_goes_through_update_settings(self) -> None:
        from types import SimpleNamespace
        from unittest.mock import Mock

        from xray_fluent.application.controller import AppController

        stored = codec.encode(SETTINGS, {"futureKey": 1})
        fake = SimpleNamespace(state=SimpleNamespace(settings=AppSettings(masking=stored)), update_settings=Mock())
        AppController.set_masking_override(fake, {"n1"}, "off")
        written = fake.update_settings.call_args.args[0]
        self.assertEqual({"n1": OFF}, codec.decode(written.masking).overrides)
        self.assertEqual(1, written.masking["futureKey"])
        self.assertEqual(stored, fake.state.settings.masking)  # the live settings are replaced, never edited


if __name__ == "__main__":
    unittest.main()
