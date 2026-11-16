"""Masking package: same vectors as the Android `:masking` tests, so both platforms agree."""

import json
import random
import unittest

from xray_fluent.masking import apply, codec, presets, singbox, tester, wireguard, xray
from xray_fluent.masking.merge import effective
from xray_fluent.masking.model import (
    OFF,
    SETTINGS_OFF,
    Core,
    Masking,
    MaskingOverride,
    MaskingSettings,
    MuxCool,
    OverrideKind,
    ServerShape,
    SingboxFragment,
    Span,
    WireGuardMasking,
    XrayFragment,
    XrayShaping,
    Xmux,
    errors,
)

REALITY_TCP = ServerShape(Core.XRAY, "vless", network="tcp", security="reality")
VISION = ServerShape(Core.XRAY, "vless", network="tcp", security="reality", flow="xtls-rprx-vision")
XHTTP = ServerShape(Core.XRAY, "vless", network="xhttp", security="reality")
KCP = ServerShape(Core.XRAY, "vless", network="kcp", security="none")
WG = ServerShape(Core.AMNEZIA, "wireguard")
ANYTLS = ServerShape(Core.SINGBOX, "anytls", security="tls")


class WireGuardTests(unittest.TestCase):
    def test_chain_accepts_the_core_tags(self) -> None:
        self.assertEqual((2 + 2 + 4 + 16 + 8 + 3, None), wireguard.validate_chain("<b 0x0100><r 2><t><rc 16><rd 8><r 3>"))

    def test_counter_tag_and_uppercase_prefix_are_refused(self) -> None:
        self.assertIn("не поддерживается ядром", wireguard.validate_chain("<b 0x01><c>")[1])
        self.assertIsNotNone(wireguard.validate_chain("<b 0X0100>")[1])
        self.assertIsNone(wireguard.validate_chain("<b 0100>")[1])

    def test_mtu_cap_and_malformed_chains(self) -> None:
        self.assertIsNotNone(wireguard.validate_chain("<r 1000><r 401>")[1])
        self.assertIsNone(wireguard.validate_chain("<r 1000><r 400>")[1])
        for chain in ("hello<b 0x01>", "   ", "<b 0x01", "<r ３>"):
            self.assertIsNotNone(wireguard.validate_chain(chain)[1], chain)

    def test_dns_chain_is_the_android_vector(self) -> None:
        expected = "<r 2><b 0x" "01000001000000000000" "0679616e646578" "027275" "00" "00010001" ">"
        self.assertEqual(expected, wireguard.dns_chain("yandex.ru"))
        self.assertEqual(expected, wireguard.dns_chain("YANDEX.RU."))
        for bad in ("localhost", "bad_label.ru", "-x.ru", ""):
            self.assertIsNone(wireguard.dns_chain(bad))

    def test_junk_rules(self) -> None:
        self.assertTrue(any(p.field == "jc" for p in errors(wireguard.validate(WireGuardMasking(jmax=30)))))
        self.assertTrue(any(p.field == "jmin" for p in errors(wireguard.validate(WireGuardMasking(jc=3, jmin=50, jmax=10)))))
        self.assertTrue(any(p.field == "jmax" for p in errors(wireguard.validate(WireGuardMasking(jc=3, jmin=0, jmax=0)))))
        self.assertEqual([], wireguard.validate(WireGuardMasking(jc=3, jmin=10, jmax=30)))

    def test_apply_keeps_server_header_fields(self) -> None:
        masked = wireguard.apply_to(
            {"h1": "1-5", "s1": 20, "jc": 9, "i2": "<r 4>"},
            WireGuardMasking(jc=3, jmin=10, jmax=30, signatures={"i1": "<r 2>", "i3": " "}),
        )
        self.assertEqual({"h1": "1-5", "s1": 20, "jc": 3, "jmin": 10, "jmax": 30, "i1": "<r 2>", "i2": "<r 4>"}, masked)

    def test_presets_are_valid(self) -> None:
        for preset in presets.all_presets():
            if preset.masking.wireguard:
                self.assertEqual([], wireguard.validate(preset.masking.wireguard), preset.id)
            if preset.masking.xray:
                self.assertEqual([], errors(xray.validate(preset.masking.xray)), preset.id)


class XrayTests(unittest.TestCase):
    def test_mux_block_and_zero_is_refused(self) -> None:
        block, notes = xray.emit(XrayShaping(mux=MuxCool(concurrency=8)), REALITY_TCP)
        self.assertEqual({"mux": {"enabled": True, "concurrency": 8, "xudpConcurrency": 16, "xudpProxyUDP443": "reject"}}, block)
        self.assertTrue(any("QUIC" in note for note in notes))
        self.assertTrue(errors(xray.validate(XrayShaping(mux=MuxCool(concurrency=0)))))
        self.assertEqual([False], [p.error for p in xray.validate(XrayShaping(mux=MuxCool(concurrency=8)))])

    def test_vision_and_multiplexed_transports(self) -> None:
        block, _ = xray.emit(XrayShaping(mux=MuxCool()), VISION)
        self.assertEqual(-1, block["mux"]["concurrency"])
        self.assertEqual((None, ["Mux не включён: xhttp уже мультиплексирует потоки, для XHTTP есть xmux."]),
                         xray.emit(XrayShaping(mux=MuxCool()), XHTTP))

    def test_xmux_vector(self) -> None:
        block, _ = xray.emit(presets.XMUX_ROTATE.masking.xray, XHTTP)
        self.assertEqual({"xmux": {"maxConcurrency": "16-32", "cMaxReuseTimes": "8-16",
                                   "hMaxRequestTimes": "60-120", "hMaxReusableSecs": "60-120"}}, block)
        self.assertIsNone(xray.emit(XrayShaping(xmux=Xmux(max_connections=Span.of(2))), REALITY_TCP)[0])
        self.assertTrue(errors(xray.validate(XrayShaping(xmux=Xmux(max_connections=Span.of(2), max_concurrency=Span(8, 16))))))

    def test_fragment_vector(self) -> None:
        block, _ = xray.emit(XrayShaping(fragment=XrayFragment()), REALITY_TCP)
        self.assertEqual({"finalmask": {"tcp": [{"type": "fragment", "settings": {
            "packets": "tlshello", "length": "100-200", "delay": "10-20"}}]}}, block)
        self.assertIsNone(xray.emit(XrayShaping(fragment=XrayFragment()), KCP)[0])
        self.assertTrue(errors(xray.validate(XrayShaping(fragment=XrayFragment(packets="0-3")))))
        self.assertTrue(errors(xray.validate(XrayShaping(fragment=XrayFragment(length=Span(0, 10))))))

    def test_xmux_goes_into_extra_when_present(self) -> None:
        outbound = {"protocol": "vless", "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/x", "extra": {"xPaddingBytes": "1-2"}}}}
        xray.apply_to_outbound(outbound, {"xmux": {"maxConnections": "2"}})
        self.assertEqual({"maxConnections": "2"}, outbound["streamSettings"]["xhttpSettings"]["extra"]["xmux"])
        plain = {"protocol": "vless", "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/x"}}}
        xray.apply_to_outbound(plain, {"xmux": {"maxConnections": "2"}})
        self.assertEqual({"maxConnections": "2"}, plain["streamSettings"]["xhttpSettings"]["xmux"])
        with self.assertRaises(ValueError):
            xray.apply_to_outbound(plain, {"sockopt": {}})

    def test_span(self) -> None:
        self.assertEqual(Span(8, 16), Span.parse(" 8 - 16 "))
        self.assertEqual(Span.of(3), Span.parse("3"))
        for bad in ("16-8", "-1", "a-b", "1-2-3"):
            self.assertIsNone(Span.parse(bad), bad)
        self.assertEqual(("8-16", "3"), (str(Span(8, 16)), str(Span.of(3))))


GLOBAL = Masking(wireguard=presets.WIREGUARD_JUNK_ONLY.masking.wireguard, xray=XrayShaping(mux=MuxCool()))


class MergeAndApplyTests(unittest.TestCase):
    def test_merge_rules(self) -> None:
        self.assertTrue(effective(MaskingSettings(False, GLOBAL), "a", WG).is_empty)
        on = MaskingSettings(True, GLOBAL)
        self.assertEqual(GLOBAL.wireguard, effective(on, "a", WG).masking.wireguard)
        self.assertIsNone(effective(on, "a", WG).masking.xray)
        off_a = MaskingSettings(True, GLOBAL, {"a": OFF})
        self.assertTrue(effective(off_a, "a", WG).is_empty)
        self.assertFalse(effective(off_a, "b", WG).is_empty)
        custom = MaskingSettings(True, GLOBAL, {"a": MaskingOverride(OverrideKind.CUSTOM, Masking(wireguard=WireGuardMasking(enabled=False)))})
        self.assertIsNone(effective(custom, "a", WG).masking.wireguard)
        self.assertEqual(GLOBAL.xray, effective(custom, "a", REALITY_TCP).masking.xray)
        broken = effective(MaskingSettings(True, Masking(wireguard=WireGuardMasking(jc=3, jmin=40, jmax=10))), None, WG)
        self.assertIsNone(broken.masking.wireguard)
        self.assertEqual(1, len(broken.notes))

    def test_shape_of_native_xray_outbound(self) -> None:
        outbound = {"protocol": "vless", "settings": {"vnext": [{"users": [{"flow": "xtls-rprx-vision"}]}]},
                    "streamSettings": {"network": "xhttp", "security": "reality"}}
        shape = apply.shape_of(outbound)
        self.assertEqual((Core.XRAY, "xhttp", "reality", True), (shape.core, shape.network, shape.security, shape.is_vision))
        self.assertIsNone(apply.shape_of({"protocol": "freedom"}))
        self.assertEqual(Core.AMNEZIA, apply.shape_of({"type": "wireguard"}).core)

    def test_apply_server_copies_and_never_touches_the_node(self) -> None:
        outbound = {"protocol": "vless", "streamSettings": {"network": "tcp", "security": "reality"}}
        masked, _ = apply.apply_server(outbound, MaskingSettings(True, GLOBAL), "a")
        self.assertIn("mux", masked)
        self.assertNotIn("mux", outbound)
        endpoint = {"type": "wireguard", "tag": "wg"}
        self.assertEqual({"jc": 3, "jmin": 10, "jmax": 30}, apply.apply_server(endpoint, MaskingSettings(True, GLOBAL), None)[0]["amnezia"])
        self.assertIs(outbound, apply.apply_server(outbound, SETTINGS_OFF, "a")[0])

    def test_singbox_fragment(self) -> None:
        settings = MaskingSettings(True, Masking(singbox=SingboxFragment(record_fragment=True, fallback_delay_ms=500)))
        masked, _ = apply.apply_server({"type": "anytls", "tls": {"enabled": True, "server_name": "x"}}, settings, None)
        self.assertEqual({"enabled": True, "server_name": "x", "fragment": True, "record_fragment": True,
                          "fragment_fallback_delay": "500ms"}, masked["tls"])
        self.assertIsNone(effective(settings, None, ServerShape(Core.SINGBOX, "anytls", security="reality")).masking.singbox)
        self.assertTrue(singbox.applies(ANYTLS))

    def test_trojan_and_vmess_are_xray_servers(self) -> None:
        # Owner decision 2026-11-16: Xray owns VLESS, VMess and Trojan; sing-box fragment no longer fits them.
        for protocol in ("trojan", "vmess"):
            outbound = {"protocol": protocol, "streamSettings": {"network": "ws", "security": "tls"}}
            shape = apply.shape_of(outbound)
            self.assertEqual((Core.XRAY, protocol, "ws", "tls"), (shape.core, shape.protocol, shape.network, shape.security))
            self.assertFalse(singbox.applies(shape))
        self.assertEqual(Core.SINGBOX, apply.shape_of({"type": "trojan", "tls": {"enabled": True}}).core)

    def test_log_line(self) -> None:
        self.assertIsNone(apply.log_line(False, 0, []))
        self.assertEqual("маскировка: включена, изменено серверов: 2; a (×2); b", apply.log_line(True, 2, ["a", "a", "b"]))


class CodecTests(unittest.TestCase):
    def test_round_trip_and_unknown_keys(self) -> None:
        settings = MaskingSettings(
            True,
            Masking(
                wireguard=presets.wireguard_dns().masking.wireguard,
                xray=XrayShaping(mux=MuxCool(enabled=False), xmux=presets.XMUX_ROTATE.masking.xray.xmux),
                singbox=SingboxFragment(fallback_delay_ms=300),
            ),
            {"a": OFF, "b": MaskingOverride(OverrideKind.CUSTOM, presets.XRAY_FRAGMENT.masking)},
        )
        text = codec.encode_text(settings, '{"schema":2,"futureFeature":{"x":1}}')
        self.assertEqual(settings, codec.decode_text(text))
        root = json.loads(text)
        self.assertEqual(1, root["schema"])
        self.assertEqual({"x": 1}, root["futureFeature"])

    def test_android_document_reads_the_same(self) -> None:
        # The exact document Android writes for the same settings (MaskingCodec, key order included).
        android = ('{"schema":1,"enabled":true,"global":{"wireguard":{"enabled":true,"jc":3,"jmin":10,"jmax":30}},'
                   '"overrides":{"p|wg":"off"}}')
        settings = codec.decode_text(android)
        self.assertEqual(MaskingSettings(True, Masking(wireguard=WireGuardMasking(jc=3, jmin=10, jmax=30)), {"p|wg": OFF}), settings)
        self.assertEqual(android, codec.encode_text(settings))

    def test_garbage_reads_as_off(self) -> None:
        self.assertEqual(SETTINGS_OFF, codec.decode_text("not json"))
        self.assertEqual(SETTINGS_OFF, codec.decode_text(None))
        odd = codec.decode_text('{"enabled":"yes","global":{"wireguard":{"jc":"3"}},"overrides":{"x":7}}')
        self.assertFalse(odd.enabled)
        self.assertIsNone(odd.global_masking.wireguard.jc)
        self.assertEqual({}, odd.overrides)


class TesterTests(unittest.TestCase):
    KB = 1024

    def stalled(self, stop_at: int, stall_ms: int, step: int = 4 * 1024) -> tester.Transfer:
        samples, t, value = [], 0, 0
        while value < stop_at:
            samples.append((t, value))
            t += 1000
            value = min(stop_at, value + step)
        samples += [(t, stop_at), (t + stall_ms, stop_at)]
        return tester.Transfer(tuple(samples), tester.End.TIMEOUT, 128 * self.KB)

    def steady(self, total: int = 128 * 1024, seconds: int = 4) -> tester.Transfer:
        return tester.Transfer(tuple((i * 1000, total * i // seconds) for i in range(seconds + 1)), tester.End.COMPLETED, total)

    def test_freeze_rules(self) -> None:
        kb = self.KB
        frozen = tester.verdict([self.stalled(18 * kb, 9000), self.stalled(20 * kb, 8500)], 128 * kb)
        self.assertEqual(("frozen", 19 * kb), (frozen.kind, frozen.offset_bytes))
        self.assertEqual("inconclusive", tester.verdict([self.stalled(18 * kb, 9000)] * 2, 10 * kb).kind)
        self.assertEqual("pass", tester.verdict([self.stalled(18 * kb, 3000), self.steady()], 128 * kb).kind)
        self.assertEqual("inconclusive", tester.verdict([self.stalled(18 * kb, 9000), self.stalled(90 * kb, 9000)], 128 * kb).kind)
        reset = tester.Transfer(self.steady().samples[:2], tester.End.RESET, 128 * kb)
        self.assertEqual("inconclusive", tester.verdict([reset], 128 * kb).kind)
        self.assertEqual("not_applicable", tester.verdict([self.steady(total=32 * kb)], 128 * kb).kind)
        self.assertEqual(tester.Verdict("pass", bytes_per_second=32 * kb), tester.verdict([self.steady()], 128 * kb))

    def test_rank_and_candidates(self) -> None:
        wg = tester.Candidate.of(presets.WIREGUARD_JUNK_ONLY)
        ranked = tester.rank([
            (tester.Candidate.of(presets.XMUX_FEW), tester.Verdict("frozen", offset_bytes=18 * self.KB), 300),
            (wg, tester.Verdict("pass", bytes_per_second=100 * self.KB), 200),
        ])
        self.assertEqual(wg, ranked[0].candidate)
        self.assertEqual("заморозка на 18 КБ", ranked[-1].reason)
        wg_candidates = tester.candidates(WG)
        self.assertEqual(tester.BASELINE, wg_candidates[0])
        self.assertTrue(all(c.override.masking.wireguard for c in wg_candidates[1:]))
        ids = [c.id for c in tester.candidates(XHTTP)]
        self.assertNotIn("xray-mux", ids)
        self.assertIn("xmux-rotate", ids)
        self.assertEqual([], tester.candidates(ServerShape(Core.HYSTERIA, "hysteria2")))

    def test_own_set_is_a_candidate_unless_it_is_a_preset(self) -> None:
        own = Masking(wireguard=WireGuardMasking(jc=5, jmin=20, jmax=40))
        self.assertEqual("current", tester.candidates(WG, own)[1].id)
        self.assertNotIn("current", [c.id for c in tester.candidates(WG, presets.WIREGUARD_JUNK_ONLY.masking)])

    def test_judge_takes_the_control_from_the_run(self) -> None:
        kb = self.KB
        baseline = tester.Measurement(tester.BASELINE, (self.stalled(18 * kb, 9000), self.stalled(17 * kb, 9000)))
        wg = tester.Candidate.of(presets.WIREGUARD_JUNK_ONLY)
        ranked = tester.judge([baseline, tester.Measurement(wg, (self.steady(), self.steady()), 250)])
        self.assertEqual(wg, ranked[0].candidate)
        self.assertEqual(250, ranked[0].first_byte_ms)
        self.assertEqual("frozen", ranked[-1].verdict.kind)
        everything = [tester.Measurement(c, (self.stalled(18 * kb, 9000),) * 2) for c in (tester.BASELINE, wg)]
        self.assertTrue(all(r.verdict.kind == "inconclusive" for r in tester.judge(everything)))
        down = tester.judge([tester.Measurement(tester.BASELINE, (), connected=False)])
        self.assertEqual("не ясно: туннель не поднялся с этими настройками", down[0].reason)

    def test_trial_changes_one_server_and_nothing_else(self) -> None:
        custom = MaskingOverride(OverrideKind.CUSTOM, presets.WIREGUARD_JUNK_ONLY.masking)
        off = MaskingSettings().with_trial("k", custom)
        self.assertEqual((True, Masking(), {"k": custom}), (off.enabled, off.global_masking, off.overrides))
        on = MaskingSettings(True, presets.XMUX_ROTATE.masking, {"other": OFF}).with_trial("k", OFF)
        self.assertEqual(presets.XMUX_ROTATE.masking, on.global_masking)
        self.assertEqual({"other": OFF, "k": OFF}, on.overrides)

    def test_plan_is_sequential_and_jittered(self) -> None:
        chosen = tester.candidates(REALITY_TCP)
        steps = tester.plan(chosen, random.Random(7))
        self.assertEqual(len(chosen) * tester.TRANSFERS_PER_CANDIDATE, len(steps))
        self.assertTrue(all(tester.PAUSE_MS[0] <= s.pause_before_ms <= tester.PAUSE_MS[1] for s in steps))
        self.assertGreater(len({s.pause_before_ms for s in steps}), 1)


class DesyncTests(unittest.TestCase):
    def test_android_desync_document_reads_the_same(self) -> None:
        # Same vector as Android MaskingMergeTest "codec writes the desync section Windows reads".
        document = ('{"schema":1,"enabled":true,"global":{"xray":{"enabled":true,"desync":'
                    '{"enabled":true,"method":"fake","splitAt":"sni","fakeTtl":5,"fakeSni":"vk.com"}}},"overrides":{}}')
        settings = MaskingSettings(True, presets.desync_fake(5).masking)
        self.assertEqual(document, codec.encode_text(settings))
        self.assertEqual(settings, codec.decode_text(document))

    def test_validation_matches_kvndesync_parse(self) -> None:
        from xray_fluent.masking.model import Desync

        def fields(desync):
            return [p.field for p in errors(xray.validate(XrayShaping(desync=desync)))]

        self.assertEqual([], xray.validate(XrayShaping(desync=Desync())))
        self.assertEqual(["desync.method"], fields(Desync(method="spoof")))
        self.assertEqual(["desync.splitAt"], fields(Desync(split_at="1401")))
        self.assertEqual(["desync.fakeTtl"], fields(Desync(fake_ttl=33)))
        self.assertEqual(["desync.fakeSni"], fields(Desync(fake_sni="not a host")))
        # Windows ignores the TTL (wrong sequence number instead): no "too high" warning.
        self.assertEqual([], xray.validate(XrayShaping(desync=Desync(fake_ttl=12))))
        self.assertEqual(["desync.method"], fields(Desync(method="oob")))

    def test_desync_is_carried_for_the_front_and_never_left_for_xray(self) -> None:
        from xray_fluent.masking import desync
        from xray_fluent.masking.model import Desync

        block, notes = xray.emit(presets.DESYNC_FAKE.masking.xray, REALITY_TCP)
        self.assertEqual({"desync": {"method": "fake", "split_at": "sni", "fake_sni": "vk.com"}}, block)
        self.assertEqual([], notes)
        outbound = {"protocol": "vless", "settings": {"vnext": [{"address": "Srv.Example", "port": 443}]}}
        xray.apply_to_outbound(outbound, block)
        self.assertIn(desync.CARRY_KEY, outbound)
        self.assertEqual({"method": "fake", "split_at": "sni", "fake_sni": "vk.com"}, desync.take(outbound))
        self.assertNotIn(desync.CARRY_KEY, outbound)
        self.assertEqual(["srv.example"], desync.server_hosts(outbound))
        block, notes = xray.emit(XrayShaping(desync=Desync(method="oob")), REALITY_TCP)
        self.assertIsNone(block)
        self.assertEqual(["Пакеты-обманки не применены: OOB на Windows нет."], notes)
        block, notes = xray.emit(XrayShaping(desync=Desync(method="split")), ServerShape(Core.XRAY, "vless", network="kcp", security="none"))
        self.assertIsNone(block)
        self.assertEqual(["Пакеты-обманки не применены: kcp идёт не по TCP."], notes)

    def test_route_rules_per_server(self) -> None:
        from xray_fluent.masking import desync

        rules = desync.route_rules(
            [
                (["srv.example"], {"method": "fake", "split_at": "sni", "fake_sni": "vk.com"}),
                (["203.0.113.7"], {"method": "disorder", "split_at": "sni"}),
                (["2001:db8::1"], {"method": "split", "split_at": "120"}),
                (["skip.example"], {"method": "oob", "split_at": "sni"}),
            ],
            "protect",
            known_addresses=lambda host: ["198.51.100.4"] if host == "srv.example" else [],
        )
        self.assertEqual([
            {"inbound": ["protect"], "domain": ["srv.example"], "ip_cidr": ["198.51.100.4/32"],
             "action": "route-options", "tls_spoof": "vk.com", "tls_spoof_method": "wrong-sequence"},
            {"inbound": ["protect"], "ip_cidr": ["203.0.113.7/32"], "action": "route-options", "kvn_desync": "disorder:sni"},
            {"inbound": ["protect"], "ip_cidr": ["2001:db8::1/128"], "action": "route-options", "kvn_desync": "split:120"},
        ], rules)
        self.assertTrue(desync.uses_windivert({"route": {"rules": rules}}))
        self.assertFalse(desync.uses_windivert({"route": {"rules": rules[1:]}}))

    def test_desync_presets_are_offered_on_windows(self) -> None:
        from xray_fluent.masking import choices
        self.assertTrue(presets.DESYNC_ENGINE_AVAILABLE)
        ids = [c.id for c in tester.candidates(REALITY_TCP)]
        self.assertIn("desync-fake", ids)
        self.assertIn("desync-disorder", ids)
        self.assertNotIn("desync-fake-3", ids)
        self.assertIn("desync-fake", [choice for choice, _ in choices.server_choices("vless")])


class ChoicesTests(unittest.TestCase):
    def test_global_desync_choice_reads_back_and_is_never_dropped(self) -> None:
        from xray_fluent.masking import choices
        from xray_fluent.masking.model import Desync

        controls = dict(wireguard="off", mux=False, xmux="off", xray_fragment=False, singbox_fragment=False)
        composed = choices.compose_global(Masking(), desync="desync-fake", **controls)
        self.assertEqual("desync-fake", choices.desync_choice(composed))
        # A set tuned in «Свои значения» survives a change of another control.
        tuned = Masking(xray=XrayShaping(desync=Desync(method="split", split_at="40")))
        self.assertEqual(choices.CUSTOM_ID, choices.desync_choice(tuned))
        kept = choices.compose_global(tuned, **{**controls, "mux": True})
        self.assertEqual(tuned.xray.desync, kept.xray.desync)
        self.assertIsNone(choices.compose_global(tuned, desync="off", **controls).xray)

    def test_presets_read_back_and_custom_is_kept(self) -> None:
        from xray_fluent.masking import choices
        composed = choices.compose_global(
            Masking(), wireguard="wg-dns", mux=True, xmux="xmux-rotate", xray_fragment=False, singbox_fragment=True,
        )
        self.assertEqual("wg-dns", choices.wireguard_choice(composed))
        self.assertEqual("xmux-rotate", choices.xmux_choice(composed))
        self.assertTrue(choices.mux_on(composed) and choices.singbox_fragment_on(composed))
        self.assertFalse(choices.xray_fragment_on(composed))
        tuned = Masking(wireguard=WireGuardMasking(jc=5, jmin=20, jmax=40))
        self.assertEqual("custom", choices.wireguard_choice(tuned))
        kept = choices.compose_global(tuned, wireguard="custom", mux=False, xmux="off", xray_fragment=False, singbox_fragment=False)
        self.assertEqual(tuned, kept)
        self.assertEqual(Masking(), choices.compose_global(tuned, wireguard="off", mux=False, xmux="off",
                                                           xray_fragment=False, singbox_fragment=False))

    def test_server_choices_and_overrides(self) -> None:
        from xray_fluent.masking import choices
        self.assertEqual(["inherit", "off", "wg-dns", "wg-more-junk", "wg-junk-only"], [c for c, _ in choices.server_choices("wireguard")])
        vless = [c for c, _ in choices.server_choices("vless")]
        self.assertIn("xmux-rotate", vless)
        self.assertNotIn("singbox-fragment", vless)
        self.assertEqual(["inherit", "off"], [c for c, _ in choices.server_choices("hysteria2")])
        settings = choices.with_override(MaskingSettings(True), {"a", "b"}, "xmux-few")
        self.assertEqual("XHTTP: мало соединений", choices.override_label(settings.override_for("a")))
        settings = choices.with_override(settings, {"a"}, "inherit")
        self.assertEqual({"b"}, set(settings.overrides))
        self.assertEqual("Выключена", choices.override_label(choices.with_override(settings, {"b"}, "off").override_for("b")))
        with self.assertRaises(ValueError):
            choices.with_override(settings, {"a"}, "nope")


if __name__ == "__main__":
    unittest.main()
