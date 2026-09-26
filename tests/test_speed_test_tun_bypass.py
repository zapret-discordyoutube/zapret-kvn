"""Временное ядро теста скорости идёт мимо sing-box TUN (без сети).

Замер кандидата (ручной тест скорости и «умная проверка») запускает xray из
собственного пути SPEED_TEST_XRAY_PATH; runtime-план TUN уводит этот путь в
direct правилом process_path, не трогая пользовательский JSON и xray.exe
гибридного сайдкара.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from xray_fluent.constants import SPEED_TEST_XRAY_PATH, XRAY_PATH_DEFAULT
from xray_fluent.engines.singbox.runtime_planner import (
    parse_singbox_document,
    plan_singbox_proxy_runtime,
    plan_singbox_runtime,
)
from xray_fluent.importer.link_parser import parse_links_text
from xray_fluent.network import speed_test_worker
from xray_fluent.network.speed_test_worker import prepare_speed_test_xray

TEMPLATE_PATH = Path(__file__).resolve().parents[1] / "data" / "templates" / "sing-box" / "default.json"
SPEED_RULE = {
    "process_path": [str(SPEED_TEST_XRAY_PATH.resolve())],
    "action": "route",
    "outbound": "direct",
}


def _node(link: str):
    nodes, errors = parse_links_text(link)
    assert not errors, errors
    return nodes[0]


VLESS = "vless://2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365@example.com:443?type=tcp&security=tls#v"
HY2 = "hy2://secret@hy.example.com:443?sni=hy.example.com#h"


class PlannerRuleTests(unittest.TestCase):
    def plan(self, planner, link: str = VLESS, payload: dict | None = None):
        raw = payload if payload is not None else json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
        before = json.loads(json.dumps(raw))
        plan = planner(parse_singbox_document(TEMPLATE_PATH, json.dumps(raw)), _node(link))
        self.assertEqual(raw, before, "пользовательский JSON не меняется")
        return plan.singbox_config["route"]["rules"]

    def test_tun_plan_routes_speed_test_core_direct_after_dns_hijack(self) -> None:
        rules = self.plan(plan_singbox_runtime)
        self.assertEqual(rules.count(SPEED_RULE), 1)
        index = rules.index(SPEED_RULE)
        # sniff и hijack-dns срабатывают раньше: DNS временного ядра отвечает sing-box.
        dns_indexes = [
            i for i, rule in enumerate(rules)
            if rule.get("action") == "sniff" or rule.get("protocol") == "dns"
        ]
        self.assertTrue(dns_indexes)
        self.assertGreater(index, max(dns_indexes))
        # …и раньше любых пользовательских правил маршрутизации.
        user_rules = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))["route"]["rules"]
        first_user_route = next(r for r in user_rules if r.get("action") == "route")
        self.assertLess(index, rules.index(first_user_route))

    def test_rule_never_matches_sidecar_xray(self) -> None:
        rules = self.plan(plan_singbox_runtime)
        paths = [path for rule in rules for path in rule.get("process_path", [])]
        self.assertNotIn(str(XRAY_PATH_DEFAULT.resolve()), paths)
        self.assertNotEqual(SPEED_TEST_XRAY_PATH.name.lower(), "xray.exe")

    def test_proxy_plan_has_no_rule(self) -> None:
        self.assertNotIn(SPEED_RULE, self.plan(plan_singbox_proxy_runtime))

    def test_hysteria_tun_plan_keeps_both_process_rules(self) -> None:
        rules = self.plan(plan_singbox_runtime, HY2)
        self.assertEqual(rules.count(SPEED_RULE), 1)
        self.assertTrue(any("hysteria" in str(rule.get("process_path", "")).lower() for rule in rules))

    def test_no_direct_outbound_means_no_rule(self) -> None:
        raw = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
        raw["outbounds"] = [o for o in raw["outbounds"] if o.get("tag") != "direct"]
        for rule in raw["route"]["rules"]:
            if rule.get("outbound") == "direct":
                rule["outbound"] = "proxy"
        raw["route"].pop("final", None)
        rules = self.plan(plan_singbox_runtime, payload=raw)
        self.assertNotIn(SPEED_RULE, rules)


class PrepareSpeedTestXrayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.source = self.tmp / "core" / "xray.exe"
        self.source.parent.mkdir()
        self.source.write_bytes(b"xray-v1")
        self.target = self.tmp / "runtime" / "speedtest" / "xray-speedtest.exe"

    def test_creates_named_link_and_reuses_it(self) -> None:
        path = prepare_speed_test_xray(self.source, self.target)
        self.assertEqual(path, self.target)
        self.assertEqual(self.target.read_bytes(), b"xray-v1")
        with patch.object(speed_test_worker.os, "link", side_effect=AssertionError("не пересоздавать")):
            self.assertEqual(prepare_speed_test_xray(self.source, self.target), self.target)

    def test_refreshes_after_core_update(self) -> None:
        prepare_speed_test_xray(self.source, self.target)
        self.source.unlink()  # апдейтер кладёт новый файл, а не пишет в старый
        self.source.write_bytes(b"xray-v2-longer")
        os.utime(self.source, (1_900_000_000, 1_900_000_000))
        self.assertEqual(prepare_speed_test_xray(self.source, self.target), self.target)
        self.assertEqual(self.target.read_bytes(), b"xray-v2-longer")

    def test_falls_back_to_copy_when_hardlink_unavailable(self) -> None:
        with patch.object(speed_test_worker.os, "link", side_effect=OSError("cross-device")):
            self.assertEqual(prepare_speed_test_xray(self.source, self.target), self.target)
        self.assertEqual(self.target.read_bytes(), b"xray-v1")

    def test_falls_back_to_source_when_target_locked(self) -> None:
        with patch.object(speed_test_worker.os, "replace", side_effect=PermissionError("in use")):
            self.assertEqual(prepare_speed_test_xray(self.source, self.target), self.source)
        self.assertFalse(self.target.with_name(self.target.name + ".tmp").exists())

    def test_missing_source_is_returned_as_is(self) -> None:
        missing = self.tmp / "nope.exe"
        self.assertEqual(prepare_speed_test_xray(missing, self.target), missing)

    def test_geo_assets_point_to_source_dir(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("XRAY_LOCATION_ASSET", None)
            env = speed_test_worker._speed_test_env(self.source)
        self.assertEqual(env["XRAY_LOCATION_ASSET"], str(self.source.parent))


class WorkerLaunchTests(unittest.TestCase):
    def test_worker_launches_temp_core_from_speed_test_path(self) -> None:
        from xray_fluent.profiles.models import Node

        calls: list[list[str]] = []

        class _Proc:
            def poll(self):
                return 1  # «ядро упало сразу» — дальше замер не идёт

        def _popen(args, **kwargs):
            calls.append(list(args))
            self.assertIn("XRAY_LOCATION_ASSET", kwargs.get("env") or {})
            return _Proc()

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "xray.exe"
            source.write_bytes(b"x")
            target = Path(tmp) / "speedtest" / "xray-speedtest.exe"
            worker = speed_test_worker.SpeedTestWorker(
                [Node(id="a", name="a", outbound={"protocol": "vless", "settings": {}})],
                xray_path=str(source),
            )
            with patch.object(speed_test_worker, "SPEED_TEST_XRAY_PATH", target), \
                    patch.object(speed_test_worker, "prepare_speed_test_xray",
                                 lambda src: prepare_speed_test_xray(src, target)), \
                    patch.object(speed_test_worker.subprocess, "Popen", _popen), \
                    patch.object(speed_test_worker, "build_xray_config", lambda *a, **k: {"inbounds": []}), \
                    patch.object(speed_test_worker.time, "sleep", lambda _s: None):
                worker.run()
        self.assertEqual(len(calls), 1)
        self.assertEqual(Path(calls[0][0]).name, "xray-speedtest.exe")

    def test_worker_waits_for_slow_core_start(self) -> None:
        # На живом Windows xray с холодным кэшем грузил geosite.dat 9–16 с:
        # замер обязан дождаться HTTP-inbound, а не стартовать через 1 с.
        from xray_fluent.profiles.models import Node

        class _Proc:
            def poll(self):
                return None

            def terminate(self):
                pass

            def wait(self, timeout=None):
                return 0

        port_checks = iter([False, False, False, True])
        results: list = []
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "xray.exe"
            source.write_bytes(b"x")
            worker = speed_test_worker.SpeedTestWorker(
                [Node(id="a", name="a", outbound={"protocol": "vless", "settings": {}})],
                xray_path=str(source), rounds=1,
            )
            worker.result.connect(lambda node_id, mbps, alive: results.append((node_id, mbps, alive)))
            with patch.object(speed_test_worker, "prepare_speed_test_xray", lambda src: Path(src)), \
                    patch.object(speed_test_worker.subprocess, "Popen", lambda *a, **k: _Proc()), \
                    patch.object(speed_test_worker, "build_xray_config", lambda *a, **k: {"inbounds": []}), \
                    patch.object(speed_test_worker, "_port_open", lambda host, port: next(port_checks)), \
                    patch.object(speed_test_worker, "measure_download_bps", lambda *a, **k: 2.0 * 1024 * 1024), \
                    patch.object(speed_test_worker.time, "sleep", lambda _s: None):
                worker.run()
        self.assertEqual(results, [("a", 2.0, True)])
        self.assertIsNone(next(port_checks, None))


if __name__ == "__main__":
    unittest.main()
