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
                    patch.object(speed_test_worker, "build_speed_test_config", lambda *a, **k: {"inbounds": []}), \
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
                    patch.object(speed_test_worker, "build_speed_test_config", lambda *a, **k: {"inbounds": []}), \
                    patch.object(speed_test_worker, "_port_open", lambda host, port: next(port_checks)), \
                    patch.object(speed_test_worker, "measure_download_bps", lambda *a, **k: 2.0 * 1024 * 1024), \
                    patch.object(speed_test_worker.time, "sleep", lambda _s: None):
                worker.run()
        self.assertEqual(results, [("a", 2.0, True)])
        self.assertIsNone(next(port_checks, None))


class _Proc:
    """Временное ядро, которое «работает», пока его не остановят."""

    def poll(self):
        return None

    def terminate(self):
        pass

    def wait(self, timeout=None):
        return 0


def _vless_node(node_id: str = "a"):
    from xray_fluent.profiles.models import Node

    return Node(id=node_id, name=node_id, outbound={"protocol": "vless", "settings": {}})


class SpeedTestConfigTests(unittest.TestCase):
    def test_temp_core_config_has_no_routing_or_geo_data(self) -> None:
        # Правила с geosite:/geoip: заставляли xray грузить гео-базы 9–16 с и
        # могли увести замер «напрямую»: у временного ядра маршрут один.
        node = _vless_node()
        node.outbound = {"protocol": "vless", "settings": {"vnext": []}, "tag": "user-tag"}

        config = speed_test_worker.build_speed_test_config(node, 23456)

        self.assertNotIn("routing", config)
        self.assertNotIn("geo", json.dumps(config))
        self.assertEqual([ib["protocol"] for ib in config["inbounds"]], ["http"])
        self.assertEqual(config["inbounds"][0]["port"], 23456)
        self.assertEqual([ob["tag"] for ob in config["outbounds"]], ["proxy"])
        self.assertEqual(node.outbound["tag"], "user-tag")  # исходная нода не тронута

    def test_busy_preferred_port_is_replaced_with_free_one(self) -> None:
        # Осиротевший xray-speedtest.exe держит порт: «порт открыт» не должен
        # сойти за готовность нашего ядра.
        with patch.object(speed_test_worker, "_port_open", lambda host, port: True), \
                patch.object(speed_test_worker, "_free_port", lambda host: 40123):
            self.assertEqual(speed_test_worker._pick_port("127.0.0.1", 19101), 40123)
        with patch.object(speed_test_worker, "_port_open", lambda host, port: False):
            self.assertEqual(speed_test_worker._pick_port("127.0.0.1", 19101), 19101)


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class _TimedResponse:
    """Ответ, отдающий чанки по расписанию фальшивых часов."""

    def __init__(self, clock: _Clock, chunks: list[tuple[float, int]], *, fail_after: bool = False):
        self._clock = clock
        self._chunks = list(chunks)
        self._fail_after = fail_after
        self.headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, _size: int) -> bytes:
        if not self._chunks:
            if self._fail_after:
                raise TimeoutError("stalled")
            return b""
        delay, size = self._chunks.pop(0)
        self._clock.now += delay
        return b"x" * size


class _Opener:
    def __init__(self, response) -> None:
        self._response = response

    def open(self, _req, timeout=None):
        return self._response


class WindowedMeasurementTests(unittest.TestCase):
    def _measure(self, chunks, **kwargs):
        clock = _Clock()
        response = _TimedResponse(clock, chunks, fail_after=kwargs.pop("fail_after", False))
        with patch.object(speed_test_worker.time, "perf_counter", clock):
            return speed_test_worker.measure_download_bps(
                _Opener(response), "https://example.invalid/f", timeout=6.0, **kwargs
            )

    def test_warmup_is_discarded_and_download_stops_after_window(self) -> None:
        # 2 с ответа, затем разгон 100 Б/с и установившиеся 1000 Б/с.
        chunks = [(2.0, 100)] + [(1.0, 100)] + [(1.0, 1000)] * 10
        clock = _Clock()
        response = _TimedResponse(clock, chunks)
        with patch.object(speed_test_worker.time, "perf_counter", clock):
            bps = speed_test_worker.measure_download_bps(
                _Opener(response), "https://example.invalid/f",
                timeout=6.0, warmup=1.0, window=3.0,
            )
        self.assertEqual(bps, 1000.0)
        self.assertEqual(len(response._chunks), 7)  # файл до конца не качался

    def test_volume_cap_before_warmup_measures_from_first_byte(self) -> None:
        # Очень быстрый сервер исчерпал лимит раньше разгона: время ответа
        # (2 с до первого байта) в скорость не входит.
        bps = self._measure([(2.0, 500), (0.5, 500)], warmup=1.0, window=3.0, max_bytes=1000)
        self.assertEqual(bps, 2000.0)

    def test_stall_inside_window_counts_received_bytes(self) -> None:
        bps = self._measure(
            [(0.1, 100), (1.0, 100), (1.0, 400)],
            warmup=1.0, window=3.0, partial_on_error=True, fail_after=True,
        )
        self.assertEqual(bps, 400.0)

    def test_without_window_time_runs_from_request_start(self) -> None:
        # Контракт «умной проверки»: обе её стороны меряются именно так.
        self.assertEqual(self._measure([(2.0, 500), (2.0, 500)]), 250.0)


class WorkerMeasurementPolicyTests(unittest.TestCase):
    def _run(self, worker, measure):
        results: list = []
        percents: list = []
        worker.result.connect(lambda node_id, mbps, alive: results.append((node_id, mbps, alive)))
        worker.node_progress.connect(lambda node_id, percent: percents.append((node_id, percent)))
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "xray.exe"
            source.write_bytes(b"x")
            worker._xray_path = str(source)
            port_checks = iter([False, True] * len(worker._nodes))
            with patch.object(speed_test_worker, "prepare_speed_test_xray", lambda src: Path(src)), \
                    patch.object(speed_test_worker.subprocess, "Popen", lambda *a, **k: _Proc()), \
                    patch.object(speed_test_worker, "_port_open", lambda host, port: next(port_checks)), \
                    patch.object(speed_test_worker, "measure_download_bps", measure), \
                    patch.object(speed_test_worker.time, "sleep", lambda _s: None):
                worker.run()
        return results, percents

    def test_failed_measurement_is_retried_once(self) -> None:
        outcomes = iter([None, 4.0 * 1024 * 1024])
        calls: list[dict] = []

        def _measure(*_a, **kwargs):
            calls.append(kwargs)
            return next(outcomes)

        worker = speed_test_worker.SpeedTestWorker(
            [_vless_node()], xray_path="", retries=1, warmup=1.0, window=3.0, partial_on_error=True,
        )
        results, _ = self._run(worker, _measure)

        self.assertEqual(results, [("a", 4.0, True)])
        self.assertEqual(len(calls), 2)
        self.assertEqual((calls[0]["warmup"], calls[0]["window"], calls[0]["partial_on_error"]), (1.0, 3.0, True))

    def test_successful_measurement_is_not_repeated(self) -> None:
        calls: list[int] = []

        def _measure(*_a, **_k):
            calls.append(1)
            return 2.0 * 1024 * 1024

        worker = speed_test_worker.SpeedTestWorker([_vless_node()], xray_path="", retries=1)
        results, _ = self._run(worker, _measure)

        self.assertEqual(results, [("a", 2.0, True)])
        self.assertEqual(len(calls), 1)

    def test_dead_server_reports_once_after_all_attempts(self) -> None:
        worker = speed_test_worker.SpeedTestWorker([_vless_node()], xray_path="", retries=1)
        results, _ = self._run(worker, lambda *_a, **_k: None)
        self.assertEqual(results, [("a", None, False)])

    def test_row_progress_is_emitted_only_when_percent_changes(self) -> None:
        def _measure(*_a, on_fraction=None, **_k):
            for _ in range(500):
                on_fraction(0.5)  # сотни чанков — один и тот же процент
            return 2.0 * 1024 * 1024

        worker = speed_test_worker.SpeedTestWorker([_vless_node()], xray_path="")
        _, percents = self._run(worker, _measure)

        self.assertEqual(len(percents), len(set(percents)))
        self.assertLess(len(percents), 10)
        self.assertEqual(percents[-1], ("a", 100))

    def test_pause_between_servers_is_cancellable(self) -> None:
        worker = speed_test_worker.SpeedTestWorker(
            [_vless_node("a"), _vless_node("b")], xray_path="", pause_range=(30.0, 30.0),
        )

        def _measure(*_a, **_k):
            worker.cancel()  # отмена приходит, пока идёт первый сервер
            return 2.0 * 1024 * 1024

        results, _ = self._run(worker, _measure)

        self.assertEqual(results, [])
        self.assertTrue(worker.was_cancelled)

if __name__ == "__main__":
    unittest.main()
