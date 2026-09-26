"""«Умная проверка» авто-переключения при низкой скорости (без сети).

Подозрение возникает только при реальном спросе (проксируемые соединения
качают), решение — после контрольного замера текущего сервера и замера
кандидатов; переключение — единственным путём set_selected_node(...,
reset_auto_switch=False), с анти-дребезгом.
"""

from __future__ import annotations

import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from xray_fluent.application import smart_switch_service as smart
from xray_fluent.application.smart_switch_service import (
    PHASE_IDLE,
    PHASE_PROBE_CANDIDATES,
    PHASE_PROBE_CURRENT,
    SMART_SWITCH_FALSE_ALARM_COOLDOWN_SEC,
    SMART_SWITCH_POST_SWITCH_HOLD_SEC,
    SMART_SWITCH_SLOW_MARK_SEC,
    SMART_SWITCH_THRESHOLD_BPS,
    SmartSwitchState,
    cancel_smart_check,
    check_smart_switch,
    decide,
    on_candidate_result,
    on_candidates_done,
    on_current_probe_measured,
    select_candidates,
)
from xray_fluent.diagnostics.proxy_demand import clash_proxy_demand, local_proxy_demand
from xray_fluent.profiles.models import AppSettings, Node

MIB = 1024 * 1024
SLOW = 20 * 1024.0  # 20 KB/s — заметно ниже порога
DEMAND = {"active": 3, "growing": 2, "down_bps": SLOW}


class _Signal:
    def __init__(self) -> None:
        self.slots: list = []

    def connect(self, slot) -> None:
        self.slots.append(slot)


class _Recorder:
    def __init__(self) -> None:
        self.calls: list = []

    def emit(self, *args) -> None:
        self.calls.append(args)


class FakeProbeWorker:
    def __init__(self, http_port) -> None:
        self.http_port = http_port
        self.measured = _Signal()
        self.finished = _Signal()
        self.started = False
        self.cancelled = False

    def start(self) -> None:
        self.started = True

    def cancel(self) -> None:
        self.cancelled = True

    def isRunning(self) -> bool:  # noqa: N802 - QThread API
        return self.started and not self.cancelled


class FakeCandidateWorker:
    def __init__(self, nodes) -> None:
        self.nodes = list(nodes)
        self.result = _Signal()
        self.completed = _Signal()
        self.finished = _Signal()
        self.started = False
        self.cancelled = False

    def start(self) -> None:
        self.started = True

    def cancel(self) -> None:
        self.cancelled = True

    def isRunning(self) -> bool:  # noqa: N802 - QThread API
        return self.started and not self.cancelled


class FakeController:
    def __init__(self, node_count: int = 5) -> None:
        nodes = [
            Node(id=f"n{i}", name=f"node-{i}", server=f"s{i}.example.com", port=443,
                 scheme="vless", outbound={"protocol": "vless"}, sort_order=i)
            for i in range(node_count)
        ]
        self.state = SimpleNamespace(settings=AppSettings(), nodes=nodes, selected_node_id="n0")
        self.connected = True
        self._switching = False
        self._reconnecting = False
        self._transition_active = False
        self._transition_pending = False
        self._connecting = False
        self._disconnecting = False
        self._auto_switch_manual_hold = False
        self._auto_switch_warmup_until = 0.0
        self._auto_switch_last_switch = 0.0
        self._speed_worker = None
        self._ping_worker = None
        self._active_session = SimpleNamespace(http_port=10809, tun_mode=False)
        self.pool: set[str] | None = None
        self.status = _Recorder()
        self.logs: list[str] = []
        self.selected: list[tuple] = []

    def _log(self, line: str) -> None:
        self.logs.append(line)

    @property
    def selected_node(self):
        return next((n for n in self.state.nodes if n.id == self.state.selected_node_id), None)

    def set_selected_node(self, node_id: str, *, reset_auto_switch: bool = True) -> None:
        self.selected.append((node_id, reset_auto_switch))
        self.state.selected_node_id = node_id

    def _rotation_available_ids(self):
        return self.pool

    # Слоты воркеров — как у AppController (там sender(), здесь не нужен).
    def _on_smart_probe_measured(self, bps) -> None:  # pragma: no cover - не вызывается
        raise AssertionError("тест вызывает on_current_probe_measured напрямую")

    def _on_smart_candidate_result(self, *args) -> None:  # pragma: no cover
        raise AssertionError

    def _on_smart_candidates_done(self) -> None:  # pragma: no cover
        raise AssertionError


class SmartSwitchTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = FakeController()
        self.probes: list[FakeProbeWorker] = []
        self.candidate_workers: list[FakeCandidateWorker] = []

        def _probe(http_port):
            worker = FakeProbeWorker(http_port)
            self.probes.append(worker)
            return worker

        def _candidates(_controller, nodes):
            worker = FakeCandidateWorker(nodes)
            self.candidate_workers.append(worker)
            return worker

        patcher_probe = patch.object(smart, "create_probe_worker", side_effect=_probe)
        patcher_cand = patch.object(smart, "create_candidate_worker", side_effect=_candidates)
        patcher_probe.start()
        patcher_cand.start()
        self.addCleanup(patcher_probe.stop)
        self.addCleanup(patcher_cand.stop)

    @property
    def state(self) -> SmartSwitchState:
        return smart.smart_state(self.controller)

    def feed(self, start: float, seconds: int, *, down_bps: float = SLOW, demand=DEMAND,
             traffic_valid: bool = True) -> float:
        """Отсчёты метрик раз в секунду; возвращает время после последнего."""
        now = start
        for _ in range(seconds + 1):
            check_smart_switch(self.controller, down_bps, traffic_valid=traffic_valid,
                               demand=demand, now=now)
            now += 1.0
        return now

    def suspect(self, start: float = 1000.0) -> float:
        now = self.feed(start, 21)
        self.assertEqual(len(self.probes), 1, self.controller.logs)
        return now

    def run_candidates(self, now: float, results: dict[str, float | None]) -> None:
        worker = self.candidate_workers[-1]
        for node_id, mbps in results.items():
            on_candidate_result(self.controller, worker, node_id, mbps, mbps is not None)
        on_candidates_done(self.controller, worker, now=now)


class SuspicionTests(SmartSwitchTestBase):
    def test_idle_low_speed_without_demand_never_probes(self) -> None:
        # Загрузка закончилась: соединений нет — это простой, а не медленный сервер.
        self.feed(1000.0, 120, down_bps=0.0, demand={"active": 0, "growing": 0, "down_bps": 0.0})
        self.assertEqual(self.probes, [])

    def test_open_but_silent_connections_are_not_demand(self) -> None:
        self.feed(1000.0, 120, down_bps=500.0, demand={"active": 4, "growing": 0, "down_bps": 0.0})
        self.assertEqual(self.probes, [])

    def test_keepalive_trickle_is_not_demand(self) -> None:
        now = 1000.0
        for second in range(120):
            growing = 1 if second % 15 == 0 else 0
            check_smart_switch(self.controller, 200.0, demand={"active": 2, "growing": growing, "down_bps": 200.0},
                               now=now + second)
        self.assertEqual(self.probes, [])

    def test_no_connection_data_means_no_suspicion(self) -> None:
        self.feed(1000.0, 120, demand=None)
        self.assertEqual(self.probes, [])

    def test_high_speed_with_demand_never_probes(self) -> None:
        fast = {"active": 3, "growing": 3, "down_bps": 2.0 * SMART_SWITCH_THRESHOLD_BPS}
        self.feed(1000.0, 120, down_bps=2.0 * SMART_SWITCH_THRESHOLD_BPS, demand=fast)
        self.assertEqual(self.probes, [])

    def test_demand_with_low_speed_for_20s_starts_one_probe(self) -> None:
        self.feed(1000.0, 19)
        self.assertEqual(self.probes, [])
        self.feed(1020.0, 10)
        self.assertEqual(len(self.probes), 1)
        self.assertTrue(self.probes[0].started)
        self.assertEqual(self.probes[0].http_port, 10809)
        self.assertEqual(self.probes[0].measured.slots, [self.controller._on_smart_probe_measured])
        self.assertEqual(self.state.phase, PHASE_PROBE_CURRENT)
        self.assertTrue(any(line.startswith("[auto-switch] подозрение") for line in self.controller.logs))

    def test_short_growth_pause_keeps_demand(self) -> None:
        # Пауза роста 3 с (TCP подвисает на медленном сервере) не сбрасывает окно.
        now = 1000.0
        for second in range(25):
            growing = 0 if second % 4 == 3 else 1
            check_smart_switch(self.controller, SLOW, demand={"active": 1, "growing": growing, "down_bps": SLOW},
                               now=now + second)
        self.assertEqual(len(self.probes), 1)

    def test_invalid_sample_resets_window(self) -> None:
        self.feed(1000.0, 15)
        self.feed(1016.0, 0, traffic_valid=False)
        self.feed(1017.0, 15)
        self.assertEqual(self.probes, [])

    def test_tun_mode_probes_directly_through_tun(self) -> None:
        self.controller._active_session = SimpleNamespace(http_port=10809, tun_mode=True)
        self.suspect()
        self.assertIsNone(self.probes[0].http_port)

    def test_no_http_port_outside_tun_does_not_probe(self) -> None:
        self.controller._active_session = SimpleNamespace(http_port=0, tun_mode=False)
        self.feed(1000.0, 30)
        self.assertEqual(self.probes, [])
        self.assertEqual(self.state.phase, PHASE_IDLE)


class GateTests(SmartSwitchTestBase):
    def assert_never_probes(self) -> None:
        self.feed(1000.0, 120)
        self.assertEqual(self.probes, [])

    def test_master_switch_off(self) -> None:
        self.controller.state.settings.auto_switch_enabled = False
        self.assert_never_probes()

    def test_low_speed_setting_off(self) -> None:
        self.controller.state.settings.auto_switch_low_speed_enabled = False
        self.assert_never_probes()

    def test_transition_in_progress(self) -> None:
        self.controller._transition_active = True
        self.assert_never_probes()

    def test_speed_test_running(self) -> None:
        self.controller._speed_worker = SimpleNamespace(isRunning=lambda: True)
        self.assert_never_probes()

    def test_ping_batch_running(self) -> None:
        self.controller._ping_worker = SimpleNamespace(isRunning=lambda: True)
        self.assert_never_probes()

    def test_manual_hold(self) -> None:
        self.controller._auto_switch_manual_hold = True
        self.assert_never_probes()

    def test_warmup_after_server_change(self) -> None:
        self.controller._auto_switch_warmup_until = 5000.0
        self.assert_never_probes()

    def test_disconnected(self) -> None:
        self.controller.connected = False
        self.assert_never_probes()

    def test_setting_default_is_on_and_persisted(self) -> None:
        self.assertTrue(AppSettings().auto_switch_low_speed_enabled)
        self.assertTrue(AppSettings.from_dict({}).auto_switch_low_speed_enabled)
        off = AppSettings(auto_switch_low_speed_enabled=False).to_dict()
        self.assertFalse(AppSettings.from_dict(off).auto_switch_low_speed_enabled)


class ProbeDecisionTests(SmartSwitchTestBase):
    def test_probe_above_threshold_is_false_alarm_with_cooldown(self) -> None:
        now = self.suspect()
        on_current_probe_measured(self.controller, self.probes[0], 3.0 * SMART_SWITCH_THRESHOLD_BPS, now=now)
        self.assertEqual(self.candidate_workers, [])
        self.assertEqual(self.controller.selected, [])
        self.assertEqual(self.state.phase, PHASE_IDLE)
        self.assertTrue(any("ложная тревога" in line for line in self.controller.logs))
        # В течение 5 минут подозрение не накапливается и замер не повторяется.
        self.feed(now + 1, int(SMART_SWITCH_FALSE_ALARM_COOLDOWN_SEC) - 5)
        self.assertEqual(len(self.probes), 1)
        # После паузы — снова можно.
        self.feed(now + SMART_SWITCH_FALSE_ALARM_COOLDOWN_SEC + 1, 25)
        self.assertEqual(len(self.probes), 2)

    def test_confirmed_slow_and_better_candidate_switches_once(self) -> None:
        now = self.suspect()
        on_current_probe_measured(self.controller, self.probes[0], 30 * 1024.0, now=now)
        self.assertEqual(self.state.phase, PHASE_PROBE_CANDIDATES)
        worker = self.candidate_workers[0]
        self.assertTrue(worker.started)
        self.assertEqual(len(worker.nodes), 3)
        self.assertNotIn("n0", [node.id for node in worker.nodes])
        self.assertEqual(worker.result.slots, [self.controller._on_smart_candidate_result])
        self.assertEqual(worker.completed.slots, [self.controller._on_smart_candidates_done])

        self.run_candidates(now + 20, {"n1": 0.05, "n2": 1.5, "n3": None})

        self.assertEqual(self.controller.selected, [("n2", False)])
        self.assertEqual(self.state.phase, PHASE_IDLE)
        level, message = self.controller.status.calls[-1]
        self.assertEqual(level, "warning")
        self.assertEqual(message, "Сервер node-0 медленный (30 KB/s) — переключено на node-2 (1536 KB/s)")
        self.assertTrue(smart.is_slow_marked(self.state, "n0", now + 21))
        self.assertTrue(any(line.startswith("[auto-switch] решение: переключение") for line in self.controller.logs))

    def test_failed_current_probe_is_inconclusive(self) -> None:
        # Ни байта через текущий сервер — не доказательство медленности
        # (destination-scope): кандидатов не меряем, не переключаемся.
        now = self.suspect()
        on_current_probe_measured(self.controller, self.probes[0], None, now=now)
        self.assertEqual(self.candidate_workers, [])
        self.assertEqual(self.controller.selected, [])
        self.assertEqual(self.state.phase, PHASE_IDLE)
        self.assertGreater(self.state.cooldown_until, now)

    def test_candidate_not_twice_as_fast_does_not_switch(self) -> None:
        now = self.suspect()
        # Текущий 100 KB/s (ниже порога), лучший кандидат 150 KB/s: ≥ порога, но < 2×.
        on_current_probe_measured(self.controller, self.probes[0], 100 * 1024.0, now=now)
        self.run_candidates(now + 20, {"n1": 150 / 1024, "n2": None})
        self.assertEqual(self.controller.selected, [])
        self.assertEqual(self.state.phase, PHASE_IDLE)
        self.assertGreater(self.state.cooldown_until, now)

    def test_candidate_below_threshold_does_not_switch(self) -> None:
        now = self.suspect()
        on_current_probe_measured(self.controller, self.probes[0], 10 * 1024.0, now=now)
        self.run_candidates(now + 20, {"n1": 0.1})  # 102 KB/s: в 10 раз быстрее, но ниже порога
        self.assertEqual(self.controller.selected, [])

    def test_no_candidates_means_no_switch(self) -> None:
        for node in self.controller.state.nodes[1:]:
            node.is_alive = False
        now = self.suspect()
        on_current_probe_measured(self.controller, self.probes[0], 10 * 1024.0, now=now)
        self.assertEqual(self.candidate_workers, [])
        self.assertEqual(self.controller.selected, [])
        self.assertEqual(self.state.phase, PHASE_IDLE)

    def test_transition_during_check_aborts_decision(self) -> None:
        now = self.suspect()
        on_current_probe_measured(self.controller, self.probes[0], 10 * 1024.0, now=now)
        self.controller._transition_active = True
        self.run_candidates(now + 20, {"n1": 2.0})
        self.assertEqual(self.controller.selected, [])
        self.assertEqual(self.state.phase, PHASE_IDLE)

    def test_setting_disabled_during_check_aborts_probe(self) -> None:
        now = self.suspect()
        self.controller.state.settings.auto_switch_low_speed_enabled = False
        on_current_probe_measured(self.controller, self.probes[0], 10 * 1024.0, now=now)
        self.assertEqual(self.candidate_workers, [])

    def test_server_changed_during_check_aborts(self) -> None:
        now = self.suspect()
        on_current_probe_measured(self.controller, self.probes[0], 10 * 1024.0, now=now)
        self.controller.state.selected_node_id = "n4"
        self.run_candidates(now + 20, {"n1": 2.0})
        self.assertEqual(self.controller.selected, [])

    def test_cancel_ignores_late_results(self) -> None:
        now = self.suspect()
        probe = self.probes[0]
        cancel_smart_check(self.controller, "запущен тест скорости")
        self.assertTrue(probe.cancelled)
        self.assertEqual(self.state.phase, PHASE_IDLE)
        on_current_probe_measured(self.controller, probe, 10 * 1024.0, now=now)
        self.assertEqual(self.candidate_workers, [])

    def test_stuck_check_is_reset_after_deadline(self) -> None:
        now = self.suspect()
        check_smart_switch(self.controller, SLOW, demand=DEMAND, now=now + smart.SMART_SWITCH_CHECK_DEADLINE_SEC + 1)
        self.assertEqual(self.state.phase, PHASE_IDLE)
        self.assertTrue(self.probes[0].cancelled)


class HysteresisTests(SmartSwitchTestBase):
    def switch_once(self, start: float, *, to: str, speed_mbps: float = 1.0) -> float:
        before = len(self.probes)
        now = self.feed(start, 21)
        self.assertEqual(len(self.probes), before + 1, self.controller.logs)
        on_current_probe_measured(self.controller, self.probes[-1], 10 * 1024.0, now=now)
        self.run_candidates(now + 20, {to: speed_mbps})
        self.assertEqual(self.controller.selected[-1], (to, False))
        return now + 20

    def test_post_switch_hold_blocks_new_checks_for_10_minutes(self) -> None:
        switched_at = self.switch_once(1000.0, to="n1")
        self.feed(switched_at + 1, int(SMART_SWITCH_POST_SWITCH_HOLD_SEC) - 5)
        self.assertEqual(len(self.probes), 1)
        self.feed(switched_at + SMART_SWITCH_POST_SWITCH_HOLD_SEC + 1, 25)
        self.assertEqual(len(self.probes), 2)

    def test_abandoned_server_is_not_a_candidate_for_30_minutes(self) -> None:
        switched_at = self.switch_once(1000.0, to="n1")
        state = self.state
        nodes = self.controller.state.nodes
        within = [n.id for n in select_candidates(nodes, "n1", state, switched_at + 15 * 60, limit=10)]
        self.assertNotIn("n0", within)
        after = [n.id for n in select_candidates(nodes, "n1", state, switched_at + SMART_SWITCH_SLOW_MARK_SEC + 1, limit=10)]
        self.assertIn("n0", after)

    def test_at_most_three_switches_per_hour(self) -> None:
        now = 1000.0
        for target in ("n1", "n2", "n3"):
            now = self.switch_once(now, to=target) + SMART_SWITCH_POST_SWITCH_HOLD_SEC + 1
        # Три переключения за ~32 минуты: четвёртое в этот час невозможно.
        self.feed(now, 25)
        self.assertEqual(len(self.probes), 3)
        self.assertEqual(len(self.controller.selected), 3)
        # Через час после первого переключения лимит освобождается.
        self.feed(1000.0 + 3600.0 + 60.0, 25)
        self.assertEqual(len(self.probes), 4)

    def test_smart_switch_stamps_shared_cooldown_but_not_cycle(self) -> None:
        switched_at = self.switch_once(1000.0, to="n1")
        self.assertEqual(self.controller._auto_switch_last_switch, switched_at)


class CandidateSelectionTests(unittest.TestCase):
    def nodes(self):
        return [
            Node(id="cur", name="cur", outbound={"protocol": "vless"}, sort_order=0),
            Node(id="dead", name="dead", outbound={"protocol": "vless"}, is_alive=False, speed_mbps=9.0),
            Node(id="fast", name="fast", outbound={"protocol": "vless"}, speed_mbps=5.0, ping_ms=200),
            Node(id="mid", name="mid", outbound={"protocol": "vless"}, speed_mbps=2.0, ping_ms=50),
            Node(id="pinged", name="pinged", outbound={"protocol": "vless"}, ping_ms=30),
            Node(id="unknown", name="unknown", outbound={"protocol": "vless"}),
            Node(id="hy2", name="hy2", outbound={"type": "hysteria2"}, speed_mbps=50.0),
            Node(id="maint", name="техработы", outbound={"protocol": "vless"}, speed_mbps=50.0),
        ]

    def test_ranking_and_filters(self) -> None:
        state = SmartSwitchState()
        picked = select_candidates(self.nodes(), "cur", state, 0.0)
        self.assertEqual([n.id for n in picked], ["fast", "mid", "pinged"])

    def test_slow_marked_nodes_are_skipped(self) -> None:
        state = SmartSwitchState()
        state.slow_until["fast"] = 100.0
        picked = select_candidates(self.nodes(), "cur", state, 50.0)
        self.assertNotIn("fast", [n.id for n in picked])

    def test_hot_switch_pool_is_preferred(self) -> None:
        state = SmartSwitchState()
        picked = select_candidates(self.nodes(), "cur", state, 0.0, available_ids={"cur", "unknown"})
        self.assertEqual([n.id for n in picked], ["unknown"])
        picked = select_candidates(self.nodes(), "cur", state, 0.0, available_ids={"cur"})
        self.assertEqual([n.id for n in picked], ["fast", "mid", "pinged"])

    def test_decide(self) -> None:
        threshold = SMART_SWITCH_THRESHOLD_BPS
        self.assertIsNone(decide(10_000.0, {}))
        self.assertIsNone(decide(10_000.0, {"a": None}))
        self.assertIsNone(decide(0.0, {"a": threshold - 1}))
        self.assertIsNone(decide(threshold * 0.9, {"a": threshold * 1.5}))
        self.assertEqual(decide(threshold * 0.5, {"a": threshold * 1.0, "b": threshold * 3.0}),
                         ("b", threshold * 3.0))


class ProxyDemandTests(unittest.TestCase):
    def conn(self, cid, up, down, chain="proxy", exe="chrome.exe"):
        return {"id": cid, "upload": up, "download": down, "chains": [chain],
                "metadata": {"processPath": f"C:\\Apps\\{exe}"}}

    def test_clash_growth_and_route_classification(self) -> None:
        prev: dict = {}
        first = clash_proxy_demand(
            [self.conn("a", 10, 100), self.conn("d", 5, 5000, chain="direct")],
            prev, 1.0, excluded_processes=frozenset(),
        )
        self.assertEqual(first["active"], 1)
        self.assertEqual(first["growing"], 1)  # новое соединение с данными
        second = clash_proxy_demand(
            [self.conn("a", 10, 100), self.conn("d", 5, 9000, chain="direct")],
            prev, 1.0, excluded_processes=frozenset(),
        )
        self.assertEqual((second["active"], second["growing"], second["down_bps"]), (1, 0, 0.0))
        third = clash_proxy_demand(
            [self.conn("a", 10, 2148)], prev, 2.0, excluded_processes=frozenset(),
        )
        self.assertEqual((third["active"], third["growing"], third["down_bps"]), (1, 1, 1024.0))
        self.assertNotIn("d", prev)

    def test_pool_member_tags_count_as_proxied(self) -> None:
        prev: dict = {}
        demand = clash_proxy_demand([self.conn("a", 1, 1, chain="__app_proxy_abc")], prev, 1.0,
                                    excluded_processes=frozenset())
        self.assertEqual(demand["active"], 1)

    def test_own_process_is_not_demand(self) -> None:
        prev: dict = {}
        demand = clash_proxy_demand([self.conn("a", 1, 999, exe="ZapretKVN.exe")], prev, 1.0)
        self.assertEqual(demand["active"], 0)

    def test_local_proxy_demand(self) -> None:
        prev: dict = {}
        proc = SimpleNamespace(exe="chrome.exe", bytes_in=1000, bytes_out=10, connections=2)
        first = local_proxy_demand([proc], prev, 2.0, excluded_processes=frozenset())
        self.assertEqual((first["active"], first["growing"]), (2, 0))
        proc.bytes_in = 5096
        second = local_proxy_demand([proc], prev, 2.0, excluded_processes=frozenset())
        self.assertEqual((second["active"], second["growing"], second["down_bps"]), (2, 1, 2048.0))
        self.assertEqual(local_proxy_demand([], prev, 2.0)["active"], 0)


class _FakeResponse(io.BytesIO):
    def __init__(self, payload: bytes, fail_after: int | None = None) -> None:
        super().__init__(payload)
        self.headers = {"Content-Length": str(len(payload))}
        self._fail_after = fail_after

        self.consumed = 0

    def read(self, size: int = -1) -> bytes:
        if self._fail_after is not None and self.tell() >= self._fail_after:
            raise TimeoutError("read timed out")
        chunk = super().read(size)
        self.consumed += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class MeasureDownloadTests(unittest.TestCase):
    def test_max_bytes_bounds_the_download(self) -> None:
        from xray_fluent.network.speed_test_worker import measure_download_bps

        response = _FakeResponse(b"x" * (8 * 64 * 1024))
        opener = SimpleNamespace(open=lambda req, timeout: response)
        bps = measure_download_bps(opener, "https://example.invalid/f", timeout=5.0, max_bytes=2 * 64 * 1024)
        self.assertIsNotNone(bps)
        self.assertEqual(response.consumed, 2 * 64 * 1024)

    def test_partial_download_counts_only_when_requested(self) -> None:
        from xray_fluent.network.speed_test_worker import measure_download_bps

        def opener(fail_after):
            return SimpleNamespace(open=lambda req, timeout: _FakeResponse(b"x" * (4 * 64 * 1024), fail_after))

        self.assertIsNone(measure_download_bps(opener(64 * 1024), "https://example.invalid/f", timeout=5.0))
        self.assertIsNotNone(measure_download_bps(opener(64 * 1024), "https://example.invalid/f", timeout=5.0, partial_on_error=True))
        self.assertIsNone(measure_download_bps(opener(0), "https://example.invalid/f", timeout=5.0, partial_on_error=True))

    def test_candidate_worker_uses_bounded_isolated_measurement(self) -> None:
        from xray_fluent.constants import ROUTING_GLOBAL, SPEED_TEST_TEMP_HTTP_PORT

        controller = SimpleNamespace(state=SimpleNamespace(settings=AppSettings()))
        worker = smart.create_candidate_worker(controller, [Node(id="a", outbound={"protocol": "vless"})])
        self.assertEqual(worker._rounds, 1)
        self.assertEqual(worker._max_bytes, smart.SMART_SWITCH_PROBE_MAX_BYTES)
        self.assertEqual(worker._url, smart.SMART_SWITCH_PROBE_URL)
        self.assertNotEqual(worker._http_port, SPEED_TEST_TEMP_HTTP_PORT)
        self.assertEqual(worker._routing.mode, ROUTING_GLOBAL)
        self.assertNotIn(".ru/", smart.SMART_SWITCH_PROBE_URL)
        self.assertNotIn("dns-query", smart.SMART_SWITCH_PROBE_URL)


if __name__ == "__main__":
    unittest.main()


class ProbeWorkerThreadingTests(unittest.TestCase):
    """Настоящий QThread-замер: результат приходит в слот GUI-потока (очередь Qt)."""

    def test_measured_signal_reaches_receiver_on_its_thread(self) -> None:
        import os
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        from PyQt6.QtCore import QCoreApplication, QEventLoop, QObject, QThread, QTimer

        from xray_fluent.network.speed_test_worker import ActiveProxySpeedProbeWorker

        app = QCoreApplication.instance() or QCoreApplication([])
        payload = b"z" * (512 * 1024)

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - http.server API
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args) -> None:
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        class _Receiver(QObject):
            def __init__(self) -> None:
                super().__init__()
                self.calls: list[tuple[object, object]] = []

            def on_measured(self, bps) -> None:
                self.calls.append((bps, QThread.currentThread()))

        receiver = _Receiver()
        env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
        with patch.dict(os.environ, env, clear=True):
            worker = ActiveProxySpeedProbeWorker(
                None,
                f"http://127.0.0.1:{server.server_address[1]}/probe.bin",
                timeout=5.0,
                max_bytes=256 * 1024,
            )
            worker.measured.connect(receiver.on_measured)
            loop = QEventLoop()
            worker.measured.connect(lambda _bps: QTimer.singleShot(0, loop.quit))
            QTimer.singleShot(10_000, loop.quit)  # жёсткий дедлайн теста
            worker.start()
            loop.exec()
            worker.wait(5000)
            app.processEvents()

        self.assertEqual(len(receiver.calls), 1)
        bps, thread = receiver.calls[0]
        self.assertIsInstance(bps, float)
        self.assertGreater(bps, 0.0)
        self.assertIs(thread, app.thread())


class ControllerWiringTests(unittest.TestCase):
    def test_app_controller_exposes_smart_switch_slots(self) -> None:
        from xray_fluent.application.controller import AppController

        for name in (
            "_check_smart_switch",
            "_on_smart_probe_measured",
            "_on_smart_candidate_result",
            "_on_smart_candidates_done",
        ):
            self.assertTrue(callable(getattr(AppController, name, None)), name)
