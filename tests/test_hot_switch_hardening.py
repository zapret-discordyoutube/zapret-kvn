"""hot-switch-hardening (П1–П5): AC-тесты.

Spec: .agent/tasks/hot-switch-hardening/spec.md

- П1/AC1–AC3: самодостаточные outbound_pool_tags в _capture_active_session и
  их сохранение после fallback-рестартов (restart_proxy_core_steps,
  tun2socks hot_swap_steps).
- П2/AC5–AC8: control-plane hot-switch вне GUI-потока (run_in_worker),
  без pump, фолбэк при отказе, generation-сериализация со сбросом устаревших
  результатов.
- П3/AC9–AC10: кэш xray_outbound_pool и его инвалидация.
- П4/AC11–AC12: auto-switch через set_selected_node с сохранением учёта
  анти-дребезга.
- П5/AC13–AC14: фоновый батч-прогрев DNS-кэша zapret без побочных эффектов.

Оффскрин: реальные ядра не запускаются (C3/A8); control-plane и резолвер —
моки; асинхронность управляется вручную (ManualExecutor + processEvents),
без реальных ожиданий.
"""

from __future__ import annotations

import threading
import time
import unittest
from concurrent.futures import Future
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

from PyQt6.QtCore import QCoreApplication

from xray_fluent.app_controller import AppController
from xray_fluent.application import async_steps
from xray_fluent.application.async_steps import RunInWorkerStep
from xray_fluent.application.auto_switch_service import check_auto_switch
from xray_fluent.application.outbound_pool_service import build_xray_outbound_pool
from xray_fluent.application.session_state import XrayRuntimeConfig
from xray_fluent.application.zapret_prewarm_service import (
    collect_prewarm_servers,
    prewarm_proxy_resolutions,
    start_proxy_dns_prewarm,
)
from xray_fluent.engines.tun2socks.operations import hot_swap_steps
from xray_fluent.engines.xray.operations import restart_proxy_core_steps
from xray_fluent.link_parser import parse_single
from xray_fluent.models import AppSettings, RoutingSettings
from xray_fluent.zapret_manager import ZapretManager

_APP = QCoreApplication.instance() or QCoreApplication([])


def _drive_until(condition, timeout_ms: int = 5000) -> bool:
    """Прокачивает event loop теста, пока condition() не станет истинным."""
    deadline = time.monotonic() + timeout_ms / 1000.0
    while time.monotonic() < deadline:
        if condition():
            return True
        _APP.processEvents()
        time.sleep(0.002)
    return condition()


def xray_nodes():
    return [
        parse_single(
            "vless://11111111-1111-1111-1111-111111111111@one.example:443"
            "?type=tcp&security=tls&sni=one.example#one"
        ),
        parse_single("trojan://secret@two.example:443?security=tls&sni=two.example#two"),
        parse_single("trojan://secret@three.example:443?security=tls&sni=three.example#three"),
    ]


def udp_nodes():
    return [
        parse_single("hy2://secret@udp-one.example:443/?insecure=1#udp-one"),
        parse_single("hy2://secret@udp-two.example:443/?insecure=1#udp-two"),
    ]


def make_session(**overrides):
    base = dict(
        node_id=None,
        node_server="",
        active_core="xray",
        tun_mode=False,
        hybrid=False,
        socks_port=10808,
        http_port=10809,
        api_port=19100,
        xray_inbound_tags=(),
        sidecar_relay_port=0,
        protect_ss_port=0,
        protect_ss_password="",
        ping_host="",
        ping_port=0,
        outbound_pool_tags={},
        hybrid_relay_selector_tags=(),
        hybrid_relay_selected_tag="",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def drive_sync_generator(generator):
    """Выполнить генератор шагов, в котором все под-шаги замоканы (нет yield)."""
    try:
        step = generator.send(None)
    except StopIteration as stop:
        return stop.value
    raise AssertionError(f"unexpected async step: {step!r}")


class SessionCaptureController:
    """Фейк-контроллер с настоящими методами захвата сессии и пула."""

    _capture_active_session = AppController._capture_active_session
    _derive_outbound_pool_tags = AppController._derive_outbound_pool_tags
    xray_outbound_pool = AppController.xray_outbound_pool
    _invalidate_xray_outbound_pool_cache = AppController._invalidate_xray_outbound_pool_cache
    _hot_switch_precheck = AppController._hot_switch_precheck

    def __init__(self, nodes):
        self.state = SimpleNamespace(
            settings=AppSettings(),
            routing=RoutingSettings(),
            nodes=nodes,
            selected_node_id=nodes[0].id if nodes else None,
        )
        self._active_session = None
        self._blocked_transition_signature = "sentinel"
        self._xray_outbound_pool_cache = None
        self._xray_outbound_pool_cache_key = None
        self.connected = True
        self.logs: list[str] = []
        self.zapret = SimpleNamespace(apply_cached_proxy_node=lambda node: True)

    @property
    def selected_node(self):
        return next(
            (node for node in self.state.nodes if node.id == self.state.selected_node_id),
            None,
        )

    def _log(self, line: str) -> None:
        self.logs.append(line)

    def _routing_signature(self, routing):
        return "routing-sig"

    def _transition_signature(self, *args):
        return "transition-sig"

    def _xray_layer_signature(self, *args):
        return "xray-sig"

    def _tun_layer_signature(self, *args):
        return "tun-sig"

    def _system_proxy_bypass_lan(self, settings=None):
        return False


class CaptureActiveSessionDefaultTagsTests(unittest.TestCase):
    """AC1: самодостаточный вывод outbound_pool_tags из пула контроллера."""

    def _capture(self, controller, node, *, core, **kwargs):
        controller._capture_active_session(node, tun=False, core=core, api_port=0, **kwargs)
        return controller._active_session

    def test_default_tags_derived_from_controller_pool_for_xray_core(self) -> None:
        nodes = xray_nodes()
        controller = SessionCaptureController(nodes)
        pool = build_xray_outbound_pool(nodes)

        session = self._capture(controller, nodes[0], core="xray")

        self.assertEqual(session.outbound_pool_tags, pool.tags)
        self.assertIn(nodes[0].id, session.outbound_pool_tags)

    def test_default_tags_derived_for_tun2socks_core(self) -> None:
        nodes = xray_nodes()
        controller = SessionCaptureController(nodes)

        session = self._capture(controller, nodes[1], core="tun2socks")

        self.assertEqual(session.outbound_pool_tags, build_xray_outbound_pool(nodes).tags)

    def test_explicit_tags_override_derived_default(self) -> None:
        nodes = xray_nodes()
        controller = SessionCaptureController(nodes)
        selector_tags = {nodes[0].id: "node_deadbeef"}

        session = self._capture(
            controller, nodes[0], core="singbox", outbound_pool_tags=selector_tags
        )

        self.assertEqual(session.outbound_pool_tags, selector_tags)

    def test_explicit_empty_tags_stay_empty(self) -> None:
        # A2: явный пустой словарь означает «ядро пул не грузило» и не должен
        # подменяться выведенным дефолтом.
        nodes = xray_nodes()
        controller = SessionCaptureController(nodes)

        session = self._capture(controller, nodes[0], core="xray", outbound_pool_tags={})

        self.assertEqual(session.outbound_pool_tags, {})

    def test_no_default_for_singbox_core(self) -> None:
        # Схема тегов sing-box (selector_tags) другая: выводить её из Xray-пула
        # нельзя, вызывающие передают её явно.
        nodes = xray_nodes()
        controller = SessionCaptureController(nodes)

        session = self._capture(controller, nodes[0], core="singbox")

        self.assertEqual(session.outbound_pool_tags, {})

    def test_no_default_without_node_or_outside_pool(self) -> None:
        nodes = xray_nodes()
        native = udp_nodes()[0]  # native sing-box outbound — вне Xray-пула
        controller = SessionCaptureController(nodes + [native])

        self.assertEqual(
            self._capture(controller, None, core="xray").outbound_pool_tags, {}
        )
        self.assertEqual(
            self._capture(controller, native, core="xray").outbound_pool_tags, {}
        )


class FakeCoreSteps:
    """QProcess-обёртка ядра: генераторные stop/start без реального процесса."""

    def __init__(self):
        self.is_running = True
        self.started_configs: list[dict] = []
        self._exe_path = "xray.exe"

    def stop_steps(self):
        self.is_running = False
        return True
        yield  # unreachable — генераторная форма как у XrayManager

    def start_steps(self, path, config):
        self.is_running = True
        self.started_configs.append(config)
        return True
        yield  # unreachable


class OperationsController(SessionCaptureController):
    """Фейк-контроллер для генераторных операций рестарта/hot-swap."""

    def __init__(self, nodes):
        super().__init__(nodes)
        self.xray = FakeCoreSteps()
        self.proxy = Mock()
        self._switching = False
        self._auto_switch_transitioning = False
        self._xray_api_port = 0
        self._tun2socks_proxy_username = "relay-user"
        self._tun2socks_proxy_password = "relay-pass"
        self.statuses: list[tuple[str, str]] = []
        self.saves = 0
        self.status = SimpleNamespace(emit=lambda *args: None)
        self.connection_changed = SimpleNamespace(emit=lambda *args: None)

    def _set_connection_status(self, phase, message, level=None):
        self.statuses.append((phase, message))

    def _stop_metrics_worker(self):
        pass

    def _start_metrics_worker(self):
        pass

    def _refresh_connected_state(self):
        self.connected = True
        return True, True

    def schedule_save(self):
        self.saves += 1

    def _handle_unexpected_disconnect(self):
        raise AssertionError("unexpected disconnect in test")

    def _prepare_node_for_runtime(self, node):
        return None


class RestartProxyCoreSessionTagsTests(unittest.TestCase):
    """AC2: после restart_proxy_core_steps hot-switch снова проходит по пулу."""

    def _run_restart(self, controller, nodes):
        pool = build_xray_outbound_pool(nodes)
        runtime = XrayRuntimeConfig(
            config={"outbounds": []},
            source_path=Path("active.json"),
            has_proxy_outbound=True,
            used_selected_node=True,
            requested_socks_port=10808,
            requested_http_port=10809,
            socks_port=10808,
            http_port=10809,
            api_port=19100,
            tun_interface_name="",
            loop_prevention_interface="",
            loop_prevention_patched_outbounds=0,
            inbound_tags=("socks-in", "http-in"),
            ping_host=nodes[0].server,
            ping_port=443,
            outbound_pool_tags=dict(pool.tags),
        )
        controller._build_runtime_xray_config = lambda node, tun_mode=False: runtime
        controller.state.settings.enable_system_proxy = False
        return drive_sync_generator(restart_proxy_core_steps(controller, "fallback restart"))

    def test_session_keeps_pool_tags_after_fallback_restart(self) -> None:
        nodes = xray_nodes()
        controller = OperationsController(nodes)

        self.assertTrue(self._run_restart(controller, nodes))

        session = controller._active_session
        pool = build_xray_outbound_pool(nodes)
        self.assertEqual(session.outbound_pool_tags, pool.tags)
        self.assertIn(controller.state.selected_node_id, session.outbound_pool_tags)

    def test_pool_tag_check_passes_after_restart(self) -> None:
        nodes = xray_nodes()
        controller = OperationsController(nodes)
        self.assertTrue(self._run_restart(controller, nodes))

        controller.logs.clear()
        plan = controller._hot_switch_precheck()

        # Проверка пула пройдена: fallback «not loaded in ... pool» не логируется.
        self.assertFalse(any("is not loaded in" in line for line in controller.logs))
        # Чистый xray-core честно уходит в переход из-за отсутствия interrupt API —
        # но уже ПОСЛЕ успешной проверки пула (это контракт AC2, а не деградация П1).
        self.assertIsNone(plan)
        self.assertTrue(any("cannot interrupt" in line for line in controller.logs))


class Tun2SocksHotSwapSessionTagsTests(unittest.TestCase):
    """AC3: TUN hot-swap захватывает теги пула, реально встроенного в конфиг."""

    def _run_hot_swap(self, controller, node):
        controller._active_session = make_session(
            node_id=controller.state.nodes[0].id,
            active_core="tun2socks",
            tun_mode=True,
            socks_port=10808,
        )
        controller._xray_api_port = 19100
        controller.state.selected_node_id = node.id
        return drive_sync_generator(hot_swap_steps(controller, "node switched", node))

    def test_session_keeps_pool_tags_after_tun_hot_swap(self) -> None:
        nodes = xray_nodes()
        controller = OperationsController(nodes)

        self.assertTrue(self._run_hot_swap(controller, nodes[1]))

        session = controller._active_session
        pool = build_xray_outbound_pool(nodes)
        self.assertEqual(session.outbound_pool_tags, pool.tags)
        self.assertIn(nodes[1].id, session.outbound_pool_tags)
        # Конфиг действительно собран с пулом (все теги пула присутствуют).
        config = controller.xray.started_configs[-1]
        config_tags = {outbound.get("tag") for outbound in config.get("outbounds", [])}
        self.assertTrue(set(pool.tags.values()) <= config_tags)

    def test_pool_tag_check_passes_after_tun_hot_swap(self) -> None:
        nodes = xray_nodes()
        controller = OperationsController(nodes)
        self.assertTrue(self._run_hot_swap(controller, nodes[1]))

        controller.logs.clear()
        controller._hot_switch_precheck()
        self.assertFalse(any("is not loaded in" in line for line in controller.logs))


class HotSwitchController:
    """Фейк-контроллер с настоящей асинхронной hot-switch машинерией."""

    _hot_switch_precheck = AppController._hot_switch_precheck
    _try_hot_switch_selected_node = AppController._try_hot_switch_selected_node
    _start_hot_switch_runner = AppController._start_hot_switch_runner
    _on_hot_switch_runner_finished = AppController._on_hot_switch_runner_finished
    _dispatch_hot_switch_request = AppController._dispatch_hot_switch_request
    _cancel_hot_switch_runner = AppController._cancel_hot_switch_runner
    _hot_switch_selected_node_steps = AppController._hot_switch_selected_node_steps
    _apply_core_outbound_tag_steps = AppController._apply_core_outbound_tag_steps

    def __init__(self, nodes, session):
        self.state = SimpleNamespace(
            settings=AppSettings(),
            routing=RoutingSettings(),
            nodes=nodes,
            selected_node_id=nodes[0].id,
        )
        self._active_session = session
        self.connected = True
        self._desired_connected = True
        self._hot_switch_runner = None
        self._hot_switch_generation = 0
        self._hot_switch_pending = False
        self._transition_generation = 0
        self._singbox_clash_api_port = 19090
        self._xray_api_port = 19085
        self.xray = SimpleNamespace(_exe_path="xray.exe")
        self.zapret = SimpleNamespace(apply_cached_proxy_node=lambda node: True)
        self.logs: list[str] = []
        self.transitions: list[str] = []
        self.captured: list[tuple[str, str, int]] = []

    @property
    def selected_node(self):
        return next(
            (node for node in self.state.nodes if node.id == self.state.selected_node_id),
            None,
        )

    def _log(self, line: str) -> None:
        self.logs.append(line)

    def _request_transition(self, reason: str) -> None:
        self.transitions.append(reason)

    def _capture_hot_switched_session(
        self, node, session, tags, tag, *, hybrid_relay_selected_tag=""
    ) -> None:
        self.captured.append((node.id, tag, threading.get_ident()))


def singbox_session_for(nodes):
    return make_session(
        node_id=nodes[0].id,
        active_core="singbox",
        hybrid=False,
        outbound_pool_tags={node.id: f"node_{index}" for index, node in enumerate(nodes)},
    )


class HotSwitchOffGuiThreadTests(unittest.TestCase):
    """AC5/AC6: control-plane на воркере, GUI-поток получает результат сигналом."""

    def test_control_plane_runs_on_worker_and_commit_on_gui_thread(self) -> None:
        nodes = xray_nodes()
        controller = HotSwitchController(nodes, singbox_session_for(nodes))
        controller.state.selected_node_id = nodes[1].id
        threads: list[int] = []

        def fake_select(api_port, selector_tag, outbound_tag):
            threads.append(threading.get_ident())
            return True, ""

        with patch("xray_fluent.app_controller.select_singbox_outbound", fake_select):
            self.assertTrue(controller._try_hot_switch_selected_node())
            self.assertTrue(_drive_until(lambda: controller.captured))

        main_thread = threading.get_ident()
        self.assertEqual(len(threads), 1)
        self.assertNotEqual(threads[0], main_thread)  # AC5: I/O вне GUI-потока
        node_id, tag, commit_thread = controller.captured[0]
        self.assertEqual(node_id, nodes[1].id)
        self.assertEqual(commit_thread, main_thread)  # результат — в GUI-потоке
        self.assertEqual(controller.transitions, [])

    def test_control_plane_step_is_run_in_worker_step(self) -> None:
        nodes = xray_nodes()
        controller = HotSwitchController(nodes, singbox_session_for(nodes))
        generator = controller._apply_core_outbound_tag_steps("singbox", "node_1")
        step = next(generator)
        self.assertIsInstance(step, RunInWorkerStep)
        generator.close()

    def test_xray_balancer_call_does_not_pump_qt_events(self) -> None:
        # AC6: горячий путь зовёт apply_balancer_override строго с pump=False.
        nodes = xray_nodes()
        controller = HotSwitchController(nodes, singbox_session_for(nodes))
        recorded: list[dict] = []

        def fake_override(xray_path, api_port, balancer_tag, outbound_tag="", **kwargs):
            recorded.append(kwargs)
            return True, ""

        with patch("xray_fluent.app_controller.apply_balancer_override", fake_override):
            generator = controller._apply_core_outbound_tag_steps("xray", "tag-x")
            step = next(generator)
            self.assertIsInstance(step, RunInWorkerStep)
            step._fn()
            generator.close()

        self.assertEqual(recorded, [{"pump": False}])


class HotSwitchFallbackTests(unittest.TestCase):
    """AC7: отказ control-plane после принятого свитча падает в очередь переходов."""

    def _finished_runner(self, *, cancelled=False, error=None, result=None):
        return SimpleNamespace(
            cancelled=cancelled, error=error, result=result, deleteLater=lambda: None
        )

    def _controller(self):
        nodes = xray_nodes()
        controller = HotSwitchController(nodes, singbox_session_for(nodes))
        controller.state.selected_node_id = nodes[1].id
        return controller

    def test_control_plane_failure_falls_back_to_transition_queue(self) -> None:
        controller = self._controller()
        controller._on_hot_switch_runner_finished(self._finished_runner(result=False))
        self.assertEqual(controller.transitions, ["node switched"])

    def test_step_error_falls_back_to_transition_queue(self) -> None:
        controller = self._controller()
        controller._on_hot_switch_runner_finished(
            self._finished_runner(result=None, error=OSError("boom"))
        )
        self.assertEqual(controller.transitions, ["node switched"])
        self.assertTrue(any("failed with error" in line for line in controller.logs))

    def test_successful_switch_does_not_touch_transition_queue(self) -> None:
        controller = self._controller()
        controller._on_hot_switch_runner_finished(self._finished_runner(result=True))
        self.assertEqual(controller.transitions, [])

    def test_cancelled_switch_without_pending_is_silent(self) -> None:
        controller = self._controller()
        controller._on_hot_switch_runner_finished(self._finished_runner(cancelled=True))
        self.assertEqual(controller.transitions, [])


class ManualExecutor:
    """Детерминированный исполнитель: задания запускаются вручную тестом."""

    def __init__(self):
        self.pending: list[tuple] = []
        self.max_inflight = 0

    def submit(self, fn):
        future = Future()
        self.pending.append((fn, future))
        self.max_inflight = max(self.max_inflight, len(self.pending))
        return future

    def run_next(self):
        fn, future = self.pending.pop(0)
        try:
            future.set_result(fn())
        except BaseException as exc:  # noqa: BLE001
            future.set_exception(exc)


class HotSwitchSerializationTests(unittest.TestCase):
    """AC8: generation-сериализация, устаревший результат отбрасывается."""

    def test_overlapping_switches_discard_stale_result(self) -> None:
        nodes = xray_nodes()
        controller = HotSwitchController(nodes, singbox_session_for(nodes))
        tags = controller._active_session.outbound_pool_tags
        executor = ManualExecutor()
        select_calls: list[str] = []

        def fake_select(api_port, selector_tag, outbound_tag):
            select_calls.append(outbound_tag)
            return True, ""

        with patch.object(async_steps, "_SUBPROCESS_EXECUTOR", executor), patch(
            "xray_fluent.app_controller.select_singbox_outbound", fake_select
        ):
            # Свитч №1: на вторую ноду; control-plane вызов ушёл в воркер.
            controller.state.selected_node_id = nodes[1].id
            self.assertTrue(controller._try_hot_switch_selected_node())
            self.assertEqual(len(executor.pending), 1)

            # Спам-клик: свитч №2 на третью ноду, пока №1 в полёте.
            controller.state.selected_node_id = nodes[2].id
            self.assertTrue(controller._try_hot_switch_selected_node())
            # Сериализация: второй control-plane вызов НЕ стартует параллельно.
            self.assertEqual(len(executor.pending), 1)
            self.assertTrue(controller._hot_switch_pending)

            # Устаревший результат №1 приходит ПОСЛЕ обгоняющего запроса №2.
            executor.run_next()
            self.assertTrue(_drive_until(lambda: len(executor.pending) == 1))
            # Устаревший успех не применён: сессия не закоммичена нодой №2.
            self.assertEqual(controller.captured, [])

            # Завершается актуальный свитч №2 — применяется только он.
            executor.run_next()
            self.assertTrue(_drive_until(lambda: controller.captured))

        self.assertEqual(
            [(node_id, tag) for node_id, tag, _thread in controller.captured],
            [(nodes[2].id, tags[nodes[2].id])],
        )
        # За всё время — не больше одного задания в полёте (строгая сериализация).
        self.assertEqual(executor.max_inflight, 1)
        self.assertEqual(controller.transitions, [])
        # Первый вызов — для устаревшей ноды, второй — для актуальной.
        self.assertEqual(select_calls, [tags[nodes[1].id], tags[nodes[2].id]])

    def test_new_transition_request_supersedes_inflight_switch(self) -> None:
        nodes = xray_nodes()
        controller = HotSwitchController(nodes, singbox_session_for(nodes))
        executor = ManualExecutor()

        with patch.object(async_steps, "_SUBPROCESS_EXECUTOR", executor), patch(
            "xray_fluent.app_controller.select_singbox_outbound",
            lambda *args: (True, ""),
        ):
            controller.state.selected_node_id = nodes[1].id
            self.assertTrue(controller._try_hot_switch_selected_node())
            # Пришёл полный переход (например, смена настроек): свитч устарел.
            controller._transition_generation += 1
            executor.run_next()
            self.assertTrue(_drive_until(lambda: controller._hot_switch_runner is None))

        self.assertEqual(controller.captured, [])


class OutboundPoolCacheTests(unittest.TestCase):
    """AC9/AC10: кэш пула и инвариант его инвалидации."""

    def test_repeated_calls_build_pool_once(self) -> None:
        nodes = xray_nodes()
        controller = SessionCaptureController(nodes)
        with patch(
            "xray_fluent.app_controller.build_xray_outbound_pool",
            side_effect=build_xray_outbound_pool,
        ) as builder:
            first = controller.xray_outbound_pool()
            for _ in range(5):
                self.assertIs(controller.xray_outbound_pool(), first)
        self.assertEqual(builder.call_count, 1)

    def test_switch_flow_signature_plus_hot_switch_builds_once(self) -> None:
        # Сценарий переключения: 4 сигнатуры + hot-switch = 5 обращений к пулу.
        nodes = xray_nodes()
        controller = SessionCaptureController(nodes)
        with patch(
            "xray_fluent.app_controller.build_xray_outbound_pool",
            side_effect=build_xray_outbound_pool,
        ) as builder:
            for _ in range(4):
                controller.xray_outbound_pool().signature_payload()
            controller.xray_outbound_pool().tag_for(nodes[1].id)
        self.assertEqual(builder.call_count, 1)

    def test_composition_change_invalidates_cache(self) -> None:
        nodes = xray_nodes()
        controller = SessionCaptureController(nodes)
        before = controller.xray_outbound_pool()

        extra = parse_single(
            "trojan://secret@four.example:443?security=tls&sni=four.example#four"
        )
        controller.state.nodes = nodes + [extra]  # замена объекта списка
        after = controller.xray_outbound_pool()

        self.assertIsNot(after, before)
        self.assertIn(extra.id, after.tags)

        controller.state.nodes.remove(extra)  # in-place изменение состава
        self.assertNotIn(extra.id, controller.xray_outbound_pool().tags)

    def test_outbound_replacement_and_reorder_invalidate_cache(self) -> None:
        nodes = xray_nodes()
        for index, node in enumerate(nodes):
            node.sort_order = index  # детерминированный базовый порядок
        controller = SessionCaptureController(nodes)
        before = controller.xray_outbound_pool()

        nodes[0].outbound = dict(nodes[0].outbound)  # пересоздание outbound
        self.assertIsNot(controller.xray_outbound_pool(), before)

        nodes[0].sort_order, nodes[1].sort_order = 5, 1  # переупорядочивание
        self.assertEqual(
            [node.id for node in controller.xray_outbound_pool().nodes],
            [nodes[1].id, nodes[2].id, nodes[0].id],  # sort_order 1, 2, 5
        )

    def test_in_place_outbound_edit_covered_by_explicit_invalidation(self) -> None:
        # Идентичность не видит правку содержимого словаря — её покрывает
        # явная инвалидация (в проде подключена к сигналу nodes_changed).
        nodes = xray_nodes()
        controller = SessionCaptureController(nodes)
        before = controller.xray_outbound_pool()

        nodes[0].outbound["protocol"] = ""  # in-place: нода выпадает из пула
        controller._invalidate_xray_outbound_pool_cache()
        after = controller.xray_outbound_pool()

        self.assertIsNot(after, before)
        self.assertNotIn(nodes[0].id, after.tags)


class AutoSwitchController:
    """Фейк-контроллер авто-переключения с настоящим set_selected_node."""

    set_selected_node = AppController.set_selected_node
    _reset_auto_switch_state = AppController._reset_auto_switch_state

    def __init__(self, nodes, *, hot_switch_result: bool):
        settings = AppSettings()
        settings.auto_switch_enabled = True
        settings.auto_switch_threshold_kbps = 50
        settings.auto_switch_delay_sec = 1
        settings.auto_switch_cooldown_sec = 30
        self.state = SimpleNamespace(
            settings=settings,
            routing=RoutingSettings(),
            nodes=nodes,
            selected_node_id=nodes[0].id,
        )
        self.connected = True
        self._desired_connected = True
        self._switching = False
        self._reconnecting = False
        self._auto_switch_low_since = time.monotonic() - 5.0
        self._auto_switch_last_switch = 0.0
        self._auto_switch_high_ticks = 0
        self._auto_switch_active_download = True
        self._auto_switch_cycle_attempts = 0
        self._auto_switch_exhausted = False
        self._auto_switch_transitioning = False
        self._hot_switch_result = hot_switch_result
        self.hot_switch_calls = 0
        self.transitions: list[str] = []
        self.selection_emissions: list[object] = []
        self.saves = 0
        self.logs: list[str] = []
        self.status = SimpleNamespace(emit=lambda *args: None)
        self.auto_switch_triggered = SimpleNamespace(emit=lambda *args: None)
        self.selection_changed = SimpleNamespace(
            emit=lambda node: self.selection_emissions.append(node)
        )

    @property
    def selected_node(self):
        return next(
            (node for node in self.state.nodes if node.id == self.state.selected_node_id),
            None,
        )

    def _log(self, line: str) -> None:
        self.logs.append(line)

    def schedule_save(self) -> None:
        self.saves += 1

    def _try_hot_switch_selected_node(self) -> bool:
        self.hot_switch_calls += 1
        return self._hot_switch_result

    def _request_transition(self, reason: str) -> None:
        self.transitions.append(reason)


class AutoSwitchSinglePathTests(unittest.TestCase):
    """AC11/AC12: авто-переключение идёт через set_selected_node."""

    def _nodes(self):
        nodes = xray_nodes()
        nodes[1].is_alive = True
        nodes[1].speed_mbps = 10.0
        return nodes

    def test_auto_switch_takes_hot_path_via_set_selected_node(self) -> None:
        nodes = self._nodes()
        controller = AutoSwitchController(nodes, hot_switch_result=True)

        check_auto_switch(controller, down_bps=2048.0)

        self.assertEqual(controller.state.selected_node_id, nodes[1].id)
        self.assertEqual(controller.hot_switch_calls, 1)  # горячий путь
        self.assertEqual(controller.transitions, [])  # без безусловного перехода

    def test_auto_switch_falls_back_to_transition_queue(self) -> None:
        nodes = self._nodes()
        controller = AutoSwitchController(nodes, hot_switch_result=False)

        check_auto_switch(controller, down_bps=2048.0)

        self.assertEqual(controller.hot_switch_calls, 1)
        self.assertEqual(controller.transitions, ["node switched"])

    def test_no_duplicate_side_effects_and_accounting_preserved(self) -> None:
        nodes = self._nodes()
        controller = AutoSwitchController(nodes, hot_switch_result=True)

        check_auto_switch(controller, down_bps=2048.0)

        # AC12: ровно одна эмиссия selection_changed и один schedule_save.
        self.assertEqual(len(controller.selection_emissions), 1)
        self.assertIs(controller.selection_emissions[0], nodes[1])
        self.assertEqual(controller.saves, 1)
        # Учёт анти-дребезга не затёрт reset-ом set_selected_node (A6):
        self.assertEqual(controller._auto_switch_cycle_attempts, 1)
        self.assertGreater(controller._auto_switch_last_switch, 0.0)
        self.assertFalse(controller._auto_switch_exhausted)
        self.assertTrue(controller._desired_connected)

    def test_manual_selection_still_resets_auto_switch_state(self) -> None:
        nodes = self._nodes()
        controller = AutoSwitchController(nodes, hot_switch_result=True)
        controller._auto_switch_last_switch = 123.0
        controller._auto_switch_cycle_attempts = 2

        controller.set_selected_node(nodes[2].id)  # ручной путь — дефолт

        self.assertEqual(controller._auto_switch_last_switch, 0.0)
        self.assertEqual(controller._auto_switch_cycle_attempts, 0)


class FakeZapret:
    proxy_protection_server = staticmethod(ZapretManager.proxy_protection_server)

    def __init__(self):
        self._proxy_resolution_cache: dict[str, set[str]] = {}
        self.protected_calls: list[set[str]] = []

    def cache_proxy_resolution(self, server: str, protected_ips: set[str]) -> None:
        if server:
            self._proxy_resolution_cache[server] = set(protected_ips)

    def _set_protected_proxy_ips(self, protected_ips: set[str]) -> None:
        self.protected_calls.append(set(protected_ips))

    def apply_cached_proxy_node(self, node) -> bool:
        return ZapretManager.apply_cached_proxy_node(self, node)

    def _resolve_server_ips(self, server: str) -> set[str]:
        raise AssertionError("resolver must be stubbed per test")


class PrewarmController(SessionCaptureController):
    def __init__(self, nodes):
        super().__init__(nodes)
        self.zapret = FakeZapret()


class ZapretPrewarmTests(unittest.TestCase):
    """AC13: батч-прогрев после подключения наполняет только DNS-кэш."""

    def test_prewarm_caches_all_pool_udp_servers(self) -> None:
        nodes = udp_nodes()  # native UDP-ноды: Xray-пул пуст → фолбэк на state.nodes
        controller = PrewarmController(nodes)
        controller.zapret._resolve_server_ips = lambda server: {"192.0.2.7"}
        submitted: list = []

        enqueued = start_proxy_dns_prewarm(controller, submit=submitted.append)

        self.assertTrue(enqueued)
        # Не блокирует: до запуска задания кэш пуст, GUI-поток ничего не ждал.
        self.assertEqual(controller.zapret._proxy_resolution_cache, {})
        submitted[0]()

        for node in nodes:
            self.assertTrue(controller.zapret.apply_cached_proxy_node(node))
        # AC14/A7: прогрев сам не трогал winws2-состояние (protected ips) —
        # единственные вызовы _set_protected_proxy_ips сделаны apply-проверкой выше.
        self.assertEqual(len(controller.zapret.protected_calls), 2)
        self.assertTrue(any("DNS prewarm" in line for line in controller.logs))

    def test_prewarm_populates_cache_only_without_winws2_side_effects(self) -> None:
        nodes = udp_nodes()
        controller = PrewarmController(nodes)
        controller.zapret._resolve_server_ips = lambda server: {"192.0.2.8"}

        start_proxy_dns_prewarm(controller, submit=lambda job: job())

        self.assertEqual(len(controller.zapret._proxy_resolution_cache), 2)
        self.assertEqual(controller.zapret.protected_calls, [])  # AC14

    def test_non_udp_nodes_are_skipped(self) -> None:
        nodes = xray_nodes()  # vless/trojan — без UDP proxy protection server
        controller = PrewarmController(nodes)

        self.assertEqual(collect_prewarm_servers(controller), [])
        self.assertFalse(start_proxy_dns_prewarm(controller, submit=lambda job: job()))

    def test_already_cached_servers_are_not_resolved_again(self) -> None:
        nodes = udp_nodes()
        controller = PrewarmController(nodes)
        first_server = ZapretManager.proxy_protection_server(nodes[0])
        controller.zapret._proxy_resolution_cache[first_server] = {"192.0.2.1"}

        servers = collect_prewarm_servers(controller)
        self.assertEqual(servers, [ZapretManager.proxy_protection_server(nodes[1])])


class ZapretPrewarmSafetyTests(unittest.TestCase):
    """AC14: ошибки резолва — молча; троттлинг между резолвами."""

    def test_resolver_errors_are_swallowed_silently(self) -> None:
        cached: dict[str, set[str]] = {}

        def resolve(server: str) -> set[str]:
            if server == "bad.example":
                raise OSError("dns failure")
            return {"192.0.2.9"}

        warmed = prewarm_proxy_resolutions(
            ["bad.example", "good.example"],
            resolve,
            lambda server, ips: cached.__setitem__(server, ips),
            throttle_sec=0.0,
        )

        self.assertEqual(warmed, 1)
        self.assertEqual(set(cached), {"good.example"})

    def test_batch_is_throttled_between_resolves(self) -> None:
        sleeps: list[float] = []

        prewarm_proxy_resolutions(
            ["a.example", "b.example"],
            lambda server: set(),
            lambda server, ips: None,
            throttle_sec=0.01,
            sleep=sleeps.append,
        )

        self.assertEqual(sleeps, [0.01, 0.01])

    def test_prewarm_job_error_does_not_escape(self) -> None:
        nodes = udp_nodes()
        controller = PrewarmController(nodes)
        controller.zapret._resolve_server_ips = Mock(side_effect=OSError("offline"))

        start_proxy_dns_prewarm(controller, submit=lambda job: job())  # не бросает

        self.assertEqual(controller.zapret._proxy_resolution_cache, {})
        self.assertEqual(controller.zapret.protected_calls, [])


if __name__ == "__main__":
    unittest.main()
