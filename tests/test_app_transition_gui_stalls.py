"""Приёмка «переход не вешает интерфейс»: реальный AppController + watchdog.

Сценарий собран из настоящего контроллера, настоящих менеджеров ядра и
настоящих QProcess (POSIX-заглушка вместо sing-box.exe). Подменены только
листовые блокирующие примитивы — ровно те вызовы, что на Windows уходят в
сокеты, subprocess и WinAPI. Каждый подменён реалистичной задержкой
(``time.sleep``): проба локального входа 0.3 с, ``sing-box check`` 0.3 с,
поиск осиротевших процессов 0.5 с, PUT Clash API 0.2 с, запись системного
прокси 0.2 с. Если такой примитив исполнится в GUI-потоке, watchdog увидит
зависание дольше порога.

Критерии (по измерению, не по чтению кода):
- connect, переключение сервера (горячее и с полным переходом), смена
  системного прокси, переподключение и disconnect дают ``max_stall_ms < 50``;
- во время переходов нет ни одного ``processEvents`` (``pump_qt_events``);
- клик во время перехода не вкладывается в идущий переход: синхронный
  ``disconnect_current`` не вызывается, итоговое состояние — последнее
  запрошенное.

Keep the ``test_app_*`` prefix: widget test modules must sort before
``tests/test_engine_process_stop.py`` which creates a bare QCoreApplication
at import time (see tests/test_app_nodes_page_view.py). Контроллер создаётся
один раз на модуль и не уничтожается (см. test_app_startup_subscription_settings).
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QEventLoop, QTimer
from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError("controller harness needs a QApplication")
app = _existing or QApplication([])

from xray_fluent.application import runtime_services
from xray_fluent.application.controller import AppController
from xray_fluent.diagnostics.gui_stall_watchdog import GuiStallWatchdog
from xray_fluent.engines.zapret.target import ResolvedZapretEndpoint
from xray_fluent.importer.link_parser import parse_single
from xray_fluent.platform.windows import subprocess_utils
from xray_fluent.platform.windows.proxy_manager import ProxyManager, SystemProxyState
from xray_fluent.profiles.models import AppState

PROBE_DELAY = 0.3
CHECK_DELAY = 0.3
KILL_ORPHANS_DELAY = 0.5
SELECTOR_DELAY = 0.2
PROXY_WINAPI_DELAY = 0.2
DNS_DELAY = 0.1
STALL_LIMIT_MS = 50.0

_POSIX = os.name != "nt"


def _spin(ms: int) -> None:
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def _spin_until(condition, timeout_ms: int = 20_000) -> bool:
    deadline = time.monotonic() + timeout_ms / 1000.0
    while time.monotonic() < deadline:
        if condition():
            return True
        _spin(5)
    return condition()


class _FakeWinProxy(ProxyManager):
    """Реальная логика enable/disable, листовые вызовы WinAPI — с задержкой."""

    def __init__(self) -> None:
        super().__init__()
        self.values: dict[str, str | int] = {"ProxyEnable": 0, "ProxyServer": "", "ProxyOverride": ""}
        self.writes: list[dict[str, str | int]] = []

    @property
    def is_supported(self) -> bool:  # type: ignore[override]
        return True

    def _read_settings(self):  # type: ignore[override]
        time.sleep(0.02)
        return dict(self.values)

    def _write_settings(self, values):  # type: ignore[override]
        time.sleep(0.05)
        self.values.update(values)
        self.writes.append(dict(values))

    def _apply_per_connection(self, proxy_server, override, enable):  # type: ignore[override]
        time.sleep(PROXY_WINAPI_DELAY)

    def _refresh_system_proxy(self) -> None:  # type: ignore[override]
        time.sleep(0.05)

    def _persist_backup(self, values) -> None:  # type: ignore[override]
        pass

    def _load_persisted_backup(self):  # type: ignore[override]
        return None

    def query_state(self) -> SystemProxyState:  # type: ignore[override]
        enabled = int(self.values.get("ProxyEnable", 0) or 0) == 1
        server = str(self.values.get("ProxyServer", "") or "")
        return SystemProxyState(
            supported=True,
            enabled=enabled,
            server=server,
            is_ours=enabled and self.is_our_proxy_server(server),
        )


def _slow_probe(port, role, **_credentials) -> bool:
    time.sleep(PROBE_DELAY)
    return True


def _slow_run_text(command, *, timeout, check=False, creationflags=None):
    time.sleep(CHECK_DELAY)
    return subprocess.CompletedProcess(command, 0, b"", b"")


def _slow_kill_orphans(process_name, executable_path, *, timeout=5.0, pump=True) -> bool:
    time.sleep(KILL_ORPHANS_DELAY)
    return False


def _slow_selector(request, timeout_sec):
    time.sleep(SELECTOR_DELAY)
    return True, "", False


def _slow_balancer(xray_path, api_port, balancer_tag, outbound_tag, *, pump=True):
    time.sleep(SELECTOR_DELAY)
    return True, ""


def _slow_relay_probe(port, *, host="127.0.0.1", connect_timeout=0.15) -> bool:
    time.sleep(0.15)
    return True


def _slow_remote_probe(self, relay_port, *, username, password, endpoint, timeout) -> None:
    time.sleep(PROBE_DELAY)


def _slow_https_probe(port, *, username, password, endpoint, timeout) -> None:
    time.sleep(PROBE_DELAY)


_AWG_STUB = """#!/usr/bin/env python3
import json, sys, time
config = json.loads(sys.stdin.readline())
ident = {key: config.get(key) for key in ("session_generation", "target_generation", "target_ref")}
def emit(stage, **fields):
    print(json.dumps({"stage": stage, **ident, **fields}), flush=True)
emit("relay_ready")
time.sleep(0.2)
emit("stats", peers=[{"last_handshake_time_sec": 1}])
sys.stdin.read()
"""


def _slow_resolve_target(spec):
    time.sleep(DNS_DELAY)
    return ResolvedZapretEndpoint(spec, ("203.0.113.10",))


def _windows_only_module_stubs() -> dict[str, types.ModuleType]:
    """win_proc_monitor грузит ctypes.windll при импорте — на POSIX заглушка.

    Ставится только на время этого класса и снимается точечно (только свои
    ключи), чтобы не подменить модуль другим тестам (test_auto_switch_dead_link)
    и не выгрузить модули, впервые импортированные за время класса.
    """

    if not _POSIX:
        return {}
    monitor = types.ModuleType("xray_fluent.platform.windows.win_proc_monitor")
    monitor.clear_pid_cache = lambda: None  # type: ignore[attr-defined]
    collector = types.ModuleType("xray_fluent.platform.windows.process_traffic_collector")
    collector.reset_connection_tracking = lambda: None  # type: ignore[attr-defined]
    return {monitor.__name__: monitor, collector.__name__: collector}


_shared: dict[str, object] = {}


@unittest.skipUnless(_POSIX, "заглушка ядра — POSIX-исполняемый скрипт; на Windows — живая проверка")
class TransitionGuiStallTests(unittest.TestCase):
    """Каждый переход измеряется watchdog'ом с порогом 50 мс."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="zkvn-stall-"))
        stub = cls.tmp / "sing-box"
        stub.write_text("#!/bin/sh\nexec sleep 3600\n", encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        xray_stub = cls.tmp / "xray"
        shutil.copy(stub, xray_stub)
        xray_stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        hysteria_stub = cls.tmp / "hysteria"
        shutil.copy(stub, hysteria_stub)
        hysteria_stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        winws_stub = cls.tmp / "winws2"
        shutil.copy(stub, winws_stub)
        winws_stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        awg_stub = cls.tmp / "zapret-amnezia"
        awg_stub.write_text(_AWG_STUB, encoding="utf-8")
        awg_stub.chmod(awg_stub.stat().st_mode | stat.S_IEXEC)
        presets = cls.tmp / "presets"
        presets.mkdir()
        (presets / "Default.txt").write_text("--wf-tcp-out=443\n--filter-tcp=443\n", encoding="utf-8")
        cls.stub = stub

        cls.pump_calls = 0
        original_pump = subprocess_utils.pump_qt_events

        def counting_pump() -> None:
            cls.pump_calls += 1
            original_pump()

        stubs = {name: module for name, module in _windows_only_module_stubs().items() if name not in sys.modules}
        sys.modules.update(stubs)
        cls.module_stubs = list(stubs)
        cls.patchers = [
            patch.object(subprocess_utils, "pump_qt_events", counting_pump),
            patch("xray_fluent.application.async_steps.pump_qt_events", counting_pump),
            patch("xray_fluent.engines.singbox.manager.resolve_configured_path", lambda *a, **k: stub),
            patch("xray_fluent.engines.singbox.manager.RUNTIME_DIR", cls.tmp),
            patch("xray_fluent.engines.singbox.manager.SINGBOX_CONFIG_FILE", cls.tmp / "singbox_config.json"),
            patch("xray_fluent.application.controller.SINGBOX_PROVIDER_FILE", cls.tmp / "singbox_nodes.json"),
            patch("xray_fluent.engines.singbox.manager.probe_listener_role", _slow_probe),
            patch("xray_fluent.engines.singbox.manager.kill_processes_by_path", _slow_kill_orphans),
            patch("xray_fluent.engines.xray.manager.resolve_configured_path", lambda *a, **k: xray_stub),
            patch("xray_fluent.engines.xray.manager.RUNTIME_DIR", cls.tmp),
            patch("xray_fluent.engines.xray.manager.XRAY_CONFIG_FILE", cls.tmp / "xray_config.json"),
            patch("xray_fluent.engines.xray.manager.probe_listener_role", _slow_probe),
            patch("xray_fluent.application.controller.apply_balancer_override", _slow_balancer),
            patch("xray_fluent.application.connection_service._is_admin", lambda: True),
            patch("xray_fluent.engines.hysteria.manager.HYSTERIA_PATH_DEFAULT", hysteria_stub),
            patch("xray_fluent.engines.hysteria.manager.HYSTERIA_CONFIG_FILE", cls.tmp / "hysteria_config.json"),
            patch("xray_fluent.engines.hysteria.manager.RUNTIME_DIR", cls.tmp),
            patch("xray_fluent.engines.hysteria.manager.kill_processes_by_path", _slow_kill_orphans),
            patch("xray_fluent.engines.hysteria.manager.HysteriaManager._probe_remote_endpoint", _slow_remote_probe),
            patch("xray_fluent.engines.sidecar.readiness.probe_loopback_relay", _slow_relay_probe),
            patch("xray_fluent.engines.amnezia.manager.AMNEZIA_PATH_DEFAULT", awg_stub),
            patch("xray_fluent.engines.amnezia.manager.probe_https", _slow_https_probe),
            patch("xray_fluent.engines.zapret.manager.WINWS2_EXE", winws_stub),
            patch("xray_fluent.engines.zapret.manager.ZAPRET_DIR", cls.tmp),
            patch("xray_fluent.engines.zapret.manager.PRESETS_DIR", presets),
            patch("xray_fluent.engines.zapret.manager.kill_processes_by_path", _slow_kill_orphans),
            patch.object(subprocess_utils, "run_text", _slow_run_text),
            patch("xray_fluent.engines.singbox.selector_api._send_selector_request", _slow_selector),
            patch.object(runtime_services, "start_metrics_worker", lambda controller: None),
        ]
        for patcher in cls.patchers:
            patcher.start()

        controller = _shared.get("controller")
        if controller is None:
            controller = AppController()
            _shared["controller"] = controller
        cls.controller = controller  # type: ignore[assignment]
        controller.schedule_save = lambda: None  # type: ignore[method-assign]
        controller.save = lambda: None  # type: ignore[method-assign]
        controller._start_metrics_worker = lambda: None  # type: ignore[method-assign]
        controller._start_proxy_dns_prewarm = lambda: None  # type: ignore[method-assign]
        controller.proxy = _FakeWinProxy()
        controller.zapret.resolve_target = _slow_resolve_target  # type: ignore[method-assign]

        cls.sync_disconnects = 0
        real_disconnect = AppController.disconnect_current

        def counting_disconnect(*args, **kwargs):
            cls.sync_disconnects += 1
            return real_disconnect(controller, *args, **kwargs)

        controller.disconnect_current = counting_disconnect  # type: ignore[method-assign]

        cls.nodes = [
            parse_single("trojan://secret@one.example:443?security=tls&sni=one.example#one"),
            parse_single("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@two.example:8388#two"),
            parse_single(
                "vless://11111111-1111-1111-1111-111111111111@three.example:443"
                "?type=tcp&security=tls&sni=three.example#three"
            ),
        ]
        cls.sidecar_nodes = [
            parse_single(
                "hy2://secret@198.51.100.20:443/?insecure=1&pinSHA256="
                + "a" * 64
                + "#hysteria"
            ),
            parse_single(
                '{"type": "wireguard", "tag": "awg", "address": ["10.0.0.2/32"], '
                '"private_key": "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=", '
                '"peers": [{"address": "198.51.100.7", "port": 51820, '
                '"public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", '
                '"allowed_ips": ["0.0.0.0/0"]}]}'
            ),
        ]
        for index, node in enumerate(cls.nodes):
            node.sort_order = index

        state = AppState()
        state.nodes = list(cls.nodes) + list(cls.sidecar_nodes)
        for index, node in enumerate(state.nodes):
            node.sort_order = index
        state.selected_node_id = cls.nodes[0].id
        state.settings.enable_system_proxy = True
        state.settings.tun_mode = False
        state.settings.singbox_path = str(stub)
        state.settings.xray_path = str(xray_stub)
        state.settings.auto_switch_enabled = False
        state.settings.zapret_target.tcp_proxy_enabled = False
        controller.state = state
        controller.zapret.set_target_settings(state.settings.zapret_target)
        controller._invalidate_xray_outbound_pool_cache()

        cls.watchdog = GuiStallWatchdog(threshold_ms=STALL_LIMIT_MS)
        cls.watchdog.start()

    @classmethod
    def tearDownClass(cls) -> None:
        controller = cls.controller
        try:
            if controller.connected or controller._desired_connected:
                controller._desired_connected = False
                controller._request_transition("test teardown")
                _spin_until(lambda: cls._idle(), 20_000)
            for manager in (controller.singbox, controller.xray, controller.hysteria, controller.amnezia):
                manager.stop()
            controller.zapret.stop(wait=True)
        finally:
            cls.watchdog.stop()
            for patcher in reversed(cls.patchers):
                patcher.stop()
            for name in cls.module_stubs:
                sys.modules.pop(name, None)
            shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def _idle(cls) -> bool:
        controller = cls.controller
        return (
            not controller._transition_active
            and not controller._transition_pending
            and not controller._transition_timer.isActive()
            and not controller._proxy_protection_workers
            and controller._hot_switch_runner is None
            and not controller._proxy_protection_wait_generation
        )

    def _measure(self, action, *, until, timeout_ms: int = 20_000) -> float:
        app.sendPostedEvents(None, 0)
        _spin(30)
        self.watchdog.reset()
        type(self).pump_calls = 0
        type(self).sync_disconnects = 0
        started = time.monotonic()
        action()
        self.assertTrue(_spin_until(lambda: until() and self._idle(), timeout_ms), "transition did not finish")
        _spin(30)
        elapsed = time.monotonic() - started
        stalls = [round(record.duration_ms) for record in self.watchdog.records]
        worst = self.watchdog.records and max(self.watchdog.records, key=lambda r: r.duration_ms)
        detail = f"stalls={stalls} elapsed={elapsed:.2f}s\n{worst.stack if worst else ''}"
        self.assertLess(self.watchdog.max_stall_ms, STALL_LIMIT_MS, detail)
        self.assertEqual(type(self).pump_calls, 0, "processEvents pumped during a transition")
        self.assertEqual(type(self).sync_disconnects, 0, "synchronous nested disconnect_current()")
        return self.watchdog.max_stall_ms

    def _connected_to(self, node) -> bool:
        session = self.controller._active_session
        return bool(
            self.controller.connected
            and session is not None
            and session.node_id == node.id
            and self.controller.singbox.is_running
        )

    def _toggle_setting(self, name: str, value: bool) -> None:
        settings = self.controller.state.settings
        setattr(settings, name, value)
        self.controller.update_settings(settings)

    def test_1_transitions_do_not_stall_gui(self) -> None:
        controller = self.controller
        native_a, native_b, hybrid = self.nodes

        # connect (native sing-box pool)
        self._measure(controller.toggle_connection, until=lambda: self._connected_to(native_a))
        self.assertTrue(controller.proxy.query_state().is_ours)

        # hot switch inside the running pool (selector PUT only)
        self._measure(
            lambda: controller.set_selected_node(native_b.id),
            until=lambda: self._connected_to(native_b),
        )

        # system proxy toggle (proxy_update)
        self._measure(
            lambda: self._toggle_setting("enable_system_proxy", False),
            until=lambda: not controller.proxy.query_state().enabled,
        )
        self.assertTrue(controller.connected)
        self._measure(
            lambda: self._toggle_setting("enable_system_proxy", True),
            until=lambda: controller.proxy.query_state().is_ours,
        )

        # full transition to a node that needs the Xray sidecar, and back
        self._measure(
            lambda: controller.set_selected_node(hybrid.id),
            until=lambda: self._connected_to(hybrid) and controller.xray.is_running,
        )
        self._measure(
            lambda: controller.set_selected_node(native_a.id),
            until=lambda: self._connected_to(native_a) and not controller.xray.is_running,
        )

        # reconnect: proxy -> TUN -> proxy
        self._measure(
            lambda: self._toggle_setting("tun_mode", True),
            until=lambda: self._connected_to(native_a) and controller._active_session.tun_mode,
        )
        self._measure(
            lambda: self._toggle_setting("tun_mode", False),
            until=lambda: self._connected_to(native_a) and not controller._active_session.tun_mode,
        )
        self.assertTrue(controller.proxy.query_state().is_ours)

        # coordinated stop before an action that needs the connection down
        # (Xray core update): the callback runs after the step transition.
        stopped: list[bool] = []
        self._measure(
            lambda: self.assertTrue(controller._run_coordinated_stop("test", stopped.append)),
            until=lambda: stopped == [True] and not controller.connected,
        )
        self._measure(controller.toggle_connection, until=lambda: self._connected_to(native_a))

        # disconnect
        self._measure(
            controller.toggle_connection,
            until=lambda: not controller.connected and not controller.singbox.is_running,
        )
        self.assertFalse(controller.proxy.query_state().enabled)

    def test_2_click_during_connect_coalesces_without_nesting(self) -> None:
        controller = self.controller
        first, second, _hybrid = self.nodes
        controller.state.selected_node_id = first.id

        clicks: list[str] = []

        def switch_mid_transition() -> None:
            clicks.append(f"active={controller._transition_active}")
            controller.set_selected_node(second.id)

        def connect_then_click() -> None:
            controller.toggle_connection()
            QTimer.singleShot(400, switch_mid_transition)

        self._measure(connect_then_click, until=lambda: self._connected_to(second))
        self.assertEqual(clicks, ["active=True"])

        # disconnect clicked while the disconnect-then-connect cycle is running
        def toggle_twice() -> None:
            controller.toggle_connection()
            QTimer.singleShot(100, controller.toggle_connection)
            QTimer.singleShot(250, controller.toggle_connection)

        self._measure(toggle_twice, until=lambda: not controller._desired_connected and not controller.connected)
        self.assertFalse(controller.singbox.is_running)
        self.assertFalse(controller.proxy.query_state().enabled)

    def test_3_sidecars_and_zapret_protection_do_not_stall_gui(self) -> None:
        controller = self.controller
        native_a, native_b, _hybrid = self.nodes
        hysteria, awg = self.sidecar_nodes
        if controller.connected or controller._desired_connected:
            controller._desired_connected = False
            controller._request_transition("reset")
            self.assertTrue(_spin_until(lambda: not controller.connected and self._idle()))
        controller.state.selected_node_id = hysteria.id

        # Hysteria2: official core behind the sing-box front
        self._measure(
            controller.toggle_connection,
            until=lambda: self._connected_to(hysteria) and controller.hysteria.is_running,
        )
        # AWG/WireGuard: replacement sidecar prepared before the front cut-over
        self._measure(
            lambda: controller.set_selected_node(awg.id),
            until=lambda: self._connected_to(awg) and controller.amnezia.is_running,
        )
        self.assertFalse(controller.hysteria.is_running)
        self._measure(
            controller.toggle_connection,
            until=lambda: not controller.connected and not controller.amnezia.is_running,
        )

        # Zapret-protected TCP targets: winws2 start, stop before DNS and the
        # pass-profile restart are coordinator steps, not GUI-thread waits.
        settings = controller.state.settings
        settings.zapret_target.tcp_proxy_enabled = True
        settings.zapret_preset = "Default"
        controller.zapret.set_target_settings(settings.zapret_target)
        controller.state.selected_node_id = native_a.id
        try:
            self._measure(
                controller.toggle_connection,
                until=lambda: self._connected_to(native_a) and controller.zapret.running,
            )
            first_winws = controller.zapret._process
            self._measure(
                lambda: controller.set_selected_node(native_b.id),
                until=lambda: self._connected_to(native_b)
                and controller.zapret.running
                and controller.zapret._process is not first_winws,
            )
            self._measure(
                controller.toggle_connection,
                until=lambda: not controller.connected and not controller.singbox.is_running,
            )
        finally:
            settings.zapret_target.tcp_proxy_enabled = False
            controller.zapret.set_target_settings(settings.zapret_target)
            controller.zapret.stop()
            _spin_until(lambda: controller.zapret._start_runner is None, 5_000)


if __name__ == "__main__":
    unittest.main()
