"""E2E: switching to a Hysteria2 server whose UDP never arrives (31.10.2026, 0.8.51).

Real AppController, real ``sing-box.exe`` front, real ``hysteria.exe`` clients
and a real local Hysteria2 server. Server «A» works. Server «B» is a UDP black
hole: a socket that swallows every datagram, exactly like 4stok seen from the
user's MGTS network (0 packets reached the server, TCP worked). Readiness
probes go through the real tunnel to a loopback HTTP server, so the test needs
no internet and no admin rights.

Before the fix (0.8.51) this test failed on every scenario:
- switch A → B: the dashboard showed «Ошибка подключения — Новый Hysteria
  sidecar не доказал readiness» while A kept serving, and B stayed selected;
- a start superseded by the user's own click published «Не удалось запустить
  sing-box proxy runtime»;
- a fresh start of B named no cause.

Keep the ``test_app_*`` prefix: the module needs a QApplication and must sort
before modules that create a bare QCoreApplication at import time.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QEventLoop, QTimer
from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
app = _existing if isinstance(_existing, QApplication) else (_existing or QApplication([]))

from xray_fluent.constants import HYSTERIA_PATH_DEFAULT, SINGBOX_PATH_DEFAULT

_HYSTERIA = Path(os.environ.get("HYSTERIA_TEST_BINARY", str(HYSTERIA_PATH_DEFAULT)))
_SINGBOX = Path(os.environ.get("SINGBOX_TEST_BINARY", str(SINGBOX_PATH_DEFAULT)))
_RUNNABLE = os.name == "nt" and _HYSTERIA.is_file() and _SINGBOX.is_file() and isinstance(app, QApplication)


def _free_port(kind: int) -> int:
    with socket.socket(socket.AF_INET, kind) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _spin(ms: int) -> None:
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def _spin_until(condition, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if condition():
            return True
        _spin(50)
    return condition()


class _LoopbackHttp:
    """Destination of every probe: proves bytes crossed the real tunnel."""

    def __init__(self) -> None:
        self.hits = 0
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(64)
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._answer, args=(conn,), daemon=True).start()

    def _answer(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(3)
            try:
                conn.recv(4096)
                self.hits += 1
                conn.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass

    def close(self) -> None:
        self._stop.set()
        self._listener.close()


class _UdpBlackHole:
    """Swallows every datagram: the server never answers, like UDP lost on the path."""

    def __init__(self) -> None:
        self.received = 0
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._drain, daemon=True).start()

    def _drain(self) -> None:
        while not self._stop.is_set():
            try:
                self._sock.recvfrom(65535)
                self.received += 1
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return

    def close(self) -> None:
        self._stop.set()
        self._sock.close()


def _http_through_socks(port: int, *, host: str, target_port: int, username: str = "", password: str = "") -> bool:
    from xray_fluent.engines.socks_probe import open_socks_connection

    raw = open_socks_connection(
        port, username=username, password=password, timeout=8,
        target_host=host, target_port=target_port,
    )
    with raw:
        raw.settimeout(8)
        raw.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        return raw.recv(64).startswith(b"HTTP/1.1 204")


@unittest.skipUnless(_RUNNABLE, "needs Windows, QApplication and the bundled sing-box/hysteria cores")
class HysteriaUdpBlackHoleSwitchE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        from xray_fluent.application import runtime_services
        from xray_fluent.application.controller import AppController
        from xray_fluent.importer.link_parser import parse_single
        from xray_fluent.profiles.models import AppState
        from tests.test_app_transition_gui_stalls import _FakeWinProxy

        cls.tmp = Path(tempfile.mkdtemp(prefix="zkvn-e2e-hy-"))
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=2))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]), critical=False)
            .sign(key, hashes.SHA256())
        )
        (cls.tmp / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (cls.tmp / "key.pem").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        ))
        pin = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

        cls.http = _LoopbackHttp()
        cls.blackhole = _UdpBlackHole()
        server_port = _free_port(socket.SOCK_DGRAM)
        (cls.tmp / "server.json").write_text(json.dumps({
            "listen": f"127.0.0.1:{server_port}",
            "tls": {"cert": str(cls.tmp / "cert.pem"), "key": str(cls.tmp / "key.pem")},
            "auth": {"type": "password", "password": "e2e-only"},
            "obfs": {"type": "salamander", "salamander": {"password": "e2e-obfs"}},
        }), encoding="utf-8")
        cls.server_log = (cls.tmp / "server.log").open("wb")
        # Own copy: the app kills leftover hysteria.exe of its own path before a start.
        server_exe = cls.tmp / "hysteria-e2e-server.exe"
        shutil.copy2(_HYSTERIA, server_exe)
        cls.server = subprocess.Popen(
            [str(server_exe), "--config", str(cls.tmp / "server.json"),
             "--disable-update-check", "--log-level", "info", "server"],
            stdout=cls.server_log, stderr=subprocess.STDOUT, creationflags=0x08000000,
        )
        deadline = time.monotonic() + 15
        while "server up and running" not in (cls.tmp / "server.log").read_text(errors="replace"):
            if cls.server.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("local Hysteria server did not start")
            time.sleep(0.05)

        def link(port: int, label: str) -> str:
            return (
                f"hy2://e2e-only@127.0.0.1:{port}/?obfs=salamander&obfs-password=e2e-obfs"
                f"&sni=localhost&insecure=1&pinSHA256={pin}#{label}"
            )

        cls.node_a = parse_single(link(server_port, "A-works"))
        cls.node_b = parse_single(link(cls.blackhole.port, "B-udp-lost"))

        http_port = cls.http.port

        def probe_through_relay(self, relay_port, *, username, password, endpoint, timeout):
            # The probe crosses the real Hysteria tunnel to a loopback server.
            if not _http_through_socks(
                relay_port, host="127.0.0.1", target_port=http_port, username=username, password=password,
            ):
                raise OSError("probe destination did not answer through the tunnel")

        cls.patchers = [
            patch("xray_fluent.engines.hysteria.manager.HysteriaManager._probe_remote_endpoint", probe_through_relay),
            patch.object(runtime_services, "start_metrics_worker", lambda controller: None),
            patch("xray_fluent.application.server_bypass.ServerBypass.learn_pool_addresses", lambda self: False),
        ]
        for patcher in cls.patchers:
            patcher.start()

        controller = AppController()
        controller.schedule_save = lambda: None  # type: ignore[method-assign]
        controller.save = lambda: None  # type: ignore[method-assign]
        controller._start_metrics_worker = lambda: None  # type: ignore[method-assign]
        controller.proxy = _FakeWinProxy()
        state = AppState()
        state.nodes = [cls.node_a, cls.node_b]
        for index, node in enumerate(state.nodes):
            node.sort_order = index
        state.selected_node_id = cls.node_a.id
        state.settings.enable_system_proxy = False
        state.settings.tun_mode = False
        state.settings.auto_switch_enabled = False
        state.settings.singbox_path = str(_SINGBOX)
        state.settings.zapret_target.tcp_proxy_enabled = False
        state.settings.zapret_target.quic_proxy_enabled = False
        state.settings.zapret_target.wireguard_enabled = False
        controller.state = state
        controller._invalidate_xray_outbound_pool_cache()
        cls.controller = controller
        cls.statuses: list[tuple[str, str]] = []
        cls.logs: list[str] = []
        controller.connection_status_changed.connect(lambda phase, message: cls.statuses.append((phase, message)))
        controller.log_line.connect(cls.logs.append)

    @classmethod
    def tearDownClass(cls) -> None:
        controller = cls.controller
        try:
            if controller.connected or controller._desired_connected:
                controller._desired_connected = False
                controller._request_transition("e2e teardown")
                _spin_until(cls._idle, 30)
            for manager in (controller.singbox, controller.xray, controller.hysteria, controller.amnezia):
                manager.stop()
        finally:
            for patcher in reversed(cls.patchers):
                patcher.stop()
            cls.server.kill()
            cls.server.wait(10)
            cls.server_log.close()
            cls.http.close()
            cls.blackhole.close()
            shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def _idle(cls) -> bool:
        c = cls.controller
        return (
            not c._transition_active
            and not c._transition_pending
            and not c._transition_timer.isActive()
            and c._hot_switch_runner is None
            and not c.bypass.waiting
        )

    def _connected_to(self, node) -> bool:
        c = self.controller
        session = c._active_session
        return bool(c.connected and session is not None and session.node_id == node.id and self._idle())

    def _ensure_disconnected(self) -> None:
        c = self.controller
        if c.connected or c._desired_connected:
            c.toggle_connection()
        self.assertTrue(_spin_until(lambda: not c.connected and self._idle(), 30), "did not disconnect")

    def _connect(self, node) -> None:
        from xray_fluent.application.selection_source import SelectionSource

        self._ensure_disconnected()
        self.controller.set_selected_node(node.id, source=SelectionSource.NODES_MENU)
        self.controller.toggle_connection()

    def _evidence(self) -> str:
        server = (self.tmp / "server.log").read_text(errors="replace")[-1500:]
        return "\n".join([repr(self.statuses[-4:]), *self.logs[-70:], "--- server ---", server])

    def _serving_traffic(self) -> bool:
        session = self.controller._active_session
        hits = self.http.hits
        # Through the sing-box front and the serving Hysteria tunnel.
        ok = _http_through_socks(session.socks_port, host="localhost", target_port=self.http.port)
        return ok and self.http.hits > hits

    def test_1_failed_switch_keeps_the_serving_server_selected_and_names_udp(self) -> None:
        from xray_fluent.application.selection_source import SelectionSource

        c = self.controller
        self._connect(self.node_a)
        self.assertTrue(_spin_until(lambda: self._connected_to(self.node_a), 60), self._evidence())
        self.assertTrue(self._serving_traffic(), "A must serve traffic before the switch")

        mark = len(self.statuses)
        c.set_selected_node(self.node_b.id, source=SelectionSource.NODES_ENTER)
        self.assertTrue(_spin_until(lambda: self._idle() and len(self.statuses) > mark and not c._pending_transport_node_id, 60))
        _spin(300)
        after = self.statuses[mark:]

        self.assertGreater(self.blackhole.received, 0, "B's client must have sent QUIC datagrams")
        self.assertTrue(c.connected, self._evidence())
        self.assertEqual(c._active_session.node_id, self.node_a.id)
        self.assertEqual(c.state.selected_node_id, self.node_a.id, "the failed server must never become selected")
        self.assertNotIn("error", [phase for phase, _ in after], after)
        phase, message = after[-1]
        self.assertEqual(phase, "running", after)
        self.assertIn("не ответил по UDP", message)
        self.assertIn("VLESS", message)
        self.assertIn(f"Соединение осталось на «{self.node_a.name}»", message)
        self.assertTrue(self._serving_traffic(), "A must keep serving after the failed switch")

    def test_2_start_superseded_by_a_click_publishes_no_error(self) -> None:
        from xray_fluent.application.selection_source import SelectionSource

        c = self.controller
        self._connect(self.node_b)
        mark = len(self.statuses)
        # The user changes their mind while B's handshake waits for a reply.
        self.assertTrue(_spin_until(lambda: c.hysteria.process_alive, 20))
        _spin(1500)
        c.set_selected_node(self.node_a.id, source=SelectionSource.NODES_ENTER)
        self.assertTrue(_spin_until(lambda: self._connected_to(self.node_a), 60), self.statuses[mark:])
        _spin(300)
        after = self.statuses[mark:]
        self.assertNotIn("error", [phase for phase, _ in after], after)
        self.assertFalse(any("Не удалось запустить sing-box" in message for _, message in after), after)
        self.assertEqual(c.state.selected_node_id, self.node_a.id)
        self.assertTrue(self._serving_traffic())

    def test_3_fresh_start_of_the_unreachable_server_names_the_cause(self) -> None:
        c = self.controller
        self._connect(self.node_b)
        mark = len(self.statuses)
        self.assertTrue(_spin_until(lambda: self._idle() and not c._desired_connected, 60), self.statuses[mark:])
        _spin(300)
        after = self.statuses[mark:]
        self.assertFalse(c.connected)
        phase, message = after[-1]
        self.assertEqual(phase, "error", after)
        self.assertIn("не ответил по UDP", message)
        self.assertNotIn("sing-box proxy runtime", message)
        self.assertEqual(c.state.selected_node_id, self.node_b.id, "the user's choice stays for the next start")


if __name__ == "__main__":
    unittest.main()
