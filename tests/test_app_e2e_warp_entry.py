"""E2E: the WARP entry hop through the real AppController (owner reports of 2026-11-26).

Real AppController, real ``sing-box.exe`` front, real ``xray.exe`` sidecar, real WARP account registered by the app's own
registration module, real Cloudflare.  The server is a public TLS host (nothing answers the VLESS protocol there), so the
connect itself cannot finish, and that is not what is checked: the checks are what the app did with the setting on, in the
order a user's connect goes: the setting is read at connect, the account is ready, the plan has the hop, the real
sing-box dials the server through the WARP endpoint.

Keep the ``test_app_*`` prefix: the module needs a QApplication and must sort before modules that create a bare
QCoreApplication at import time.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QEventLoop, QTimer
from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
app = _existing if isinstance(_existing, QApplication) else (_existing or QApplication([]))

from xray_fluent.constants import SINGBOX_PATH_DEFAULT, XRAY_PATH_DEFAULT

_SINGBOX = Path(os.environ.get("SINGBOX_TEST_BINARY", str(SINGBOX_PATH_DEFAULT)))
_RUNNABLE = os.name == "nt" and _SINGBOX.is_file() and isinstance(app, QApplication)
_LINK = "vless://11111111-1111-1111-1111-111111111111@example.org:443?security=tls&sni=example.org&type=tcp&encryption=none#e2e"


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


class _WarpE2EBase(unittest.TestCase):
    # True: the account points the tunnel at an address nothing answers, like a network that drops the WARP UDP ports.
    BLOCKED = False

    @classmethod
    def setUpClass(cls) -> None:
        from xray_fluent.application import runtime_services
        from xray_fluent.application.controller import AppController
        from xray_fluent.importer.link_parser import parse_single
        from xray_fluent.network import warp_registration
        from xray_fluent.profiles.models import AppState
        from tests.test_app_transition_gui_stalls import _FakeWinProxy

        cls.tmp = Path(tempfile.mkdtemp(prefix="zkvn-e2e-warp-"))
        cls.account = cls.tmp / "warp-entry-profile.json"
        cls.registration = warp_registration.ensure_account(cls.account)  # the real API
        if cls.BLOCKED:
            import json

            document = json.loads(cls.account.read_text(encoding="utf-8"))
            for peer in document["peers"]:
                peer["endpoint"] = {"v4": "192.0.2.1:2408", "v6": "", "host": "192.0.2.1:2408", "ports": [2408]}
            cls.account.write_text(json.dumps(document), encoding="utf-8")
        cls.patchers = [
            patch.object(runtime_services, "start_metrics_worker", lambda controller: None),
            patch("xray_fluent.application.server_bypass.ServerBypass.learn_pool_addresses", lambda self: False),
            patch("xray_fluent.application.controller.DATA_DIR", cls.tmp),
        ]
        for patcher in cls.patchers:
            patcher.start()
        controller = AppController()
        controller.schedule_save = lambda: None  # type: ignore[method-assign]
        controller.save = lambda: None  # type: ignore[method-assign]
        controller._start_metrics_worker = lambda: None  # type: ignore[method-assign]
        controller.proxy = _FakeWinProxy()
        state = AppState()
        node = parse_single(_LINK)
        node.sort_order = 0
        state.nodes = [node]
        state.selected_node_id = node.id
        state.settings.enable_system_proxy = False
        state.settings.tun_mode = False
        state.settings.auto_switch_enabled = False
        state.settings.singbox_path = str(_SINGBOX)
        state.settings.xray_path = str(XRAY_PATH_DEFAULT)
        state.settings.warp_entry_hop = True
        state.settings.log_level = "info"  # the dial through the endpoint is an INFO line of sing-box
        state.settings.server_ipv6_first = True
        state.settings.zapret_target.tcp_proxy_enabled = False
        state.settings.zapret_target.quic_proxy_enabled = False
        state.settings.zapret_target.wireguard_enabled = False
        controller.state = state
        controller._invalidate_xray_outbound_pool_cache()
        cls.controller = controller
        cls.node = node
        cls.logs: list[str] = []
        controller.log_line.connect(cls.logs.append)
        cls.statuses: list[tuple[str, str]] = []
        controller.status.connect(lambda level, message: cls.statuses.append((level, message)))

    @classmethod
    def tearDownClass(cls) -> None:
        controller = cls.controller
        try:
            if controller.connected or controller._desired_connected:
                controller._desired_connected = False
                controller._request_transition("e2e teardown")
                _spin_until(lambda: not controller._transition_active, 30)
            for manager in (controller.singbox, controller.xray, controller.hysteria, controller.amnezia):
                manager.stop()
        finally:
            for patcher in reversed(cls.patchers):
                patcher.stop()
            shutil.rmtree(cls.tmp, ignore_errors=True)

    def _seen(self, text: str) -> bool:
        return any(text in line for line in self.logs)


@unittest.skipUnless(_RUNNABLE, "needs Windows, QApplication and the bundled sing-box core")
class WarpEntryE2E(_WarpE2EBase):
    def test_the_account_was_registered_by_the_app_over_the_real_api(self) -> None:
        self.assertTrue(self.registration.ok, str(self.registration))
        self.assertTrue(self.account.is_file())

    def test_connect_with_the_setting_on_plans_the_hop_and_a_request_crosses_it(self) -> None:
        from xray_fluent.application.selection_source import SelectionSource

        c = self.controller
        c.set_selected_node(self.node.id, source=SelectionSource.NODES_MENU)
        if not c._desired_connected:
            c.toggle_connection()
        evidence = lambda: "\n".join(self.logs[-60:])  # noqa: E731
        self.assertTrue(_spin_until(lambda: self._seen("[warp-entry]"), 60), "no [warp-entry] line at all\n" + evidence())
        self.assertTrue(
            _spin_until(lambda: self._seen("вход через WARP: серверов через вход="), 60),
            "the plan did not get the hop\n" + evidence(),
        )
        # Xray dials its server on demand: one request through the app's own local proxy, as a browser would send it.
        self.assertTrue(_spin_until(lambda: c._active_session is not None and c.connected, 60), evidence())
        session = c._active_session
        import threading
        import urllib.request

        def browse() -> None:
            # The WARP tunnel needs a few seconds after the connect (a handshake that goes unanswered is retried on the
            # next address, core patch warp-entry-recovery): requests sent before that fail fast, as a browser's first
            # load does, so the request is repeated like a user's refresh until the host's reply shows up in the log.
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{session.http_port}"})
            )
            deadline = time.monotonic() + 100
            while time.monotonic() < deadline and not self._seen('malformed HTTP response "'):
                try:
                    opener.open("http://example.com/", timeout=30).read(16)
                except Exception:  # noqa: BLE001 - the host speaks no VLESS: its reply in the sing-box log is the evidence
                    pass
                time.sleep(1)

        threading.Thread(target=browse, daemon=True).start()
        # The whole real chain answered: proxy -> sing-box front -> Xray -> protect inbound -> WARP endpoint -> the host.
        # The host replies with HTTP/2 frames to a request that is not HTTP; the real sing-box logs that reply as a
        # malformed HTTP response, which is the bytes of a real server coming back through the hop.
        self.assertTrue(
            _spin_until(lambda: self._seen('malformed HTTP response "'), 110),
            "no reply of the host came back through the hop in 110 s\n" + evidence(),
        )
        self.assertFalse(self._seen("endpoint not initialized"), evidence())


@unittest.skipUnless(_RUNNABLE, "needs Windows, QApplication and the bundled sing-box core")
class WarpEntryBlockedE2E(_WarpE2EBase):
    BLOCKED = True

    def test_a_tunnel_that_never_comes_up_is_named_to_the_user(self) -> None:
        from xray_fluent.application.selection_source import SelectionSource
        from xray_fluent.network.warp_hop_health import TUNNEL_DOWN

        c = self.controller
        c.set_selected_node(self.node.id, source=SelectionSource.NODES_MENU)
        if not c._desired_connected:
            c.toggle_connection()
        self.assertTrue(_spin_until(lambda: c._active_session is not None and c.connected, 60), "\n".join(self.logs[-40:]))
        session = c._active_session
        import threading
        import urllib.request

        def browse() -> None:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{session.http_port}"})
            )
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and not any(TUNNEL_DOWN == m for _, m in self.statuses):
                try:
                    opener.open("http://example.com/", timeout=10).read(16)
                except Exception:  # noqa: BLE001 - nothing can answer here
                    pass
                time.sleep(0.5)

        threading.Thread(target=browse, daemon=True).start()
        self.assertTrue(
            _spin_until(lambda: any(TUNNEL_DOWN == m for _, m in self.statuses), 70),
            "the user was not told that the tunnel does not come up\n" + "\n".join(self.logs[-40:]),
        )
        self.assertTrue(self._seen("[warp-entry] Вход через WARP не поднимается"), "the message is not in the log")


if __name__ == "__main__":
    unittest.main()
