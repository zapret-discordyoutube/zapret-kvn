"""E2E: the WARP entry hop through the real AppController, on the real servers of the vpnbot test person.

Owner decisions 2026-11-25/26: the hop works where the censor blocks it, and tests run on real data only.  Real
AppController, real ``sing-box.exe`` front, real ``xray.exe``/``hysteria.exe`` helpers, the WARP account registered by
the app's own registration module, real Cloudflare, and the real servers of the test person (see
``tests/real_subscription.py``).  The checks are what the app did with the setting on, in the order a user's connect
goes: the setting is read at connect, the account is ready, the plan has the hop, the real sing-box dials the server
through the WARP endpoint, and a real web page comes back through server and hop.

Nothing here prints a server name, address or key: the assertions name counts and shapes only.

Keep the ``test_app_*`` prefix: the module needs a QApplication and must sort before modules that create a bare
QCoreApplication at import time.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QEventLoop, QTimer
from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
app = _existing if isinstance(_existing, QApplication) else (_existing or QApplication([]))

from tests import real_subscription
from xray_fluent.constants import SINGBOX_PATH_DEFAULT, XRAY_PATH_DEFAULT

_SINGBOX = Path(os.environ.get("SINGBOX_TEST_BINARY", str(SINGBOX_PATH_DEFAULT)))
_RUNNABLE = (
    os.name == "nt" and _SINGBOX.is_file() and isinstance(app, QApplication) and real_subscription.available()
)
_SKIP = "needs Windows, QApplication, the bundled sing-box core and the real test subscription"
#: Seconds one server gets to bring a real page through the hop (the tunnel needs 5-10 s, a blocked address more).
_PAGE_WAIT = 75


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
    #: The protocols of the test person's servers this class imports (the first one is the main server's).
    SCHEMES = ("vless",)
    # True: the account points the tunnel at an address nothing answers, like a network that drops the WARP UDP ports.
    BLOCKED = False
    # True: the VPN (TUN) mode, which captures the helpers' own sockets; it changes the routes of the machine.
    TUN = False

    @classmethod
    def setUpClass(cls) -> None:
        from xray_fluent.application import runtime_services
        from xray_fluent.application.controller import AppController
        from xray_fluent.network import warp_registration
        from xray_fluent.profiles.models import AppState
        from tests.test_app_transition_gui_stalls import _FakeWinProxy

        cls.tmp = Path(tempfile.mkdtemp(prefix="zkvn-e2e-warp-"))
        cls.account = cls.tmp / "warp-entry-profile.json"
        # An account registered by an earlier run may be reused (KVN_E2E_ACCOUNT): the registration API answers 429 when
        # one address registers many devices, which a series of single-server runs would do.
        reused = os.environ.get("KVN_E2E_ACCOUNT", "")
        if reused and Path(reused).is_file():
            shutil.copyfile(reused, cls.account)
        cls.registration = warp_registration.ensure_account(cls.account)  # the real API
        if reused and not Path(reused).is_file() and cls.account.is_file() and not cls.BLOCKED:
            shutil.copyfile(cls.account, reused)
        if cls.BLOCKED:
            import json

            document = json.loads(cls.account.read_text(encoding="utf-8"))
            for peer in document["peers"]:
                peer["endpoint"] = {"v4": "192.0.2.1:2408", "v6": "", "host": "192.0.2.1:2408", "ports": [2408]}
            cls.account.write_text(json.dumps(document), encoding="utf-8")
        # The shipped sing-box config with one user setting changed: the log level (the user's own raw JSON is the
        # place for it), so that the INFO line of a dial through the WARP endpoint shows up in the app's log.
        import json as _json

        from xray_fluent.constants import SINGBOX_TEMPLATES_DIR

        cls.configs = cls.tmp / "configs-sing-box"
        cls.configs.mkdir()
        shipped = _json.loads((SINGBOX_TEMPLATES_DIR / "default.json").read_text(encoding="utf-8"))
        shipped["log"]["level"] = "info"
        (cls.configs / "default.json").write_text(_json.dumps(shipped), encoding="utf-8")
        cls.patchers = [
            patch("xray_fluent.application.controller.SINGBOX_CONFIGS_DIR", cls.configs),
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
        nodes = [node for scheme in cls.SCHEMES for node in real_subscription.nodes_of(scheme)]
        for order, node in enumerate(nodes):
            node.sort_order = order
        state.nodes = list(nodes)
        state.selected_node_id = nodes[0].id
        state.settings.enable_system_proxy = False
        state.settings.tun_mode = cls.TUN
        state.settings.auto_switch_enabled = False
        state.settings.singbox_path = str(_SINGBOX)
        state.settings.xray_path = str(XRAY_PATH_DEFAULT)
        state.settings.warp_entry_hop = True
        state.settings.server_ipv6_first = True
        state.settings.zapret_target.tcp_proxy_enabled = False
        state.settings.zapret_target.quic_proxy_enabled = False
        state.settings.zapret_target.wireguard_enabled = False
        controller.state = state
        controller._invalidate_xray_outbound_pool_cache()
        cls.controller = controller
        cls.nodes = nodes
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
            controller.slot_runtime.stop()
            for manager in (controller.singbox, controller.xray, controller.hysteria, controller.amnezia):
                manager.stop()
        finally:
            for patcher in reversed(cls.patchers):
                patcher.stop()
            shutil.rmtree(cls.tmp, ignore_errors=True)

    def _seen(self, text: str) -> bool:
        return any(text in line for line in self.logs)

    def _everything(self) -> str:
        """Debug only (KVN_E2E_DEBUG=1): the last lines and statuses, addresses and names taken out."""
        import re

        topic = os.environ.get("KVN_E2E_DEBUG_TOPIC", "")
        lines = [line for line in self.logs if topic in line.lower()] if topic else self.logs
        rows = [f"[status {level}] {message}" for level, message in self.statuses[-8:]] + lines[-80:]
        return "\n".join(
            re.sub(r"[0-9a-fA-F:.]{7,}|[\w-]+(\.[\w-]+){2,}", "<x>", re.sub(r"^\[(sing-box|xray)\]\[[^\]]*\]\s*", "[\\1] ", row))[:230]
            for row in rows
        )

    def _evidence(self) -> str:
        if os.environ.get("KVN_E2E_DEBUG"):
            return self._everything()
        # Only lines about the hop, with every address and name taken out: this text lands in test failures.
        import re

        lines = [
            re.sub(r"^\[sing-box\]\[[^\]]*\]\s*", "[sing-box] ", line)  # the prefix carries the server's display name
            for line in self.logs[-300:]
            if "warp" in line.lower() or "protect" in line.lower() or "[slots]" in line
        ]
        return "\n".join(re.sub(r"[0-9a-fA-F:.]{7,}|[\w-]+(\.[\w-]+){2,}", "<x>", line) for line in lines[-25:])

    def _page_through(self, node, wait: float) -> int | None:
        """Select this server, and fetch a real page through the app's own local proxy until it answers."""
        from xray_fluent.application.selection_source import SelectionSource

        c = self.controller
        c.set_selected_node(node.id, source=SelectionSource.NODES_MENU)
        if not c._desired_connected:
            c.toggle_connection()
        if not _spin_until(lambda: c._active_session is not None and c.connected, 60):
            return None
        port = c._active_session.http_port
        result: dict[str, int] = {}

        def browse() -> None:
            # The WARP tunnel needs a few seconds after the connect (an unanswered handshake is retried on the next
            # address, core patch warp-entry-candidates): requests sent before that fail, as a browser's first load
            # does, so the request is repeated like a user's refresh.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"}))
            deadline = time.monotonic() + wait
            while time.monotonic() < deadline and "status" not in result:
                try:
                    with opener.open("http://example.com/", timeout=20) as reply:
                        if b"Example Domain" in reply.read(2048):
                            result["status"] = reply.status
                except Exception:  # noqa: BLE001 - not up yet: the next refresh decides
                    time.sleep(1)

        worker = threading.Thread(target=browse, daemon=True)
        worker.start()
        _spin_until(lambda: not worker.is_alive(), wait + 5)
        return result.get("status")

    def _a_real_page_comes_back(self) -> None:
        """At least one real server of the protocol brings a real page through the hop (a server may be down)."""
        for node in self.nodes:
            status = self._page_through(node, _PAGE_WAIT)
            if status == 200:
                break
        else:
            self.fail("no server of the test person brought a page through the hop\n" + self._evidence())
        self.assertTrue(self._seen("[warp-entry]"), "no [warp-entry] line at all\n" + self._evidence())
        self.assertTrue(
            self._seen("вход через WARP: серверов через вход="), "the plan did not get the hop\n" + self._evidence()
        )
        self.assertTrue(
            any(
                "warp[kvn-warp-entry]" in line and ("outbound connection to" in line or "outbound packet connection" in line)
                for line in self.logs
            ),
            "the page did not cross the WARP endpoint\n" + self._evidence(),
        )


@unittest.skipUnless(_RUNNABLE, _SKIP)
class WarpEntryE2E(_WarpE2EBase):
    SCHEMES = ("vless",)

    def test_the_account_was_registered_by_the_app_over_the_real_api(self) -> None:
        self.assertTrue(self.registration.ok, str(self.registration))
        self.assertTrue(self.account.is_file())

    def test_a_real_vless_server_brings_a_real_page_through_the_hop(self) -> None:
        self._a_real_page_comes_back()
        self.assertFalse(self._seen("endpoint not initialized"), self._evidence())


@unittest.skipUnless(
    _RUNNABLE and os.environ.get("KVN_E2E_HYSTERIA_UDP") == "1",
    _SKIP + " and KVN_E2E_HYSTERIA_UDP=1: only where the test person's Hysteria2 servers answer over UDP at all "
    "(from the win10 VM none does, with or without the hop)",
)
class WarpEntryHysteriaProxyModeE2E(_WarpE2EBase):
    """Hysteria2 dials its server from its own UDP socket: in the proxy mode it talks to a loopback relay of sing-box."""

    SCHEMES = ("hysteria2",)

    def test_a_real_hysteria_server_brings_a_real_page_through_the_hop_in_the_proxy_mode(self) -> None:
        self._a_real_page_comes_back()


@unittest.skipUnless(_RUNNABLE, _SKIP)
class WarpEntryAmneziaE2E(_WarpE2EBase):
    """The real AmneziaWG server of the test person: the helper talks to a loopback relay of sing-box (both modes)."""

    SCHEMES = ("awg",)

    def test_the_real_amnezia_server_brings_a_real_page_through_the_hop(self) -> None:
        self._a_real_page_comes_back()


@unittest.skipUnless(_RUNNABLE and os.environ.get("KVN_E2E_TUN") == "1", _SKIP + " and KVN_E2E_TUN=1 (it changes the routes)")
class WarpEntryHysteriaTunE2E(_WarpE2EBase):
    """In the VPN mode the TUN captures hysteria.exe's own UDP socket and its process rule leads into the hop."""

    SCHEMES = ("hysteria2",)
    TUN = True

    def test_a_real_hysteria_server_brings_a_real_page_through_the_hop(self) -> None:
        self._a_real_page_comes_back()


@unittest.skipUnless(_RUNNABLE and os.environ.get("KVN_E2E_TUN") == "1", _SKIP + " and KVN_E2E_TUN=1 (it changes the routes)")
class WarpEntryAmneziaTunE2E(_WarpE2EBase):
    """The same relay under the TUN."""

    SCHEMES = ("awg",)
    TUN = True

    def test_the_real_amnezia_server_brings_a_real_page_through_the_hop_under_the_tun(self) -> None:
        self._a_real_page_comes_back()


@unittest.skipUnless(_RUNNABLE and os.environ.get("KVN_E2E_TUN") == "1", _SKIP + " and KVN_E2E_TUN=1 (it changes the routes)")
class WarpEntrySlotsTunE2E(_WarpE2EBase):
    """A service slot has its own helper process and its own server; under the TUN that helper enters through the hop too."""

    SCHEMES = ("hysteria2", "vless")
    TUN = True

    def test_a_service_slot_reaches_its_own_server_through_the_hop(self) -> None:
        from xray_fluent.application.selection_source import SelectionSource

        c = self.controller
        c.set_selected_node(self.nodes[0].id, source=SelectionSource.NODES_MENU)
        ok, message = c.set_service_slots({"ai"})
        self.assertTrue(ok, message.splitlines()[0] if message else "")
        if not c._desired_connected:
            c.toggle_connection()
        self.assertTrue(_spin_until(lambda: c.connected, 120), self._evidence())
        self.assertTrue(
            _spin_until(lambda: "ai" in c.slot_runtime.active_slots, 90),
            "the AI slot did not come up\n" + "\n".join(line[:160] for line in self.logs if "[slots]" in line)[-1500:],
        )
        port = c._active_session.http_port
        result: dict[str, int] = {}

        def browse() -> None:
            # ChatGPT is in the AI slot's domains; any HTTP answer (even a refusal page) proves the whole path.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": f"http://127.0.0.1:{port}"}))
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline and "status" not in result:
                try:
                    with opener.open("https://chatgpt.com/", timeout=25) as reply:
                        result["status"] = reply.status
                except urllib.error.HTTPError as error:
                    result["status"] = error.code
                except Exception:  # noqa: BLE001 - not up yet
                    time.sleep(1)

        worker = threading.Thread(target=browse, daemon=True)
        worker.start()
        _spin_until(lambda: not worker.is_alive(), 95)
        self.assertIn("status", result, "no answer through the slot\n" + self._evidence())
        dials = [
            line for line in self.logs
            if "warp[kvn-warp-entry]" in line and ("outbound connection to" in line or "outbound packet connection" in line)
        ]
        self.assertGreaterEqual(
            len(dials), 2, "the main server and the slot server must both be dialled through the hop\n" + self._evidence()
        )
        self.assertTrue(
            any("found process path" in line and "-slot-" in line for line in self.logs),
            "the slot helper's own sockets were not seen by the router\n" + self._evidence(),
        )


@unittest.skipUnless(_RUNNABLE, _SKIP)
class WarpEntryBlockedAddressE2E(_WarpE2EBase):
    """The account's own WARP address is a black hole (what a censor does to it): the tunnel must still come up."""

    SCHEMES = ("vless",)
    BLOCKED = True

    def test_a_blocked_account_address_still_gets_the_tunnel_through_another_edge(self) -> None:
        from xray_fluent.network.warp_hop_health import TUNNEL_DOWN

        self._a_real_page_comes_back()
        self.assertFalse(
            any(TUNNEL_DOWN == m for _, m in self.statuses), "the user was told the tunnel is down although it recovered"
        )


if __name__ == "__main__":
    unittest.main()
