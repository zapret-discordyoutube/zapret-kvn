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


_SHARED_ACCOUNT: Path | None = None


def _shared_account() -> Path:
    """The account file of this run, shared by the classes (registered once); removed when the process ends."""
    global _SHARED_ACCOUNT
    if _SHARED_ACCOUNT is None:
        import atexit

        directory = Path(tempfile.mkdtemp(prefix="zkvn-e2e-warp-shared-"))
        _SHARED_ACCOUNT = directory / "account.json"
        atexit.register(shutil.rmtree, directory, True)
    return _SHARED_ACCOUNT


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
    # True: no account is copied in and none is registered by the class itself: the app has to get its own.
    FRESH = False

    @classmethod
    def setUpClass(cls) -> None:
        from xray_fluent.application import runtime_services
        from xray_fluent.application.controller import AppController
        from xray_fluent.network import warp_registration
        from xray_fluent.profiles.models import AppState
        from tests.test_app_transition_gui_stalls import _FakeWinProxy

        cls.tmp = Path(tempfile.mkdtemp(prefix="zkvn-e2e-warp-"))
        cls.account = cls.tmp / "warp-entry-profile.json"
        # One account serves the whole run: the registration API answers 429 when one address registers many devices
        # (the release gate of 0.8.125 failed that way after a day of real-API runs: every class registered its own WireGuard
        # and MASQUE accounts).  KVN_E2E_ACCOUNT names a file kept between runs; without it the first class registers and the
        # others of the same run copy it.  The MASQUE account (`<file>.masque`, registered by the app beside the connect)
        # is shared the same way.
        reused = os.environ.get("KVN_E2E_ACCOUNT", "")
        shared = Path(reused) if reused else _shared_account()
        if shared.is_file() and not cls.FRESH:
            shutil.copyfile(shared, cls.account)
        masque_shared = Path(str(shared) + ".masque")
        if masque_shared.is_file() and not cls.FRESH:
            shutil.copyfile(masque_shared, Path(str(cls.account) + ".masque"))
        if cls.FRESH:
            cls.registration = warp_registration.Outcome(False, "none", "the app registers its own account")
        else:
            cls.registration = warp_registration.ensure_account(cls.account)  # the real API
        if not cls.registration.ok and "429" in cls.registration.detail:
            # Cloudflare refuses new devices from this address for a while: nothing about the app is proven or refuted.
            raise unittest.SkipTest("the registration API answers 429 (too many devices from this address): unproven now")
        if not shared.is_file() and cls.account.is_file() and not cls.BLOCKED and not cls.FRESH:
            shutil.copyfile(cls.account, shared)
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
            # keep the MASQUE account the app registered for the classes that follow
            reused = os.environ.get("KVN_E2E_ACCOUNT", "")
            masque_file = Path(str(cls.account) + ".masque")
            masque_shared = Path(str(Path(reused) if reused else _shared_account()) + ".masque")
            if masque_file.is_file() and not masque_shared.is_file():
                shutil.copyfile(masque_file, masque_shared)
        except OSError:
            pass
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


class _FirewallBlocked(_WarpE2EBase):
    """The network drops the WARP WireGuard ports (and, when asked, UDP 443) for the real core: only MASQUE can get through.

    A Windows Firewall rule on the real ``sing-box.exe`` stands in for the carrier that cuts WireGuard (the owner's mobile
    data, 2026-11-26): the packets never leave the machine, and nothing about the tunnel is faked.
    """

    SCHEMES = ("vless",)
    #: UDP remote ports the rule drops.
    UDP_PORTS = "2408,500,4500,1701,854,934"
    #: One address whose TCP 443 is dropped too ("" = none).
    TCP_BLOCKED_IP = ""
    _RULE = "kvn-e2e-warp-block"

    @classmethod
    def setUpClass(cls) -> None:
        import subprocess

        super().setUpClass()
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={cls._RULE}"], capture_output=True)
        added = subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule", f"name={cls._RULE}", "dir=out", "action=block",
                "protocol=UDP", f"remoteport={cls.UDP_PORTS}", f"program={_SINGBOX.resolve()}",
            ],
            capture_output=True,  # bytes: netsh answers in the console code page of the machine, not in UTF-8
        )
        if added.returncode != 0:
            raise unittest.SkipTest("cannot add the firewall rule (needs an administrator), netsh code " + str(added.returncode))
        if cls.TCP_BLOCKED_IP:
            # TCP 443 to ONE address (the account's own MASQUE edge): the rule of a censor that cut an address, not a block
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={cls._RULE}-tcp"], capture_output=True)
            added = subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule", f"name={cls._RULE}-tcp", "dir=out", "action=block",
                    "protocol=TCP", "remoteport=443", f"remoteip={cls.TCP_BLOCKED_IP}", f"program={_SINGBOX.resolve()}",
                ],
                capture_output=True,
            )
            if added.returncode != 0:
                raise unittest.SkipTest("cannot add the TCP firewall rule, netsh code " + str(added.returncode))
        shown = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={cls._RULE}"], capture_output=True)
        if shown.returncode != 0:
            raise AssertionError("the firewall rule that stands for the carrier is not there after it was added")

    @classmethod
    def tearDownClass(cls) -> None:
        import subprocess

        try:
            super().tearDownClass()
        finally:
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={cls._RULE}"], capture_output=True)
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={cls._RULE}-tcp"], capture_output=True)

    def _tunnel_answered_at(self, transport: str) -> bool:
        return any("WARP tunnel answered at " + transport in line for line in self.logs)


@unittest.skipUnless(_RUNNABLE, _SKIP)
class WarpEntryWireGuardBlockedE2E(_FirewallBlocked):
    """WireGuard to every WARP port is dropped: the hop comes up over MASQUE and a real page comes back."""

    def test_a_real_page_comes_back_over_masque_when_wireguard_is_dropped(self) -> None:
        self._a_real_page_comes_back()
        self.assertTrue(self._tunnel_answered_at("masque-"), "the tunnel did not come up over MASQUE\n" + self._evidence())


@unittest.skipUnless(_RUNNABLE, _SKIP)
class WarpEntryQuicAndWireGuardBlockedE2E(_FirewallBlocked):
    """WireGuard and UDP 443 are dropped: the hop comes up over MASQUE on HTTP/2 (TCP 443) and a real page comes back."""

    UDP_PORTS = "2408,500,4500,1701,854,934,443"

    def test_a_real_page_comes_back_over_masque_http2_when_quic_is_dropped_too(self) -> None:
        self._a_real_page_comes_back()
        self.assertTrue(self._tunnel_answered_at("masque-http2"), "the tunnel did not come up over HTTP/2\n" + self._evidence())


@unittest.skipUnless(_RUNNABLE, _SKIP)
class WarpEntryApiBlockedE2E(_WarpE2EBase):
    """The network blocks the registration API (the owner's mobile data, 2026-11-27): no account can be made directly.

    A Windows Firewall rule on this Python process drops TCP 443 to every address of the API; the VPN's own helper (the real
    sing-box) is not blocked, which is what a tunnel to a server outside the provider's reach looks like.  The first connect
    must go on without the hop and say so, register both accounts THROUGH the VPN, restart by itself and bring a real page
    through the WARP endpoint.  That a real provider behaves like the rule is proven only on the owner's network."""

    SCHEMES = ("vless",)
    FRESH = True
    _RULE = "kvn-e2e-warp-api-block"

    @classmethod
    def setUpClass(cls) -> None:
        import socket
        import subprocess
        import sys

        from xray_fluent.network import warp_registration

        addresses = {info[4][0] for info in socket.getaddrinfo(warp_registration.API_HOST, 443, socket.AF_INET)}
        addresses.update(warp_registration.KNOWN_ADDRESSES)
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={cls._RULE}"], capture_output=True)
        # A venv's python.exe starts the base interpreter, which is the process that really opens the sockets: block both.
        programs = {Path(sys.executable).resolve(), Path(getattr(sys, "_base_executable", sys.executable)).resolve()}
        for index, program in enumerate(sorted(programs)):
            added = subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule", f"name={cls._RULE}", "dir=out", "action=block",
                    "protocol=TCP", "remoteport=443", f"remoteip={','.join(sorted(addresses))}", f"program={program}",
                ],
                capture_output=True,
            )
            if added.returncode != 0:
                raise unittest.SkipTest("cannot add the firewall rule (needs an administrator), netsh code " + str(added.returncode))
        try:
            super().setUpClass()
        except BaseException:
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={cls._RULE}"], capture_output=True)
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        import subprocess

        try:
            super().tearDownClass()
        finally:
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={cls._RULE}"], capture_output=True)

    def test_the_app_registers_its_accounts_through_the_vpn_and_restarts_with_the_hop(self) -> None:
        from xray_fluent.network import warp_masque_account, warp_registration

        c = self.controller
        # the precondition: the rule really blocks the API from this process
        probe = warp_registration.ensure_account(self.tmp / "probe.json", timeout=4.0, budget=10.0)
        self.assertFalse(probe.ok, "the API is reachable directly: the rule does not block it")
        c._warp_direct_failed_at = -1e9
        self.assertFalse(self.account.is_file())
        from xray_fluent.application.selection_source import SelectionSource

        c.set_selected_node(self.nodes[0].id, source=SelectionSource.NODES_MENU)
        c.toggle_connection()
        self.assertTrue(_spin_until(lambda: c.connected, 120), "the connect without the hop did not come up\n" + self._evidence())
        self.assertTrue(
            any("Не удалось зарегистрировать аккаунт WARP напрямую" in message for _, message in self.statuses),
            "the user was not told that this connect runs without the hop\n" + self._evidence(),
        )
        self.assertTrue(
            _spin_until(lambda: self._seen("аккаунт WARP зарегистрирован через VPN"), 150),
            "the accounts were not registered through the VPN\n" + self._evidence(),
        )
        self.assertTrue(warp_registration.account_file_ready(self.account))
        self.assertTrue(warp_masque_account.ready(warp_masque_account.account_path(self.account)))
        _spin_until(lambda: not c._transition_active and c.connected, 90)
        self._a_real_page_comes_back()


@unittest.skipUnless(_RUNNABLE, _SKIP)
class WarpEntryDeadHopE2E(_WarpE2EBase):
    """Every path to the WARP edge is dropped for the real core (the owner's mobile network, 2026-11-27): the connect must not die.

    A Windows Firewall rule on the real ``sing-box.exe`` drops every packet to the WARP address ranges (WireGuard ports,
    QUIC, and the HTTP/2 MASQUE on TCP 443) while everything else, our server included, is open: the tunnel can carry
    nothing over any candidate.  The app must say so, reconnect WITHOUT the entry by itself and bring a real page through the
    server.  That a real carrier behaves like the rule is proven only on the owner's network."""

    SCHEMES = ("vless",)
    _RULE = "kvn-e2e-warp-dead"
    _RANGES = "162.159.192.0/22,162.159.198.0/24,188.114.96.0/22"

    @classmethod
    def setUpClass(cls) -> None:
        import subprocess

        super().setUpClass()
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={cls._RULE}"], capture_output=True)
        added = subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule", f"name={cls._RULE}", "dir=out", "action=block",
                "protocol=any", f"remoteip={cls._RANGES}", f"program={_SINGBOX.resolve()}",
            ],
            capture_output=True,
        )
        if added.returncode != 0:
            raise unittest.SkipTest("cannot add the firewall rule (needs an administrator), netsh code " + str(added.returncode))

    @classmethod
    def tearDownClass(cls) -> None:
        import subprocess

        try:
            super().tearDownClass()
        finally:
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={cls._RULE}"], capture_output=True)

    def test_a_dead_hop_falls_back_to_the_server_without_it(self) -> None:
        from xray_fluent.application.selection_source import SelectionSource

        c = self.controller
        c.set_selected_node(self.nodes[0].id, source=SelectionSource.NODES_MENU)
        c.toggle_connection()
        self.assertTrue(
            _spin_until(lambda: self._seen("не пропускает трафик ни по одному кандидату"), 180),
            "the app did not give the hop up\n" + self._evidence(),
        )
        self.assertTrue(
            any("не заработал в этой сети" in message for _, message in self.statuses),
            "the user was not told\n" + self._evidence(),
        )
        # the reconnect without the hop: the pause line of the next connect, then a real page through the server
        self.assertTrue(
            _spin_until(lambda: self._seen("вход через WARP приостановлен после отказа"), 120),
            "the reconnect did not run without the hop\n" + self._evidence(),
        )
        _spin_until(lambda: not c._transition_active and c.connected, 90)
        self.assertTrue(c.connected, "the connection is down after the fallback\n" + self._evidence())
        port = c._active_session.http_port
        result: dict[str, int] = {}

        def browse() -> None:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"}))
            deadline = time.monotonic() + _PAGE_WAIT
            while time.monotonic() < deadline and "status" not in result:
                try:
                    with opener.open("http://example.com/", timeout=20) as reply:
                        if b"Example Domain" in reply.read(2048):
                            result["status"] = reply.status
                except Exception:  # noqa: BLE001 - not up yet
                    time.sleep(1)

        worker = threading.Thread(target=browse, daemon=True)
        worker.start()
        _spin_until(lambda: not worker.is_alive(), _PAGE_WAIT + 5)
        self.assertEqual(200, result.get("status"), "no page through the server after the fallback\n" + self._evidence())


@unittest.skipUnless(_RUNNABLE, _SKIP)
class WarpEntryMasqueAddressBlockedE2E(_FirewallBlocked):
    """WireGuard, QUIC and the account's own MASQUE address (162.159.198.2) are dropped: another address of the MASQUE block
    carries the hop (owner 2026-11-27, "try more WARP address ranges and ports"; core patch warp-entry-masque-edges)."""

    UDP_PORTS = "2408,500,4500,1701,854,934,443"
    TCP_BLOCKED_IP = "162.159.198.2"

    def test_a_real_page_comes_back_over_another_masque_address_when_the_accounts_own_one_is_cut(self) -> None:
        self._a_real_page_comes_back()
        self.assertTrue(self._tunnel_answered_at("masque-http2 edge="), "the tunnel did not come up over another MASQUE edge\n" + self._evidence())


@unittest.skipUnless(_RUNNABLE, _SKIP)
class WarpEntryApiBlockedTunE2E(WarpEntryApiBlockedE2E):
    """The same as `WarpEntryApiBlockedE2E` in the VPN (TUN) mode, the mode of the owner's PC (2026-11-27): the connect without
    the hop, the registration through the VPN, the restart and the page must work with the TUN adapter too."""

    TUN = True

    def test_the_app_registers_its_accounts_through_the_vpn_and_restarts_with_the_hop(self) -> None:
        super().test_the_app_registers_its_accounts_through_the_vpn_and_restarts_with_the_hop()


if __name__ == "__main__":
    unittest.main()
