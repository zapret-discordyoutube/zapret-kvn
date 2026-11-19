"""The network side of the path check after a failure (schema 3, owner decisions 2026-11-19).

The app only collects facts: every probe it ran, what came back and how long it took (``checks.py``); vpnbot
judges. The owner asked three times for the check to stay quiet on the wire («always do it randomly so TSPU doesn't
notice, and not make unnecessary requests to the servers»; «make sure there are no unnecessary checks that could
trigger DPI»; «check as rarely as possible and only if it's really necessary»), so:
- no hand-made packet ever goes on the wire: TLS probes use the system's TLS stack (OpenSSL here), the same
  ClientHello as countless ordinary programs, never one that could become this app's fingerprint; no QUIC probe;
- the ladder is minimal: each probe runs only while it can still change the answer, nothing runs when the core's
  own code already proves the server answered (``needs_path_check``), and a UDP line gets no probe of the server;
- the reporter runs it rarely (once per server per day, once per install per 10 minutes);
- neutral names are drawn from pools on each run, with random gaps between probes.

Ladder (docs/CLIENT_REPORTS.md, «Path check»):
- ``control_front`` (TCP to our pool front); silent -> ``control_neutral`` (TCP+TLS to a neutral Russian site), stop;
- the address the start used, else ``dns_doh`` (encrypted, our resolver), else ``dns_system`` (plaintext: only
  when DoH did not answer);
- TCP lines: ``tcp_target``; silent and port != 443 -> ``tcp_443``; answered and TLS -> ``tls_real``; no answer
  -> ``tls_neutral``;
- UDP lines: nothing more (the core's own handshake already was the probe of the server).

Windows has no per-socket bypass of the TUN, so the caller runs this only while requests are really direct. The
freeze (``flow``) is measured through the session's local HTTP proxy, and the no-data probes (``tunnel_*``,
``direct_*``) through the Xray relay. Same ladder as Android ``BlockProbe.kt``.
"""

from __future__ import annotations

import errno
import ipaddress
import random
import socket
import ssl
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field

from ..engines.socks_probe import HTTPS_ENDPOINTS, open_socks_connection, recv_exact
from ..network.bootstrap_dns import BootstrapNameNotFound, resolve_doh
from . import checks as k
from .checks import Check

#: Not a Russian address, or the profile's "Russia directly" rule would take it past the server; the same file
#: as the speed test. At most FREEZE_READ_BYTES are read.
FREEZE_URL = "https://fra.download.datapacket.com/100mb.bin"
FREEZE_READ_BYTES = 64 * 1024
FREEZE_STALL_S = 5.0
CONNECT_TIMEOUT_S = 4.0
ANSWER_TIMEOUT_S = 5.0
#: Neutral Russian names: open in any filtering mode, white lists included.
NEUTRAL_NAMES = ("ya.ru", "vk.com", "www.gosuslugi.ru", "ozon.ru", "www.wildberries.ru")
#: Random pause between two probes, seconds.
GAP_S = (0.15, 0.7)
#: Core codes that prove the server's address answered: a path probe would only repeat what is known.
ANSWERED_CORE_CODES = frozenset({
    "TARGET_AUTH_REJECTED", "TARGET_CONNECTION_REFUSED", "TARGET_CONNECTION_CLOSED", "TARGET_OBFS_REJECTED",
    "TARGET_TLS_REJECTED", "TARGET_TLS_INTERNAL", "TARGET_TLS_UNKNOWN_AUTHORITY", "TARGET_PIN_MISMATCH",
    "TARGET_DESTINATION_UNREACHABLE",
})
_REFUSED_ERRNOS = {errno.ECONNREFUSED, 10061}          # + WSAECONNREFUSED
_RESET_ERRNOS = {errno.ECONNRESET, errno.ECONNABORTED, 10054, 10053}
_TIMEOUT_ERRNOS = {errno.ETIMEDOUT, 10060}            # + WSAETIMEDOUT


@dataclass(frozen=True, slots=True)
class ProbeTarget:
    host: str
    port: int
    #: The TLS name (server_name / Reality serverName); None — the host, when it is not an IP.
    server_name: str | None
    uses_tls: bool
    udp: bool
    #: For the report (schema 2/3): the scheme, transport and security as in the profile.
    protocol: str = ""
    transport: str | None = None
    security: str | None = None
    #: What the core's first hop runs over (schema 3 ``carrier``).
    carrier: str = "tcp"


@dataclass(frozen=True, slots=True)
class PathFacts:
    checks: dict[str, Check] = field(default_factory=dict)
    #: The address that was probed (``server_ip`` of the report when the start named none).
    probed_address: str | None = None


def needs_path_check(core_code: str | None) -> bool:
    """No probe when the core already proved the address answered, or the failure is the device's own."""
    code = str(core_code or "")
    return code not in ANSWERED_CORE_CODES and not code.startswith("LOCAL_") and code != k.NETWORK_LOST


def literal_address(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return None


def _pick(values: frozenset[str] | set[str] | None) -> str | None:
    if not values:
        return None
    return sorted(values, key=lambda item: (":" in item, item))[0]


def result_of(exc: BaseException, *, connected: bool) -> str:
    """An error as a probe result: before the connection was up a RST is ``refused``, after it ``reset``."""
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return k.TIMEOUT
    code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
    if code in _TIMEOUT_ERRNOS:
        return k.TIMEOUT
    if isinstance(exc, ConnectionRefusedError) or code in _REFUSED_ERRNOS:
        return k.RESET if connected else k.REFUSED
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError)) or code in _RESET_ERRNOS:
        return k.RESET if connected else k.REFUSED
    return k.UNKNOWN


class BlockProbe:
    def __init__(
        self,
        front_hosts: Callable[[], list[str]],
        *,
        rng: random.Random | None = None,
        connect: Callable[[tuple[str, int], float], socket.socket] = lambda address, timeout: socket.create_connection(address, timeout=timeout),
        system_lookup: Callable[[str], set[str]] | None = None,
        doh_lookup: Callable[[str], set[str]] = lambda host: resolve_doh(host),
        hello: Callable[[socket.socket, str], str] | None = None,
        clock: Callable[[], float] = time.monotonic,
        pause: Callable[[float], None] = time.sleep,
    ) -> None:
        self._front_hosts = front_hosts
        self._rng = rng or random.SystemRandom()
        self._connect = connect
        self._system_lookup = system_lookup or _system_addresses
        self._doh_lookup = doh_lookup
        self._hello = hello or system_hello
        self._clock = clock
        self._pause = pause

    # ── the ladder ──

    def run(self, target: ProbeTarget, *, known_address: str | None = None) -> PathFacts:
        found: dict[str, Check] = {}
        front = self._front_address()
        found["control_front"] = self._timed(lambda: self._tcp(front, 443) if front else k.UNKNOWN)
        if found["control_front"].r != k.ANSWERED:
            self._gap()
            neutral = self._rng.choice(NEUTRAL_NAMES)
            found["control_neutral"] = self._timed(lambda: self._tls_by_name(neutral))
            return PathFacts(found)

        address = literal_address(target.host) or (literal_address(known_address) if known_address else None)
        if address is None:
            address = self._resolve(target.host, found)
        if address is None:
            return PathFacts(found)

        if target.udp:
            return PathFacts(found, address)

        self._gap()
        found["tcp_target"] = self._timed(lambda: self._tcp(address, target.port))
        if found["tcp_target"].r != k.ANSWERED:
            if found["tcp_target"].r in (k.TIMEOUT, k.UNKNOWN) and target.port != 443:
                self._gap()
                found["tcp_443"] = self._timed(lambda: self._tcp(address, 443))
            return PathFacts(found, address)
        name = target.server_name or target.host
        if not target.uses_tls or not name or literal_address(name):
            return PathFacts(found, address)
        self._gap()
        found["tls_real"] = self._timed(lambda: self._tls(address, target.port, name))
        if found["tls_real"].r != k.ANSWERED:
            self._gap()
            neutral = self._rng.choice(NEUTRAL_NAMES)
            found["tls_neutral"] = self._timed(lambda: self._tls(address, target.port, neutral))
        return PathFacts(found, address)

    def _resolve(self, host: str, found: dict[str, Check]) -> str | None:
        """DoH first (encrypted); the system resolver, which sends the server's name in plaintext, only when DoH did
        not answer."""
        self._gap()
        doh: set[str] = set()
        started = self._clock()
        try:
            doh = set(self._doh_lookup(host))
            result = k.ANSWERED if doh else k.UNKNOWN
        except BootstrapNameNotFound:
            result = k.NXDOMAIN
        except OSError:
            result = k.UNKNOWN
        found["dns_doh"] = Check(result, k.clamp_ms((self._clock() - started) * 1000))
        if doh:
            return _pick(doh)
        if result == k.NXDOMAIN:
            return None
        self._gap()
        system: set[str] = set()
        started = self._clock()
        try:
            system = set(self._system_lookup(host))
            result = k.ANSWERED if system else k.NXDOMAIN
        except socket.gaierror as exc:
            result = k.NXDOMAIN if exc.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5), 11001) else k.TIMEOUT
        except OSError:
            result = k.UNKNOWN
        found["dns_system"] = Check(result, k.clamp_ms((self._clock() - started) * 1000))
        return _pick(system)

    # ── one probe each ──

    def _timed(self, probe: Callable[[], str]) -> Check:
        started = self._clock()
        try:
            result = probe()
        except Exception:
            result = k.UNKNOWN
        return Check(result, k.clamp_ms((self._clock() - started) * 1000))

    def _gap(self) -> None:
        self._pause(self._rng.uniform(*GAP_S))

    def _front_address(self) -> str | None:
        hosts = list(self._front_hosts())
        self._rng.shuffle(hosts)
        for host in hosts[:3]:
            try:
                address = _pick({item for item in self._system_lookup(host) if ":" not in item})
            except OSError:
                address = None
            if address:
                return address
        return None

    def _tcp(self, address: str, port: int) -> str:
        try:
            sock = self._connect((address, port), CONNECT_TIMEOUT_S)
        except OSError as exc:
            return result_of(exc, connected=False)
        sock.close()
        return k.ANSWERED

    def _tls(self, address: str, port: int, name: str) -> str:
        """ClientHello with ``name``; the connection itself failing is ``unknown`` (TCP is its own probe)."""
        try:
            sock = self._connect((address, port), CONNECT_TIMEOUT_S)
        except OSError:
            return k.UNKNOWN
        return self._hello(sock, name)

    def _tls_by_name(self, name: str) -> str:
        """TCP and TLS to a neutral site by name (``control_neutral``): connect errors count too."""
        try:
            address = _pick({item for item in self._system_lookup(name) if ":" not in item})
        except OSError:
            return k.UNKNOWN
        if not address:
            return k.UNKNOWN
        try:
            sock = self._connect((address, 443), CONNECT_TIMEOUT_S)
        except OSError as exc:
            return result_of(exc, connected=False)
        return self._hello(sock, name)



def system_hello(sock: socket.socket, name: str, *, timeout: float = ANSWER_TIMEOUT_S,
                 context: ssl.SSLContext | None = None) -> str:
    """A handshake by the system's TLS stack (no hand-made bytes: owner 2026-11-19). Any word from the server — a
    certificate (trusted or not, for this name or not) or an alert — is an answer; silence is ``timeout``; a RST or EOF
    instead of an answer is ``reset``. The socket is closed."""
    try:
        sock.settimeout(timeout)
        with (context or ssl.create_default_context()).wrap_socket(
            sock, server_hostname=name, do_handshake_on_connect=False
        ) as tls:
            tls.do_handshake()
        return k.ANSWERED
    except ssl.SSLCertVerificationError:
        return k.ANSWERED
    except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
        return k.RESET
    except ssl.SSLError as exc:
        # "TLSV1_ALERT_…" / "SSLV3_ALERT_…": the server spoke TLS and refused this hello.
        return k.ANSWERED if "ALERT" in str(getattr(exc, "reason", "") or "").upper() else k.UNKNOWN
    except OSError as exc:
        return result_of(exc, connected=True)
    finally:
        sock.close()


def _system_addresses(host: str) -> set[str]:
    resolved: set[str] = set()
    for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
        address = literal_address(str(info[4][0]))
        if address:
            resolved.add(address)
    return resolved


# ── through the tunnel: the freeze after a success, and the no-data probes ──


def measure_flow(proxy_port: int | None, *, url: str = FREEZE_URL, opener: urllib.request.OpenerDirector | None = None,
                 clock: Callable[[], float] = time.monotonic) -> Check | None:
    """``flow``: 64 KiB through the session; ``b`` — body bytes before a stall. None — no local proxy (not run)."""
    if opener is None:
        if not proxy_port:
            return None
        proxy = f"http://127.0.0.1:{int(proxy_port)}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    request = urllib.request.Request(url, headers={
        "Connection": "close", "Accept-Encoding": "identity", "Range": f"bytes=0-{FREEZE_READ_BYTES - 1}",
    })
    started = clock()

    def done(result: str, read: int) -> Check:
        return Check(result, k.clamp_ms((clock() - started) * 1000), b=read)

    try:
        response = opener.open(request, timeout=FREEZE_STALL_S)
    except OSError as exc:
        reason = getattr(exc, "reason", None)   # urllib wraps the socket error in URLError.reason
        return done(result_of(reason if isinstance(reason, BaseException) else exc, connected=True), 0)
    total = 0
    try:
        with response:
            if response.status not in (200, 206):
                return done(k.UNKNOWN, 0)
            while total < FREEZE_READ_BYTES:
                chunk = response.read(min(8192, FREEZE_READ_BYTES - total))
                if not chunk:
                    break
                total += len(chunk)
    except OSError as exc:
        return done(result_of(exc, connected=True), total)
    return done(k.ANSWERED if total >= FREEZE_READ_BYTES else k.RESET, total)


@dataclass(frozen=True, slots=True)
class Relay:
    port: int
    username: str
    password: str


def https_answers(sock: socket.socket, name: str, path: str) -> None:
    with ssl.create_default_context().wrap_socket(sock, server_hostname=name) as tls:
        tls.sendall(f"HEAD {path} HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode("ascii"))
        if not recv_exact(tls, 5).startswith(b"HTTP/"):
            raise OSError("no HTTP answer")


class NoDataProbe:
    """Tunnel up, no data (owner 2026-11-19): the same connectivity-check service by a literal address
    (``tunnel_a``: no DNS in the tunnel) and by its name (``tunnel_b``: DNS through the tunnel), and the same two
    directly (``direct_a``/``direct_b``) when requests are really direct. The address comes from our DoH outside the
    tunnel; the names are the relay check's own (node policy rejects public DoH and IP-discovery services)."""

    def __init__(
        self,
        *,
        rng: random.Random | None = None,
        doh_lookup: Callable[[str], set[str]] = lambda host: resolve_doh(host),
        through_relay: Callable[[Relay, str, str, str, float], None] | None = None,
        direct: Callable[[str, str, str, float], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
        pause: Callable[[float], None] = time.sleep,
        timeout: float = 8.0,
    ) -> None:
        self._rng = rng or random.SystemRandom()
        self._doh_lookup = doh_lookup
        self._through_relay = through_relay or _https_through_relay
        self._direct = direct or _https_direct
        self._clock = clock
        self._pause = pause
        self._timeout = timeout

    def run(self, relay: Relay, *, direct_allowed: bool) -> dict[str, Check]:
        name, _sni, path = self._rng.choice(HTTPS_ENDPOINTS)
        try:
            address = _pick({item for item in self._doh_lookup(name) if ":" not in item})
        except OSError:
            address = None
        plan: list[tuple[str, Callable[[], None]]] = [("tunnel_b", lambda: self._through_relay(relay, name, name, path, self._timeout))]
        if address:
            plan.append(("tunnel_a", lambda: self._through_relay(relay, address, name, path, self._timeout)))
        self._rng.shuffle(plan)
        if direct_allowed:
            direct: list[tuple[str, Callable[[], None]]] = [("direct_b", lambda: self._direct(name, name, path, self._timeout))]
            if address:
                direct.append(("direct_a", lambda: self._direct(address, name, path, self._timeout)))
            self._rng.shuffle(direct)
            plan += direct
        found: dict[str, Check] = {}
        for index, (probe, work) in enumerate(plan):
            if index:
                self._pause(self._rng.uniform(*GAP_S))
            started = self._clock()
            try:
                work()
                result = k.ANSWERED
            except OSError as exc:
                result = no_data_result(probe, exc, self._clock() - started)
            except Exception:
                result = k.UNKNOWN
            found[probe] = Check(result, k.clamp_ms((self._clock() - started) * 1000))
        return found


LOOKUP_SILENT_S = 5.0
"""A failed name lookup that took this long got no answer."""


class LocalRelayError(OSError):
    """The core's own local SOCKS inbound refused the connection: the app's side, proves nothing about the path."""


def no_data_result(probe: str, exc: OSError, seconds: float) -> str:
    """One no-data probe's error as a result (vpnbot 2026-11-19: tunnel_a «refused» after 2 s, tunnel_b «unknown»).

    Through the tunnel the core's local inbound accepts the connection before the core dials anything, so a drop
    there is the core's flow dropped (``reset``), never a refusal. Directly a RST is ``refused`` only to the SYN.
    A name lookup with no answer in :data:`LOOKUP_SILENT_S` is ``timeout``; a quick failure proves nothing."""
    if isinstance(exc, LocalRelayError):
        return k.UNKNOWN
    if isinstance(exc, socket.gaierror):
        return k.TIMEOUT if seconds >= LOOKUP_SILENT_S else k.UNKNOWN
    if isinstance(exc, (ssl.SSLEOFError, ssl.SSLZeroReturnError)):
        return k.RESET
    if isinstance(exc, ssl.SSLError):
        return k.UNKNOWN
    connected = probe.startswith("tunnel_") or bool(getattr(exc, "after_connect", False))
    return result_of(exc, connected=connected)


def _https_through_relay(relay: Relay, target: str, name: str, path: str, timeout: float) -> None:
    try:
        sock = open_socks_connection(relay.port, username=relay.username, password=relay.password,
                                     timeout=timeout, target_host=target)
    except ConnectionRefusedError as exc:     # only the local connect to 127.0.0.1 can be refused here
        raise LocalRelayError(str(exc)) from exc
    try:
        https_answers(sock, name, path)
    finally:
        sock.close()


def _https_direct(target: str, name: str, path: str, timeout: float) -> None:
    sock = socket.create_connection((target, 443), timeout=timeout)
    try:
        https_answers(sock, name, path)
    except OSError as exc:
        exc.after_connect = True              # a RST now is a reset, not a refusal
        raise
    finally:
        sock.close()
