"""The network side of the block diagnosis (owner decision 2026-11-19): facts for ``diagnosis.diagnose``.

Every probe goes straight from the PC with a short deadline: TCP to the server and to its IP on 443, one TLS
ClientHello with the real name, a neutral name and the real name on our pool front, system DNS against our
DoH. Windows has no per-socket bypass of the TUN, so the caller runs this only while no TUN session is up
(after a failed connect the session is gone). The freeze is measured through the session's local HTTP proxy.
Same steps as Android ``BlockProbe.kt``.
"""

from __future__ import annotations

import errno
import ipaddress
import random
import socket
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, replace

from ..network.bootstrap_dns import BootstrapNameNotFound, resolve_doh
from .diagnosis import (
    ANSWER_TIMEOUT_S,
    CONNECT_TIMEOUT_S,
    NEUTRAL_NAMES,
    DiagnosisFacts,
    ProbeResult,
    client_hello,
    judge_first_byte,
)

#: Not a Russian address, or the profile's "Russia directly" rule would take it past the server; the same file
#: as the speed test. At most FREEZE_READ_BYTES are read.
FREEZE_URL = "https://fra.download.datapacket.com/100mb.bin"
FREEZE_READ_BYTES = 64 * 1024
FREEZE_STALL_S = 5.0
_RESET_ERRNOS = {errno.ECONNREFUSED, errno.ECONNRESET, 10054, 10061}  # + WSAECONNRESET, WSAECONNREFUSED
_TIMEOUT_ERRNOS = {errno.ETIMEDOUT, 10060}  # + WSAETIMEDOUT


@dataclass(frozen=True, slots=True)
class ProbeTarget:
    host: str
    port: int
    #: The TLS name (server_name / Reality serverName); None — the host, when it is not an IP.
    server_name: str | None
    uses_tls: bool
    udp: bool
    #: For the report (schema 2): the scheme, transport and security as in the profile.
    protocol: str = ""
    transport: str | None = None
    security: str | None = None


def literal_address(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return None


def _pick(values: frozenset[str] | set[str] | None) -> str | None:
    if not values:
        return None
    ordered = sorted(values, key=lambda item: (":" in item, item))
    return ordered[0]


def _judge_connect_error(exc: OSError) -> ProbeResult:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return ProbeResult.TIMEOUT
    code = getattr(exc, "winerror", None) or exc.errno
    if code in _TIMEOUT_ERRNOS:
        return ProbeResult.TIMEOUT
    if code in _RESET_ERRNOS or isinstance(exc, (ConnectionRefusedError, ConnectionResetError)):
        return ProbeResult.RESET
    return ProbeResult.UNKNOWN


class BlockProbe:
    def __init__(
        self,
        front_hosts: Callable[[], list[str]],
        *,
        rng: random.Random | None = None,
        connect: Callable[[tuple[str, int], float], socket.socket] = lambda address, timeout: socket.create_connection(address, timeout=timeout),
        system_lookup: Callable[[str], set[str]] | None = None,
        doh_lookup: Callable[[str], set[str]] = lambda host: resolve_doh(host),
    ) -> None:
        self._front_hosts = front_hosts
        self._rng = rng or random.SystemRandom()
        self._connect = connect
        self._system_lookup = system_lookup or _system_addresses
        self._doh_lookup = doh_lookup

    def run(self, target: ProbeTarget) -> DiagnosisFacts:
        front = None
        for host in self._front_hosts()[:3]:
            try:
                front = _pick({item for item in self._system_lookup(host) if ":" not in item})
            except OSError:
                front = None
            if front:
                break
        control = self._tcp(front, 443) if front else ProbeResult.UNKNOWN
        if not front or control is not ProbeResult.ANSWERED:
            return DiagnosisFacts(control=control)

        literal = literal_address(target.host)
        system_dns: frozenset[str] | None = None
        doh_dns: frozenset[str] | None = None
        name_missing = False
        if literal is None:
            try:
                system_dns = frozenset(self._system_lookup(target.host))
            except socket.gaierror as exc:
                system_dns = frozenset() if exc.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5), 11001) else None
            except OSError:
                system_dns = None
            try:
                doh_dns = frozenset(self._doh_lookup(target.host)) or None
            except BootstrapNameNotFound:
                name_missing = True
            except OSError:
                doh_dns = None
        address = literal or _pick(doh_dns) or _pick(system_dns)
        facts = DiagnosisFacts(
            control=control, system_dns=system_dns, doh_dns=doh_dns, doh_name_missing=name_missing,
            uses_tls=target.uses_tls, udp_transport=target.udp,
        )
        if address is None:
            return facts
        facts = replace(facts, probed_address=address)
        if target.udp:
            # A UDP port cannot be checked over TCP: 443 of the same IP tells whether the address is alive.
            return replace(facts, tcp_other_port=self._tcp(address, 443))
        tcp_target = self._tcp(address, target.port)
        facts = replace(facts, tcp_target=tcp_target)
        if tcp_target is ProbeResult.TIMEOUT and target.port != 443:
            facts = replace(facts, tcp_other_port=self._tcp(address, 443))
        name = target.server_name or target.host
        if not target.uses_tls or tcp_target is not ProbeResult.ANSWERED or not name or literal_address(name):
            return facts
        real = self._tls(address, target.port, name)
        facts = replace(facts, tls_real_name=real)
        if real is ProbeResult.ANSWERED:
            return facts
        neutral = self._tls(address, target.port, self._rng.choice(NEUTRAL_NAMES))
        facts = replace(facts, tls_neutral_name=neutral)
        if neutral is ProbeResult.ANSWERED:
            facts = replace(facts, tls_real_name_elsewhere=self._tls(front, 443, name))
        return facts

    def _tcp(self, address: str, port: int) -> ProbeResult:
        try:
            sock = self._connect((address, port), CONNECT_TIMEOUT_S)
        except OSError as exc:
            return _judge_connect_error(exc)
        sock.close()
        return ProbeResult.ANSWERED

    def _tls(self, address: str, port: int, name: str) -> ProbeResult:
        """ClientHello with ``name``; the connection itself failing is UNKNOWN (TCP is judged separately)."""
        try:
            sock = self._connect((address, port), CONNECT_TIMEOUT_S)
        except OSError:
            return ProbeResult.UNKNOWN
        try:
            sock.settimeout(ANSWER_TIMEOUT_S)
            sock.sendall(client_hello(name, self._rng))
            data = sock.recv(1)
            return judge_first_byte(data[0] if data else -1)
        except (socket.timeout, TimeoutError):
            return ProbeResult.TIMEOUT
        except OSError as exc:
            return ProbeResult.RESET if _judge_connect_error(exc) is ProbeResult.RESET else ProbeResult.UNKNOWN
        finally:
            sock.close()


def _system_addresses(host: str) -> set[str]:
    resolved: set[str] = set()
    for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
        address = literal_address(str(info[4][0]))
        if address:
            resolved.add(address)
    return resolved


def measure_freeze(proxy_port: int | None, *, url: str = FREEZE_URL, opener: urllib.request.OpenerDirector | None = None) -> int | None:
    """Bytes that came through the session before a stall; None — everything asked for came, or no measure."""
    if opener is None:
        if not proxy_port:
            return None
        proxy = f"http://127.0.0.1:{int(proxy_port)}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    request = urllib.request.Request(url, headers={
        "Connection": "close", "Accept-Encoding": "identity", "Range": f"bytes=0-{FREEZE_READ_BYTES - 1}",
    })
    try:
        response = opener.open(request, timeout=FREEZE_STALL_S)
    except OSError:
        return None
    total = 0
    try:
        with response:
            if response.status not in (200, 206):
                return None
            while total < FREEZE_READ_BYTES:
                chunk = response.read(min(8192, FREEZE_READ_BYTES - total))
                if not chunk:
                    break
                total += len(chunk)
    except (socket.timeout, TimeoutError):
        return total
    except OSError:
        return None  # a reset is not a freeze: the freeze is silence
    return None
