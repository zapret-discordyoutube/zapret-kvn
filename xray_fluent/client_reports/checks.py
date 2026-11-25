"""Schema 3 facts of an attempt (vpnbot «schema 3 live» 2026-11-19): the probes the app ran, raw.

The app keeps no rule and no text (owner 2026-11-19: analytics live in vpnbot, the apps are open source). It names
each probe by its wire name, says what came back (``r``), how long it took (``ms``), for a flow probe how many bytes
it read (``b``), and for the system DNS whether its answer overlaps our DoH (``same``). vpnbot judges. Same names
and limits as Android ``ReportChecks.kt`` and vpnbot ``client_reports/contract.py``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

#: The app's own health check through the tunnel (vpnbot 2026-11-20): sent on a failure with no core code where the
#: check got no data. Off until vpnbot's «health live»: before that a report with it is refused as an unknown probe.
HEALTH = "health"
HEALTH_LIVE = True

#: The WARP entry hop's start (owner 2026-11-25: «make more logs and put them in the database»): the app's own account
#: registration and whether the hop's tunnel came up. Agreed with the WARP chat; vpnbot must admit the two names (and
#: settings.warp_entry, details warp_retries) first: until its «live» message everything WARP stays out of the report,
#: because a report with an unknown probe is refused whole.
WARP_REGISTER = "warp_register"
WARP_TUNNEL = "warp_tunnel"
WARP_PROBES = (WARP_REGISTER, WARP_TUNNEL)
WARP_LIVE = False

#: Every probe the contract admits, in its order.
PROBES = (
    "control_front", "control_neutral", "dns_system", "dns_doh", "tcp_preflight", "tcp_target", "tcp_443",
    "tls_real", "tls_neutral", "tls_front", "quic_neutral", "quic_target", "tunnel_a", "tunnel_b", "direct_a",
    "direct_b", "flow",
) + ((HEALTH,) if HEALTH_LIVE else ()) + (WARP_PROBES if WARP_LIVE else ())
#: Probes that move data: only they may carry ``b``.
FLOW_PROBES = frozenset({"tunnel_a", "tunnel_b", "direct_a", "direct_b", "flow"})
DNS_PROBES = frozenset({"dns_system", "dns_doh"})

ANSWERED = "answered"
TIMEOUT = "timeout"
#: RST or EOF after the connection was up.
RESET = "reset"
#: RST to SYN (or ICMP port unreachable for UDP): something at the address answered.
REFUSED = "refused"
#: The probe could not run for a local reason: proves nothing.
UNKNOWN = "unknown"
#: DNS only: the name does not exist (DoH: every trusted resolver that answered said so).
NXDOMAIN = "nxdomain"
RESULTS = (ANSWERED, TIMEOUT, RESET, REFUSED, UNKNOWN)

MAX_CHECK_MS = 60_000
MAX_CHECK_BYTES = 1_000_000_000

CARRIERS = ("tcp", "udp")
NETWORK_LOST = "NETWORK_LOST"
_CORE_CODE = re.compile(r"^(TARGET|LOCAL)_[A-Z0-9_]{1,48}$")


@dataclass(frozen=True, slots=True)
class Check:
    r: str
    ms: int
    b: int | None = None
    same: bool | None = None


def _whole(value: object, high: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= high


def is_valid_check(probe: str, check: Check) -> bool:
    if probe not in PROBES or not isinstance(check, Check):
        return False
    allowed = RESULTS + ((NXDOMAIN,) if probe in DNS_PROBES else ())
    if check.r not in allowed or not _whole(check.ms, MAX_CHECK_MS):
        return False
    if check.b is not None and (probe not in FLOW_PROBES or not _whole(check.b, MAX_CHECK_BYTES)):
        return False
    if check.same is not None and (probe != "dns_system" or check.r != ANSWERED or not isinstance(check.same, bool)):
        return False
    return True


def are_valid_checks(checks: Iterable[tuple[str, Check]]) -> bool:
    items = list(checks)
    names = [probe for probe, _check in items]
    return len(names) == len(set(names)) and all(is_valid_check(probe, check) for probe, check in items)


def ordered(checks: Mapping[str, Check]) -> tuple[tuple[str, Check], ...]:
    """The checks in the contract's order, invalid ones left out (a bad probe never loses the report)."""
    return tuple((probe, checks[probe]) for probe in PROBES if probe in checks and is_valid_check(probe, checks[probe]))


def check_json(check: Check) -> dict[str, object]:
    item: dict[str, object] = {"r": check.r, "ms": int(check.ms)}
    if check.b is not None:
        item["b"] = int(check.b)
    if check.same is not None:
        item["same"] = bool(check.same)
    return item


def warp_checks(facts: object | None) -> dict[str, Check]:
    """The WARP hop's probes from the app's own facts (``WarpFacts`` of the controller; read by name so this module
    never imports the network layer). Empty until vpnbot admits them (WARP_LIVE), when the hop was off, and for a
    step that did not run (None: the account already existed, nothing was asked)."""
    if not WARP_LIVE or facts is None or getattr(facts, "enabled", False) is not True:
        return {}
    found: dict[str, Check] = {}
    for probe, step in ((WARP_REGISTER, getattr(facts, "register", None)), (WARP_TUNNEL, getattr(facts, "tunnel", None))):
        if isinstance(step, tuple) and len(step) == 2 and isinstance(step[1], int) and not isinstance(step[1], bool):
            check = Check(str(step[0]), clamp_ms(step[1]))
            if is_valid_check(probe, check):
                found[probe] = check
    return found


def clamp_ms(value: float) -> int:
    return max(0, min(int(value), MAX_CHECK_MS))


def core_code_of(value: str | None) -> str:
    """The core's own code as the contract admits it, or ``""`` (CORE_UNCLASSIFIED, TRANSITION_* … are not codes of
    the server path: they are left out rather than refusing the report)."""
    text = str(value or "").strip()
    return text if text == NETWORK_LOST or _CORE_CODE.fullmatch(text) else ""


_UDP_SCHEMES = frozenset({"hysteria2", "hy2", "hysteria", "tuic", "wireguard", "wg", "awg", "amneziawg"})
_UDP_TRANSPORTS = frozenset({"quic", "kcp", "mkcp", "udp"})


def carrier_of(scheme: str, transport: str | None = None, alpn: Iterable[str] = ()) -> str:
    """What the core's first hop to the server runs over: UDP for QUIC-based and WireGuard lines, mKCP and QUIC
    transports, XHTTP over HTTP/3; TCP for everything else."""
    if str(scheme or "").lower() in _UDP_SCHEMES:
        return "udp"
    kind = str(transport or "").lower()
    if kind in _UDP_TRANSPORTS:
        return "udp"
    if kind == "xhttp" and [str(item).lower() for item in alpn] == ["h3"]:
        return "udp"
    return "tcp"
