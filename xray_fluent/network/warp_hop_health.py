"""What the real core says about the WARP entry hop, counted per connect (owner request 2026-11-26: more logs).

The hop's tunnel needs a few seconds after the connect, and on a network that blocks the WARP UDP ports it never comes
up: the core then answers every connection with `endpoint not initialized`.  Reports from such a network held only
those lines and no explanation.  This class reads the core's own lines about the hop (pure, no Qt), keeps the counts,
and says once, in plain words, when the tunnel is clearly not coming up.  Addresses never leave a line: only ports and
counts are kept.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

HOP = "kvn-warp-entry"
API = "kvn-warp-api"

_RETRY = re.compile(r"endpoint/warp\[" + HOP + r"\]: WARP handshake did not answer at \S*?:(\d+), trying")
_NOT_READY = "using outbound/warp[" + HOP + "]: endpoint not initialized"
_LOOKUP = re.compile(r"using outbound/warp\[" + HOP + r"\]: lookup .*deadline exceeded")
_REGISTRATION = re.compile(r"endpoint/warp\[" + HOP + r"\]: Post ")
# A MASQUE candidate that stayed silent: the rotation of a running tunnel says "WARP candidate masque-x did not answer", the
# start of a tunnel that never answered says "WARP handshake did not answer at masque-x" (real captures of both forms).
_CANDIDATE_FAILED = re.compile(
    r"endpoint/warp\[" + HOP + r"\]: (?:WARP candidate masque-\S+(?: sni=\S+)? did not answer"
    r"|WARP handshake did not answer at masque-\S+(?: sni=\S+)?, trying)"
)
_ANSWERED = re.compile(r"endpoint/warp\[" + HOP + r"\]: WARP tunnel answered at \S*?:(\d+) \(attempt (\d+)\)")

#: Enough evidence to tell the user: the tunnel is not coming up (not just slow).
NOT_READY_LIMIT = 5
#: The start recovery (core patch warp-entry-recovery) tries four candidates, 4 s each: only after four unanswered
#: handshakes is the tunnel given up (a start that needs two or three retries is slow, not blocked).
RETRY_LIMIT = 4
LOOKUP_LIMIT = 3
TUNNEL_DOWN = (
    "Вход через WARP не поднимается: туннель WARP не отвечает. Возможно, сеть блокирует UDP-порты WARP "
    "(2408, 500, 1701, 4500). Выключите вход через WARP или смените сеть."
)
LOOKUP_STUCK = (
    "Вход через WARP: не удаётся определить адрес сервера. Выключите вход через WARP или выберите другой сервер."
)


@dataclass
class HopHealth:
    """Counts of what the core said about the hop since this connect."""

    handshake_retries: int = 0
    ports_tried: list[int] = field(default_factory=list)
    not_initialized: int = 0
    lookup_timeouts: int = 0
    registration_errors: int = 0
    candidates_failed: int = 0
    _told: set[str] = field(default_factory=set)

    def observe(self, line: str) -> str | None:
        """Count one core line; returns a message for the user the first time a limit is crossed."""
        if HOP not in line and API not in line:
            return None
        retry = _RETRY.search(line)
        if retry:
            self.handshake_retries += 1
            port = int(retry.group(1))
            if port not in self.ports_tried:
                self.ports_tried.append(port)
        elif _NOT_READY in line:
            self.not_initialized += 1
        elif _LOOKUP.search(line):
            self.lookup_timeouts += 1
        elif _REGISTRATION.search(line):
            self.registration_errors += 1
        elif _CANDIDATE_FAILED.search(line):
            self.candidates_failed += 1
            return None
        else:
            return None
        if (self.not_initialized >= NOT_READY_LIMIT or self.handshake_retries >= RETRY_LIMIT) and "down" not in self._told:
            self._told.add("down")
            return TUNNEL_DOWN
        if self.lookup_timeouts >= LOOKUP_LIMIT and "lookup" not in self._told:
            self._told.add("lookup")
            return LOOKUP_STUCK
        return None

    def timeline(self, line: str, seconds: float) -> str | None:
        """A log line for the core's own words about the start of the tunnel, with the seconds since the connect.

        Owner request 2026-11-26 ("taking too long, improve the logs", the same as on Android): a slow start must say
        when each address was given up and when the tunnel answered.  Ports only, never addresses."""
        if HOP not in line:
            return None
        retry = _RETRY.search(line)
        if retry:
            return (
                f"рукопожатие WARP не ответило на порту {retry.group(1)}, пробуется следующий адрес "
                f"({seconds:.0f} с после подключения)"
            )
        answered = _ANSWERED.search(line)
        if answered:
            return (
                f"туннель WARP ответил на порту {answered.group(1)}, попытка {answered.group(2)} "
                f"({seconds:.0f} с после подключения)"
            )
        return None

    def summary(self, seconds: int) -> str:
        ports = ",".join(str(port) for port in self.ports_tried) or "-"
        return (
            f"[warp-entry] итог за {seconds} с после подключения: повторов рукопожатия={self.handshake_retries} "
            f"(порты {ports}), отказов «endpoint not initialized»={self.not_initialized}, "
            f"таймаутов поиска адреса={self.lookup_timeouts}, ошибок регистрации={self.registration_errors}"
        )


@dataclass(frozen=True)
class WarpFacts:
    """What the connect report needs to know about the WARP hop (read-only, the reports module wires to this).

    `register` and `tunnel` are `(result, ms)` with `result` one of answered/timeout/reset/refused/unknown (the probe
    vocabulary of the report contract), or None when nothing ran or the hop was off: then no probe is sent at all."""

    enabled: bool
    register: tuple[str, int] | None
    retries: int | None
    tunnel: tuple[str, int] | None


def registration_result(ok: bool, detail: str) -> str:
    """The probe vocabulary word for how the app's own account registration ended."""
    if ok:
        return "answered"
    lowered = detail.lower()
    if "reset" in lowered or "forcibly closed" in lowered or "eof" in lowered:
        return "reset"
    if "refused" in lowered:
        return "refused"
    if "timeout" in lowered or "timed out" in lowered:
        return "timeout"
    return "unknown"


def tunnel_result(health: HopHealth) -> str:
    """The first seconds of the tunnel: refusals or unanswered handshakes mean it is not coming up."""
    if health.not_initialized > 0 or health.handshake_retries >= RETRY_LIMIT:
        return "timeout"
    return "answered"


#: A plain HTTP page that answers 204 to anyone: the same kind of address the apps already use for connectivity checks.
PROBE_URL = "http://cp.cloudflare.com/generate_204"


def traffic_passes_through(port: int, *, timeout: float = 8.0) -> bool:
    """One real request through the app's local HTTP proxy: does traffic cross the connection (and so the hop) at all?

    The request leaves through the VPN server like any page the user opens, so a provider sees nothing it does not see
    already.  Used by the controller to give a dead WARP entry up (owner 2026-11-27): the core's own lines differ by the
    way the network blocks (silence, resets, refused sockets), real traffic does not."""
    import urllib.request

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"}))
    try:
        with opener.open(PROBE_URL, timeout=timeout) as reply:
            return 200 <= reply.status < 400
    except Exception:  # noqa: BLE001 - any failure means "nothing crossed"
        return False
