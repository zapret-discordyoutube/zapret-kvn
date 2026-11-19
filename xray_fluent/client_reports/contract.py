"""The report contract, the server-id header, the attempt classifier, queue and token.

Everything here is pure and unit-tested; the same rules as the Android module
``client-reports`` (both apps must send what vpnbot ``client_reports/contract.py``
admits, because one field outside it refuses the whole batch).
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import threading
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

SCHEMA = 1
MAX_BATCH = 50
MAX_ELAPSED_MS = 600_000
MAX_AGE_MS = 7 * 24 * 3600 * 1000
# A queued report is sent while the ingest still takes it: a margin for the trip and its clock.
_FRESHNESS_MARGIN_MS = 3600 * 1000
_CLOCK_AHEAD_MS = 5 * 60 * 1000

#: vpnbot catalogue products (protocol_ports/<product>/catalogue.py).
PRODUCTS = frozenset({"awg", "hysteria2", "mtproto", "vless", "wireguard"})
#: vpnbot_contracts.observer_probe.TARGET_STEPS, in the order a client walks them.
STEPS = ("resolve", "connect", "handshake", "auth", "tunnel", "request")
SENT_DIRECT = "direct"
SENT_TUNNEL = "tunnel"

SERVER_IDS_HEADER = "zapret-server-ids"
MAX_HEADER_CHARS = 16 * 1024
#: The inflated map is refused above this: ~1000 servers are ~110 KB of JSON.
MAX_INFLATED_BYTES = 512 * 1024

_INSTALL_ID = re.compile(r"[0-9a-f]{32}")
_SERVER_ID = re.compile(r"[a-z0-9_-]{1,64}")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,47}")
_VERSION = re.compile(r"[0-9A-Za-z.+-]{1,32}")
_NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_NETWORK_TOKEN = re.compile(r"[A-Za-z0-9_.-]{1,256}")


class Outcome(str, Enum):
    CONNECTED = "connected"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class AppIdentity:
    name: str
    version: str
    platform: str


@dataclass(frozen=True, slots=True)
class ServerRef:
    server_id: str
    product: str


@dataclass(frozen=True, slots=True)
class AttemptRecord:
    """One attempt in the device queue; install id and ``sent_via`` are added when sent."""

    server_id: str
    product: str
    outcome: Outcome
    failed_step: str
    detail: str
    elapsed_ms: int
    attempted_at_ms: int
    network_token: str


def is_install_id(value: str) -> bool:
    return bool(_INSTALL_ID.fullmatch(value or ""))


def is_network_token(value: str) -> bool:
    return bool(_NETWORK_TOKEN.fullmatch(value or ""))


def is_app_identity(app: AppIdentity) -> bool:
    return bool(_NAME.fullmatch(app.name) and _VERSION.fullmatch(app.version) and _NAME.fullmatch(app.platform))


def is_valid(record: AttemptRecord) -> bool:
    if not _SERVER_ID.fullmatch(record.server_id) or record.product not in PRODUCTS:
        return False
    if isinstance(record.elapsed_ms, bool) or not 0 <= int(record.elapsed_ms) <= MAX_ELAPSED_MS:
        return False
    if record.attempted_at_ms <= 0:
        return False
    if record.detail and not _CODE.fullmatch(record.detail):
        return False
    if record.network_token and not is_network_token(record.network_token):
        return False
    if record.outcome is Outcome.FAILED:
        return record.failed_step in STEPS
    return record.failed_step == ""


def is_fresh(record: AttemptRecord, now_ms: int) -> bool:
    return (
        now_ms - record.attempted_at_ms < MAX_AGE_MS - _FRESHNESS_MARGIN_MS
        and record.attempted_at_ms - now_ms < _CLOCK_AHEAD_MS
    )


def iso_utc(epoch_ms: int) -> str:
    """``2026-11-19T12:34:56Z``: ISO-8601 with a zone, whole seconds."""
    return datetime.fromtimestamp(epoch_ms // 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def batch_json(install_id: str, app: AppIdentity, records: list[AttemptRecord], sent_via: str) -> str:
    """The body of ``POST /v1/reports``: exactly the contract's fields."""
    if not is_install_id(install_id) or not is_app_identity(app):
        raise ValueError("install_id or app")
    if sent_via not in (SENT_DIRECT, SENT_TUNNEL) or not 1 <= len(records) <= MAX_BATCH:
        raise ValueError("sent_via or batch size")
    reports = []
    for record in records:
        if not is_valid(record):
            raise ValueError("record")
        item: dict[str, object] = {
            "schema": SCHEMA,
            "install_id": install_id,
            "app": {"name": app.name, "version": app.version, "platform": app.platform},
            "server_id": record.server_id,
            "product": record.product,
            "outcome": record.outcome.value,
        }
        if record.outcome is Outcome.FAILED:
            item["failed_step"] = record.failed_step
        if record.detail:
            item["detail"] = record.detail
        item["elapsed_ms"] = int(record.elapsed_ms)
        item["attempted_at"] = iso_utc(record.attempted_at_ms)
        item["sent_via"] = sent_via
        if record.network_token:
            item["network_token"] = record.network_token
        reports.append(item)
    return json.dumps({"reports": reports}, ensure_ascii=False, separators=(",", ":"))


# ── the server-id header ──


def parse_server_ids(value: str | None) -> dict[str, ServerRef]:
    """``zapret-server-ids``: unpadded base64url of zlib (RFC 1950) JSON ``{"<link name>": {"server_id", "product"}}``.

    zlib since 19.11.2026 (vpnbot, owner confirmed): a large VLESS map is ~111 KB uncompressed,
    the server keeps the value at or below 14 336 chars.

    Entries outside the contract are skipped; a malformed value gives no map. The id
    is never guessed from the name: a server without an entry is not reported.
    """
    raw = str(value or "").strip()
    if not raw or len(raw) > MAX_HEADER_CHARS:
        return {}
    try:
        compressed = base64.urlsafe_b64decode(raw.rstrip("=") + "=" * (-len(raw.rstrip("=")) % 4))
        inflater = zlib.decompressobj()
        data = inflater.decompress(compressed, MAX_INFLATED_BYTES + 1)
        if len(data) > MAX_INFLATED_BYTES or inflater.unconsumed_tail or not inflater.eof:
            return {}
        root = json.loads(data.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError, zlib.error):
        return {}
    if not isinstance(root, dict):
        return {}
    result: dict[str, ServerRef] = {}
    for name, entry in root.items():
        if not isinstance(name, str) or not name.strip() or not isinstance(entry, dict):
            continue
        server_id, product = entry.get("server_id"), entry.get("product")
        if not isinstance(server_id, str) or not _SERVER_ID.fullmatch(server_id):
            continue
        if not isinstance(product, str) or product not in PRODUCTS:
            continue
        result[name] = ServerRef(server_id, product)
    return result


def products_for_scheme(scheme: str | None) -> frozenset[str]:
    """Catalogue products a node of this link scheme can be (one name may exist in two products)."""
    value = str(scheme or "").strip().lower()
    # The VLESS product's subscription also carries Trojan/Shadowsocks/VMess lines: product vless.
    if value in {"vless", "trojan", "ss", "shadowsocks", "vmess"}:
        return frozenset({"vless"})
    if value in {"hysteria2", "hy2"}:
        return frozenset({"hysteria2"})
    if value in {"wireguard", "awg", "amneziawg", "wg"}:
        return frozenset({"wireguard", "awg"})
    return frozenset()


# ── the attempt classifier ──


@dataclass(frozen=True, slots=True)
class AttemptFacts:
    cancelled: bool = False
    succeeded: bool = False
    #: Failure code of the native core for this server (runtime_contract.HysteriaFailureCode names).
    core_code: str | None = None
    network_lost: bool = False
    #: No traffic passed the server: the functional HTTPS probe through it failed.
    traffic_failed: bool = False
    tcp_preflight_failed: bool = False
    udp_transport: bool = False


@dataclass(frozen=True, slots=True)
class AttemptVerdict:
    outcome: Outcome
    failed_step: str
    detail: str


def _failed(step: str, detail: str) -> AttemptVerdict:
    return AttemptVerdict(Outcome.FAILED, step, detail)


def classify(facts: AttemptFacts) -> AttemptVerdict | None:
    """The attempt on vpnbot's ladder; ``None`` when the failure is not about the server."""
    if facts.cancelled:
        return AttemptVerdict(Outcome.CANCELLED, "", "cancelled")
    if facts.succeeded:
        return AttemptVerdict(Outcome.CONNECTED, "", "")
    if facts.network_lost:
        return None
    code = facts.core_code
    if code:
        if code.startswith("LOCAL_"):
            return None
        verdict = _by_core_code(code, facts)
        if verdict is not None:
            return verdict
    if not facts.traffic_failed:
        return None
    if not facts.udp_transport and facts.tcp_preflight_failed:
        return _failed("connect", "tcp_timeout")
    return _failed("request", "no_response")


def _by_core_code(code: str, facts: AttemptFacts) -> AttemptVerdict | None:
    if code == "TARGET_AUTH_REJECTED":
        return _failed("auth", "auth_rejected")
    if code in {"TARGET_TLS_REJECTED", "TARGET_TLS_INTERNAL", "TARGET_TLS_UNKNOWN_AUTHORITY", "TARGET_PIN_MISMATCH"}:
        return _failed("handshake", "tls_failed")
    if code == "TARGET_OBFS_REJECTED":
        return _failed("handshake", "obfs_rejected")
    if code == "TARGET_CONNECTION_REFUSED":
        return _failed("connect", "connection_refused")
    if code == "TARGET_CONNECTION_CLOSED":
        return _failed("handshake", "connection_closed")
    if code == "TARGET_NETWORK_TIMEOUT":
        if facts.udp_transport:
            return _failed("handshake", "udp_no_answer")
        if facts.tcp_preflight_failed:
            return _failed("connect", "tcp_timeout")
        return _failed("handshake", "handshake_timeout")
    if code == "TARGET_DESTINATION_UNREACHABLE":
        return _failed("request", "destination_unreachable")
    return None


# ── the device queue and the network token ──


def _queue_line(record: AttemptRecord) -> str:
    return json.dumps({
        "v": 1, "s": record.server_id, "p": record.product, "o": record.outcome.value,
        "f": record.failed_step, "d": record.detail, "e": int(record.elapsed_ms),
        "t": int(record.attempted_at_ms), "n": record.network_token,
    }, ensure_ascii=True, separators=(",", ":"))


def _parse_queue_line(line: str) -> AttemptRecord | None:
    try:
        data = json.loads(line)
        if not isinstance(data, dict) or data.get("v") != 1:
            return None
        record = AttemptRecord(
            server_id=str(data["s"]), product=str(data["p"]), outcome=Outcome(data["o"]),
            failed_step=str(data["f"]), detail=str(data["d"]), elapsed_ms=int(data["e"]),
            attempted_at_ms=int(data["t"]), network_token=str(data["n"]),
        )
    except (ValueError, KeyError, TypeError):
        return None
    return record if is_valid(record) else None


def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(text, encoding="utf-8")
    os.replace(temp, path)


class ReportQueue:
    """JSON line per attempt, written whole; at most ``capacity`` records, a week at most."""

    DEFAULT_CAPACITY = 500

    def __init__(self, path: Path, capacity: int = DEFAULT_CAPACITY) -> None:
        self._path = Path(path)
        self._capacity = capacity
        self._lock = threading.Lock()

    def add(self, record: AttemptRecord) -> None:
        if not is_valid(record):
            return
        with self._lock:
            self._write((self._read() + [record])[-self._capacity:])

    def pending(self, now_ms: int) -> list[AttemptRecord]:
        with self._lock:
            records = self._read()
            fresh = [record for record in records if is_fresh(record, now_ms)]
            if len(fresh) != len(records):
                self._write(fresh)
            return fresh

    def remove(self, sent: list[AttemptRecord]) -> None:
        if not sent:
            return
        with self._lock:
            left = self._read()
            for record in sent:
                if record in left:
                    left.remove(record)
            self._write(left)

    def size(self) -> int:
        with self._lock:
            return len(self._read())

    def _read(self) -> list[AttemptRecord]:
        try:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        return [record for record in (_parse_queue_line(line) for line in lines if line.strip()) if record]

    def _write(self, records: list[AttemptRecord]) -> None:
        if not records:
            self._path.unlink(missing_ok=True)
            return
        _write_atomic(self._path, "".join(_queue_line(record) + "\n" for record in records))


@dataclass(frozen=True, slots=True)
class NetworkToken:
    value: str
    obtained_at_ms: int


class NetworkTokenCache:
    """The token of ``GET /v1/network``: the network the ingest saw, signed for this install.

    Windows has no stable handle of the physical network that survives a move between
    networks, so a token is trusted only for a short while: an attempt is reported with a
    token obtained close to it (``usable_ms``), and a new one is asked when it is older
    than ``refresh_after_ms``.
    """

    def __init__(self, path: Path, *, usable_ms: int = 2 * 3600 * 1000, refresh_after_ms: int = 3600 * 1000) -> None:
        self._path = Path(path)
        self._usable_ms = usable_ms
        self._refresh_after_ms = refresh_after_ms
        self._lock = threading.Lock()
        self._cached: NetworkToken | None = None
        self._loaded = False

    def current(self, now_ms: int) -> str:
        with self._lock:
            token = self._load()
            if token is None or not 0 <= now_ms - token.obtained_at_ms < self._usable_ms:
                return ""
            return token.value

    def needs_refresh(self, now_ms: int) -> bool:
        with self._lock:
            token = self._load()
            return token is None or not 0 <= now_ms - token.obtained_at_ms < self._refresh_after_ms

    def store(self, token: NetworkToken) -> None:
        if not is_network_token(token.value):
            return
        with self._lock:
            self._cached, self._loaded = token, True
            _write_atomic(self._path, f"{token.obtained_at_ms}\n{token.value}\n")

    def _load(self) -> NetworkToken | None:
        if not self._loaded:
            self._loaded = True
            try:
                lines = self._path.read_text(encoding="utf-8").splitlines()
                token = NetworkToken(lines[1], int(lines[0]))
                self._cached = token if is_network_token(token.value) else None
            except (OSError, ValueError, IndexError):
                self._cached = None
        return self._cached


class SendAction(str, Enum):
    REMOVE = "remove"          # accepted (202)
    DROP = "drop"              # refused by the contract (400, 413): a retry gives the same
    KEEP_AND_STOP = "keep"     # rate limit or ingest failure: keep, wait for the next report
    TRY_OTHER_PATH = "other"   # no answer: keep and try the other path


def after_response(status: int | None) -> SendAction:
    if status is None:
        return SendAction.TRY_OTHER_PATH
    if status in (200, 202):
        return SendAction.REMOVE
    if status in (400, 413):
        return SendAction.DROP
    return SendAction.KEEP_AND_STOP





# ── ingest names (owner 2026-11-19) ──
#
# reports.zapret.moe is usually cut in Russia (the zone zapret.moe is filtered by SNI), so the ingest is also
# served under random names of the zapret-links pool (service ``reports``: a bridge to the same ingest, which
# still sees the sender's network). The names come from the shared zapret-links feed: ``services.reports.hosts``
# of its entry pages (script.google.com and the GitHub gist, both serve targets.json verbatim). The app keeps only
# a fixed seed: pool names are never removed (zapret-links only stops handing them out), so the names of the
# release day stay a working reserve. Same rules as Android ``IngestHosts``.

INGEST_FIXED = "reports.zapret.moe"
INGEST_SEED = ("oeifnxndqq.fuckingspeedtest.com", "wkjjjdcycb.osjcpjzipyb.click", INGEST_FIXED)
INGEST_FEEDS = (
    "https://script.google.com/macros/s/AKfycbzcEPk67WW6fYC0vPVm397QyDFHd4m-SrfKDBnfvG8jAD-n_HXVv8AqQnEHZ6A42oIh/exec?format=json",
    "https://gist.githubusercontent.com/fuckyourkn/ecb9b6a03f53bddcdd47023ebc12d4f9/raw/targets.json",
)
MAX_FEED_BYTES = 64 * 1024
MAX_INGEST_HOSTS = 8
TRIES_PER_PATH = 4
# One request body. The TSPU freezes a TCP connection to part of the foreign networks after ~25 packets both ways
# (~16 KB), counted per connection: a TLS handshake with a certificate is ~6-8 packets, 8 KB of body ~6, the answer
# 1-2, so one request stays near 15 packets, and every batch goes on its own new connection.
MAX_BODY_BYTES = 8 * 1024
FAILED_FOR_MS = 30 * 60 * 1000
FEED_MAX_AGE_MS = 24 * 3600 * 1000
FEED_RETRY_AFTER_MS = 3600 * 1000

_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")


def domain_of(host: str) -> str:
    return host.split(".", 1)[1] if "." in host else host


def is_host_name(host: str) -> bool:
    return len(host) <= 253 and _HOST.fullmatch(host) is not None


def parse_ingest_feed(text: str | bytes) -> list[str]:
    """``services.reports.hosts`` of an entry page or links.json; a name only under ``domains`` of the same document
    (without it, under a seed domain), at most ``MAX_INGEST_HOSTS``. A broken document gives nothing."""
    try:
        document = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(document, dict):
        return []
    raw_domains = document.get("domains")
    domains = [d.lower() for d in raw_domains if isinstance(d, str)] if isinstance(raw_domains, list) else []
    if not domains:
        domains = [domain_of(h) for h in INGEST_SEED]
    services = document.get("services")
    reports = services.get("reports") if isinstance(services, dict) else None
    hosts = reports.get("hosts") if isinstance(reports, dict) else None
    if not isinstance(hosts, list):
        return []
    out: list[str] = []
    for item in hosts:
        if not isinstance(item, str):
            continue
        host = item.strip().lower()
        if is_host_name(host) and any(host.endswith("." + d) for d in domains) and host not in out:
            out.append(host)
        if len(out) >= MAX_INGEST_HOSTS:
            break
    return out


def ingest_order(learned: list[str], failed: set[str] | frozenset[str], rng: Any) -> list[str]:
    """The names for one send: the feed's and the seed, shuffled, alternating domains; ``failed`` (recently silent)
    at the end, the cut ``INGEST_FIXED`` last of the working ones. ``rng`` is a ``random.Random``-like object."""
    every = list(dict.fromkeys([*learned, *INGEST_SEED]))
    fresh = [h for h in every if h not in failed]
    pool = [h for h in fresh if h != INGEST_FIXED]
    rng.shuffle(pool)
    groups: dict[str, list[str]] = {}
    for host in pool:
        groups.setdefault(domain_of(host), []).append(host)
    interleaved: list[str] = []
    queues = list(groups.values())
    while any(queues):
        for queue in queues:
            if queue:
                interleaved.append(queue.pop(0))
    return interleaved + [h for h in fresh if h == INGEST_FIXED] + [h for h in every if h in failed]


def take_batch(records: list[Any], max_count: int, max_bytes: int, body_bytes: Callable[[list[Any]], int]) -> list[Any]:
    """The head of the queue: consecutive records while the body is at most ``max_bytes`` and the count at most
    ``max_count``; one record always goes (it is under a kilobyte)."""
    size = 0
    for count in range(1, min(max_count, len(records)) + 1):
        if count > 1 and body_bytes(records[:count]) > max_bytes:
            break
        size = count
    return records[:size]


class IngestHostCache:
    """The ingest names learnt from the feed and when. The feed is asked on an event (a send), never by a timer:
    when the names are older than a day or none answered, at most once an hour."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._loaded = False
        self._hosts: list[str] = []
        self._fetched_at_ms = 0
        self._last_attempt_ms: int | None = None

    def hosts(self) -> list[str]:
        with self._lock:
            self._load()
            return list(self._hosts)

    def feed_due(self, now_ms: int, *, nothing_answered: bool) -> bool:
        with self._lock:
            self._load()
            if self._last_attempt_ms is not None and 0 <= now_ms - self._last_attempt_ms < FEED_RETRY_AFTER_MS:
                return False
            return nothing_answered or not self._hosts or not 0 <= now_ms - self._fetched_at_ms < FEED_MAX_AGE_MS

    def note_feed_attempt(self, now_ms: int) -> None:
        with self._lock:
            self._last_attempt_ms = now_ms

    def store(self, learned: list[str], now_ms: int) -> None:
        if not learned:
            return
        with self._lock:
            self._load()
            self._hosts = list(learned[:MAX_INGEST_HOSTS])
            self._fetched_at_ms = int(now_ms)
            _write_atomic(self._path, "\n".join([str(int(now_ms)), *self._hosts]) + "\n")

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            lines = [line.strip() for line in self._path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self._fetched_at_ms = int(lines[0])
            # The domains were checked against the feed's ``domains`` when stored; here only the shape.
            self._hosts = list(dict.fromkeys(h.lower() for h in lines[1:] if is_host_name(h.lower())))[:MAX_INGEST_HOSTS]
        except (OSError, ValueError, IndexError):
            self._hosts, self._fetched_at_ms = [], 0
