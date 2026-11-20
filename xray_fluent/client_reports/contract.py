"""The report contract, the server-id header, the attempt outcome, queue and token.

Everything here is pure and unit-tested; the same rules as the Android module
``client-reports`` (both apps must send what vpnbot ``client_reports/contract.py``
admits, because one field outside it refuses the whole batch).
"""

from __future__ import annotations

import base64
import ipaddress
import unicodedata
import binascii
import json
import os
import re
import secrets
import threading
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from . import checks as k
from .checks import Check

#: Schema 3 since 2026-11-19 (vpnbot «schema 3 live» 21:37 UTC): raw probe facts, the server judges. A queue line
#: written before (with failed_step/detail) is still sent as schema 2, which vpnbot keeps admitting.
SCHEMA = 3
LEGACY_SCHEMA = 2
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
_REPORT_ID = re.compile(r"[0-9a-f]{32}")
_RELAY_KEY = re.compile(r"[0-9a-f]{10}")
_SERVER_ID = re.compile(r"[a-z0-9_-]{1,64}")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,47}")
_VERSION = re.compile(r"[0-9A-Za-z.+-]{1,32}")
_NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_NETWORK_TOKEN = re.compile(r"[A-Za-z0-9_.-]{1,256}")
_SHORT = re.compile(r"[a-z0-9]{1,16}")
_SETTING = re.compile(r"[a-z0-9_]{1,24}")
_VERSION_VALUE = re.compile(r"[0-9A-Za-z.+_-]{1,32}")
_HOST_NAME = re.compile(r"[A-Za-z0-9.-]{1,253}")
_PSEUDO = re.compile(r"(\d+\.\d+\.\d+)-0\.\d{14}-([0-9a-f]{12})")
NETWORK_TYPES = frozenset({"wifi", "cellular", "ethernet", "other"})
MODES = frozenset({"tun", "proxy"})
VERSION_KEYS = frozenset({"os", "xray", "hysteria", "singbox", "amnezia"})
MAX_FOREIGN_NAME = 64


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
    #: «… через Россию» lines (vpnbot «via live» 2026-11-19 19:37 UTC): a neutral 10-hex key of the relay node the
    #: line dials; the report carries it so vpnbot keeps such attempts out of the target's own verdict.
    via: str = ""


def is_ip_literal(value: str) -> bool:
    """An IP literal without a zone, as the receiver takes it (``server_ip``, ``foreign.host``)."""
    if not value or "%" in value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_control_or_format(ch: str) -> bool:
    return unicodedata.category(ch) in {"Cc", "Cf", "Cs", "Cn"}


@dataclass(frozen=True, slots=True)
class ForeignServer:
    """A server outside the service's subscriptions: sent by itself, address included, and by the «Отправить отчёт»
    button (owner 2026-11-19).
    Its address and port go in the shared ``AttemptDetails.server_ip`` / ``port``."""

    host: str
    protocol: str
    name: str = ""

    @staticmethod
    def of(host: str, protocol: str, name: str) -> ForeignServer | None:
        clean_name = "".join(ch for ch in str(name or "") if not _is_control_or_format(ch)).strip()[:MAX_FOREIGN_NAME]
        candidate = ForeignServer(str(host or "").strip().strip("[]").lower(), str(protocol or "").lower(), clean_name)
        return candidate if is_valid_foreign(candidate) else None


def is_valid_foreign(foreign: ForeignServer) -> bool:
    host_ok = is_ip_literal(foreign.host) or (
        bool(_HOST_NAME.fullmatch(foreign.host)) and any(ch.isalpha() for ch in foreign.host)
    )
    return (
        host_ok and bool(_SHORT.fullmatch(foreign.protocol)) and len(foreign.name) <= MAX_FOREIGN_NAME
        and not any(_is_control_or_format(ch) for ch in foreign.name)
    )


@dataclass(frozen=True, slots=True)
class ReportSettings:
    mode: str | None = None
    dns: str | None = None
    masking: str | None = None
    quic_blocked: bool | None = None
    ipv6: bool | None = None

    def cleaned(self) -> ReportSettings | None:
        result = ReportSettings(
            mode=self.mode if self.mode in MODES else None,
            dns=self.dns if self.dns and _SETTING.fullmatch(self.dns) else None,
            masking=self.masking if self.masking and _SETTING.fullmatch(self.masking) else None,
            quic_blocked=self.quic_blocked if isinstance(self.quic_blocked, bool) else None,
            ipv6=self.ipv6 if isinstance(self.ipv6, bool) else None,
        )
        return None if result == ReportSettings() else result


@dataclass(frozen=True, slots=True)
class AttemptDetails:
    """Schema 2 details, all optional: a bad value drops out instead of losing the report (``cleaned``)."""

    server_ip: str | None = None
    port: int | None = None
    transport: str | None = None
    security: str | None = None
    network_type: str | None = None
    settings: ReportSettings | None = None
    versions: tuple[tuple[str, str], ...] = ()

    def cleaned(self) -> AttemptDetails:
        ip = (self.server_ip or "").strip().strip("[]")
        transport = (self.transport or "").lower()
        security = (self.security or "").lower()
        return AttemptDetails(
            server_ip=ip if is_ip_literal(ip) else None,
            port=self.port if isinstance(self.port, int) and not isinstance(self.port, bool) and 0 < self.port < 65536 else None,
            transport=transport if _SHORT.fullmatch(transport) else None,
            security=security if _SHORT.fullmatch(security) else None,
            network_type=self.network_type if self.network_type in NETWORK_TYPES else None,
            settings=self.settings.cleaned() if self.settings is not None else None,
            versions=tuple(sorted(
                (key, value) for key, value in self.versions
                if key in VERSION_KEYS and isinstance(value, str) and _VERSION_VALUE.fullmatch(value)
            )),
        )


def short_version(value: str | None) -> str | None:
    """``app/v2.14.0`` → ``2.14.0``, ``module@v3.1.x`` → ``3.1.x``, a Go pseudo-version → ``base-commit``."""
    if not value:
        return None
    text = str(value).strip().rsplit("@", 1)[-1].rsplit("/", 1)[-1].removeprefix("v")
    pseudo = _PSEUDO.fullmatch(text)
    if pseudo:
        text = f"{pseudo.group(1)}-{pseudo.group(2)}"
    text = text[:32]
    return text if text and _VERSION_VALUE.fullmatch(text) else None


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
    #: A foreign server instead of server_id/product (those are empty then).
    foreign: ForeignServer | None = None
    details: AttemptDetails = AttemptDetails()
    #: One attempt, one id (vpnbot «report_id live» 2026-11-19): made once when the attempt is recorded and kept in the
    #: queue, so a re-send after a lost reply is stored once. Empty for queue lines written before it (sent without).
    report_id: str = ""
    #: The relay key of a «… через Россию» line (see ServerRef.via); only with server_id, never with foreign.
    via: str = ""
    #: Schema 3: what the core's first hop ran over ("tcp"/"udp"); empty only on a schema 2 line from the queue.
    carrier: str = ""
    #: Schema 3: the core's own code (checks.core_code_of) or "".
    core_code: str = ""
    #: Schema 3: the probes that ran, in the contract's order.
    checks: tuple[tuple[str, Check], ...] = ()
    #: Schema 3 completion (vpnbot «completion live» 2026-11-19 22:16 UTC): False — the first copy, sent at once while
    #: the path check runs; True — the same report_id whole, after the check; None — a report that is final at once.
    complete: bool | None = None

    @property
    def schema(self) -> int:
        return SCHEMA if self.carrier else LEGACY_SCHEMA


def new_report_id() -> str:
    """32 lowercase hex characters from the system's random source."""
    return secrets.token_hex(16)


def is_install_id(value: str) -> bool:
    return bool(_INSTALL_ID.fullmatch(value or ""))


def is_network_token(value: str) -> bool:
    return bool(_NETWORK_TOKEN.fullmatch(value or ""))


def is_app_identity(app: AppIdentity) -> bool:
    return bool(_NAME.fullmatch(app.name) and _VERSION.fullmatch(app.version) and _NAME.fullmatch(app.platform))


def is_valid(record: AttemptRecord) -> bool:
    # Exactly one of the two: a catalogue server or a foreign one.
    ours = bool(_SERVER_ID.fullmatch(record.server_id)) and record.product in PRODUCTS
    if record.foreign is None and not ours:
        return False
    if record.foreign is not None and (record.server_id or record.product or not is_valid_foreign(record.foreign)):
        return False
    if record.details != record.details.cleaned():
        return False
    if isinstance(record.elapsed_ms, bool) or not 0 <= int(record.elapsed_ms) <= MAX_ELAPSED_MS:
        return False
    if record.attempted_at_ms <= 0:
        return False
    if record.detail and not _CODE.fullmatch(record.detail):
        return False
    if record.network_token and not is_network_token(record.network_token):
        return False
    if record.report_id and not _REPORT_ID.fullmatch(record.report_id):
        return False
    if record.via and (record.foreign is not None or not _RELAY_KEY.fullmatch(record.via)):
        return False
    if record.carrier:
        # Schema 3: no app verdict, only facts.
        return (
            record.carrier in k.CARRIERS and record.failed_step == "" and record.detail == ""
            and record.core_code == k.core_code_of(record.core_code)
            and len(record.checks) <= len(k.PROBES) and k.are_valid_checks(record.checks)
            and (record.complete is None or (isinstance(record.complete, bool) and bool(record.report_id)))
        )
    if record.core_code or record.checks or record.complete is not None:
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


def batch_json(install_id: str, app: AppIdentity, records: list[AttemptRecord], sent_via: str,
               clock_offset_ms: int = 0, sent_offsets: Mapping[str, int] | None = None) -> str:
    """The body of ``POST /v1/reports``: exactly the contract's fields. ``clock_offset_ms`` is the ingest's clock
    minus ours (:meth:`ReportClock.applied`): ``attempted_at`` goes in the ingest's time, so a PC clock running ahead
    is not refused as «in the future» (vpnbot 2026-11-20). ``sent_offsets``: the offset a report_id was already
    accepted with, so its completion copy carries the very same ``attempted_at``."""
    if not is_install_id(install_id) or not is_app_identity(app):
        raise ValueError("install_id or app")
    if sent_via not in (SENT_DIRECT, SENT_TUNNEL) or not 1 <= len(records) <= MAX_BATCH:
        raise ValueError("sent_via or batch size")
    reports = []
    for record in records:
        if not is_valid(record):
            raise ValueError("record")
        item: dict[str, object] = {
            "schema": record.schema,
            "install_id": install_id,
            "app": {"name": app.name, "version": app.version, "platform": app.platform},
        }
        if record.foreign is None:
            item["server_id"] = record.server_id
            item["product"] = record.product
            if record.via:
                item["via"] = record.via
        else:
            foreign: dict[str, str] = {"host": record.foreign.host, "protocol": record.foreign.protocol}
            if record.foreign.name:
                foreign["name"] = record.foreign.name
            item["foreign"] = foreign
        item["outcome"] = record.outcome.value
        if record.carrier:
            item["carrier"] = record.carrier
            if record.core_code:
                item["core_code"] = record.core_code
            if record.checks:
                item["checks"] = {probe: k.check_json(check) for probe, check in record.checks}
            if record.complete is not None:
                item["complete"] = record.complete
        else:
            if record.outcome is Outcome.FAILED:
                item["failed_step"] = record.failed_step
            if record.detail:
                item["detail"] = record.detail
        item["elapsed_ms"] = int(record.elapsed_ms)
        offset = (sent_offsets or {}).get(record.report_id, clock_offset_ms) if record.report_id else clock_offset_ms
        item["attempted_at"] = iso_utc(record.attempted_at_ms + int(offset))
        item["sent_via"] = sent_via
        if record.network_token:
            item["network_token"] = record.network_token
        if record.report_id:
            item["report_id"] = record.report_id
        item.update(_details_json(record.details))
        reports.append(item)
    return json.dumps({"reports": reports}, ensure_ascii=False, separators=(",", ":"))


def _details_json(details: AttemptDetails) -> dict[str, object]:
    """The optional schema 2 fields: only known values (absent = unknown)."""
    out: dict[str, object] = {}
    for key in ("server_ip", "port", "transport", "security", "network_type"):
        value = getattr(details, key)
        if value is not None:
            out[key] = value
    if details.settings is not None:
        settings = {key: getattr(details.settings, key) for key in ("mode", "dns", "masking", "quic_blocked", "ipv6")}
        out["settings"] = {key: value for key, value in settings.items() if value is not None}
    if details.versions:
        out["versions"] = dict(details.versions)
    return out


def _details_from(data: dict) -> AttemptDetails:
    settings = data.get("settings") if isinstance(data.get("settings"), dict) else None
    versions = data.get("versions") if isinstance(data.get("versions"), dict) else {}
    return AttemptDetails(
        server_ip=data.get("server_ip"), port=data.get("port"), transport=data.get("transport"),
        security=data.get("security"), network_type=data.get("network_type"),
        settings=ReportSettings(**{key: settings.get(key) for key in ("mode", "dns", "masking", "quic_blocked", "ipv6")})
        if settings else None,
        versions=tuple((str(key), value) for key, value in versions.items()),
    ).cleaned()


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
        ref = _server_id_entry(entry)
        if ref is not None:
            result[name] = ref
    return result


def _server_id_entry(entry: dict) -> ServerRef | None:
    """One header entry. A server's own line is ``{"server_id", "product"}``; a line through a
    Russian entry point is ``{"relay_of", "product", "via"}`` with no ``server_id`` (vpnbot,
    owner decision 19.11.2026), so a parser that does not know ``via`` skips it instead of
    counting the relay attempt against the target. Every other shape is skipped."""
    product = entry.get("product")
    if not isinstance(product, str) or product not in PRODUCTS:
        return None
    if "server_id" in entry:
        server_id = entry["server_id"]
        if "relay_of" in entry or "via" in entry:
            return None
        if not isinstance(server_id, str) or not _SERVER_ID.fullmatch(server_id):
            return None
        return ServerRef(server_id, product)
    target, via = entry.get("relay_of"), entry.get("via")
    if not isinstance(target, str) or not _SERVER_ID.fullmatch(target):
        return None
    if not isinstance(via, str) or not _RELAY_KEY.fullmatch(via):
        return None
    return ServerRef(target, product, via)


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


# ── the attempt as facts (schema 3) ──


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


def outcome_of(facts: AttemptFacts) -> Outcome:
    """The attempt as a fact, not a verdict (schema 3): the server judges from ``core_code`` and the checks."""
    if facts.cancelled:
        return Outcome.CANCELLED
    if facts.succeeded:
        return Outcome.CONNECTED
    return Outcome.FAILED


def attempt_core_code(facts: AttemptFacts) -> str:
    """The core code a report carries: a lost network is ``NETWORK_LOST``; other codes only in the contract's shape."""
    if facts.network_lost:
        return k.NETWORK_LOST
    return k.core_code_of(facts.core_code)


# ── the ingest's answer: vpnbot's verdict per report (schema 3) ──

MAX_VERDICT_TEXT = 300


@dataclass(frozen=True, slots=True)
class ServerVerdict:
    """What vpnbot concluded about one report; ``text`` is shown to the person as is (the app has no texts)."""

    detail: str
    level: str
    confidence: str
    text: str


def parse_reply(body: bytes | None, count: int) -> list[ServerVerdict | None]:
    """``{"verdicts": [...]}`` of a 202, in batch order; anything malformed is ``None`` (the notice falls back to its
    neutral line), never an error."""
    empty: list[ServerVerdict | None] = [None] * count
    try:
        data = json.loads((body or b"").decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return empty
    items = data.get("verdicts") if isinstance(data, dict) else None
    if not isinstance(items, list) or len(items) != count:
        return empty
    out: list[ServerVerdict | None] = []
    for item in items:
        verdict = None
        if isinstance(item, dict) and all(isinstance(item.get(key), str) for key in ("detail", "level", "confidence", "text")):
            text = "".join(ch for ch in item["text"] if not _is_control_or_format(ch)).strip()[:MAX_VERDICT_TEXT]
            if text and _CODE.fullmatch(item["detail"]):
                verdict = ServerVerdict(item["detail"], item["level"][:24], item["confidence"][:24], text)
        out.append(verdict)
    return out


# ── the device queue and the network token ──


_QUEUE_VERSION = 3


def _queue_line(record: AttemptRecord) -> str:
    line: dict[str, object] = {
        "v": _QUEUE_VERSION, "s": record.server_id, "p": record.product, "o": record.outcome.value,
        "f": record.failed_step, "d": record.detail, "e": int(record.elapsed_ms),
        "t": int(record.attempted_at_ms), "n": record.network_token,
    }
    if record.report_id:
        line["r"] = record.report_id
    if record.via:
        line["w"] = record.via
    if record.foreign is not None:
        line["g"] = {"h": record.foreign.host, "p": record.foreign.protocol, "m": record.foreign.name}
    details = _details_json(record.details)
    if details:
        line["x"] = details
    if record.carrier:
        line["c"] = record.carrier
        if record.core_code:
            line["k"] = record.core_code
        if record.checks:
            line["q"] = {probe: k.check_json(check) for probe, check in record.checks}
        if record.complete is not None:
            line["z"] = record.complete
    return json.dumps(line, ensure_ascii=True, separators=(",", ":"))


def _parse_queue_line(line: str) -> AttemptRecord | None:
    try:
        data = json.loads(line)
        # Version 1 = schema 1 lines from before 2026-11-19: read as reports without details.
        if not isinstance(data, dict) or data.get("v") not in (1, 2, _QUEUE_VERSION):
            return None
        g = data.get("g")
        foreign = ForeignServer(str(g.get("h", "")), str(g.get("p", "")), str(g.get("m", ""))) if isinstance(g, dict) else None
        record = AttemptRecord(
            server_id=str(data["s"]), product=str(data["p"]), outcome=Outcome(data["o"]),
            failed_step=str(data["f"]), detail=str(data["d"]), elapsed_ms=int(data["e"]),
            attempted_at_ms=int(data["t"]), network_token=str(data["n"]), foreign=foreign,
            details=_details_from(data["x"]) if isinstance(data.get("x"), dict) else AttemptDetails(),
            report_id=str(data.get("r") or ""),
            via=str(data.get("w") or ""),
            carrier=str(data.get("c") or ""),
            core_code=str(data.get("k") or ""),
            checks=_checks_from(data.get("q")),
            complete=data.get("z") if isinstance(data.get("z"), bool) else None,
        )
    except (ValueError, KeyError, TypeError):
        return None
    return record if is_valid(record) else None


def _checks_from(value: object) -> tuple[tuple[str, Check], ...]:
    if not isinstance(value, dict):
        return ()
    found: dict[str, Check] = {}
    for probe, item in value.items():
        if isinstance(item, dict):
            found[str(probe)] = Check(item.get("r"), item.get("ms"), item.get("b"), item.get("same"))
    # A line edited by hand with a bad probe is invalid as a whole (is_valid), not silently trimmed.
    return tuple((probe, found[probe]) for probe in found)


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
        """A record with the report_id of one still waiting replaces it (an unsent first copy gives way to its
        completion: one record per attempt)."""
        if not is_valid(record):
            return
        with self._lock:
            kept = [old for old in self._read() if not (record.report_id and old.report_id == record.report_id)]
            self._write((kept + [record])[-self._capacity:])

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


class ReportClock:
    """The ingest's clock from the ``Date`` header of its replies (vpnbot 2026-11-20: PCs whose clock runs ahead had
    whole batches refused as ``client_report_invalid_attempted_at``; the ingest takes now − 7 days … now + 10 min). The
    app's own freshness check uses the same wrong clock, so only the ingest's time can tell. An offset under
    :data:`THRESHOLD_MS` is ignored: ``Date`` has whole seconds and the reply takes a round trip. Same as Android
    ``ReportClock``."""

    THRESHOLD_MS = 60_000

    def __init__(self) -> None:
        self._offset_ms = 0

    def learn(self, server_ms: int | None, local_ms: int) -> None:
        if server_ms and server_ms > 0:
            self._offset_ms = int(server_ms) - int(local_ms)

    def applied(self) -> int:
        return self._offset_ms if abs(self._offset_ms) > self.THRESHOLD_MS else 0


def date_header_ms(value: str | None) -> int | None:
    """An HTTP ``Date`` header as epoch milliseconds, or None."""
    if not value:
        return None
    try:
        from email.utils import parsedate_to_datetime
        moment = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if moment is None or moment.tzinfo is None:
        return None
    return int(moment.timestamp() * 1000)


SPLIT_BUDGET = 16


def deliver(batch: list, send, resolved, budget: list[int] | None = None) -> SendAction | None:
    """A refused batch (400 or 413) is never dropped with its good reports (vpnbot 2026-11-20: the ingest validates the
    whole batch and names no index). ``send(part)`` says what happened to one batch; a refused one is split in halves
    until the refused reports stand alone, and only those are dropped. ``resolved(part, action)`` gets every part that
    is done (accepted or refused alone). None when the whole batch is done, else the action that stopped the rest.
    The split makes at most :data:`SPLIT_BUDGET` extra requests; past it the refused part is dropped whole. Same as
    Android ``BatchDelivery``."""
    budget = [SPLIT_BUDGET] if budget is None else budget
    action = send(batch)
    if action is SendAction.REMOVE or (action is SendAction.DROP and (len(batch) == 1 or budget[0] < 2)):
        resolved(batch, action)
        return None
    if action is not SendAction.DROP:
        return action
    budget[0] -= 2
    half = len(batch) // 2
    for part in (batch[:half], batch[half:]):
        stopped = deliver(part, send, resolved, budget)
        if stopped is not None:
            return stopped
    return None


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
