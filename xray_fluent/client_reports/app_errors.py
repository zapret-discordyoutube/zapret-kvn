"""App errors not about any server (vpnbot «app_error live» 2026-11-20, owner's decision).

A code from a closed set of steps, how often it happened and, for a crash, only the frames — never a message, a path,
an address or a URL (a Windows traceback holds ``C:\\Users\\<name>``; frames keep only ``module.function:line`` relative
to the package). vpnbot groups crashes itself (code + frames without lines); the app sends no hash. Same as Android
``client-reports/AppErrors.kt``.
"""

from __future__ import annotations

import json
import os
import re
import threading
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import TracebackType

from .contract import (
    MAX_AGE_MS,
    AttemptDetails,
    _details_from,
    _details_json,
    iso_utc,
    is_network_token,
    new_report_id,
)

KIND = "app_error"
SCHEMA = 1
STEP_START = "start"
STEP_SUBSCRIPTION = "subscription"
STEP_UPDATE = "update"
STEP_PERMISSION = "permission"
STEP_CRASH = "crash"
STEP_STORAGE = "storage"
STEPS = frozenset({STEP_START, STEP_SUBSCRIPTION, STEP_UPDATE, STEP_PERMISSION, STEP_CRASH, STEP_STORAGE})
ROUTES = frozenset({"direct", "proxy", "tunnel"})
MAX_COUNT = 100_000
MAX_FRAMES = 16
#: One send per code and app version a day: a broken install does not flood (the rest is counted).
SEND_EVERY_MS = 24 * 3600 * 1000
MAX_PENDING = 32
_FRESHNESS_MARGIN_MS = 3600 * 1000

_CODE = re.compile(r"^[a-z]{1,16}:[A-Za-z0-9_.-]{1,64}$")
_FRAME = re.compile(r"^[A-Za-z0-9_$.<>-]{1,72}:[0-9]{1,6}$")
_REPORT_ID = re.compile(r"^[0-9a-f]{32}$")
_CODE_VALUE_BAD = re.compile(r"[^A-Za-z0-9_.-]")
_FRAME_NAME_BAD = re.compile(r"[^A-Za-z0-9_$.<>-]")
_PACKAGES = ("xray_fluent", "zapret_update")


@dataclass(frozen=True, slots=True)
class SubscriptionFact:
    """Only with step ``subscription``: whether it is our service's subscription and which way it was fetched."""

    ours: bool
    route: str


@dataclass(frozen=True, slots=True)
class AppError:
    step: str
    code: str
    frames: tuple[str, ...] = ()
    subscription: SubscriptionFact | None = None


@dataclass(frozen=True, slots=True)
class AppErrorRecord:
    report_id: str
    error: AppError
    count: int
    occurred_at_ms: int
    app_version: str
    network_token: str = ""
    details: AttemptDetails = field(default_factory=AttemptDetails)


def code(prefix: str, value: str) -> str | None:
    """``prefix:value`` in the contract's shape; the value's other characters become ``_``."""
    cleaned = _CODE_VALUE_BAD.sub("_", str(value or "").strip())[:64]
    text = f"{prefix}:{cleaned}"
    return text if _CODE.match(text) else None


def frame(name: str, line: int | None) -> str | None:
    """``name:line``: only allowed characters (the tail when too long), an unknown line is 0."""
    cleaned = _FRAME_NAME_BAD.sub("_", str(name or ""))[-72:].lstrip(".")
    if not cleaned:
        return None
    text = f"{cleaned}:{max(0, min(int(line or 0), 999_999))}"
    return text if _FRAME.match(text) else None


def module_of(filename: str) -> str:
    """A source file as a module name relative to the app's package, never a drive, a user dir or a path:
    ``…\\xray_fluent\\application\\controller.py`` → ``xray_fluent.application.controller``; anything else → its stem."""
    parts = [part for part in re.split(r"[\\/]+", str(filename or "")) if part]
    if not parts:
        return "unknown"
    stem = parts[-1].rsplit(".", 1)[0] if parts[-1].endswith((".py", ".pyc", ".pyw")) else parts[-1]
    for index, part in enumerate(parts[:-1]):
        if part in _PACKAGES:
            return ".".join([*parts[index:-1], stem])
    return stem


def frames_of(tb: TracebackType | None) -> tuple[str, ...]:
    """A traceback's frames, innermost first: ``module.function:line``."""
    if tb is None:
        return ()
    found: list[str] = []
    for summary in reversed(traceback.extract_tb(tb)):
        item = frame(f"{module_of(summary.filename)}.{summary.name}", summary.lineno)
        if item is not None:
            found.append(item)
        if len(found) == MAX_FRAMES:
            break
    return tuple(found)


def crash_of(exc_type: type[BaseException], tb: TracebackType | None) -> AppError | None:
    found = code("crash", getattr(exc_type, "__name__", "Exception"))
    return AppError(STEP_CRASH, found, frames_of(tb)) if found else None


def start_error_of(error: BaseException | None) -> AppError:
    """A start that failed before any server was chosen: the core's own code (``runtime-errors.json``), ``port:bind``
    for a local port conflict; the text itself is only classified here, never sent."""
    if error is None:
        return AppError(STEP_START, "start:failed")
    try:
        from ..diagnostics.runtime_errors import classify_core_error

        found = classify_core_error(str(error))[0]
    except Exception:
        found = "CORE_UNCLASSIFIED"
    if found == "LOCAL_BIND_COLLISION":
        return AppError(STEP_START, "port:bind")
    return AppError(STEP_START, code("start", found) or "start:failed")


def subscription_error_of(status: int | None, error: BaseException | None, ours: bool, route: str) -> AppError | None:
    """A subscription that could not be fetched: the HTTP class when the server answered, else the transport error."""
    if status is not None:
        value = "http_4xx" if 400 <= status <= 499 else "http_5xx" if 500 <= status <= 599 else "http_other"
    else:
        value = transport_of(error)
    found = code("sub", value)
    if found is None:
        return None
    return AppError(STEP_SUBSCRIPTION, found, subscription=SubscriptionFact(bool(ours), route if route in ROUTES else "direct"))


def transport_of(error: BaseException | None) -> str:
    import socket
    import ssl

    chain: list[BaseException] = []
    current = error
    while current is not None and len(chain) < 8:
        chain.append(current)
        current = current.__cause__ or current.__context__
    text = " ".join(str(item) for item in chain).lower()
    if any(isinstance(item, (socket.timeout, TimeoutError)) for item in chain) or "timed out" in text:
        return "timeout"
    if any(isinstance(item, socket.gaierror) for item in chain) or "getaddrinfo" in text or "name or service" in text:
        return "dns"
    if any(isinstance(item, ssl.SSLError) for item in chain) or "certificate" in text or "ssl" in text:
        return "tls"
    if any(isinstance(item, ConnectionRefusedError) for item in chain) or "refused" in text:
        return "refused"
    if any(isinstance(item, (ConnectionResetError, ConnectionAbortedError)) for item in chain) or "reset" in text:
        return "reset"
    if any(isinstance(item, OSError) for item in chain):
        return "unreachable"
    return "other"


def is_valid(error: AppError) -> bool:
    return (
        error.step in STEPS and bool(_CODE.match(error.code)) and len(error.frames) <= MAX_FRAMES
        and all(_FRAME.match(item) for item in error.frames)
        and (error.subscription is None or (error.step == STEP_SUBSCRIPTION and error.subscription.route in ROUTES))
    )


def common(details: AttemptDetails) -> AttemptDetails:
    """Only what app errors carry: network type, settings, versions (never an address or a port)."""
    return AttemptDetails(network_type=details.network_type, settings=details.settings, versions=details.versions).cleaned()


def record_json(install_id: str, app_name: str, platform: str, record: AppErrorRecord, sent_via: str,
                clock_offset_ms: int = 0) -> dict[str, object]:
    """The record of the batch body: exactly the contract's fields, ``occurred_at`` in the ingest's time."""
    item: dict[str, object] = {
        "kind": KIND,
        "schema": SCHEMA,
        "install_id": install_id,
        "report_id": record.report_id,
        "app": {"name": app_name, "version": record.app_version, "platform": platform},
        "step": record.error.step,
        "code": record.error.code,
        "count": max(1, min(int(record.count), MAX_COUNT)),
        "occurred_at": iso_utc(record.occurred_at_ms + int(clock_offset_ms)),
        "sent_via": sent_via,
    }
    if record.network_token:
        item["network_token"] = record.network_token
    if record.error.frames:
        item["frames"] = list(record.error.frames)
    if record.error.subscription is not None:
        item["subscription"] = {"ours": bool(record.error.subscription.ours), "route": record.error.subscription.route}
    item.update(_details_json(common(record.details)))
    return item


def _key(error: AppError) -> str:
    sub = f"{error.subscription.ours}/{error.subscription.route}" if error.subscription else ""
    return "|".join((error.step, error.code, ",".join(error.frames), sub))


class AppErrorStore:
    """Pending app errors on disk (one small JSON file): the same error while unsent adds to its count; after a send the
    next one of the same code and version waits :data:`SEND_EVERY_MS`; at most :data:`MAX_PENDING`, dropped after the
    ingest's 7 days."""

    def __init__(self, path: Path, now_ms: Callable[[], int]) -> None:
        self._path = Path(path)
        self._now_ms = now_ms
        self._lock = threading.Lock()

    def add(self, error: AppError, app_version: str, network_token: str, details: AttemptDetails,
            at_ms: int | None = None) -> AppErrorRecord | None:
        if not is_valid(error):
            return None
        at = self._now_ms() if at_ms is None else int(at_ms)
        with self._lock:
            pending, sent, seen = self._read()
            key = _key(error)
            for index, old in enumerate(pending):
                if _key(old.error) == key and old.app_version == app_version:
                    record = replace(old, count=min(old.count + 1, MAX_COUNT), occurred_at_ms=min(old.occurred_at_ms, at))
                    pending[index] = record
                    break
            else:
                record = AppErrorRecord(new_report_id(), error, 1, at, app_version,
                                        network_token if is_network_token(network_token) else "", common(details))
                pending.append(record)
            del pending[:-MAX_PENDING]
            self._write(pending, sent, seen)
            return record

    def due(self, limit: int) -> list[AppErrorRecord]:
        """The errors that may go now, oldest first."""
        now = self._now_ms()
        with self._lock:
            pending, sent, seen = self._read()
            fresh = [item for item in pending if now - item.occurred_at_ms < MAX_AGE_MS - _FRESHNESS_MARGIN_MS]
            if len(fresh) != len(pending):
                self._write(fresh, sent, seen)
            return [item for item in fresh if now - sent.get(_send_key(item), 0) >= SEND_EVERY_MS][:limit]

    def sent(self, records: list[AppErrorRecord]) -> None:
        """The ingest took (or refused alone) these: they leave and their code waits a day. Repeats counted while one
        was on its way stay as a new pending error with a new report_id."""
        if not records:
            return
        now = self._now_ms()
        with self._lock:
            pending, sent, seen = self._read()
            for done in records:
                for index, current in enumerate(pending):
                    if current.report_id == done.report_id:
                        if current.count > done.count:
                            pending[index] = replace(current, report_id=new_report_id(),
                                                     count=current.count - done.count, occurred_at_ms=now)
                        else:
                            del pending[index]
                        break
                sent[_send_key(done)] = now
            sent = {key: at for key, at in sent.items() if now - at <= 2 * SEND_EVERY_MS}
            self._write(pending, sent, seen)

    def size(self) -> int:
        with self._lock:
            return len(self._read()[0])

    def _read(self) -> tuple[list[AppErrorRecord], dict[str, int], int]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return [], {}, 0
        if not isinstance(data, dict):
            return [], {}, 0
        pending = [item for item in (_parse(raw) for raw in data.get("pending") or []) if item is not None]
        sent = {str(key): int(value) for key, value in (data.get("sent") or {}).items() if isinstance(value, int)}
        return pending, sent, int(data.get("seen") or 0)

    def _write(self, pending: list[AppErrorRecord], sent: dict[str, int], seen: int) -> None:
        data = {"v": 1, "pending": [_encode(item) for item in pending], "sent": sent, "seen": seen}
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temp = self._path.with_name(self._path.name + ".tmp")
            temp.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
            os.replace(temp, self._path)
        except OSError:
            pass


def _send_key(record: AppErrorRecord) -> str:
    return f"{record.error.code}|{record.app_version}"


def _encode(record: AppErrorRecord) -> dict[str, object]:
    out: dict[str, object] = {
        "id": record.report_id, "step": record.error.step, "code": record.error.code, "frames": list(record.error.frames),
        "count": record.count, "t": record.occurred_at_ms, "ver": record.app_version, "n": record.network_token,
        "x": _details_json(common(record.details)),
    }
    if record.error.subscription is not None:
        out["ours"] = record.error.subscription.ours
        out["route"] = record.error.subscription.route
    return out


def _parse(raw: object) -> AppErrorRecord | None:
    if not isinstance(raw, dict):
        return None
    try:
        sub = SubscriptionFact(bool(raw["ours"]), str(raw.get("route") or "")) if isinstance(raw.get("ours"), bool) else None
        error = AppError(str(raw.get("step") or ""), str(raw.get("code") or ""),
                         tuple(str(item) for item in raw.get("frames") or []), sub)
        report_id = str(raw.get("id") or "")
        version = str(raw.get("ver") or "")
        if not is_valid(error) or not _REPORT_ID.match(report_id) or not version:
            return None
        token = str(raw.get("n") or "")
        return AppErrorRecord(
            report_id, error, max(1, min(int(raw["count"]), MAX_COUNT)), int(raw["t"]), version,
            token if is_network_token(token) else "",
            common(_details_from(raw.get("x") if isinstance(raw.get("x"), dict) else {})),
        )
    except (KeyError, TypeError, ValueError):
        return None


# ── the process-wide sink: a crash in any thread, a failure deep in the importer or updater ──

_sink: Callable[[AppError], None] | None = None
_early: list[tuple[AppError, int]] = []
_sink_lock = threading.Lock()


def set_sink(sink: Callable[[AppError], None] | None) -> None:
    """The reporter takes app errors from here on; those noted before it existed go now."""
    global _sink
    with _sink_lock:
        _sink = sink
        early, _early[:] = list(_early), []
    if sink is not None:
        for error, _at in early:
            _call(sink, error)


def note(error: AppError | None) -> None:
    """An app error from anywhere in the app; never raises."""
    if error is None:
        return
    with _sink_lock:
        sink = _sink
        if sink is None:
            if len(_early) < 8:
                _early.append((error, 0))
            return
    _call(sink, error)


def note_crash(exc_type: type[BaseException], tb: TracebackType | None) -> None:
    try:
        note(crash_of(exc_type, tb))
    except Exception:
        pass


def _call(sink: Callable[[AppError], None], error: AppError) -> None:
    try:
        sink(error)
    except Exception:
        pass
