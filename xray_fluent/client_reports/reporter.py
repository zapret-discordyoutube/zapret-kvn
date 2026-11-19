"""Network side of the connection reports: queue on disk, send directly first, then via the tunnel.

The decisions (contract, classification, queue, token) live in ``contract``. Here:
the install id, ``GET /v1/network`` (only directly — through the tunnel the ingest
would see the VPN server's network), ``POST /v1/reports`` and the one functional HTTPS
probe through the Xray relay after a VLESS connect (owner decision 19.11.2026: like the
Hysteria/AmneziaWG engines already do at start). No timers: work runs when a report
is queued and at start-up, on one background thread.

After a failure ``probe.BlockProbe`` checks the path step by step (``diagnosis``): the conclusion goes into the
report and onto the failure notice (``on_failure_changed``); the «Отправить отчёт» button is ``force_report``.
After a success the freeze is measured through the session, once per server per ``MIN_INTERVAL_MS``.
"""

from __future__ import annotations

import json
import random
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from ..engines.socks_probe import HTTPS_ENDPOINTS, probe_https
from .contract import (
    INGEST_FEEDS,
    AttemptDetails,
    ForeignServer,
    short_version,
    new_report_id,
    FAILED_FOR_MS,
    MAX_BATCH,
    MAX_BODY_BYTES,
    MAX_FEED_BYTES,
    TRIES_PER_PATH,
    MAX_ELAPSED_MS,
    SENT_DIRECT,
    SENT_TUNNEL,
    AppIdentity,
    AttemptFacts,
    AttemptRecord,
    IngestHostCache,
    NetworkToken,
    NetworkTokenCache,
    ReportQueue,
    SendAction,
    ServerRef,
    after_response,
    batch_json,
    classify,
    classify_forced,
    domain_of,
    ingest_order,
    is_install_id,
    is_network_token,
    parse_ingest_feed,
    products_for_scheme,
    take_batch,
)
from .diagnosis import MIN_INTERVAL_MS, Diagnosis, DiagnosisFacts, describe, diagnose, diagnose_udp, freeze
from .probe import BlockProbe, ProbeTarget, measure_freeze


APP_NAME = "zapret-kvn"
PLATFORM = "windows"
_TIMEOUT = 15.0
_PROBE_TIMEOUT = 10.0
_MAX_ANSWER_BYTES = 4096
UDP_SCHEMES = frozenset({"hysteria2", "hy2", "wireguard", "awg", "amneziawg", "wg", "tuic"})


def server_ref_for(node: Any, subscriptions: list[Any]) -> ServerRef | None:
    """The catalogue server a node of the service's own subscription names; ``None`` otherwise."""
    subscription_id = getattr(node, "subscription_id", None)
    if not subscription_id:
        return None
    subscription = next((item for item in subscriptions if getattr(item, "id", None) == subscription_id), None)
    if subscription is None or not getattr(subscription, "service", False):
        return None
    entry = (getattr(subscription, "server_ids", None) or {}).get(getattr(node, "provider_name", "") or "")
    if not isinstance(entry, dict):
        return None
    products = products_for_scheme(getattr(node, "scheme", ""))
    server_id, product = entry.get("server_id"), entry.get("product")
    if not isinstance(server_id, str) or product not in products:
        return None
    return ServerRef(server_id, str(product))


def probe_target_for(node: Any) -> ProbeTarget | None:
    """The server of a node as a path-check target: address, port, TLS name, whether TLS, whether UDP."""
    host = str(getattr(node, "server", "") or "").strip()
    try:
        port = int(getattr(node, "port", 0) or 0)
    except (TypeError, ValueError):
        return None
    if not host or not 0 < port < 65536:
        return None
    scheme = str(getattr(node, "scheme", "") or "").lower()
    udp = scheme in UDP_SCHEMES
    outbound = getattr(node, "outbound", None) or {}
    stream = outbound.get("streamSettings") if isinstance(outbound, dict) else None
    stream = stream if isinstance(stream, dict) else {}
    security = str(stream.get("security") or "").lower()
    name = None
    for key in ("realitySettings", "tlsSettings"):
        settings = stream.get(key)
        if isinstance(settings, dict) and str(settings.get("serverName") or "").strip():
            name = str(settings["serverName"]).strip()
            break
    if name is None and isinstance(outbound, dict) and isinstance(outbound.get("tls"), dict):
        name = str(outbound["tls"].get("server_name") or "").strip() or None
    quic = scheme in {"hysteria2", "hy2", "hysteria", "tuic"}
    network = str(stream.get("network") or "").lower()
    transport = "quic" if quic else "udp" if udp else (network or "tcp")
    report_security = "tls" if quic else (security or "none")
    # Hysteria/TUIC carry TLS over QUIC: there is no TCP TLS step for them.
    return ProbeTarget(
        host=host, port=port, server_name=name, uses_tls=not udp and security in {"tls", "reality"}, udp=udp,
        protocol="hysteria2" if scheme == "hy2" else scheme, transport=transport, security=report_security,
    )


_VERSION_NUMBER = re.compile(r"v?(\d+\.\d+\.\d+[0-9A-Za-z.+_-]*)")
_versions_cache: tuple[tuple[str, str], ...] | None = None


def core_versions() -> tuple[tuple[str, str], ...]:
    """OS and core versions for the report, asked once per app run (each core answers ``version``)."""
    global _versions_cache
    if _versions_cache is not None:
        return _versions_cache
    found: list[tuple[str, str]] = []
    try:
        import platform

        os_version = short_version(platform.version())
        if os_version:
            found.append(("os", os_version))
        from ..constants import HYSTERIA_PATH_DEFAULT, SINGBOX_PATH_DEFAULT
        from ..engines.singbox.core_updater import installed_version
        from ..engines.xray import get_xray_version

        for key, text in (
            ("xray", get_xray_version("") or ""),
            ("singbox", installed_version(SINGBOX_PATH_DEFAULT) if SINGBOX_PATH_DEFAULT.exists() else ""),
            ("hysteria", _hysteria_version(HYSTERIA_PATH_DEFAULT)),
        ):
            match = _VERSION_NUMBER.search(text or "")
            value = short_version(match.group(1)) if match else None
            if value:
                found.append((key, value))
    except Exception:
        pass
    _versions_cache = tuple(found)
    return _versions_cache


def _hysteria_version(exe: Path) -> str:
    if not exe.exists():
        return ""
    try:
        from ..platform.windows.subprocess_utils import result_output_text, run_text

        text = result_output_text(run_text([str(exe), "version"], timeout=5.0))
    except Exception:
        return ""
    for line in str(text).splitlines():
        if "version" in line.lower():
            return line
    return ""


def probe_relay(port: int, username: str, password: str, *, timeout: float = _PROBE_TIMEOUT) -> bool:
    """One HTTPS request through the Xray relay SOCKS inbound; the first answering endpoint wins."""
    for endpoint in HTTPS_ENDPOINTS:
        try:
            probe_https(port, username=username, password=password, endpoint=endpoint, timeout=timeout)
            return True
        except (OSError, ValueError):
            continue
    return False


class SendStatus(str, Enum):
    AVAILABLE = "available"
    SENDING = "sending"
    SENT = "sent"
    QUEUED = "queued"
    #: Not a server of the service's subscription: the diagnosis is shown, the button waits for schema 2.
    NOT_OURS = "not_ours"


@dataclass(frozen=True, slots=True)
class FailureReport:
    """The last failure for the notice: what the path check found and what happened to the report."""

    attempt: int
    checking: bool
    #: The finding (Russian); None — not checked (checked recently, or the check is still running).
    diagnosis_text: str | None
    detail: str | None
    status: SendStatus


class _PendingFailure:
    def __init__(self, attempt: int, ref: ServerRef | None, scheme: str, facts: AttemptFacts, elapsed_ms: int,
                 attempted_at_ms: int, target: ProbeTarget | None, name: str = "") -> None:
        self.attempt = attempt
        #: The node's name: the name of a foreign server in its report.
        self.name = name
        self.ref = ref
        self.scheme = scheme
        self.facts = facts
        self.elapsed_ms = elapsed_ms
        self.attempted_at_ms = attempted_at_ms
        self.target = target
        self.checking = False
        self.checked = False
        self.diagnosis: Diagnosis | None = None
        self.diagnosis_facts: DiagnosisFacts | None = None
        self.record: AttemptRecord | None = None
        self.status = SendStatus.NOT_OURS if ref is None and target is None else SendStatus.AVAILABLE


class ClientReporter:
    def __init__(
        self,
        root: Path,
        app_version: str,
        *,
        tunnel_proxy_port: Callable[[], int | None],
        direct_is_direct: Callable[[], bool] = lambda: True,
        log: Callable[[str], None] = lambda _line: None,
        now_ms: Callable[[], int] = lambda: int(time.time() * 1000),
        opener: Callable[[bool, int | None], urllib.request.OpenerDirector] | None = None,
        probe: BlockProbe | None = None,
        freeze_probe: Callable[[int | None], int | None] = measure_freeze,
        on_failure_changed: Callable[[FailureReport | None], None] = lambda _report: None,
        context: Callable[[], AttemptDetails] = AttemptDetails,
        server_address: Callable[[str], str | None] = lambda _host: None,
    ) -> None:
        self._root = Path(root)
        self._app = AppIdentity(APP_NAME, _safe_version(app_version), PLATFORM)
        self._queue = ReportQueue(self._root / "queue.jsonl")
        self._tokens = NetworkTokenCache(self._root / "network-token")
        self._ingest = IngestHostCache(self._root / "ingest-hosts")
        self._random = random.SystemRandom()
        self._failed_hosts: dict[str, int] = {}
        self._tunnel_proxy_port = tunnel_proxy_port
        # In TUN mode Windows has no per-socket bypass: a "direct" request follows the user's routing and may leave
        # through the VPN server, so the ingest would record the server's network. Then only the tunnel path is used.
        self._direct_is_direct = direct_is_direct
        self._log = log
        self._now_ms = now_ms
        self._opener = opener or _build_opener
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._stopped_until_next = False
        self._probe = probe
        self._freeze_probe = freeze_probe
        self._on_failure_changed = on_failure_changed
        # Schema 2: what is the same for all attempts now (mode, masking, versions) and the address the start used.
        self._context = context
        self._server_address = server_address
        self._probed_at: dict[str, int] = {}
        self._freeze_checked_at: dict[str, int] = {}
        self._failure: _PendingFailure | None = None
        self._failure_lock = threading.Lock()

    # ── entry points (any thread; work goes to a daemon thread) ──

    def on_attempt(
        self,
        ref: ServerRef | None,
        scheme: str,
        facts: AttemptFacts,
        *,
        elapsed_ms: int,
        attempted_at_ms: int,
        relay: tuple[int, str, str] | None = None,
        target: ProbeTarget | None = None,
        attempt: int = 0,
        name: str = "",
    ) -> None:
        """One finished attempt; ``relay`` asks for the VLESS probe before the verdict. A report is written only for
        a server of the service; the path check and the notice work for any server."""
        if ref is None and (facts.succeeded or facts.cancelled) and relay is None:
            if facts.succeeded:
                self._clear_failure()
            return
        self._spawn(lambda: self._attempt(ref, scheme, facts, elapsed_ms, attempted_at_ms, relay, target, attempt, name))

    def begin_attempt(self, attempt: int) -> None:
        """A new connection attempt: the previous failure leaves the notice."""
        with self._failure_lock:
            if self._failure is not None and self._failure.attempt != attempt:
                self._failure = None
                self._on_failure_changed(None)

    def force_report(self) -> None:
        """The «Отправить отчёт» button: a failure without a report yet is written (``local_*`` when it is not about
        the server) and the queue is sent now. The result arrives through ``on_failure_changed``."""
        pending = self._failure
        # A foreign server is sent in full (address, port, protocol, name), but only by this button.
        if pending is None or (pending.ref is None and self._foreign_of(pending) is None):
            return
        pending.status = SendStatus.SENDING
        self._publish(pending)
        self._spawn(lambda: self._force(pending))

    def _force(self, pending: _PendingFailure) -> None:
        try:
            if pending.record is None:
                pending.record = self._write(
                    pending.ref, classify_forced(pending.facts, pending.diagnosis), pending.elapsed_ms,
                    pending.attempted_at_ms, self._details(pending.target, pending.diagnosis_facts),
                    foreign=self._foreign_of(pending) if pending.ref is None else None, flush=False,
                )
            self._stopped_until_next = False
            self._flush(wait=True)
        finally:
            pending.status = self._status_of(pending)
            self._log(f"[client-report] report by button: {'sent' if pending.status is SendStatus.SENT else 'queued'}")
            self._publish(pending)

    def flush(self) -> None:
        if self._stopped_until_next:
            return
        self._spawn(self._flush)

    def prefetch_token(self) -> None:
        """Ask ``GET /v1/network`` now, while requests are really direct (no TUN session): app start, the start of a
        connection, after a disconnect. In TUN mode the token cannot be asked later."""
        if not self._direct_is_direct() or not self._tokens.needs_refresh(self._now_ms()):
            return
        self._spawn(self._refresh_token)

    # ── work ──

    def _spawn(self, work: Callable[[], None]) -> None:
        def run() -> None:
            try:
                work()
            except Exception as exc:  # never let a report break the app
                self._log(f"[client-report] failed: {type(exc).__name__}")
        threading.Thread(target=run, name="client-report", daemon=True).start()

    def _attempt(
        self,
        ref: ServerRef | None,
        scheme: str,
        facts: AttemptFacts,
        elapsed_ms: int,
        attempted_at_ms: int,
        relay: tuple[int, str, str] | None,
        target: ProbeTarget | None = None,
        attempt: int = 0,
        name: str = "",
    ) -> None:
        udp = str(scheme or "").lower() in UDP_SCHEMES
        if relay is not None:
            started = time.monotonic()
            passed = probe_relay(*relay)
            elapsed_ms += int((time.monotonic() - started) * 1000)
            facts = AttemptFacts(succeeded=passed, traffic_failed=not passed)
            self._log(f"[client-report] VLESS check through the server: {'passed' if passed else 'no answer'}")
        facts = AttemptFacts(
            cancelled=facts.cancelled, succeeded=facts.succeeded, core_code=facts.core_code,
            network_lost=facts.network_lost, traffic_failed=facts.traffic_failed,
            tcp_preflight_failed=facts.tcp_preflight_failed, udp_transport=udp,
        )
        if facts.cancelled or facts.succeeded:
            diagnosis = self._check_freeze(target) if facts.succeeded else None
            if facts.succeeded:
                self._clear_failure()
            if ref is not None:
                self._write(ref, classify(facts, diagnosis), elapsed_ms, attempted_at_ms, self._details(target, None))
            return
        self._on_failure(_PendingFailure(attempt, ref, scheme, facts, elapsed_ms, attempted_at_ms, target, name))

    def _on_failure(self, pending: _PendingFailure) -> None:
        with self._failure_lock:
            self._failure = pending
        self._publish(pending)
        target = pending.target
        # In TUN mode a "direct" socket follows the user's routing: the probes would test the VPN, not the path.
        if (target is not None and self._probe is not None and not pending.facts.network_lost
                and self._direct_is_direct() and self._take_slot(self._probed_at, target.host)):
            pending.checking = True
            self._publish(pending)
            try:
                facts = self._probe.run(target)
            except Exception as exc:  # a probe never breaks a report
                self._log(f"[client-report] path check failed: {type(exc).__name__}")
                facts = None
            pending.diagnosis_facts = facts
            pending.diagnosis = (diagnose_udp(facts) if target.udp else diagnose(facts)) if facts is not None else None
            pending.checked = True
            pending.checking = False
            found = f"{pending.diagnosis.failed_step}/{pending.diagnosis.detail}" if pending.diagnosis else "no conclusion"
            self._log(f"[client-report] path check -> {found} ({_summary(facts)})")
        if pending.ref is not None:
            pending.record = self._write(
                pending.ref, classify(pending.facts, pending.diagnosis), pending.elapsed_ms, pending.attempted_at_ms,
                self._details(pending.target, pending.diagnosis_facts),
            )
        pending.status = self._status_of(pending)
        self._publish(pending)

    def _check_freeze(self, target: ProbeTarget | None) -> Diagnosis | None:
        """The freeze after a success: at most once per server per ``MIN_INTERVAL_MS``, TCP servers only."""
        if target is None or target.udp or self._probe is None or not self._take_slot(self._freeze_checked_at, target.host):
            return None
        port = self._tunnel_proxy_port()
        try:
            stalled = self._freeze_probe(int(port) if port else None)
        except Exception:
            stalled = None
        diagnosis = freeze(stalled)
        self._log(
            "[client-report] freeze check -> "
            + (f"stalled after {stalled} B" if stalled is not None else "no stall")
            + (", freeze_16k" if diagnosis else "")
        )
        return diagnosis

    def _take_slot(self, stamps: dict[str, int], key: str) -> bool:
        now = self._now_ms()
        with self._lock:
            last = stamps.get(key)
            if last is not None and now - last < MIN_INTERVAL_MS:
                return False
            stamps[key] = now
            for stale in [name for name, at in stamps.items() if now - at >= MIN_INTERVAL_MS]:
                stamps.pop(stale, None)
            stamps[key] = now
            return True

    def _foreign_of(self, pending: _PendingFailure) -> ForeignServer | None:
        target = pending.target
        if target is None:
            return None
        return ForeignServer.of(target.host, target.protocol or pending.scheme, pending.name)

    def _details(self, target: ProbeTarget | None, facts: DiagnosisFacts | None) -> AttemptDetails:
        """The report's details: the common part from ``context`` and this server's address, port, transport."""
        try:
            base = self._context()
        except Exception:
            base = AttemptDetails()
        if target is None:
            return base.cleaned()
        from dataclasses import replace

        from .probe import literal_address

        try:
            noted = self._server_address(target.host)
        except Exception:
            noted = None
        return replace(
            base,
            server_ip=literal_address(target.host) or noted or (facts.probed_address if facts else None),
            port=target.port, transport=target.transport, security=target.security,
        ).cleaned()

    def _status_of(self, pending: _PendingFailure) -> SendStatus:
        if pending.record is None:
            return SendStatus.NOT_OURS if pending.ref is None and self._foreign_of(pending) is None else SendStatus.AVAILABLE
        return SendStatus.QUEUED if pending.record in self._queue.pending(self._now_ms()) else SendStatus.SENT

    def _publish(self, pending: _PendingFailure) -> None:
        if self._failure is not pending:
            return
        self._on_failure_changed(FailureReport(
            attempt=pending.attempt,
            checking=pending.checking,
            diagnosis_text=describe(pending.diagnosis, pending.diagnosis_facts) if pending.checked else None,
            detail=pending.diagnosis.detail if pending.diagnosis else None,
            status=pending.status,
        ))

    def _clear_failure(self) -> None:
        with self._failure_lock:
            had = self._failure is not None
            self._failure = None
        if had:
            self._on_failure_changed(None)

    def _write(
        self,
        ref: ServerRef | None,
        verdict: Any,
        elapsed_ms: int,
        attempted_at_ms: int,
        details: AttemptDetails | None = None,
        *,
        foreign: ForeignServer | None = None,
        flush: bool = True,
    ) -> AttemptRecord | None:
        if verdict is None or (ref is None and foreign is None):
            return None
        if self._tokens.needs_refresh(self._now_ms()):
            self._refresh_token()
        record = AttemptRecord(
            server_id=ref.server_id if ref else "", product=ref.product if ref else "", outcome=verdict.outcome,
            failed_step=verdict.failed_step, detail=verdict.detail,
            elapsed_ms=max(0, min(int(elapsed_ms), MAX_ELAPSED_MS)),
            attempted_at_ms=int(attempted_at_ms), network_token=self._tokens.current(self._now_ms()),
            foreign=foreign, details=(details or AttemptDetails()).cleaned(), report_id=new_report_id(),
        )
        self._queue.add(record)
        step = f" at {verdict.failed_step} ({verdict.detail})" if verdict.failed_step else ""
        who = f"{ref.product}/{ref.server_id}" if ref else f"foreign {foreign.protocol if foreign else ''}"
        self._log(f"[client-report] {who} {verdict.outcome.value}{step}, queued {self._queue.size()}")
        if flush:
            self._stopped_until_next = False
            self._flush()
        return record

    def _flush(self, wait: bool = False) -> None:
        if not self._flush_lock.acquire(blocking=wait):
            return
        try:
            while True:
                install_id = self._install_id()
                batch = take_batch(
                    self._queue.pending(self._now_ms()), MAX_BATCH, MAX_BODY_BYTES,
                    lambda records: len(batch_json(install_id, self._app, records, SENT_DIRECT).encode("utf-8")),
                )
                if not batch:
                    return
                action = self._send(batch)
                if action in (SendAction.REMOVE, SendAction.DROP):
                    self._queue.remove(batch)
                    continue
                self._stopped_until_next = action is SendAction.KEEP_AND_STOP
                return
        finally:
            self._flush_lock.release()

    def _send(self, batch: list[AttemptRecord]) -> SendAction:
        """Directly, then through the tunnel; up to ``TRIES_PER_PATH`` ingest names on each path. When no name
        answered, the feed of names is asked once and the send repeated."""
        if self._ingest.feed_due(self._now_ms(), nothing_answered=False):
            self._refresh_feed()
        action = self._send_once(batch)
        if action is None and self._ingest.feed_due(self._now_ms(), nothing_answered=True) and self._refresh_feed():
            action = self._send_once(batch)
        if action is None:
            self._log(f"[client-report] batch {len(batch)} not sent: no ingest name answered")
            return SendAction.TRY_OTHER_PATH
        return action

    def _routes(self) -> list[tuple[str, int | None]]:
        routes: list[tuple[str, int | None]] = [(SENT_DIRECT, None)] if self._direct_is_direct() else []
        port = self._tunnel_proxy_port()
        if port:
            routes.append((SENT_TUNNEL, int(port)))
        elif not self._direct_is_direct():
            # TUN session without a local HTTP inbound: a request without a proxy is captured by the TUN itself.
            # If the user's routing sends it out directly after all, it is still labelled tunnel, and the ingest takes
            # no network from the source of a tunnel report: never a false network.
            routes.append((SENT_TUNNEL, None))
        return routes

    def _send_once(self, batch: list[AttemptRecord]) -> SendAction | None:
        install_id = self._install_id()
        for via, proxy_port in self._routes():
            body = batch_json(install_id, self._app, batch, via).encode("utf-8")
            for host in self._host_order()[:TRIES_PER_PATH]:
                status = self._post(host, body, proxy_port)
                action = after_response(status)
                if action is SendAction.TRY_OTHER_PATH:
                    self._note_failed(host)
                    continue
                self._log(f"[client-report] batch {len(batch)}, {len(body)} B ({via}, {domain_of(host)}) -> HTTP {status}")
                return action
        return None

    def _host_order(self) -> list[str]:
        now = self._now_ms()
        with self._lock:
            for host in [h for h, at in self._failed_hosts.items() if now - at >= FAILED_FOR_MS]:
                del self._failed_hosts[host]
            failed = set(self._failed_hosts)
        return ingest_order(self._ingest.hosts(), failed, self._random)

    def _note_failed(self, host: str) -> None:
        with self._lock:
            self._failed_hosts[host] = self._now_ms()

    def _refresh_feed(self) -> bool:
        """Ingest names from the zapret-links feed (entry pages on script.google.com and the gist), directly, then
        through the tunnel. True when at least one name was learnt."""
        self._ingest.note_feed_attempt(self._now_ms())
        for _via, proxy_port in self._routes():
            for feed in INGEST_FEEDS:
                text = self._get(feed, proxy_port, MAX_FEED_BYTES)
                hosts = parse_ingest_feed(text) if text is not None else []
                if hosts:
                    self._ingest.store(hosts, self._now_ms())
                    self._log(f"[client-report] ingest names from the feed {urllib.parse.urlsplit(feed).hostname}: {len(hosts)}")
                    return True
        self._log("[client-report] the feed of ingest names did not answer")
        return False

    def _get(self, url: str, proxy_port: int | None, max_bytes: int) -> bytes | None:
        request = urllib.request.Request(url, headers={"Connection": "close"})
        try:
            with self._opener(proxy_port is not None, proxy_port).open(request, timeout=_TIMEOUT) as response:
                if int(response.status) != 200:
                    return None
                data = response.read(max_bytes + 1)
                return data if len(data) <= max_bytes else None
        except (OSError, ValueError, urllib.error.HTTPError):
            return None

    def _post(self, host: str, body: bytes, proxy_port: int | None) -> int | None:
        """One short connection per request (urllib never reuses one; ``Connection: close`` says so to the server)."""
        request = urllib.request.Request(
            f"https://{host}/v1/reports", data=body, method="POST",
            headers={"Content-Type": "application/json", "Connection": "close"},
        )
        try:
            with self._opener(proxy_port is not None, proxy_port).open(request, timeout=_TIMEOUT) as response:
                return int(response.status)
        except urllib.error.HTTPError as exc:
            return int(exc.code)
        except (OSError, ValueError):
            return None

    def _refresh_token(self) -> None:
        """``GET /v1/network`` only directly: through the tunnel the ingest would see the VPN server's network."""
        if not self._direct_is_direct():
            return
        if self._ingest.feed_due(self._now_ms(), nothing_answered=False):
            self._refresh_feed()
        data: Any = None
        for host in self._host_order()[:TRIES_PER_PATH]:
            text = self._get(f"https://{host}/v1/network?install_id={self._install_id()}", None, _MAX_ANSWER_BYTES)
            if text is None:
                self._note_failed(host)
                continue
            try:
                data = json.loads(text.decode("utf-8"))
            except ValueError:
                data = None
            break
        token = data.get("network_token") if isinstance(data, dict) else None
        if isinstance(token, str) and is_network_token(token):
            self._tokens.store(NetworkToken(token, self._now_ms()))
            self._log("[client-report] network token received")

    def _install_id(self) -> str:
        with self._lock:
            path = self._root / "install-id"
            try:
                value = path.read_text(encoding="utf-8").strip()
                if is_install_id(value):
                    return value
            except OSError:
                pass
            value = secrets.token_hex(16)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value, encoding="utf-8")
            return value


def _summary(facts: DiagnosisFacts | None) -> str:
    """The probe steps in one line for the log (no addresses)."""
    if facts is None:
        return "probe failed"
    dns = f"{len(facts.system_dns) if facts.system_dns is not None else '-'}/{len(facts.doh_dns) if facts.doh_dns is not None else '-'}"
    return (
        f"control={facts.control.value} tcp={facts.tcp_target.value} tcp443={facts.tcp_other_port.value} "
        f"tls={facts.tls_real_name.value} neutral={facts.tls_neutral_name.value} "
        f"elsewhere={facts.tls_real_name_elsewhere.value} dns={dns}" + (" nxdomain" if facts.doh_name_missing else "")
    )


def _build_opener(via_proxy: bool, proxy_port: int | None) -> urllib.request.OpenerDirector:
    if via_proxy and proxy_port:
        address = f"http://127.0.0.1:{int(proxy_port)}"
        return urllib.request.build_opener(urllib.request.ProxyHandler({"http": address, "https": address}))
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _safe_version(version: str) -> str:
    cleaned = "".join(ch for ch in str(version or "") if (ch.isascii() and ch.isalnum()) or ch in ".+-")[:32]
    return cleaned or "0"
