"""Network side of the connection reports: queue on disk, send directly first, then via the tunnel.

The decisions (contract, classification, queue, token) live in ``contract``. Here:
the install id, ``GET /v1/network`` (only directly — through the tunnel the ingest
would see the VPN server's network), ``POST /v1/reports`` and the one functional HTTPS
probe through the Xray relay after a VLESS connect (owner decision 19.11.2026: like the
Hysteria/AmneziaWG engines already do at start). No timers: work runs when a report
is queued and at start-up, on one background thread.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..engines.socks_probe import HTTPS_ENDPOINTS, probe_https
from .contract import (
    MAX_BATCH,
    MAX_ELAPSED_MS,
    SENT_DIRECT,
    SENT_TUNNEL,
    AppIdentity,
    AttemptFacts,
    AttemptRecord,
    NetworkToken,
    NetworkTokenCache,
    ReportQueue,
    SendAction,
    ServerRef,
    after_response,
    batch_json,
    classify,
    is_install_id,
    is_network_token,
    products_for_scheme,
)


ENDPOINT = "https://reports.zapret.moe"
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


def probe_relay(port: int, username: str, password: str, *, timeout: float = _PROBE_TIMEOUT) -> bool:
    """One HTTPS request through the Xray relay SOCKS inbound; the first answering endpoint wins."""
    for endpoint in HTTPS_ENDPOINTS:
        try:
            probe_https(port, username=username, password=password, endpoint=endpoint, timeout=timeout)
            return True
        except (OSError, ValueError):
            continue
    return False


class ClientReporter:
    def __init__(
        self,
        root: Path,
        app_version: str,
        *,
        tunnel_proxy_port: Callable[[], int | None],
        log: Callable[[str], None] = lambda _line: None,
        now_ms: Callable[[], int] = lambda: int(time.time() * 1000),
        opener: Callable[[bool, int | None], urllib.request.OpenerDirector] | None = None,
    ) -> None:
        self._root = Path(root)
        self._app = AppIdentity(APP_NAME, _safe_version(app_version), PLATFORM)
        self._queue = ReportQueue(self._root / "queue.jsonl")
        self._tokens = NetworkTokenCache(self._root / "network-token")
        self._tunnel_proxy_port = tunnel_proxy_port
        self._log = log
        self._now_ms = now_ms
        self._opener = opener or _build_opener
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._stopped_until_next = False

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
    ) -> None:
        """One finished attempt; ``relay`` asks for the VLESS probe before the verdict."""
        if ref is None:
            return
        self._spawn(lambda: self._record(ref, scheme, facts, elapsed_ms, attempted_at_ms, relay))

    def flush(self) -> None:
        if self._stopped_until_next:
            return
        self._spawn(self._flush)

    # ── work ──

    def _spawn(self, work: Callable[[], None]) -> None:
        def run() -> None:
            try:
                work()
            except Exception as exc:  # never let a report break the app
                self._log(f"[client-report] failed: {type(exc).__name__}")
        threading.Thread(target=run, name="client-report", daemon=True).start()

    def _record(
        self,
        ref: ServerRef,
        scheme: str,
        facts: AttemptFacts,
        elapsed_ms: int,
        attempted_at_ms: int,
        relay: tuple[int, str, str] | None,
    ) -> None:
        udp = str(scheme or "").lower() in UDP_SCHEMES
        if relay is not None:
            started = time.monotonic()
            passed = probe_relay(*relay)
            elapsed_ms += int((time.monotonic() - started) * 1000)
            facts = AttemptFacts(succeeded=passed, traffic_failed=not passed)
            self._log(f"[client-report] VLESS check through the server: {'passed' if passed else 'no answer'}")
        verdict = classify(AttemptFacts(
            cancelled=facts.cancelled, succeeded=facts.succeeded, core_code=facts.core_code,
            network_lost=facts.network_lost, traffic_failed=facts.traffic_failed,
            tcp_preflight_failed=facts.tcp_preflight_failed, udp_transport=udp,
        ))
        if verdict is None:
            return
        if self._tokens.needs_refresh(self._now_ms()):
            self._refresh_token()
        record = AttemptRecord(
            server_id=ref.server_id, product=ref.product, outcome=verdict.outcome,
            failed_step=verdict.failed_step, detail=verdict.detail,
            elapsed_ms=max(0, min(int(elapsed_ms), MAX_ELAPSED_MS)),
            attempted_at_ms=int(attempted_at_ms), network_token=self._tokens.current(self._now_ms()),
        )
        self._queue.add(record)
        step = f" at {verdict.failed_step} ({verdict.detail})" if verdict.failed_step else ""
        self._log(
            f"[client-report] {ref.product}/{ref.server_id} {verdict.outcome.value}{step}, queued {self._queue.size()}"
        )
        self._stopped_until_next = False
        self._flush()

    def _flush(self) -> None:
        if not self._flush_lock.acquire(blocking=False):
            return
        try:
            while True:
                batch = self._queue.pending(self._now_ms())[:MAX_BATCH]
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
        install_id = self._install_id()
        routes: list[tuple[str, int | None]] = [(SENT_DIRECT, None)]
        port = self._tunnel_proxy_port()
        if port:
            routes.append((SENT_TUNNEL, int(port)))
        for via, proxy_port in routes:
            body = batch_json(install_id, self._app, batch, via).encode("utf-8")
            status = self._post(body, proxy_port)
            action = after_response(status)
            if action is SendAction.TRY_OTHER_PATH:
                continue
            self._log(f"[client-report] batch {len(batch)} ({via}) -> HTTP {status}")
            return action
        return SendAction.TRY_OTHER_PATH

    def _post(self, body: bytes, proxy_port: int | None) -> int | None:
        request = urllib.request.Request(
            f"{ENDPOINT}/v1/reports", data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with self._opener(proxy_port is not None, proxy_port).open(request, timeout=_TIMEOUT) as response:
                return int(response.status)
        except urllib.error.HTTPError as exc:
            return int(exc.code)
        except (OSError, ValueError):
            return None

    def _refresh_token(self) -> None:
        request = urllib.request.Request(f"{ENDPOINT}/v1/network?install_id={self._install_id()}")
        try:
            with self._opener(False, None).open(request, timeout=_TIMEOUT) as response:
                if int(response.status) != 200:
                    return
                data = json.loads(response.read(_MAX_ANSWER_BYTES).decode("utf-8"))
        except (OSError, ValueError, urllib.error.HTTPError):
            return
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


def _build_opener(via_proxy: bool, proxy_port: int | None) -> urllib.request.OpenerDirector:
    if via_proxy and proxy_port:
        address = f"http://127.0.0.1:{int(proxy_port)}"
        return urllib.request.build_opener(urllib.request.ProxyHandler({"http": address, "https": address}))
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _safe_version(version: str) -> str:
    cleaned = "".join(ch for ch in str(version or "") if (ch.isascii() and ch.isalnum()) or ch in ".+-")[:32]
    return cleaned or "0"
