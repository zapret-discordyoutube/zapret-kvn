"""Minimal Clash-compatible selector client for a running sing-box."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, build_opener, ProxyHandler

from ...constants import PROXY_HOST


# Вызов идёт на loopback, но ядро отвечает не мгновенно: под нагрузкой диска или
# сразу после старта двух секунд не хватало, переключение объявлялось отвергнутым
# и уходило в полный перезапуск ядра — со стороны это выглядело случайным сбоем.
COMMAND_TIMEOUT_SEC = 6.0

# PUT задаёт выбранный узел, повтор приводит к тому же состоянию, поэтому
# ретраи безопасны.
COMMAND_ATTEMPTS = 3
RETRY_DELAY_SEC = 0.4

# A cold sing-box start can spend several seconds loading local providers and
# remote rule-set state before the Clash API begins listening.  Hot switches
# keep the short retry budget above; startup gets a bounded readiness window.
STARTUP_READY_TIMEOUT_SEC = 12.0
STARTUP_RETRY_DELAY_SEC = 0.25
STARTUP_REQUEST_TIMEOUT_SEC = 1.0


def build_selector_url(api_port: int, selector_tag: str) -> str:
    if int(api_port) <= 0:
        raise ValueError("Порт Clash API sing-box не задан")
    if not str(selector_tag or "").strip():
        raise ValueError("Тег selector sing-box не задан")
    return f"http://{PROXY_HOST}:{int(api_port)}/proxies/{quote(str(selector_tag), safe='')}"


def _selector_request(
    api_port: int,
    selector_tag: str,
    outbound_tag: str,
) -> tuple[Request | None, str]:
    if not str(outbound_tag or "").strip():
        return None, "Тег outbound sing-box не задан"
    try:
        url = build_selector_url(api_port, selector_tag)
    except ValueError as exc:
        return None, str(exc)
    return (
        Request(
            url,
            data=json.dumps({"name": str(outbound_tag)}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PUT",
        ),
        "",
    )


def _send_selector_request(request: Request, timeout_sec: float) -> tuple[bool, str, bool]:
    """Return ``(ok, message, retryable)`` for one loopback PUT."""

    try:
        # Never inherit the system proxy for a loopback control-plane call.
        with build_opener(ProxyHandler({})).open(
            request, timeout=max(0.05, float(timeout_sec))
        ) as response:
            if 200 <= int(response.status) < 300:
                return True, "", False
            return False, f"HTTP {response.status}", False
    except HTTPError as exc:
        # The core is ready and rejected the target; restarting cannot repair
        # an invalid selector member.
        return False, f"HTTP {exc.code}: {exc.reason}", False
    except (URLError, OSError, TimeoutError) as exc:
        return False, f"{type(exc).__name__}: {exc}", True


def select_outbound(api_port: int, selector_tag: str, outbound_tag: str) -> tuple[bool, str]:
    request, problem = _selector_request(api_port, selector_tag, outbound_tag)
    if request is None:
        return False, problem
    last_error = ""
    for attempt in range(1, COMMAND_ATTEMPTS + 1):
        ok, last_error, retryable = _send_selector_request(request, COMMAND_TIMEOUT_SEC)
        if ok or not retryable:
            return ok, last_error
        if attempt < COMMAND_ATTEMPTS:
            time.sleep(RETRY_DELAY_SEC)
    return False, last_error


def select_outbound_when_ready(
    api_port: int,
    selector_tag: str,
    outbound_tag: str,
    *,
    timeout_sec: float = STARTUP_READY_TIMEOUT_SEC,
    wait: Callable[[float], None] = time.sleep,
) -> tuple[bool, str]:
    """Pin a selector during cold start, waiting for the local API listener.

    Connection refusals and loopback timeouts mean that the control plane is
    not ready yet, so they are retried until the bounded deadline.  An HTTP
    response is authoritative and is never retried.
    """

    request, problem = _selector_request(api_port, selector_tag, outbound_tag)
    if request is None:
        return False, problem

    deadline = time.monotonic() + max(0.05, float(timeout_sec))
    last_error = ""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False, last_error or "Clash API sing-box не стал доступен вовремя"
        ok, last_error, retryable = _send_selector_request(
            request,
            min(STARTUP_REQUEST_TIMEOUT_SEC, remaining),
        )
        if ok or not retryable:
            return ok, last_error
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False, last_error
        wait(min(STARTUP_RETRY_DELAY_SEC, remaining))
