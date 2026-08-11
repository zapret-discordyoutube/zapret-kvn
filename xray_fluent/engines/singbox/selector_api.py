"""Minimal Clash-compatible selector client for a running sing-box."""

from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, build_opener, ProxyHandler

from ...constants import PROXY_HOST


COMMAND_TIMEOUT_SEC = 2.0


def build_selector_url(api_port: int, selector_tag: str) -> str:
    if int(api_port) <= 0:
        raise ValueError("Порт Clash API sing-box не задан")
    if not str(selector_tag or "").strip():
        raise ValueError("Тег selector sing-box не задан")
    return f"http://{PROXY_HOST}:{int(api_port)}/proxies/{quote(str(selector_tag), safe='')}"


def select_outbound(api_port: int, selector_tag: str, outbound_tag: str) -> tuple[bool, str]:
    if not str(outbound_tag or "").strip():
        return False, "Тег outbound sing-box не задан"
    try:
        url = build_selector_url(api_port, selector_tag)
    except ValueError as exc:
        return False, str(exc)
    request = Request(
        url,
        data=json.dumps({"name": str(outbound_tag)}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    try:
        # Never inherit the system proxy for a loopback control-plane call.
        with build_opener(ProxyHandler({})).open(request, timeout=COMMAND_TIMEOUT_SEC) as response:
            if 200 <= int(response.status) < 300:
                return True, ""
            return False, f"HTTP {response.status}"
    except HTTPError as exc:
        return False, f"HTTP {exc.code}: {exc.reason}"
    except (URLError, OSError, TimeoutError) as exc:
        return False, f"{type(exc).__name__}: {exc}"
