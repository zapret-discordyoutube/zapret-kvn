"""Minimal Clash-compatible selector client for a running sing-box."""

from __future__ import annotations

import json
import time
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
    last_error = ""
    for attempt in range(1, COMMAND_ATTEMPTS + 1):
        try:
            # Never inherit the system proxy for a loopback control-plane call.
            with build_opener(ProxyHandler({})).open(
                request, timeout=COMMAND_TIMEOUT_SEC
            ) as response:
                if 200 <= int(response.status) < 300:
                    return True, ""
                return False, f"HTTP {response.status}"
        except HTTPError as exc:
            # Ядро ответило и отказало: повтор даст тот же ответ.
            return False, f"HTTP {exc.code}: {exc.reason}"
        except (URLError, OSError, TimeoutError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt < COMMAND_ATTEMPTS:
                time.sleep(RETRY_DELAY_SEC)
    return False, last_error
