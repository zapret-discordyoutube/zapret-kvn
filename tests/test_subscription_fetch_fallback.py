"""Direct-first subscription fetch: fall back to the VPN proxy only on a
transport failure (no response), never after the server already answered.

A subscription URL points at the provider's own infrastructure and answers the
same on any network path.  When a direct attempt reaches the server — even with
a 404 (revoked link / device limit) — that answer is authoritative and must be
surfaced, instead of being masked by a proxy attempt whose TLS handshake to the
same host times out through a degraded tunnel.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch
import urllib.error

from xray_fluent.importer import subscription_http as sh
from xray_fluent.importer.subscription_http import (
    SubscriptionFetchError,
    SubscriptionFetchResult,
    SubscriptionServerResponseError,
    SUBSCRIPTION_PARSER_REVISION,
    fetch_subscription,
)


def _subscription() -> SimpleNamespace:
    return SimpleNamespace(
        url="https://sub.example/a",
        parser_revision=SUBSCRIPTION_PARSER_REVISION,
        etag="",
        last_modified="",
    )


class SubscriptionFetchFallbackTest(unittest.TestCase):
    def test_direct_server_response_is_terminal_no_proxy_attempt(self) -> None:
        attempts: list[bool] = []

        def fake(_sub, *, via_proxy, **_kw):
            attempts.append(via_proxy)
            raise SubscriptionServerResponseError("HTTP 404")

        with patch.object(sh, "_fetch_once", side_effect=fake):
            with self.assertRaises(SubscriptionFetchError) as ctx:
                fetch_subscription(_subscription(), mode="auto", proxy_port=1080)

        # Only the direct attempt ran; a real 404 is never retried via the VPN.
        self.assertEqual(attempts, [False])
        self.assertIn("HTTP 404", str(ctx.exception))

    def test_transport_failure_falls_back_to_proxy(self) -> None:
        attempts: list[bool] = []
        proxied = SubscriptionFetchResult(data=b"ok", status=200, via_proxy=True)

        def fake(_sub, *, via_proxy, **_kw):
            attempts.append(via_proxy)
            if not via_proxy:
                raise urllib.error.URLError("_ssl.c:993 handshake timed out")
            return proxied

        with patch.object(sh, "_fetch_once", side_effect=fake):
            result = fetch_subscription(_subscription(), mode="auto", proxy_port=1080)

        # No response on the direct path -> the proxy attempt runs and wins.
        self.assertEqual(attempts, [False, True])
        self.assertIs(result, proxied)

    def test_transport_failure_without_proxy_reports_error(self) -> None:
        def fake(_sub, *, via_proxy, **_kw):
            raise urllib.error.URLError("handshake timed out")

        with patch.object(sh, "_fetch_once", side_effect=fake):
            with self.assertRaises(SubscriptionFetchError) as ctx:
                fetch_subscription(_subscription(), mode="auto", proxy_port=None)

        self.assertIn("Не удалось загрузить подписку", str(ctx.exception))

    def test_proxy_server_response_after_direct_transport_failure_is_terminal(self) -> None:
        attempts: list[bool] = []

        def fake(_sub, *, via_proxy, **_kw):
            attempts.append(via_proxy)
            if not via_proxy:
                raise urllib.error.URLError("connection refused")
            raise SubscriptionServerResponseError("HTTP 404")

        with patch.object(sh, "_fetch_once", side_effect=fake):
            with self.assertRaises(SubscriptionFetchError) as ctx:
                fetch_subscription(_subscription(), mode="auto", proxy_port=1080)

        # Direct had no response, proxy reached the server: surface that answer.
        self.assertEqual(attempts, [False, True])
        self.assertIn("HTTP 404", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
