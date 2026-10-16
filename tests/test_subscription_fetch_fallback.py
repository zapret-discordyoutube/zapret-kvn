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


class CleartextSubscriptionTest(unittest.TestCase):
    """http:// напрямую показал бы провайдеру весь список серверов."""

    def _http(self, url: str = "http://sub.example/a") -> SimpleNamespace:
        subscription = _subscription()
        subscription.url = url
        return subscription

    def test_cleartext_goes_only_through_the_tunnel(self) -> None:
        attempts: list[bool] = []
        proxied = SubscriptionFetchResult(data=b"ok", status=200, via_proxy=True)

        def fake(_sub, *, via_proxy, **_kw):
            attempts.append(via_proxy)
            return proxied

        with patch.object(sh, "_fetch_once", side_effect=fake):
            result = fetch_subscription(self._http(), mode="auto", proxy_port=1080)
        self.assertEqual(attempts, [True])
        self.assertIs(result, proxied)

    def test_cleartext_without_tunnel_is_refused_without_network(self) -> None:
        with patch.object(sh, "_fetch_once") as fetch:
            for mode in ("auto", "direct"):
                with self.assertRaises(SubscriptionFetchError) as ctx:
                    fetch_subscription(self._http(), mode=mode, proxy_port=None)
                self.assertIn("http://", str(ctx.exception))
        fetch.assert_not_called()

    def test_local_network_http_stays_direct(self) -> None:
        for url in ("http://127.0.0.1:8080/s", "http://192.168.1.5/s", "http://localhost/s"):
            self.assertFalse(sh.cleartext_over_internet(url), url)
        self.assertTrue(sh.cleartext_over_internet("http://8.8.8.8/s"))
        self.assertFalse(sh.cleartext_over_internet("https://sub.example/s"))

    def test_direct_redirect_to_cleartext_is_refused(self) -> None:
        handler = sh._SafeRedirectHandler(direct=True)
        with self.assertRaises(SubscriptionFetchError):
            handler.redirect_request(None, None, 302, "Found", {}, "http://sub.example/plain")
