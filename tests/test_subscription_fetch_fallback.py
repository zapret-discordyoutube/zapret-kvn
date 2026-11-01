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
import urllib.error
from types import SimpleNamespace
from unittest.mock import patch

from xray_fluent.importer import subscription_http as sh
from xray_fluent.importer.subscription_http import (
    SUBSCRIPTION_PARSER_REVISION,
    SubscriptionFetchError,
    SubscriptionFetchResult,
    SubscriptionServerResponseError,
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


class BrowserStackSubscriptionTest(unittest.TestCase):
    """Прямая попытка — стеком Chromium (рукопожатие как у Chrome), с семантикой urllib."""

    @staticmethod
    def _model(etag: str = ""):
        from xray_fluent.profiles.models import Subscription

        return Subscription(url="https://sub.example/a", etag=etag)

    def _fetch(self, response=None, error=None, *, sub=None):
        from xray_fluent.network import browser_fetch

        calls = []

        class _Service:
            def available(self):
                return True

            def fetch(self, url, *, headers, timeout, max_bytes):
                calls.append((url, dict(headers)))
                if error is not None:
                    raise error
                return response

        with patch.object(browser_fetch, "SERVICE", _Service()), patch.object(sh, "build_opener") as legacy:
            result = sh._fetch_once(sub or self._model(), url="https://sub.example/a", via_proxy=False,
                                    proxy_port=None, timeout=5, max_bytes=1024)
        legacy.return_value.open.assert_not_called()
        return result, calls

    def test_body_and_headers_come_from_the_browser_stack(self) -> None:
        from xray_fluent.network.browser_fetch import BrowserResponse

        result, calls = self._fetch(BrowserResponse(status=200, headers=(("ETag", "v1"),), body=b"vless://x"))
        self.assertEqual((result.data, result.headers["etag"], result.via_proxy), (b"vless://x", "v1", False))
        self.assertEqual(calls[0][0], "https://sub.example/a")
        self.assertIn("User-Agent", calls[0][1])  # профиль клиента подписки сохраняется

    def test_server_refusal_is_terminal(self) -> None:
        from xray_fluent.network.browser_fetch import BrowserResponse

        with self.assertRaises(SubscriptionServerResponseError):
            self._fetch(BrowserResponse(status=404))

    def test_no_response_is_a_transport_failure(self) -> None:
        from xray_fluent.network.browser_fetch import BrowserFetchError

        with self.assertRaises(urllib.error.URLError):
            self._fetch(error=BrowserFetchError("net::ERR_CONNECTION_RESET"))

    def test_oversized_body_is_refused(self) -> None:
        from xray_fluent.network.browser_fetch import BrowserResponse

        with self.assertRaises(SubscriptionServerResponseError):
            self._fetch(BrowserResponse(status=200, body=b"x" * 2048, truncated=True))

    def test_redirect_to_cleartext_is_refused(self) -> None:
        from xray_fluent.network.browser_fetch import BrowserResponse

        with self.assertRaises(SubscriptionFetchError) as caught:
            self._fetch(BrowserResponse(status=302, redirect_refused="http://sub.example/plain"))
        self.assertIn("http://", str(caught.exception))

    def test_local_network_http_goes_direct_through_urllib(self) -> None:
        """Подписка из локальной сети по http://: стек Chromium открытый текст не берёт."""

        import http.server
        import threading

        from xray_fluent.network import browser_fetch
        from xray_fluent.profiles.models import Subscription

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"vless://00000000-0000-4000-8000-000000000001@203.0.113.10:443?security=tls#Node\n"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        class _Service:
            calls = 0

            def available(self):
                return True

            def fetch(self, *_args, **_kwargs):
                _Service.calls += 1
                raise browser_fetch.BrowserFetchError("browserfetch: only https is allowed: http")

        subscription = Subscription(url=f"http://127.0.0.1:{server.server_port}/sub", parser_revision=SUBSCRIPTION_PARSER_REVISION)
        with patch.object(browser_fetch, "SERVICE", _Service()):
            result = fetch_subscription(subscription, mode="auto", proxy_port=None)
        self.assertEqual((result.status, result.via_proxy, _Service.calls), (200, False, 0))
        self.assertTrue(result.data.startswith(b"vless://"))

    def test_not_modified_needs_a_conditional_request(self) -> None:
        from xray_fluent.network.browser_fetch import BrowserResponse

        result, calls = self._fetch(BrowserResponse(status=304), sub=self._model(etag="v1"))
        self.assertTrue(result.not_modified)
        self.assertEqual(calls[0][1]["If-None-Match"], "v1")


class UnreachableSubscriptionMessageTest(unittest.TestCase):
    """Таймаут прямого пути не виден, если VPN довёз подписку; полный отказ — простыми словами."""

    _DEADLINE = "browser-fetch: context deadline exceeded"

    def _browser(self, error):
        from xray_fluent.network import browser_fetch

        class _Service:
            def available(self):
                return True

            def fetch(self, url, *, headers, timeout, max_bytes):
                raise error

        return patch.object(browser_fetch, "SERVICE", _Service())

    def test_direct_deadline_is_hidden_when_the_vpn_route_succeeds(self) -> None:
        from xray_fluent.network.browser_fetch import BrowserFetchError

        proxied = SubscriptionFetchResult(data=b"ok", status=200, via_proxy=True)
        real_once = sh._fetch_once

        from xray_fluent.profiles.models import Subscription

        subscription = Subscription(url="https://sub.example/a", parser_revision=SUBSCRIPTION_PARSER_REVISION)
        directs: list[BaseException] = []

        def direct(sub, **kw):
            try:
                return real_once(sub, **kw)
            except Exception as exc:  # тест: запомнить, чем кончился прямой путь
                directs.append(exc)
                raise

        def route(sub, **kw):
            return proxied if kw["via_proxy"] else direct(sub, **kw)

        with self._browser(BrowserFetchError(self._DEADLINE)), patch.object(sh, "_fetch_once", side_effect=route):
            result = fetch_subscription(subscription, mode="auto", proxy_port=1080)
        self.assertIsInstance(directs[0], urllib.error.URLError)
        self.assertIs(result, proxied)

    def test_direct_deadline_without_vpn_says_what_failed(self) -> None:
        from xray_fluent.network.browser_fetch import BrowserFetchError
        from xray_fluent.profiles.models import Subscription

        subscription = Subscription(url="https://sub.example/a", parser_revision=SUBSCRIPTION_PARSER_REVISION)
        with self._browser(BrowserFetchError(self._DEADLINE)), self.assertRaises(sh.SubscriptionUnreachableError) as caught:
            fetch_subscription(subscription, mode="auto", proxy_port=None)
        message = str(caught.exception)
        self.assertRegex(
            message,
            r"^Не удалось загрузить подписку напрямую: сервер не ответил за \d+ с\. "
            r"VPN не был подключён, через VPN не пробовали$",
        )
        self.assertNotIn("deadline", message)
        self.assertNotIn("urlopen", message)
        self.assertTrue(caught.exception.tunnel_untried)

    def test_explicit_direct_mode_is_not_waiting_for_the_vpn(self) -> None:
        def fake(_sub, *, via_proxy, **_kw):
            raise urllib.error.URLError(ConnectionRefusedError(10061, "refused"))

        with patch.object(sh, "_fetch_once", side_effect=fake), self.assertRaises(sh.SubscriptionUnreachableError) as caught:
            fetch_subscription(_subscription(), mode="direct", proxy_port=1080)
        self.assertEqual(str(caught.exception), "Не удалось загрузить подписку напрямую: сервер отклонил подключение")
        self.assertFalse(caught.exception.tunnel_untried)

    def test_both_routes_failed_names_each_route(self) -> None:
        def fake(_sub, *, via_proxy, **_kw):
            if via_proxy:
                raise urllib.error.URLError(OSError("Tunnel connection failed: 502 Bad Gateway"))
            raise urllib.error.URLError(self._DEADLINE)

        with patch.object(sh, "_fetch_once", side_effect=fake), self.assertRaises(sh.SubscriptionUnreachableError) as caught:
            fetch_subscription(_subscription(), mode="auto", proxy_port=1080)
        self.assertRegex(
            str(caught.exception),
            r"^Не удалось загрузить подписку ни напрямую, ни через VPN: "
            r"напрямую — сервер не ответил за \d+ с; через VPN — VPN не пропустил запрос к серверу$",
        )
        self.assertFalse(caught.exception.tunnel_untried)

    def test_route_still_silent_at_the_deadline(self) -> None:
        import threading

        release = threading.Event()

        def fake(_sub, *, via_proxy, **_kw):
            release.wait(5)
            raise urllib.error.URLError("late")

        try:
            with patch.object(sh, "_fetch_once", side_effect=fake), self.assertRaises(sh.SubscriptionUnreachableError) as caught:
                fetch_subscription(_subscription(), mode="auto", proxy_port=None, deadline=0.3)
        finally:
            release.set()
        self.assertEqual(
            str(caught.exception),
            "Не удалось загрузить подписку напрямую: сервер не ответил за 1 с. "
            "VPN не был подключён, через VPN не пробовали",
        )
