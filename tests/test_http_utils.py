from __future__ import annotations

import ssl
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.error
import urllib.request

from xray_fluent.network import http_utils


class _FakeSslContext:
    def __init__(self) -> None:
        self.options = 0


class _FakeResponse:
    def __init__(self, data: bytes, *, content_length: str | None = None) -> None:
        self._data = data
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length
        self.status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self, limit: int = -1) -> bytes:
        return self._data if limit < 0 else self._data[:limit]

    def geturl(self) -> str:
        return "https://git.zapret.moe/test"


class HttpUtilsTests(unittest.TestCase):
    def test_shared_context_keeps_tls_verification_enabled(self) -> None:
        self.assertTrue(http_utils._ssl_ctx.check_hostname)
        self.assertEqual(http_utils._ssl_ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_native_trust_store_context_is_preferred(self) -> None:
        context = _FakeSslContext()
        factory = Mock(return_value=context)

        with patch.object(
            http_utils,
            "_truststore",
            SimpleNamespace(SSLContext=factory),
        ):
            result = http_utils._make_ssl_context()

        self.assertIs(result, context)
        factory.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)

    def test_stdlib_context_remains_a_dependency_fallback(self) -> None:
        context = _FakeSslContext()

        with (
            patch.object(http_utils, "_truststore", None),
            patch.object(ssl, "create_default_context", return_value=context) as factory,
        ):
            result = http_utils._make_ssl_context()

        self.assertIs(result, context)
        factory.assert_called_once_with()

    def test_fetch_bytes_retries_transient_handshake_timeout(self) -> None:
        opener = Mock()
        opener.open.side_effect = [
            urllib.error.URLError(TimeoutError("handshake timed out")),
            _FakeResponse(b"ok"),
        ]

        with (
            patch.object(http_utils, "_route_opener", return_value=opener),
            patch.object(http_utils.time, "sleep"),
        ):
            response = http_utils.fetch_bytes(
                "https://git.zapret.moe/test",
                max_bytes=16,
                attempts_per_route=2,
            )

        self.assertEqual(response.data, b"ok")
        self.assertEqual(response.route, "direct")
        self.assertEqual(opener.open.call_count, 2)

    def test_fetch_bytes_prefers_explicit_proxy_when_requested(self) -> None:
        routes: list[str | None] = []
        opener = Mock()
        opener.open.return_value = _FakeResponse(b"ok")

        def make_opener(proxy_url: str | None):
            routes.append(proxy_url)
            return opener

        with patch.object(http_utils, "_route_opener", side_effect=make_opener):
            response = http_utils.fetch_bytes(
                "https://git.zapret.moe/test",
                max_bytes=16,
                proxy_url="http://127.0.0.1:1391",
                prefer_proxy=True,
            )

        self.assertEqual(response.route, "proxy")
        self.assertEqual(routes, ["http://127.0.0.1:1391"])

    def test_fetch_bytes_does_not_retry_certificate_failure(self) -> None:
        opener = Mock()
        certificate_error = ssl.SSLCertVerificationError(1, "bad certificate")
        opener.open.side_effect = urllib.error.URLError(certificate_error)

        with patch.object(http_utils, "_route_opener", return_value=opener):
            with self.assertRaises(urllib.error.URLError):
                http_utils.fetch_bytes(
                    "https://git.zapret.moe/test",
                    max_bytes=16,
                    attempts_per_route=2,
                )

        opener.open.assert_called_once()

    def test_fetch_bytes_rejects_oversized_response(self) -> None:
        opener = Mock()
        opener.open.return_value = _FakeResponse(b"012345", content_length="6")

        with patch.object(http_utils, "_route_opener", return_value=opener):
            with self.assertRaises(http_utils.HttpResponseTooLarge):
                http_utils.fetch_bytes(
                    "https://git.zapret.moe/test",
                    max_bytes=5,
                )

    def test_route_specific_451_falls_back_from_proxy_to_direct(self) -> None:
        seen_hosts: list[tuple[str, str]] = []

        class ProxyOpener:
            def open(self, request, *, timeout):
                request.set_proxy("127.0.0.1:1391", "http")
                seen_hosts.append(("proxy", request.host))
                raise urllib.error.HTTPError(
                    request.full_url, 451, "Unavailable", {}, None
                )

        class DirectOpener:
            def open(self, request, *, timeout):
                seen_hosts.append(("direct", request.host))
                return _FakeResponse(b"ok")

        proxy_opener = ProxyOpener()
        direct_opener = DirectOpener()

        def make_opener(proxy_url: str | None):
            return proxy_opener if proxy_url else direct_opener

        with patch.object(http_utils, "_route_opener", side_effect=make_opener):
            response = http_utils.fetch_bytes(
                urllib.request.Request("https://git.zapret.moe/test"),
                max_bytes=16,
                proxy_url="http://127.0.0.1:1391",
                prefer_proxy=True,
                fallback_http_statuses=frozenset({451}),
            )

        self.assertEqual(response.route, "direct")
        self.assertEqual(
            seen_hosts,
            [("proxy", "127.0.0.1:1391"), ("direct", "git.zapret.moe")],
        )


if __name__ == "__main__":
    unittest.main()
