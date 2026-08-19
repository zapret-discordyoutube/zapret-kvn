"""Shared HTTP utilities with verified TLS and bounded network retries."""

from __future__ import annotations

import http.client
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.request import Request

try:
    import truststore as _truststore
except ImportError:  # Keep source checkouts usable before dependencies are installed.
    _truststore = None


def _make_ssl_context() -> ssl.SSLContext:
    """Create a verified SSL context backed by the native system trust store.

    On Windows, truststore delegates certificate-chain validation to CryptoAPI.
    This matches native clients and lets Windows build an alternate valid chain
    or fetch a missing intermediate certificate.  The stdlib context remains a
    fallback for development environments where dependencies are not installed.
    """
    if _truststore is not None:
        ctx = _truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    else:
        ctx = ssl.create_default_context()

    # OpenSSL 3.x raises UNEXPECTED_EOF_WHILE_READING when a remote endpoint
    # omits close_notify.  This flag affects shutdown handling, not certificate
    # verification.
    # Available since OpenSSL 3.0 / Python 3.10+
    if hasattr(ssl, "OP_IGNORE_UNEXPECTED_EOF"):
        ctx.options |= ssl.OP_IGNORE_UNEXPECTED_EOF
    return ctx


_ssl_ctx = _make_ssl_context()


class HttpResponseTooLarge(ValueError):
    """The remote response exceeded the caller's explicit size limit."""


class HttpFetchError(OSError):
    """All permitted network routes and retry attempts failed."""

    def __init__(self, causes: tuple[BaseException, ...]):
        self.causes = causes
        super().__init__(f"HTTP request failed after {len(causes)} attempt(s)")


@dataclass(frozen=True, slots=True)
class HttpResponseData:
    data: bytes
    final_url: str
    status: int
    route: str


def urlopen(request: Request | str, *, timeout: float = 15):
    """Drop-in replacement for urllib.request.urlopen with SSL fix."""
    return urllib.request.urlopen(request, timeout=timeout, context=_ssl_ctx)


def build_opener(*handlers: urllib.request.BaseHandler) -> urllib.request.OpenerDirector:
    """Build opener that uses the patched SSL context."""
    https_handler = urllib.request.HTTPSHandler(context=_ssl_ctx)
    return urllib.request.build_opener(https_handler, *handlers)


def _is_retryable_error(error: BaseException) -> bool:
    if isinstance(error, urllib.error.HTTPError):
        return error.code in {408, 425, 429, 500, 502, 503, 504}

    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, ssl.SSLCertVerificationError):
        return False
    if isinstance(reason, socket.gaierror):
        return reason.errno == socket.EAI_AGAIN
    return isinstance(
        reason,
        (
            TimeoutError,
            socket.timeout,
            ConnectionError,
            ssl.SSLEOFError,
            ssl.SSLZeroReturnError,
            http.client.RemoteDisconnected,
            http.client.IncompleteRead,
            http.client.BadStatusLine,
        ),
    )


def _route_opener(proxy_url: str | None) -> urllib.request.OpenerDirector:
    if proxy_url:
        proxy_handler = urllib.request.ProxyHandler(
            {"http": proxy_url, "https": proxy_url}
        )
    else:
        # An explicit empty handler makes the direct route deterministic and
        # prevents ambient environment/system proxy settings from changing it.
        proxy_handler = urllib.request.ProxyHandler({})
    return build_opener(proxy_handler)


def _clone_request(request: Request | str) -> Request | str:
    if isinstance(request, str):
        return request
    # ProxyHandler mutates Request.host/tunnel state in-place. Each route must
    # receive a pristine copy or a failed proxy attempt can poison the direct
    # fallback and silently send it through the same proxy again.
    return Request(
        request.full_url,
        data=request.data,
        headers=dict(request.header_items()),
        origin_req_host=request.origin_req_host,
        unverifiable=request.unverifiable,
        method=request.get_method(),
    )


def fetch_bytes(
    request: Request | str,
    *,
    timeout: float = 10,
    max_bytes: int,
    proxy_url: str | None = None,
    attempts_per_route: int = 2,
    prefer_proxy: bool = False,
    retry_delay: float = 0.2,
    fallback_http_statuses: frozenset[int] = frozenset(),
) -> HttpResponseData:
    """Fetch a small response through explicit routes with bounded retries.

    This helper intentionally reads the body inside the retry boundary, so a
    reset or timeout during ``read()`` can be retried just like a failed TLS
    handshake. Large streaming downloads should keep their own transfer logic.
    """
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if attempts_per_route <= 0:
        raise ValueError("attempts_per_route must be positive")

    routes: list[tuple[str, str | None]] = [("direct", None)]
    if proxy_url:
        proxy_route = ("proxy", proxy_url)
        routes = [proxy_route, routes[0]] if prefer_proxy else [routes[0], proxy_route]

    causes: list[BaseException] = []
    for route_name, route_proxy in routes:
        for attempt in range(attempts_per_route):
            try:
                opener = _route_opener(route_proxy)
                with opener.open(_clone_request(request), timeout=timeout) as response:
                    content_length = response.headers.get("Content-Length")
                    if content_length:
                        try:
                            declared_length = int(content_length)
                        except ValueError:
                            declared_length = 0
                        if declared_length > max_bytes:
                            raise HttpResponseTooLarge(
                                f"HTTP response exceeds {max_bytes} bytes"
                            )

                    data = response.read(max_bytes + 1)
                    if len(data) > max_bytes:
                        raise HttpResponseTooLarge(
                            f"HTTP response exceeds {max_bytes} bytes"
                        )
                    return HttpResponseData(
                        data=data,
                        final_url=str(response.geturl()),
                        status=int(getattr(response, "status", 200) or 200),
                        route=route_name,
                    )
            except HttpResponseTooLarge:
                raise
            except Exception as exc:
                if (
                    isinstance(exc, urllib.error.HTTPError)
                    and exc.code in fallback_http_statuses
                ):
                    exc.close()
                    causes.append(exc)
                    # The response is definitive for this route, but another
                    # egress path can legitimately have different policy.
                    break
                if not _is_retryable_error(exc):
                    raise
                if isinstance(exc, urllib.error.HTTPError):
                    exc.close()
                causes.append(exc)
                if attempt + 1 < attempts_per_route and retry_delay > 0:
                    time.sleep(retry_delay)

    raise HttpFetchError(tuple(causes)) from (causes[-1] if causes else None)
