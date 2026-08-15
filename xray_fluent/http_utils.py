"""Shared HTTP utilities with SSL error resilience."""

from __future__ import annotations

import ssl
import urllib.request
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


def urlopen(request: Request | str, *, timeout: float = 15):
    """Drop-in replacement for urllib.request.urlopen with SSL fix."""
    return urllib.request.urlopen(request, timeout=timeout, context=_ssl_ctx)


def build_opener(*handlers: urllib.request.BaseHandler) -> urllib.request.OpenerDirector:
    """Build opener that uses the patched SSL context."""
    https_handler = urllib.request.HTTPSHandler(context=_ssl_ctx)
    return urllib.request.build_opener(https_handler, *handlers)
