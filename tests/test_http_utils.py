from __future__ import annotations

import ssl
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from xray_fluent import http_utils


class _FakeSslContext:
    def __init__(self) -> None:
        self.options = 0


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


if __name__ == "__main__":
    unittest.main()
