import unittest


class SelectorRetryTests(unittest.TestCase):
    """Переключение узла идёт по loopback, но отказ там означает полный
    перезапуск ядра, поэтому единичный таймаут не должен решать исход."""

    def test_transient_timeout_is_retried(self) -> None:
        from urllib.error import URLError

        from xray_fluent.engines.singbox import selector_api

        attempts = []

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        class Opener:
            def open(self, request, timeout):
                attempts.append(timeout)
                if len(attempts) < 3:
                    raise URLError("timed out")
                return Response()

        original_opener = selector_api.build_opener
        original_delay = selector_api.RETRY_DELAY_SEC
        selector_api.build_opener = lambda *args, **kwargs: Opener()
        selector_api.RETRY_DELAY_SEC = 0
        try:
            ok, output = selector_api.select_outbound(9090, "select", "node")
        finally:
            selector_api.build_opener = original_opener
            selector_api.RETRY_DELAY_SEC = original_delay

        self.assertTrue(ok, output)
        self.assertEqual(3, len(attempts))
        self.assertGreaterEqual(attempts[0], 5.0)

    def test_rejection_by_the_core_is_not_retried(self) -> None:
        from urllib.error import HTTPError

        from xray_fluent.engines.singbox import selector_api

        attempts = []

        class Opener:
            def open(self, request, timeout):
                attempts.append(timeout)
                raise HTTPError("url", 404, "Not Found", None, None)

        original_opener = selector_api.build_opener
        selector_api.build_opener = lambda *args, **kwargs: Opener()
        try:
            ok, output = selector_api.select_outbound(9090, "select", "node")
        finally:
            selector_api.build_opener = original_opener

        self.assertFalse(ok)
        self.assertEqual(1, len(attempts))
        self.assertIn("404", output)


if __name__ == "__main__":
    unittest.main()
