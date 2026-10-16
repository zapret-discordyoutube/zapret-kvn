"""Клиент браузерного стека (xray_fluent/network/browser_fetch.py) на подделке процесса."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import threading
import unittest

from xray_fluent.network.browser_fetch import (
    BrowserFetchError,
    BrowserFetchService,
    BrowserFetchUnavailable,
)

FAKE = Path(__file__).resolve().parent / "fixtures" / "fake_browser_fetch.py"


def _service() -> BrowserFetchService:
    return BrowserFetchService(executable=lambda: FAKE, launcher=lambda exe: [sys.executable, "-I", str(exe)])


class BrowserFetchServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = _service()
        self.addCleanup(self.service.close)

    def test_request_round_trip_keeps_method_headers_and_body(self) -> None:
        response = self.service.fetch(
            "https://8.8.8.8/dns-query", method="POST",
            headers=(("accept", "application/dns-message"),), body=b"\x00\x01", timeout=5,
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(response.header("content-type"), "application/json")
        echo = json.loads(response.body)
        self.assertEqual(echo["method"], "POST")
        self.assertEqual(echo["headers"], [["accept", "application/dns-message"]])
        self.assertEqual(echo["body"], "AAE=")

    def test_parallel_requests_share_one_process(self) -> None:
        results: list[int] = []

        def run() -> None:
            results.append(self.service.fetch("https://example.com/", timeout=5).status)

        threads = [threading.Thread(target=run) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertEqual(results, [200] * 8)

    def test_network_error_is_reported(self) -> None:
        with self.assertRaises(BrowserFetchError) as caught:
            self.service.fetch("https://fail.example/", timeout=5)
        self.assertNotIsInstance(caught.exception, BrowserFetchUnavailable)

    def test_crashed_process_fails_pending_and_restarts(self) -> None:
        with self.assertRaises(BrowserFetchError):
            self.service.fetch("https://crash.example/", timeout=5)
        self.assertEqual(self.service.fetch("https://example.com/", timeout=5).status, 200)

    def test_core_without_chromium_library_is_unavailable(self) -> None:
        with self.assertRaises(BrowserFetchUnavailable):
            self.service.fetch("https://nolib.example/", timeout=5)

    def test_missing_core_is_unavailable(self) -> None:
        service = BrowserFetchService(executable=lambda: Path("/nonexistent/sing-box.exe"))
        self.assertFalse(service.available())
        with self.assertRaises(BrowserFetchUnavailable):
            service.fetch("https://example.com/", timeout=1)


if __name__ == "__main__":
    unittest.main()
