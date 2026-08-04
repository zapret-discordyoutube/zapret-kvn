from __future__ import annotations

import unittest
from unittest.mock import Mock

from xray_fluent.background_workers import ProxyProtectionResolver, StateSaveWorker


class BackgroundWorkerTests(unittest.TestCase):
    def test_proxy_resolution_reports_generation_and_result(self) -> None:
        events: list[tuple[int, str, set[str], Exception | None]] = []
        worker = ProxyProtectionResolver(
            7,
            "proxy.example.com",
            lambda _server: {"203.0.113.7"},
        )
        worker.resolved.connect(lambda *args: events.append(args))

        worker.run()

        self.assertEqual(events, [(7, "proxy.example.com", {"203.0.113.7"}, None)])

    def test_proxy_resolution_returns_errors_instead_of_raising(self) -> None:
        error = OSError("DNS unavailable")
        events = []

        def fail(_server: str) -> set[str]:
            raise error

        worker = ProxyProtectionResolver(8, "proxy.example.com", fail)
        worker.resolved.connect(lambda *args: events.append(args))

        worker.run()

        self.assertEqual(events, [(8, "proxy.example.com", set(), error)])

    def test_state_save_worker_delegates_write_off_the_caller(self) -> None:
        storage = Mock()
        state = object()
        worker = StateSaveWorker(storage, state)

        worker.run()

        storage.save.assert_called_once_with(state)


if __name__ == "__main__":
    unittest.main()
