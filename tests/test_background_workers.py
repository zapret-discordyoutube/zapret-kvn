from __future__ import annotations

import threading
import time
import unittest
from unittest.mock import Mock

from PyQt6.QtCore import Qt

from xray_fluent.network.background_workers import ProxyProtectionResolver, StateWriter


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

    def test_state_writer_writes_off_the_caller_thread(self) -> None:
        caller = threading.get_ident()
        writes = []
        storage = Mock()
        storage.write_serialized.side_effect = lambda payload, pw: writes.append((payload, pw, threading.get_ident()))
        writer = StateWriter(storage)
        writer.submit("{}", "pw")
        self.assertTrue(writer.close())
        self.assertEqual([(p, pw) for p, pw, _ in writes], [("{}", "pw")])
        self.assertNotEqual(writes[0][2], caller)

    def test_state_writer_coalesces_to_latest_snapshot(self) -> None:
        gate = threading.Event()
        writes = []

        def slow_write(payload, pw):
            gate.wait(2)
            writes.append(payload)

        storage = Mock()
        storage.write_serialized.side_effect = slow_write
        writer = StateWriter(storage)
        writer.submit("first", "")
        time.sleep(0.05)  # писатель занят первым снимком
        for payload in ("second", "third", "latest"):
            writer.submit(payload, "")
        gate.set()
        self.assertTrue(writer.close())
        self.assertEqual(writes, ["first", "latest"])

    def test_state_writer_reports_failures(self) -> None:
        storage = Mock()
        storage.write_serialized.side_effect = OSError("disk full")
        writer = StateWriter(storage)
        errors = []
        writer.failed.connect(errors.append, Qt.ConnectionType.DirectConnection)
        writer.submit("{}", "")
        self.assertTrue(writer.close())
        self.assertEqual(errors, ["disk full"])

if __name__ == "__main__":
    unittest.main()
