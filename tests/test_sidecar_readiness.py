from __future__ import annotations

import socket
import unittest
from unittest.mock import patch

from PyQt6.QtCore import QCoreApplication

from xray_fluent.engines.sidecar import wait_for_loopback_relay

_APP = QCoreApplication.instance() or QCoreApplication([])


class WaitForLoopbackRelayTests(unittest.TestCase):
    def test_returns_true_when_listener_accepts(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            self.assertTrue(wait_for_loopback_relay(port, host="127.0.0.1", timeout=2.0))

    def test_returns_false_on_timeout_when_nothing_listens(self) -> None:
        # Reserve then close a port so the connection is refused for the whole wait.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        with patch("xray_fluent.engines.sidecar.readiness.sleep_with_events"):
            self.assertFalse(wait_for_loopback_relay(port, host="127.0.0.1", timeout=0.2))

    def test_should_continue_false_aborts_immediately(self) -> None:
        calls: list[int] = []

        def stop_now() -> bool:
            calls.append(1)
            return False

        with patch("xray_fluent.engines.sidecar.readiness.sleep_with_events") as sleeper:
            self.assertFalse(
                wait_for_loopback_relay(1, host="127.0.0.1", timeout=5.0, should_continue=stop_now)
            )
        self.assertEqual(len(calls), 1)
        sleeper.assert_not_called()


if __name__ == "__main__":
    unittest.main()
