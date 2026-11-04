from __future__ import annotations

import os
import socket
import subprocess
import unittest
from unittest.mock import patch

from xray_fluent.engines.xray import balancer_api as api


def _result(code: int, text: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(["xray"], code, stdout=text.encode(), stderr=b"")


class DialRetryTests(unittest.TestCase):
    def run_override(self, results, *, pump=False):
        calls: list[list[str]] = []
        queue = list(results)

        def fake_run(command, **_kwargs):
            calls.append(list(command))
            return queue.pop(0)

        with (
            patch.object(api, "run_text", fake_run),
            patch.object(api, "run_text_pumped", fake_run),
            patch.object(api, "result_output_text", lambda result: result.stdout.decode()),
            patch.object(api.time, "sleep", lambda _s: None),
        ):
            outcome = api.apply_balancer_override("xray", 19085, "bal", "proxy-1", pump=pump)
        return outcome, calls

    def test_call_uses_a_longer_timeout_than_the_cores_three_seconds(self) -> None:
        (ok, _text), calls = self.run_override([_result(0)])
        self.assertTrue(ok)
        self.assertIn(f"--timeout={api.API_CALL_TIMEOUT_SEC}", calls[0])
        self.assertGreater(api.API_CALL_TIMEOUT_SEC, 3)
        self.assertGreater(api.COMMAND_TIMEOUT_SEC, api.API_CALL_TIMEOUT_SEC)

    def test_failed_dial_is_retried_in_a_worker_and_can_succeed(self) -> None:
        (ok, _text), calls = self.run_override(
            [_result(1, "failed to dial 127.0.0.1:19085"), _result(1, "failed to dial 127.0.0.1:19085"), _result(0)]
        )
        self.assertTrue(ok)
        self.assertEqual(len(calls), 3)

    def test_main_thread_pumped_call_never_sleeps_between_retries(self) -> None:
        (ok, text), calls = self.run_override([_result(1, "failed to dial 127.0.0.1:19085")], pump=True)
        self.assertFalse(ok)
        self.assertEqual(len(calls), 1)
        self.assertIn("failed to dial", text)

    def test_other_errors_are_not_retried(self) -> None:
        (ok, text), calls = self.run_override([_result(1, "rpc error: balancer not found")])
        self.assertFalse(ok)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("TCP до порта", text)

    def test_final_dial_failure_explains_what_this_pc_sees(self) -> None:
        with patch.object(api, "describe_api_reachability", lambda port: f"диагноз порта {port}"):
            (ok, text), calls = self.run_override([_result(1, "failed to dial 127.0.0.1:19085")] * api.DIAL_ATTEMPTS)
        self.assertFalse(ok)
        self.assertEqual(len(calls), api.DIAL_ATTEMPTS)
        self.assertTrue(text.endswith("[диагноз порта 19085]"), text)


class ReachabilityTests(unittest.TestCase):
    def test_open_port_is_reported_as_tcp_ok_grpc_silent(self) -> None:
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            text = api.describe_api_reachability(server.getsockname()[1])
        self.assertIn("есть", text)
        self.assertIn("gRPC не ответил", text)

    def test_closed_port_is_reported_and_proxy_env_names_never_values(self) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://user:secret@10.0.0.1:3128"}):
            text = api.describe_api_reachability(port)
        self.assertIn("не открылся", text)
        self.assertIn("HTTPS_PROXY", text)
        self.assertNotIn("secret", text)
        self.assertNotIn("10.0.0.1", text)


if __name__ == "__main__":
    unittest.main()
