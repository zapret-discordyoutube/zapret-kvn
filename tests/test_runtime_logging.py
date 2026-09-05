from __future__ import annotations

import unittest
from concurrent.futures import Future
from unittest.mock import patch

from PyQt6.QtCore import QProcess

from xray_fluent.application.hysteria_runtime_contract import HysteriaFailureCode
from xray_fluent.engines.hysteria.manager import HysteriaManager
from xray_fluent.models import Node
from xray_fluent.runtime_logging import (
    RuntimeLogContext,
    RuntimeNodeIdentity,
    contextualize_runtime_log,
    redact_runtime_log,
)


class RuntimeLoggingTests(unittest.TestCase):
    def test_singbox_outbound_tag_resolves_to_safe_node_identity(self) -> None:
        node = Node(
            id="node-id",
            name="Pinned Hysteria",
            scheme="hysteria2",
            server="2001:db8::1",
            port=443,
        )
        identity = RuntimeNodeIdentity.from_node(node)
        context = RuntimeLogContext(
            engine="sing-box",
            role="front",
            mode="tun",
            generation=7,
            outbound_nodes={"__app_nodes/node_hash": identity},
        )

        detailed = contextualize_runtime_log(
            "ERROR connection using outbound/hysteria2[__app_nodes/node_hash]: "
            "CRYPTO_ERROR 0x150 (remote)",
            context=context,
        )

        self.assertIn('node="Pinned Hysteria"', detailed)
        self.assertIn("endpoint=[2001:db8::1]:443", detailed)
        self.assertIn("protocol=hysteria2", detailed)
        self.assertIn("generation=7", detailed)

    def test_unknown_tag_is_not_misattributed_to_selected_node(self) -> None:
        selected = RuntimeNodeIdentity.from_node(
            Node(name="Selected", scheme="hysteria2", server="selected.example", port=443)
        )
        context = RuntimeLogContext(
            engine="sing-box",
            role="front",
            mode="proxy",
            generation=1,
            selected=selected,
        )

        detailed = contextualize_runtime_log(
            "ERROR using outbound/mystery[unknown-tag]: failed",
            context=context,
        )

        self.assertIn("outbound=unknown-tag", detailed)
        self.assertNotIn("selected.example", detailed)

    def test_redaction_removes_ansi_uris_and_named_secrets(self) -> None:
        raw = (
            "\x1b[31mERROR\x1b[0m hy2://auth@example.com:443/"
            "?obfs-password=cover&pinSHA256=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd password=another "
            '"client_key": "private material"'
        )

        clean = redact_runtime_log(raw)

        for secret in (
            "auth",
            "cover",
            "deadbeef",
            "another",
            "private material",
            "\x1b",
        ):
            self.assertNotIn(secret, clean)
        self.assertIn("ERROR", clean)


class HysteriaLifecycleLoggingTests(unittest.TestCase):
    def test_typed_original_failure_precedes_windows_62097_stop_callback(self) -> None:
        manager = HysteriaManager()
        manager._running = True
        manager._failure_reported = False
        manager._last_failure_code = HysteriaFailureCode.TARGET_NETWORK_TIMEOUT
        events: list[tuple[str, object]] = []
        manager.failure.connect(
            lambda code, _message, _generation: events.append(("failure", code))
        )
        manager.stopped.connect(lambda code: events.append(("stopped", code)))

        with patch.object(manager, "_flush_stdout_buffer"), patch.object(
            manager, "_cleanup_config"
        ):
            manager._on_finished(62097, QProcess.ExitStatus.CrashExit)

        self.assertEqual(
            events,
            [
                ("failure", HysteriaFailureCode.TARGET_NETWORK_TIMEOUT.value),
                ("stopped", 62097),
            ],
        )

    def test_unexpected_exit_during_start_is_classified_as_startup(self) -> None:
        manager = HysteriaManager()
        manager._starting = True
        manager._failure_reported = False
        errors: list[str] = []
        manager.error.connect(errors.append)

        with patch.object(manager, "_flush_stdout_buffer"), patch.object(
            manager, "_cleanup_config"
        ):
            manager._on_finished(23, QProcess.ExitStatus.CrashExit)

        self.assertEqual(len(errors), 1)
        self.assertIn("stage=startup_exit", errors[0])
        self.assertIn("код 23", errors[0])

    def test_hysteria_context_and_uri_are_never_mixed(self) -> None:
        manager = HysteriaManager()
        manager._attempt = 3
        manager._context = RuntimeNodeIdentity.from_node(
            Node(name="Server A", scheme="hysteria2", server="hy.example", port=443)
        )
        manager._secret_values = ("cover-secret",)

        message = manager._format_message(
            "failed hy2://auth@hy.example:443/?obfs-password=cover-secret",
            stage="remote_handshake",
        )

        self.assertIn('node="Server A"', message)
        self.assertIn("endpoint=hy.example:443", message)
        self.assertNotIn("auth@", message)
        self.assertNotIn("cover-secret", message)

    def test_remote_tls_internal_error_schedules_one_chrome_compatibility_retry(self) -> None:
        manager = HysteriaManager()
        manager._running = True
        manager._compatibility_generation = 9
        manager._compatibility_config = {
            "server": "hy2://secret@example.com:443/",
            "quic": {"disableChromeParrot": False},
        }
        manager._compatibility_relay_port = 11809
        manager._compatibility_context = RuntimeNodeIdentity.from_node(
            Node(name="Server A", scheme="hysteria2", server="example.com", port=443)
        )

        with patch("xray_fluent.engines.hysteria.manager.QTimer.singleShot") as single_shot:
            manager._emit_process_line(
                "connect error: CRYPTO_ERROR 0x150 (remote): tls: internal error"
            )

        self.assertTrue(manager._chrome_fallback_pending)
        self.assertTrue(manager._chrome_fallback_used)
        self.assertEqual(single_shot.call_count, 1)
        callback = single_shot.call_args.args[1]
        with patch.object(manager, "start", return_value=True) as start:
            callback()

        self.assertFalse(manager._chrome_fallback_pending)
        self.assertEqual(start.call_count, 1)
        retry_config = start.call_args.args[0]
        self.assertTrue(retry_config["quic"]["disableChromeParrot"])
        self.assertFalse(manager._compatibility_config["quic"]["disableChromeParrot"])
        self.assertTrue(start.call_args.kwargs["_compatibility_retry"])

    def test_second_remote_tls_internal_error_is_terminal_without_third_retry(self) -> None:
        manager = HysteriaManager()
        manager._attempt = 2
        manager._running = True
        manager._chrome_fallback_used = True
        manager._chrome_fallback_pending = False
        manager._chrome_fallback_in_progress = False
        errors: list[str] = []
        manager.error.connect(errors.append)

        with patch("xray_fluent.engines.hysteria.manager.QTimer.singleShot") as single_shot:
            manager._emit_process_line(
                "connect error: CRYPTO_ERROR 0x150 (remote): tls: internal error"
            )

        self.assertEqual(single_shot.call_count, 0)
        self.assertEqual(len(errors), 1)
        self.assertIn("stage=remote_handshake", errors[0])
        self.assertNotIn("hy2://", errors[0])

    def test_external_stop_invalidates_pending_compatibility_retry(self) -> None:
        manager = HysteriaManager()
        manager._compatibility_generation = 3
        manager._compatibility_config = {"server": "hy2://secret@example.com:443/"}
        manager._compatibility_relay_port = 11809
        manager._chrome_fallback_pending = True

        manager.stop(expected=True)

        self.assertGreater(manager._compatibility_generation, 3)
        self.assertIsNone(manager._compatibility_config)
        self.assertFalse(manager._chrome_fallback_pending)

    def test_chrome_fallback_survives_unexpected_process_exit(self) -> None:
        manager = HysteriaManager()
        manager._running = True
        manager._compatibility_generation = 11
        manager._compatibility_config = {
            "server": "hy2://secret@example.com:443/",
            "quic": {"disableChromeParrot": False},
        }
        manager._compatibility_relay_port = 11809
        manager._chrome_fallback_pending = True
        manager._chrome_fallback_used = True
        states: list[bool] = []
        errors: list[str] = []
        manager.state_changed.connect(states.append)
        manager.error.connect(errors.append)

        with patch.object(manager, "_flush_stdout_buffer"), patch.object(
            manager, "_cleanup_config"
        ):
            manager._on_finished(23, QProcess.ExitStatus.CrashExit)

        self.assertEqual(states, [])
        self.assertEqual(errors, [])
        self.assertIsNotNone(manager._compatibility_config)
        with patch.object(manager, "start", return_value=True) as start:
            manager._run_chrome_parrot_fallback(11)
        self.assertEqual(start.call_count, 1)

    def test_failed_compatibility_retry_emits_stopped_state(self) -> None:
        manager = HysteriaManager()
        manager._running = True
        manager._compatibility_generation = 5
        manager._compatibility_config = {
            "server": "hy2://secret@example.com:443/",
            "quic": {"disableChromeParrot": False},
        }
        manager._compatibility_relay_port = 11809
        states: list[bool] = []
        manager.state_changed.connect(states.append)

        def failed_start(*_args, **_kwargs):
            manager._running = False
            return False

        with patch.object(manager, "start", side_effect=failed_start):
            manager._run_chrome_parrot_fallback(5)

        self.assertEqual(states, [False])
        self.assertIsNone(manager._compatibility_config)

    def test_functional_readiness_accepts_an_independent_endpoint_winner(self) -> None:
        manager = HysteriaManager()

        def probe(_relay_port, *, endpoint, **_kwargs):
            if endpoint[1] == "cloudflare-dns.com":
                raise OSError("provider unavailable")

        with patch.object(
            manager._process,
            "state",
            return_value=QProcess.ProcessState.Running,
        ), patch.object(manager, "_probe_remote_endpoint", side_effect=probe):
            self.assertTrue(
                manager._wait_until_remote_ready(
                    11809,
                    username="",
                    password="",
                    timeout=1.0,
                )
            )

    def test_readiness_does_not_probe_after_reported_pin_failure(self) -> None:
        manager = HysteriaManager()
        manager._emit_process_line(
            "connect error: INTERNAL_ERROR (local): no certificate matches the pinned hash"
        )
        with (
            patch.object(manager._process, "state", return_value=QProcess.ProcessState.Running),
            patch.object(manager, "_probe_remote_endpoint") as probe,
        ):
            self.assertFalse(manager._wait_until_remote_ready(11809, username="", password=""))
        probe.assert_not_called()
        self.assertEqual(manager.last_failure_code, HysteriaFailureCode.TARGET_PIN_MISMATCH)

    def test_security_error_supersedes_earlier_timeout_without_losing_raw_logs(self) -> None:
        for security_line, code in (
            ('x509: certificate signed by unknown authority', HysteriaFailureCode.TARGET_TLS_UNKNOWN_AUTHORITY),
            ('no certificate matches the pinned hash', HysteriaFailureCode.TARGET_PIN_MISMATCH),
            ('authentication error: invalid user', HysteriaFailureCode.TARGET_AUTH_REJECTED),
            ('obfs rejected', HysteriaFailureCode.TARGET_OBFS_REJECTED),
        ):
            with self.subTest(code=code):
                manager = HysteriaManager()
                failures = []
                manager.failure.connect(lambda *event: failures.append(event))
                timeout = 'connect error: timeout: no recent network activity'
                manager._emit_process_line(timeout)
                manager._emit_process_line(security_line)
                manager._emit_process_line(timeout)
                manager._emit_process_line(security_line)
                self.assertEqual([event[0] for event in failures],
                                 [HysteriaFailureCode.TARGET_NETWORK_TIMEOUT.value, code.value])
                self.assertEqual(manager.last_failure_code, code)
                self.assertTrue(any(timeout in line for line in manager._last_output_lines))
                self.assertTrue(any(security_line in line for line in manager._last_output_lines))
                with (
                    patch.object(manager._process, 'state', return_value=QProcess.ProcessState.Running),
                    patch.object(manager, '_probe_remote_endpoint') as probe,
                ):
                    self.assertFalse(manager._wait_until_remote_ready(11809, username='', password=''))
                probe.assert_not_called()

    def test_process_log_security_failure_stops_readiness_retry_wave(self) -> None:
        manager = HysteriaManager()
        original = "connect error: INTERNAL_ERROR (local): no certificate matches the pinned hash"
        failures = []
        manager.failure.connect(lambda *event: failures.append(event))
        clock = [0.0]

        class CompletedProbes:
            def __init__(self, **_kwargs):
                pass

            def submit(self, function, *args, **kwargs):
                future = Future()
                try:
                    future.set_result(function(*args, **kwargs))
                except OSError as error:
                    future.set_exception(error)
                return future

            def shutdown(self, **_kwargs):
                pass

        def process_events(delay):
            clock[0] += delay
            if not failures:
                manager._emit_process_line(original)

        with (
            patch.object(manager._process, "state", return_value=QProcess.ProcessState.Running),
            patch.object(manager, "_probe_remote_endpoint", side_effect=OSError("SOCKS CONNECT rejected")) as probe,
            patch("xray_fluent.engines.hysteria.manager.ThreadPoolExecutor", CompletedProbes),
            patch("xray_fluent.engines.hysteria.manager.sleep_with_events", side_effect=process_events),
            patch("xray_fluent.engines.hysteria.manager.time.monotonic", side_effect=lambda: clock[0]),
        ):
            self.assertFalse(manager._wait_until_remote_ready(11809, username="", password="", timeout=0.5))
        self.assertEqual(probe.call_count, 3)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0][0], HysteriaFailureCode.TARGET_PIN_MISMATCH.value)
        self.assertIn(original, failures[0][1])
        self.assertLess(clock[0], 0.5)
        self.assertFalse(any("functional HTTPS probes failed" in line for line in manager._last_output_lines))


if __name__ == "__main__":
    unittest.main()
