from __future__ import annotations

import unittest
from unittest.mock import patch

from PyQt6.QtCore import QProcess

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
            "?obfs-password=cover&pinSHA256=deadbeef password=another "
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


if __name__ == "__main__":
    unittest.main()
