"""Адреса серверов не выходят в логи и экспорт: вместо них «<сервер node_ref>»."""

from __future__ import annotations

import io
import json
import logging
from pathlib import Path
import tempfile
import unittest
import zipfile

from xray_fluent.diagnostics import runtime_logging
from xray_fluent.diagnostics.export import export_diagnostics
from xray_fluent.diagnostics.runtime_errors import RecordedRuntimeFailure, core_failure
from xray_fluent.diagnostics.runtime_logging import (
    RuntimeLogContext,
    RuntimeNodeIdentity,
    ServerAddressLogFilter,
    contextualize_runtime_log,
    node_ref,
    redact_runtime_log,
    redact_server_addresses,
    register_server_aliases,
    register_server_nodes,
)
from xray_fluent.profiles.models import AppState, Node


# Строки из реального лога пользователя (VLESS Reality через xray-сайдкар в TUN).
URANUS = Node(
    id="uranus-node-id",
    name="🇫🇮 Финский сервер Uranus · VLESS TCP · Reality · Yandex",
    scheme="vless",
    server="185-109-21-120.sslip.io",
    port=8443,
)
LEAKS = ("185-109-21-120", "185.109.21.120", "sslip.io")


class ServerAddressRedactionTests(unittest.TestCase):
    def setUp(self) -> None:
        runtime_logging._SERVER_ADDRESSES.clear()
        register_server_nodes([URANUS])
        self.ref = node_ref(URANUS.id)

    def tearDown(self) -> None:
        runtime_logging._SERVER_ADDRESSES.clear()

    def assertNoLeak(self, text: str) -> None:
        for leak in LEAKS:
            self.assertNotIn(leak, text)

    def test_hostname_and_embedded_ip_become_node_ref(self) -> None:
        line = redact_server_addresses(
            "outbound/direct[direct]: outbound connection to 185-109-21-120.sslip.io:8443"
        )
        self.assertEqual(line, f"outbound/direct[direct]: outbound connection to <сервер {self.ref}>:8443")
        line = redact_server_addresses("dial tcp 185.109.21.120:8443: i/o timeout")
        self.assertEqual(line, f"dial tcp <сервер {self.ref}>:8443: i/o timeout")

    def test_destinations_and_local_ports_stay_visible(self) -> None:
        line = (
            "2026/09/27 01:14:05.293136 from udp:127.0.0.1:57691 accepted udp:142.251.38.99:443 "
            "[__app_hybrid_relay_in -> __app_proxy_a76157cc257e86acf904]"
        )
        self.assertEqual(redact_server_addresses(line), line)
        line = "ERROR connection upload closed: read tcp 127.0.0.1:19200->127.0.0.1:59045: wsarecv"
        self.assertEqual(redact_server_addresses(line), line)

    def test_address_boundaries(self) -> None:
        register_server_nodes([Node(id="n2", server="1.2.3.4", port=80)])
        register_server_nodes([Node(id="n3", server="vpn.example.com", port=443)])
        ref2, ref3 = node_ref("n2"), node_ref("n3")
        self.assertEqual(
            redact_server_addresses("11.2.3.45 1.2.3.4:80 1.2.3.40 1.2.3.4."),
            f"11.2.3.45 <сервер {ref2}>:80 1.2.3.40 <сервер {ref2}>.",
        )
        self.assertEqual(
            redact_server_addresses("cdn.vpn.example.com VPN.Example.com. vpn.example.community"),
            f"cdn.vpn.example.com <сервер {ref3}>. vpn.example.community",
        )

    def test_ipv6_server(self) -> None:
        register_server_nodes([Node(id="v6", server="2a01:4f8::1", port=443)])
        ref = node_ref("v6")
        self.assertEqual(
            redact_server_addresses("dial [2a01:4f8::1]:443 via 2a01:4f8::10"),
            f"dial [<сервер {ref}>]:443 via 2a01:4f8::10",
        )

    def test_local_and_private_servers_are_not_masked(self) -> None:
        register_server_nodes([
            Node(id="lo", server="127.0.0.1", port=1080),
            Node(id="lan", server="192.168.0.10", port=1080),
            Node(id="name", server="localhost", port=1080),
        ])
        line = "relay 127.0.0.1:1080 lan 192.168.0.10:1080 localhost:1080"
        self.assertEqual(redact_server_addresses(line), line)

    def test_ips_resolved_by_the_app_join_their_server(self) -> None:
        register_server_nodes([Node(id="dom", server="vpn.example.org", port=443)])
        register_server_aliases("vpn.example.org", ["45.12.34.56"])
        register_server_aliases("unknown.example.net", ["45.12.34.99"])
        self.assertEqual(
            redact_server_addresses("dial 45.12.34.56:443 and 45.12.34.99:443"),
            f"dial <сервер {node_ref('dom')}>:443 and 45.12.34.99:443",
        )

    def test_context_prefix_has_no_address(self) -> None:
        identity = RuntimeNodeIdentity.from_node(URANUS)
        context = RuntimeLogContext("xray", "sidecar", "tun", 3, selected=identity)
        line = contextualize_runtime_log(
            "2026/09/27 01:14:01.431184 from tcp:127.0.0.1:58933 rejected "
            "proxy/socks: failed to read request > EOF",
            context=context,
        )
        self.assertNoLeak(line)
        self.assertNotIn("endpoint=", line)
        self.assertIn(f"node_ref={self.ref}", line)
        self.assertIn("Uranus", line)

    def test_runtime_error_message_is_masked(self) -> None:
        failure = core_failure("sing-box", "runtime", "dial tcp 185.109.21.120:8443: i/o timeout")
        self.assertNoLeak(failure.message)
        self.assertNoLeak(redact_runtime_log("to 185-109-21-120.sslip.io:8443"))

    def test_file_log_filter_masks_module_records(self) -> None:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.addFilter(ServerAddressLogFilter())
        logger = logging.getLogger("tests.log_server_redaction")
        logger.addHandler(handler)
        logger.propagate = False
        try:
            logger.warning("resolve %s -> %s", "185-109-21-120.sslip.io", "185.109.21.120")
        finally:
            logger.removeHandler(handler)
        self.assertNoLeak(stream.getvalue())
        self.assertIn(f"<сервер {self.ref}>", stream.getvalue())

    def test_export_archive_has_no_server_address(self) -> None:
        state = AppState()
        state.nodes = [URANUS]
        runtime_logging._SERVER_ADDRESSES.clear()  # экспорт сам регистрирует узлы состояния
        logs = ["[sing-box] outbound connection to 185-109-21-120.sslip.io:8443"]
        failure = core_failure("xray", "runtime", "failed to dial 185.109.21.120:8443")
        runtime = {"components": {"xray": {"last_written_config": {"config": {
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "185-109-21-120.sslip.io", "port": 8443}]}}],
            "dns": {"servers": ["8.8.8.8"]},
        }}}}}
        with tempfile.TemporaryDirectory() as folder:
            path = export_diagnostics(
                Path(folder) / "diag.zip", state, logs,
                runtime_errors=[RecordedRuntimeFailure(failure, 1.0, 1.0)], runtime=runtime,
            )
            with zipfile.ZipFile(path) as archive:
                files = {name: archive.read(name).decode("utf-8") for name in archive.namelist()}
        text = "\n".join(files.values())
        self.assertNoLeak(text)
        self.assertIn(self.ref, text)
        self.assertIn("8.8.8.8", files["runtime_redacted.json"])
        exported = json.loads(files["state_redacted.json"])
        self.assertTrue(any("Uranus" in str(node.get("name")) for node in exported["nodes"]))


if __name__ == "__main__":
    unittest.main()
