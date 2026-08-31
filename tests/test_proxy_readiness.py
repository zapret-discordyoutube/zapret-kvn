from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from xray_fluent.proxy_readiness import (
    probe_http_proxy_listener,
    probe_listener_role,
    probe_socks5_listener,
)


def _client(response: bytes) -> Mock:
    client = Mock()
    client.__enter__ = Mock(return_value=client)
    client.__exit__ = Mock(return_value=False)
    client.recv.return_value = response
    return client


class ProxyReadinessTests(unittest.TestCase):
    @patch("xray_fluent.proxy_readiness.socket.create_connection")
    def test_socks_probe_requires_socks5_no_auth_reply(self, connect: Mock) -> None:
        client = _client(b"\x05\x00")
        connect.return_value = client

        self.assertTrue(probe_socks5_listener(1390))

        client.sendall.assert_called_once_with(b"\x05\x01\x00")
        connect.assert_called_once_with(("127.0.0.1", 1390), timeout=0.35)

    @patch("xray_fluent.proxy_readiness.socket.create_connection")
    def test_socks_probe_rejects_unrelated_tcp_listener(self, connect: Mock) -> None:
        connect.return_value = _client(b"HTTP/1.1 400")

        self.assertFalse(probe_socks5_listener(1390))

    @patch("xray_fluent.proxy_readiness.socket.create_connection")
    def test_http_probe_requires_http_status_line(self, connect: Mock) -> None:
        client = _client(b"HTTP/1.1 400 Bad Request")
        connect.return_value = client

        self.assertTrue(probe_http_proxy_listener(1391))

        request = client.sendall.call_args.args[0]
        self.assertTrue(request.startswith(b"OPTIONS * HTTP/1.1\r\n"))

    @patch("xray_fluent.proxy_readiness.probe_socks5_listener", return_value=True)
    @patch("xray_fluent.proxy_readiness.probe_http_proxy_listener", return_value=True)
    def test_role_dispatch_is_protocol_specific(self, http_probe: Mock, socks_probe: Mock) -> None:
        self.assertTrue(probe_listener_role(1390, "SOCKS"))
        self.assertTrue(probe_listener_role(1391, "HTTP"))

        socks_probe.assert_called_once_with(1390)
        http_probe.assert_called_once_with(1391)


if __name__ == "__main__":
    unittest.main()
