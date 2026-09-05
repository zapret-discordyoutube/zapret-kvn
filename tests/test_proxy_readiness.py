from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from xray_fluent.network.proxy_readiness import (
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
    @patch("xray_fluent.network.proxy_readiness.socket.create_connection")
    def test_socks_probe_requires_socks5_no_auth_reply(self, connect: Mock) -> None:
        client = _client(b"\x05\x00")
        connect.return_value = client

        self.assertTrue(probe_socks5_listener(1390))

        client.sendall.assert_called_once_with(b"\x05\x01\x00")
        connect.assert_called_once_with(("127.0.0.1", 1390), timeout=0.35)

    @patch("xray_fluent.network.proxy_readiness.socket.create_connection")
    def test_socks_probe_rejects_unrelated_tcp_listener(self, connect: Mock) -> None:
        connect.return_value = _client(b"HTTP/1.1 400")

        self.assertFalse(probe_socks5_listener(1390))

    @patch("xray_fluent.network.proxy_readiness.socket.create_connection")
    def test_http_probe_requires_http_status_line(self, connect: Mock) -> None:
        client = _client(b"HTTP/1.1 400 Bad Request")
        connect.return_value = client

        self.assertTrue(probe_http_proxy_listener(1391))

        request = client.sendall.call_args.args[0]
        self.assertTrue(request.startswith(b"OPTIONS * HTTP/1.1\r\n"))

    @patch("xray_fluent.network.proxy_readiness.probe_socks5_listener", return_value=True)
    @patch("xray_fluent.network.proxy_readiness.probe_http_proxy_listener", return_value=True)
    def test_role_dispatch_is_protocol_specific(self, http_probe: Mock, socks_probe: Mock) -> None:
        self.assertTrue(probe_listener_role(1390, "SOCKS"))
        self.assertTrue(probe_listener_role(1391, "HTTP"))

        socks_probe.assert_called_once_with(1390)
        http_probe.assert_called_once_with(1391)

    @patch("xray_fluent.network.proxy_readiness.socket.create_connection")
    def test_socks_probe_rejects_listener_without_usable_auth(self, connect: Mock) -> None:
        # A listening SOCKS server is not ready when it rejects admission.
        client = _client(b"\x05\xff")
        connect.return_value = client

        self.assertFalse(probe_socks5_listener(11808))

        client.sendall.assert_called_once_with(b"\x05\x01\x00")

    @patch("xray_fluent.network.proxy_readiness.socket.create_connection")
    def test_socks_probe_completes_password_subnegotiation(self, connect: Mock) -> None:
        client = _client(b"")
        client.recv.side_effect = [b"\x05\x02", b"\x01\x00"]
        connect.return_value = client

        self.assertTrue(
            probe_socks5_listener(11808, username="sidecar-a1b2c3", password="secret")
        )

        greeting = client.sendall.call_args_list[0].args[0]
        self.assertEqual(b"\x05\x01\x02", greeting)
        auth_frame = client.sendall.call_args_list[1].args[0]
        self.assertEqual(
            b"\x01" + bytes((len(b"sidecar-a1b2c3"),)) + b"sidecar-a1b2c3"
            + bytes((len(b"secret"),)) + b"secret",
            auth_frame,
        )

    @patch("xray_fluent.network.proxy_readiness.socket.create_connection")
    def test_socks_probe_rejects_failed_password_auth(self, connect: Mock) -> None:
        client = _client(b"")
        client.recv.side_effect = [b"\x05\x02", b"\x01\x01"]
        connect.return_value = client

        self.assertFalse(probe_socks5_listener(11808, username="user", password="bad"))

    @patch("xray_fluent.network.proxy_readiness.socket.create_connection")
    def test_socks_probe_rejects_auth_downgrade(self, connect: Mock) -> None:
        client = _client(b"\x05\x00")
        connect.return_value = client

        self.assertFalse(probe_socks5_listener(11808, username="user", password="pass"))

        client.sendall.assert_called_once_with(b"\x05\x01\x02")

    @patch("xray_fluent.network.proxy_readiness.socket.create_connection")
    def test_socks_probe_rejects_unoffered_method_choice(self, connect: Mock) -> None:
        connect.return_value = _client(b"\x05\x02")

        self.assertFalse(probe_socks5_listener(11808))

    @patch("xray_fluent.network.proxy_readiness.probe_socks5_listener", return_value=True)
    def test_role_dispatch_forwards_credentials_only_to_socks(self, socks_probe: Mock) -> None:
        self.assertTrue(
            probe_listener_role(11808, "SOCKS", username="user", password="pass")
        )
        socks_probe.assert_called_once_with(11808, username="user", password="pass")

    @patch("xray_fluent.network.proxy_readiness.probe_tcp_listener", return_value=True)
    def test_role_dispatch_ignores_credentials_for_tcp_roles(self, tcp_probe: Mock) -> None:
        self.assertTrue(probe_listener_role(19085, "API", username="user", password="pass"))
        tcp_probe.assert_called_once_with(19085)


if __name__ == "__main__":
    unittest.main()
