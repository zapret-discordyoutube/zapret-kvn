"""Причина сетевого отказа простыми словами: одинаково для Chromium и urllib."""

from __future__ import annotations

import socket
import ssl
import unittest
import urllib.error

from xray_fluent.network.browser_fetch import BrowserFetchError
from xray_fluent.network.fetch_failure import (
    SLOW_TRANSFER,
    SlowTransferError,
    describe_transport_failure,
)


class DescribeTransportFailureTest(unittest.TestCase):
    def test_chromium_deadline_is_silence_with_the_waited_time(self) -> None:
        # Так приходит молчащий сервер или заглохший DoH: текст ядра — без фазы.
        error = urllib.error.URLError(str(BrowserFetchError("browser-fetch: context deadline exceeded")))
        self.assertEqual(describe_transport_failure(error, 15.4), "сервер не ответил за 15 с")

    def test_chromium_codes(self) -> None:
        cases = {
            "net::ERR_NAME_NOT_RESOLVED": "не удалось узнать адрес сервера (DNS)",
            "net::ERR_CONNECTION_TIMED_OUT": "сервер не ответил за 3 с",
            "net::ERR_CONNECTION_REFUSED": "сервер отклонил подключение",
            "net::ERR_CONNECTION_RESET": "соединение оборвалось — похоже на блокировку",
            "net::ERR_NETWORK_ACCESS_DENIED": "доступ в сеть запрещён брандмауэром или антивирусом",
            "net::ERR_INTERNET_DISCONNECTED": "нет доступа к сети",
            "net::ERR_CERT_AUTHORITY_INVALID": "сертификат сервера не прошёл проверку",
            "net::ERR_SSL_PROTOCOL_ERROR": "сбой защищённого соединения (TLS) — похоже на блокировку",
            "browser-fetch: нет ответа за 15 с": "сервер не ответил за 3 с",
        }
        for text, expected in cases.items():
            with self.subTest(text):
                error = urllib.error.URLError(f"browser-fetch: {text}")
                self.assertEqual(describe_transport_failure(error, 3.0), expected)

    def test_urllib_reasons(self) -> None:
        cases = (
            (TimeoutError("timed out"), "сервер не ответил за 15 с"),
            (TimeoutError(), "сервер не ответил за 15 с"),
            (socket.gaierror(11001, "getaddrinfo failed"), "не удалось узнать адрес сервера (DNS)"),
            (ConnectionRefusedError(10061, "refused"), "сервер отклонил подключение"),
            (ConnectionResetError(10054, "reset"), "соединение оборвалось — похоже на блокировку"),
            (ssl.SSLEOFError(8, "EOF occurred in violation of protocol"), "соединение оборвалось — похоже на блокировку"),
            (OSError("Tunnel connection failed: 502 Bad Gateway"), "VPN не пропустил запрос к серверу"),
            (SlowTransferError("медленно"), SLOW_TRANSFER),
        )
        for reason, expected in cases:
            with self.subTest(repr(reason)):
                self.assertEqual(describe_transport_failure(urllib.error.URLError(reason), 15.0), expected)
                self.assertEqual(describe_transport_failure(reason, 15.0), expected)

    def test_unknown_error_keeps_its_text(self) -> None:
        self.assertEqual(
            describe_transport_failure(OSError("something odd"), 1.0),
            "сетевая ошибка (something odd)",
        )


if __name__ == "__main__":
    unittest.main()
