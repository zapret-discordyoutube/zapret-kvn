"""Причина сетевого отказа — простыми словами.

Один и тот же отказ стеки называют по-разному: Chromium (``browser-fetch``) —
кодом ``net::ERR_…`` или ``context deadline exceeded``, urllib — исключением
``socket``/``ssl`` внутри ``URLError``. Пользователь должен увидеть, что
случилось (адрес не нашёлся, сервер молчит, соединение оборвали), а не текст
исключения. Технический текст остаётся в журнале.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import urllib.error


class SlowTransferError(TimeoutError):
    """Сервер ответил, но тело идёт медленнее общего срока загрузки."""


SLOW_TRANSFER = "сервер отдаёт ответ слишком медленно — похоже на ограничение скорости"

# Порядок важен: ERR_CONNECTION_TIMED_OUT — таймаут, а не «соединение оборвалось».
_CHROMIUM_PHRASES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("ERR_TIMED_OUT", "ERR_CONNECTION_TIMED_OUT", "context deadline exceeded", "нет ответа за"), ""),
    (("ERR_NAME_NOT_RESOLVED", "ERR_NAME_RESOLUTION_FAILED", "ERR_DNS_"), "не удалось узнать адрес сервера (DNS)"),
    (("ERR_CONNECTION_REFUSED",), "сервер отклонил подключение"),
    (
        ("ERR_CONNECTION_RESET", "ERR_CONNECTION_CLOSED", "ERR_CONNECTION_ABORTED", "ERR_EMPTY_RESPONSE"),
        "соединение оборвалось — похоже на блокировку",
    ),
    (("ERR_NETWORK_ACCESS_DENIED", "ERR_ACCESS_DENIED"), "доступ в сеть запрещён брандмауэром или антивирусом"),
    (("ERR_INTERNET_DISCONNECTED", "ERR_ADDRESS_UNREACHABLE", "ERR_NETWORK_CHANGED"), "нет доступа к сети"),
    (("ERR_CERT_",), "сертификат сервера не прошёл проверку"),
    (("ERR_SSL_",), "сбой защищённого соединения (TLS) — похоже на блокировку"),
    (("ERR_PROXY_", "ERR_TUNNEL_CONNECTION_FAILED", "Tunnel connection failed"), "VPN не пропустил запрос к серверу"),
)


def no_answer(waited: float) -> str:
    return f"сервер не ответил за {max(1, round(waited))} с"


def describe_transport_failure(error: BaseException, waited: float) -> str:
    """Фраза для отказа без ответа сервера; ``waited`` — сколько ждал маршрут."""

    reason: object = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, SlowTransferError):
        return SLOW_TRANSFER
    text = str(reason)
    for markers, phrase in _CHROMIUM_PHRASES:
        if any(marker in text for marker in markers):
            return phrase or no_answer(waited)
    if isinstance(reason, (TimeoutError, socket.timeout)) or "timed out" in text:
        return no_answer(waited)
    if isinstance(reason, socket.gaierror):
        return "не удалось узнать адрес сервера (DNS)"
    if isinstance(reason, ConnectionRefusedError):
        return "сервер отклонил подключение"
    if isinstance(
        reason,
        (ConnectionResetError, ConnectionAbortedError, http.client.HTTPException, ssl.SSLEOFError),
    ):
        return "соединение оборвалось — похоже на блокировку"
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "сертификат сервера не прошёл проверку"
    if isinstance(reason, ssl.SSLError):
        return "сбой защищённого соединения (TLS) — похоже на блокировку"
    if isinstance(reason, PermissionError):
        return "доступ в сеть запрещён брандмауэром или антивирусом"
    return f"сетевая ошибка ({text.strip() or reason.__class__.__name__})"
