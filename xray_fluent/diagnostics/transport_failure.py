"""Plain-language cause of a UDP sidecar (Hysteria2, AmneziaWG/WireGuard) start failure.

The text names only what the app observed: whether the server answered at
all, whether Windows had a route, what the server rejected. It never guesses
beyond that evidence; unknown failures return ``None`` and the caller keeps
the original core message.
"""

from __future__ import annotations

from typing import Iterable

from ..engines.hysteria.runtime_contract import SECURITY_FAILURES, HysteriaFailureCode

# Hysteria2, AmneziaWG and WireGuard all ride on UDP; VLESS and Trojan use TCP.
UDP_ONLY_ADVICE = (
    "Hysteria2, AmneziaWG и WireGuard работают только через UDP — "
    "выберите сервер VLESS или Trojan."
)

_NO_ROUTE_MARKERS = (
    "unreachable network",
    "network is unreachable",
    "no route to host",
    "сеть недоступна",
)


def _server_label(server_name: str) -> str:
    name = str(server_name or "").strip()
    return f"Сервер «{name}»" if name else "Сервер"


def _seen(lines: Iterable[str], markers: Iterable[str]) -> bool:
    lowered = [str(line or "").lower() for line in lines]
    return any(marker in line for line in lowered for marker in markers)


def no_network_message() -> str:
    return (
        "Нет сети: Windows не нашла маршрута в интернет, поэтому до сервера не дойти. "
        "Проверьте подключение к интернету."
    )


def udp_unanswered_message(server_name: str, protocol: str) -> str:
    return (
        f"{_server_label(server_name)} не ответил по UDP: пакеты {protocol} до него не доходят. "
        "Сеть или провайдер режет UDP к этому серверу, либо сервер выключен. "
        f"{UDP_ONLY_ADVICE}"
    )


def hysteria_failure_message(
    server_name: str,
    *,
    code: HysteriaFailureCode | None,
    remote_authenticated: bool,
    output_lines: Iterable[str] = (),
) -> str | None:
    lines = list(output_lines)
    label = _server_label(server_name)
    if code is HysteriaFailureCode.TARGET_AUTH_REJECTED:
        return f"{label} отклонил пароль Hysteria2. Обновите подписку."
    if code is HysteriaFailureCode.TARGET_OBFS_REJECTED:
        return f"{label} не принял обфускацию (obfs) Hysteria2. Обновите подписку."
    if code is HysteriaFailureCode.TARGET_PIN_MISMATCH:
        return f"Сертификат сервера «{server_name}» не совпал с закреплённым — подключение остановлено ради безопасности."
    if code in SECURITY_FAILURES:
        return f"Сертификат сервера «{server_name}» не прошёл проверку — подключение остановлено ради безопасности."
    if code is HysteriaFailureCode.LOCAL_BIND_COLLISION:
        return "Локальный порт Hysteria2 занят другой программой. Повторите подключение."
    if remote_authenticated:
        # The server answered and accepted the password; only egress failed.
        if code in {HysteriaFailureCode.TARGET_NETWORK_TIMEOUT, None, HysteriaFailureCode.CORE_UNCLASSIFIED}:
            return f"{label} подключился, но сайты через него не открываются: проверка HTTPS не прошла."
        return None
    if _seen(lines, _NO_ROUTE_MARKERS):
        return no_network_message()
    if code is HysteriaFailureCode.TARGET_CONNECTION_REFUSED:
        return f"{label} ответил, что порт закрыт: Hysteria2 на нём сейчас не принимает подключения."
    if code is HysteriaFailureCode.TARGET_NETWORK_TIMEOUT or _seen(lines, ("no recent network activity",)):
        return udp_unanswered_message(server_name, "Hysteria2")
    return None


def amnezia_failure_message(server_name: str, *, stage: str, message: str) -> str | None:
    lowered = str(message or "").lower()
    if _seen((lowered,), _NO_ROUTE_MARKERS):
        return no_network_message()
    if stage == "handshake_readiness" or "no authenticated handshake observed" in lowered:
        return udp_unanswered_message(server_name, "AmneziaWG/WireGuard")
    return None
