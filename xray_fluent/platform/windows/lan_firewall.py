"""Прокси для устройств локальной сети: правило брандмауэра Windows и адрес ПК.

PS5, телевизор или телефон без своего VPN подключаются к локальному прокси
ПК.  Ядро слушает все адреса, но входящие соединения из сети Windows режет,
пока нет разрешающего правила.  Правило — по программе ядра и только для
локальной подсети (``remoteip=localsubnet``): из интернета и из чужих сетей
через этот ПК прокси недоступен, даже если сеть отмечена как общественная.
"""

from __future__ import annotations

import ipaddress
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from ...constants import SINGBOX_PATH_DEFAULT, XRAY_PATH_DEFAULT
from .subprocess_utils import result_output_text, run_text

log = logging.getLogger(__name__)

RULE_NAME = "ZapretKVN LAN proxy"
# Интерфейсы туннеля sing-box и Xray (tun2socks).
_TUNNEL_INTERFACES = {"xftun", "ZapretKVN_TUN"}
_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="xray_fluent_lan_firewall")


def rule_commands(enabled: bool, programs: list[Path]) -> list[list[str]]:
    """Команды netsh: снять прежние правила и, если включено, поставить новые."""

    commands = [["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_NAME}"]]
    if enabled:
        for program in programs:
            commands.append([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={RULE_NAME}", "dir=in", "action=allow", "enable=yes",
                f"program={program}", "protocol=TCP", "remoteip=localsubnet", "profile=any",
            ])
    return commands


def _apply_blocking(enabled: bool, programs: list[Path]) -> str:
    """Применить правило; пусто — успех, иначе текст ошибки."""

    errors: list[str] = []
    for index, command in enumerate(rule_commands(enabled, programs)):
        result = run_text(command, timeout=15.0)
        # Удаление несуществующего правила — не ошибка.
        if index and result.returncode != 0:
            errors.append(result_output_text(result).strip() or f"код {result.returncode}")
    return "; ".join(errors)


def apply_lan_proxy_firewall(enabled: bool, logger: Callable[[str], None] | None = None) -> None:
    """Включить или снять правило в фоне; GUI-поток не ждёт netsh."""

    if sys.platform != "win32":
        return
    programs = [Path(SINGBOX_PATH_DEFAULT).resolve(), Path(XRAY_PATH_DEFAULT).resolve()]

    def job() -> None:
        try:
            error = _apply_blocking(enabled, programs)
        except Exception as exc:  # netsh недоступен, таймаут
            error = str(exc)
        state = "открыт" if enabled else "закрыт"
        message = (
            f"[lan-proxy] прокси для локальной сети {state}"
            if not error else f"[lan-proxy] правило брандмауэра не применено: {error}"
        )
        log.info(message)
        if logger is not None:
            try:
                logger(message)
            except Exception:
                pass

    _EXECUTOR.submit(job)


def lan_addresses() -> list[str]:
    """Адреса ПК в домашней сети (частные IPv4 работающих интерфейсов), без сети и DNS.

    Интерфейс туннеля не в счёт: его адрес другим устройствам недоступен.
    """

    from PyQt6.QtNetwork import QAbstractSocket, QNetworkInterface

    wanted = QNetworkInterface.InterfaceFlag.IsUp | QNetworkInterface.InterfaceFlag.IsRunning
    found: list[str] = []
    for interface in QNetworkInterface.allInterfaces():
        flags = interface.flags()
        if (flags & wanted) != wanted or flags & QNetworkInterface.InterfaceFlag.IsLoopBack:
            continue
        if interface.humanReadableName() in _TUNNEL_INTERFACES or interface.name() in _TUNNEL_INTERFACES:
            continue
        for entry in interface.addressEntries():
            ip = entry.ip()
            if ip.protocol() != QAbstractSocket.NetworkLayerProtocol.IPv4Protocol:
                continue
            try:
                address = ipaddress.ip_address(ip.toString())
            except ValueError:
                continue
            if address.is_private and not address.is_loopback and not address.is_link_local:
                found.append(str(address))
    return found
