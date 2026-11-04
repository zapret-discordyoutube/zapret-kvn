"""Снимок физической сети для режима TUN.

В TUN основной маршрут идёт через виртуальный адаптер, поэтому обычный отпечаток сети
(локальный адрес на пути к 8.8.8.8) всегда равен адресу самого TUN и не замечает смену
Wi-Fi или кабеля. Физическая сеть при этом остаётся в таблице маршрутов строкой маршрута по
умолчанию: шлюз и адрес физического адаптера. Отпечаток здесь — набор таких строк без строк
нашего TUN, поэтому создание и удаление адаптера его не меняет и цикла переподключений нет.
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess

#: Метка вида отпечатка: монитор не принимает переход между видами за смену сети.
PHYSICAL_PREFIX = "phys:"

# Строка маршрута по умолчанию из ``route print -4``: сеть, маска, шлюз, адрес интерфейса,
# метрика. Заголовки зависят от языка Windows, строки с числами — нет; шлюз бывает словом
# («On-link», «Подключено»), поэтому он берётся как любой текст между маской и адресом.
_DEFAULT_ROW = re.compile(
    r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(.+?)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s*$",
    re.MULTILINE,
)


def is_physical_fingerprint(value: str) -> bool:
    return value.startswith(PHYSICAL_PREFIX)


def has_network(value: str) -> bool:
    """Есть ли сеть по отпечатку любого вида (``0.0.0.0`` и пустой физический набор — нет)."""
    return value not in ("", "0.0.0.0", PHYSICAL_PREFIX)


def tun_networks(config: object) -> list[ipaddress.IPv4Network]:
    """IPv4-сети TUN из активного конфига sing-box (``address`` и прежнее ``inet4_address``)."""
    networks: list[ipaddress.IPv4Network] = []
    inbounds = config.get("inbounds") if isinstance(config, dict) else None
    for inbound in inbounds or []:
        if not isinstance(inbound, dict) or str(inbound.get("type") or "").strip().lower() != "tun":
            continue
        for key in ("address", "inet4_address"):
            value = inbound.get(key)
            items = [value] if isinstance(value, str) else list(value or [])
            for item in items:
                try:
                    network = ipaddress.ip_interface(str(item).strip()).network
                except ValueError:
                    continue
                if isinstance(network, ipaddress.IPv4Network):
                    networks.append(network)
    return networks


def physical_fingerprint(route_text: str, tun_nets: list[ipaddress.IPv4Network]) -> str:
    """``phys:шлюз>адрес;…`` по строкам маршрута по умолчанию, кроме строк нашего TUN."""
    pairs: set[str] = set()
    for gateway, interface in _DEFAULT_ROW.findall(route_text or ""):
        try:
            address = ipaddress.IPv4Address(interface)
        except ValueError:
            continue
        if any(address in network for network in tun_nets):
            continue
        pairs.add(f"{gateway.strip()}>{interface}")
    return PHYSICAL_PREFIX + ";".join(sorted(pairs))


def read_route_table(timeout: float = 4.0) -> str:
    """Таблица маршрутов по умолчанию; пустая строка — прочитать не удалось (это не «сети нет»)."""
    if os.name != "nt":
        return ""
    try:
        result = subprocess.run(
            ["route", "print", "-4", "0.0.0.0"],
            capture_output=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    # Числа ASCII, а слова в заголовках не нужны: любая однобайтовая кодировка подходит.
    return result.stdout.decode("latin-1", errors="replace")
