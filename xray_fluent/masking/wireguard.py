"""WireGuard / AmneziaWG masking: I-packet chains, the DNS-like I1, junk validation, emission.

Limits come from the core we ship, amneziawg-go v3.1.20261116 (`device/obf.go` obfBuilders:
b t r rc rd d ds dz; no `<c>`; `obf_bytes.go` strips only a lowercase "0x"; `uapi.go:880`
refuses jmin > jmax). Same rules and messages as Android `masking/wireguard`.
"""

from __future__ import annotations

import re
from typing import Any

from .model import SIGNATURE_KEYS, Problem, WireGuardMasking

TAGS = frozenset({"b", "t", "r", "rc", "rd"})
CORE_UNKNOWN = frozenset({"c"})
MAX_PACKET_BYTES = 1400  # 1500 Ethernet MTU - 20 IPv4 - 8 UDP, rounded down
MAX_JUNK_COUNT = 128
_TIMESTAMP_BYTES = 4
_HEX = re.compile(r"^[0-9a-fA-F]+$")

DNS_DOMAINS = ("yandex.ru", "vk.com", "mail.ru", "ozon.ru", "avito.ru", "gosuslugi.ru")
_DNS_HEADER_AFTER_ID = "0100" "0001" "0000" "0000" "0000"
_DNS_QTYPE_A_CLASS_IN = "0001" "0001"
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def validate_chain(chain: str) -> tuple[int | None, str | None]:
    """(packet bytes, None) for a valid chain, (None, reason) otherwise."""
    cursor, size, tags = 0, 0, 0
    while cursor < len(chain):
        if chain[cursor].isspace():
            cursor += 1
            continue
        if chain[cursor] != "<":
            return None, "Текст вне тегов: допускаются только теги вида <b 0x…>, <r 16>."
        end = chain.find(">", cursor + 1)
        if end < 0:
            return None, "Нет закрывающего символа «>»."
        parts = chain[cursor + 1:end].split()
        if not parts or len(parts) > 2:
            return None, "Пустой или неверный тег."
        tag, argument = parts[0], (parts[1] if len(parts) > 1 else None)
        if tag == "b":
            hex_value = argument[2:] if argument and argument.startswith("0x") else (argument or "")
            if not hex_value or len(hex_value) % 2 or not _HEX.match(hex_value):
                return None, "Тег <b> должен содержать байты в hex, например <b 0x0100>."
            size += len(hex_value) // 2
        elif tag in {"r", "rc", "rd"}:
            if argument is None or not (argument.isascii() and argument.isdigit()) or not 1 <= int(argument) <= MAX_PACKET_BYTES:
                return None, f"Тег <{tag}> ждёт размер от 1 до {MAX_PACKET_BYTES} байт."
            size += int(argument)
        elif tag == "t":
            if argument is not None:
                return None, "Тег <t> не принимает аргумент."
            size += _TIMESTAMP_BYTES
        elif tag in CORE_UNKNOWN:
            return None, f"Тег <{tag}> не поддерживается ядром AmneziaWG: подключение не запустится."
        else:
            return None, f"Неизвестный тег <{tag}>. Допустимы: <b>, <t>, <r>, <rc>, <rd>."
        if size > MAX_PACKET_BYTES:
            return None, f"Пакет больше {MAX_PACKET_BYTES} байт: его раздробит IP, а это заметно."
        tags += 1
        cursor = end + 1
    if not tags:
        return None, "Нет ни одного тега."
    return size, None


def dns_chain(domain: str) -> str | None:
    """I1 shaped like a DNS query; `<r 2>` = a fresh random transaction id per packet."""
    name = str(domain).strip().rstrip(".").lower()
    labels = name.split(".")
    if not name or len(name) > 253 or len(labels) < 2 or any(not _LABEL.match(label) for label in labels):
        return None
    qname = "".join(f"{len(label):02x}" + label.encode("ascii").hex() for label in labels) + "00"
    return f"<r 2><b 0x{_DNS_HEADER_AFTER_ID}{qname}{_DNS_QTYPE_A_CLASS_IN}>"


def validate(masking: WireGuardMasking) -> list[Problem]:
    problems: list[Problem] = []
    if masking.has_junk and None in (masking.jc, masking.jmin, masking.jmax):
        problems.append(Problem("jc", "Мусорные пакеты задаются тремя числами сразу: Jc, Jmin и Jmax."))
    if masking.jc is not None and not 0 <= masking.jc <= MAX_JUNK_COUNT:
        problems.append(Problem("jc", f"Число мусорных пакетов: от 0 до {MAX_JUNK_COUNT}."))
    for name, value in (("jmin", masking.jmin), ("jmax", masking.jmax)):
        if value is not None and not 0 <= value <= MAX_PACKET_BYTES:
            problems.append(Problem(name, f"Размер мусорного пакета: от 0 до {MAX_PACKET_BYTES} байт."))
    if masking.jmin is not None and masking.jmax is not None and masking.jmin > masking.jmax:
        problems.append(Problem("jmin", "Jmin не может быть больше Jmax."))
    if (masking.jc or 0) > 0 and not masking.jmax:
        problems.append(Problem("jmax", "При мусорных пакетах нужен Jmax больше 0, иначе пакеты пустые."))
    for key, chain in masking.signatures.items():
        if key not in SIGNATURE_KEYS:
            problems.append(Problem(key, f"Неизвестное поле {key}: допустимы I1-I5."))
        elif chain.strip():
            _, reason = validate_chain(chain)
            if reason:
                problems.append(Problem(key, f"{key.upper()}: {reason}"))
    return problems


def apply_to(current: dict[str, Any] | None, masking: WireGuardMasking) -> dict[str, Any]:
    """The endpoint's `amnezia` object with junk and I1-I5 set; every other key kept as imported."""
    result = dict(current or {})
    for key in ("jc", "jmin", "jmax"):
        value = getattr(masking, key)
        if value is not None:
            result[key] = value
    for key in SIGNATURE_KEYS:
        chain = masking.signatures.get(key, "")
        if chain.strip():
            result[key] = chain.strip()
    return result
