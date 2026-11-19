"""Where and how a server is closed (owner decision 2026-11-19): the pure part.

After a failed attempt the app checks the path step by step, and on each step swaps one thing: the same IP on
port 443, the same name on another IP, another name on the same IP. Here only the conclusion from those
results; the network is in ``probe.py``. Steps and codes are the same as Android
(``client-reports/.../BlockDiagnosis.kt`` and ``TlsProbe.kt``); the ClientHello bytes are the same too.

"Answered" for TLS means any TLS record came back (ServerHello or even an alert): a server that does not like
the swapped name answers with an alert and is not closed. Closed means silence or a reset after ClientHello.
"""

from __future__ import annotations

import random as _random
import struct
from dataclasses import dataclass
from enum import Enum


class ProbeResult(str, Enum):
    ANSWERED = "answered"
    TIMEOUT = "timeout"
    RESET = "reset"
    #: The probe could not run for a local reason (no network, no address): proves nothing.
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class DiagnosisFacts:
    #: TCP to a known-good address (our pool front in Russia). No answer: the PC's own network is down.
    control: ProbeResult = ProbeResult.UNKNOWN
    #: Server name addresses from the system DNS; None — not asked (IP in the link), empty — no answer.
    system_dns: frozenset[str] | None = None
    #: The same name from our DoH; None — not asked or DoH did not answer.
    doh_dns: frozenset[str] | None = None
    #: Every trusted DoH said the name does not exist: the server's name is wrong, not blocked.
    doh_name_missing: bool = False
    tcp_target: ProbeResult = ProbeResult.UNKNOWN
    #: TCP to the same IP on 443 (only when the server port is not 443 and stayed silent).
    tcp_other_port: ProbeResult = ProbeResult.UNKNOWN
    uses_tls: bool = False
    tls_real_name: ProbeResult = ProbeResult.UNKNOWN
    tls_neutral_name: ProbeResult = ProbeResult.UNKNOWN
    tls_real_name_elsewhere: ProbeResult = ProbeResult.UNKNOWN
    udp_transport: bool = False
    stalled_after_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class Diagnosis:
    failed_step: str
    detail: str


#: The TSPU freezes a connection after ~25 packets (~16 KB, less on mobile). The probe reads up to 64 KB,
#: so a transfer that went past the window never falls into it.
FREEZE_MIN_BYTES = 1_000
FREEZE_MAX_BYTES = 24_000
#: One server is probed at most this often (owner: only after a failure, rarely).
MIN_INTERVAL_MS = 10 * 60 * 1000


def diagnose(facts: DiagnosisFacts) -> Diagnosis | None:
    """The closed step. TCP, TLS and freeze come first: a poisoned system DNS does not matter when the app took
    the address from our DoH, so DNS is named only when nothing below it is closed."""
    if facts.control is not ProbeResult.ANSWERED:
        return None
    verdict = _tcp(facts)
    if verdict is not None:
        return verdict
    if facts.uses_tls and not facts.udp_transport:
        verdict = _tls(facts)
        if verdict is not None:
            return verdict
    if facts.stalled_after_bytes is not None and FREEZE_MIN_BYTES <= facts.stalled_after_bytes <= FREEZE_MAX_BYTES:
        return Diagnosis("request", "freeze_16k")
    return _dns(facts)


def diagnose_udp(facts: DiagnosisFacts) -> Diagnosis | None:
    """IP-level check of a UDP server: only silence on 443 means a closed IP (a reset proves the address is
    alive; Hysteria may not listen on TCP)."""
    if facts.control is not ProbeResult.ANSWERED:
        return None
    if facts.tcp_other_port is ProbeResult.TIMEOUT:
        return Diagnosis("connect", "ip_blocked")
    return _dns(facts)


def freeze(stalled_after_bytes: int | None) -> Diagnosis | None:
    """The freeze step after a successful connect: the only one that turns "connected" into a failure."""
    if stalled_after_bytes is not None and FREEZE_MIN_BYTES <= stalled_after_bytes <= FREEZE_MAX_BYTES:
        return Diagnosis("request", "freeze_16k")
    return None


def _dns(facts: DiagnosisFacts) -> Diagnosis | None:
    if facts.doh_name_missing:
        return Diagnosis("resolve", "dns_nxdomain")
    if facts.system_dns is None:
        return None
    if not facts.system_dns:
        return Diagnosis("resolve", "dns_no_answer")
    if facts.doh_dns and not (facts.system_dns & facts.doh_dns):
        return Diagnosis("resolve", "dns_poisoned")
    return None


def _tcp(facts: DiagnosisFacts) -> Diagnosis | None:
    target = facts.tcp_target
    if target in (ProbeResult.ANSWERED, ProbeResult.UNKNOWN):
        return None
    if target is ProbeResult.RESET:
        # Someone answered: the address is alive, the server or a filter cuts it; cannot tell which.
        return Diagnosis("connect", "tcp_reset")
    other = facts.tcp_other_port
    if other in (ProbeResult.ANSWERED, ProbeResult.RESET):
        return Diagnosis("connect", "port_blocked")
    if other is ProbeResult.TIMEOUT:
        return Diagnosis("connect", "ip_blocked")
    return Diagnosis("connect", "tcp_timeout")


def _tls(facts: DiagnosisFacts) -> Diagnosis | None:
    if facts.tls_real_name in (ProbeResult.ANSWERED, ProbeResult.UNKNOWN):
        return None
    # On the swapped probes only silence is a filter: a server (our front too) closes the connection without
    # an answer for a name that is not its own, so a reset there proves nothing.
    neutral = facts.tls_neutral_name
    if neutral is ProbeResult.ANSWERED:
        if facts.tls_real_name_elsewhere is ProbeResult.TIMEOUT:
            return Diagnosis("handshake", "sni_blocked_everywhere")
        return Diagnosis("handshake", "sni_blocked")
    if neutral is ProbeResult.TIMEOUT:
        return Diagnosis("handshake", "tls_blocked")
    return None


_TEXTS = {
    "ip_blocked": "Адрес сервера закрыт целиком: не отвечают ни его порт, ни порт 443.",
    "port_blocked": "Закрыт порт сервера: тот же адрес на порту 443 отвечает.",
    "tcp_timeout": "Сервер молчит в ответ на соединение.",
    "tcp_reset": "Соединение с сервером сбрасывается.",
    "sni_blocked": "Закрыто имя сервера (SNI): с другим именем тот же адрес отвечает.",
    "sni_blocked_everywhere": "Имя сервера (SNI) закрыто на любом адресе.",
    "tls_blocked": "TLS-рукопожатие с адресом сервера обрывается при любом имени.",
    "freeze_16k": "Соединение с сервером замирает после ~16 КБ.",
    "dns_poisoned": "Системный DNS подменяет адрес сервера.",
    "dns_no_answer": "Системный DNS не находит имя сервера.",
    "dns_nxdomain": "Имени сервера нет в DNS.",
}


def describe(diagnosis: Diagnosis | None, facts: DiagnosisFacts | None) -> str:
    """The line for the failure notice (Russian, the user reads it)."""
    if diagnosis is not None:
        return _TEXTS.get(diagnosis.detail, f"Найдена блокировка: {diagnosis.detail}.")
    if facts is None:
        return "Проверка пути до сервера не проводилась."
    if facts.control is not ProbeResult.ANSWERED:
        return "Проверка пути не удалась: сеть компьютера не открывает даже рабочий адрес."
    if facts.tcp_target is ProbeResult.ANSWERED and (
        not facts.uses_tls or facts.udp_transport or facts.tls_real_name is ProbeResult.ANSWERED
    ):
        return "Путь до сервера открыт: адрес, порт и имя отвечают."
    return "Проверка пути до сервера ничего не показала."


# ── the ClientHello of the TLS probe (same bytes as Android TlsProbe.clientHello) ──

CONNECT_TIMEOUT_S = 4.0
ANSWER_TIMEOUT_S = 5.0
#: Neutral names: open in any filtering mode, white lists included.
NEUTRAL_NAMES = ("ya.ru", "vk.com", "www.gosuslugi.ru")
_CIPHERS = (0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8)
_SIGNATURES = (0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)


def _u16(value: int) -> bytes:
    return struct.pack("!H", value)


def _ext(kind: int, data: bytes) -> bytes:
    return _u16(kind) + _u16(len(data)) + data


def client_hello(server_name: str, rng: _random.Random | None = None) -> bytes:
    """One TLS 1.3 ClientHello with the chosen SNI; only the first byte of the answer is read."""
    rnd = rng or _random.SystemRandom()

    def random_bytes(count: int) -> bytes:
        return bytes(rnd.getrandbits(8) for _ in range(count))

    name = server_name.rstrip(".").encode("ascii")
    h2, h1 = b"h2", b"http/1.1"
    extensions = b"".join((
        _ext(0x0000, _u16(len(name) + 3) + b"\x00" + _u16(len(name)) + name),
        _ext(0x0017, b""),
        _ext(0xFF01, b"\x00"),
        _ext(0x000A, _u16(6) + _u16(0x001D) + _u16(0x0017) + _u16(0x0018)),
        _ext(0x000B, b"\x01\x00"),
        _ext(0x000D, _u16(len(_SIGNATURES) * 2) + b"".join(_u16(s) for s in _SIGNATURES)),
        _ext(0x0010, _u16(2 + len(h2) + len(h1)) + bytes([len(h2)]) + h2 + bytes([len(h1)]) + h1),
        _ext(0x002B, b"\x04" + _u16(0x0304) + _u16(0x0303)),
        _ext(0x002D, b"\x01\x01"),
        _ext(0x0033, _u16(36) + _u16(0x001D) + _u16(32) + random_bytes(32)),
    ))
    body = (
        _u16(0x0303)
        + random_bytes(32)
        + b"\x20" + random_bytes(32)
        + _u16(len(_CIPHERS) * 2) + b"".join(_u16(c) for c in _CIPHERS)
        + b"\x01\x00"
        + _u16(len(extensions)) + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16" + _u16(0x0301) + _u16(len(handshake)) + handshake


def judge_first_byte(first: int) -> ProbeResult:
    """First byte of the answer to ClientHello; -1 — the connection closed without an answer."""
    return ProbeResult.RESET if first < 0 else ProbeResult.ANSWERED


def server_name_of(hello: bytes) -> str | None:
    try:
        at = 5 + 4 + 2 + 32
        at += 1 + hello[at]
        at += 2 + struct.unpack_from("!H", hello, at)[0]
        at += 1 + hello[at]
        end = at + 2 + struct.unpack_from("!H", hello, at)[0]
        at += 2
        while at < end:
            kind, length = struct.unpack_from("!HH", hello, at)
            if kind == 0:
                size = struct.unpack_from("!H", hello, at + 7)[0]
                return hello[at + 9:at + 9 + size].decode("ascii")
            at += 4 + length
    except (IndexError, struct.error, UnicodeDecodeError):
        return None
    return None
