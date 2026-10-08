"""Доверенное разрешение имени VPN-сервера до поднятия туннеля.

Системный резолвер на российских сетях отвечает NXDOMAIN на заблокированные
имена, а открытый DNS к публичным резолверам перехватывается. Имя сервера
поэтому сначала спрашивается по DoH у нескольких резолверов по литеральному
IP: в TLS-приветствии нет имени сервера (SNI для IP не отправляется), а
сертификат проверяется по IP из SAN. Ответ запоминается: когда защищённый
путь недоступен, а системный резолвер лжёт или молчит, остаётся последний
адрес, полученный доверенным путём.

Модуль не знает о маршрутизации и не меняет конфиг ядра. Он отдаёт адреса
тем, кто владеет bootstrap-контрактом: Zapret-правилу сервера и планировщику
sing-box.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .http_utils import _make_ssl_context

# Адреса резолверов из `direct-doh` шаблона sing-box. У всех сертификат содержит
# IP в SAN, поэтому соединение по литеральному адресу проходит обычную проверку.
# Quad9 (9.9.9.9) здесь нет: он отвечает только по HTTP/2, а этот клиент говорит
# HTTP/1.1; его место занимает второй адрес Cloudflare.
DOH_SERVERS: tuple[str, ...] = ("8.8.8.8", "1.1.1.1", "94.140.14.14", "8.8.4.4", "1.0.0.1")
DOH_PATH = "/dns-query"

# Столько же хранит Android-клиент: дольше недели адрес сервера чаще устаревает,
# чем помогает.
CACHE_MAX_AGE_SEC = 7 * 24 * 3600
_REFRESH_MIN_INTERVAL_SEC = 600.0

_TYPE_A = 1
_TYPE_AAAA = 28
_RCODE_NXDOMAIN = 3


class BootstrapDnsError(OSError):
    """Ни один доверенный резолвер не дал ответа."""


class BootstrapNameNotFound(BootstrapDnsError):
    """Доверенный резолвер подтвердил, что имени не существует."""


@dataclass(frozen=True)
class BootstrapResolution:
    addresses: frozenset[str]
    # "literal" | "doh" | "system" | "cache"
    source: str


def _normalize_host(host: str) -> str:
    return str(host or "").strip().strip("[]").rstrip(".").lower()


def build_query(name: str, qtype: int) -> bytes:
    labels = _normalize_host(name).encode("idna").split(b".")
    question = b"".join(bytes([len(label)]) + label for label in labels if label) + b"\x00"
    # ID 0: RFC 8484 просит нулевой идентификатор, чтобы ответы кешировались.
    return struct.pack("!HHHHHH", 0, 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", qtype, 1)


def _skip_name(payload: bytes, offset: int) -> int:
    while True:
        length = payload[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length


def parse_response(payload: bytes) -> tuple[int, list[str]]:
    """Вернуть ``(rcode, адреса)`` из DNS-ответа; мусор — ``ValueError``."""

    try:
        _ident, flags, questions, answers, _ns, _extra = struct.unpack("!HHHHHH", payload[:12])
        offset = 12
        for _ in range(questions):
            offset = _skip_name(payload, offset) + 4
        addresses: list[str] = []
        for _ in range(answers):
            offset = _skip_name(payload, offset)
            rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", payload[offset:offset + 10])
            offset += 10
            rdata = payload[offset:offset + rdlength]
            offset += rdlength
            if len(rdata) != rdlength:
                raise ValueError("truncated record")
            if (rtype == _TYPE_A and rdlength == 4) or (rtype == _TYPE_AAAA and rdlength == 16):
                addresses.append(str(ipaddress.ip_address(rdata)))
    except (IndexError, struct.error) as exc:
        raise ValueError("malformed DNS response") from exc
    return flags & 0x000F, addresses


def _usable(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return not (ip.is_unspecified or ip.is_multicast or ip.is_loopback)


def _doh_lookup(server: str, host: str, timeout: float) -> set[str]:
    """A и AAAA одним TLS-соединением к одному резолверу."""

    connection = http.client.HTTPSConnection(server, 443, timeout=timeout, context=_make_ssl_context())
    try:
        found: set[str] = set()
        name_missing = False
        for qtype in (_TYPE_A, _TYPE_AAAA):
            connection.request(
                "POST",
                DOH_PATH,
                body=build_query(host, qtype),
                headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"},
            )
            response = connection.getresponse()
            body = response.read(65535)
            if response.status != 200:
                raise BootstrapDnsError(f"DoH {server}: HTTP {response.status}")
            rcode, addresses = parse_response(body)
            if rcode == _RCODE_NXDOMAIN:
                name_missing = True
                break
            if rcode != 0:
                raise BootstrapDnsError(f"DoH {server}: rcode {rcode}")
            found.update(address for address in addresses if _usable(address))
        if name_missing and not found:
            raise BootstrapNameNotFound(host)
        return found
    finally:
        connection.close()


def resolve_doh(
    host: str,
    *,
    timeout: float = 3.0,
    servers: Iterable[str] = DOH_SERVERS,
    lookup: Callable[[str, str, float], set[str]] = _doh_lookup,
) -> set[str]:
    """Первый непустой ответ любого из резолверов; все опрашиваются сразу."""

    targets = tuple(servers)
    executor = ThreadPoolExecutor(max_workers=max(1, len(targets)), thread_name_prefix="bootstrap-doh")
    try:
        futures = [executor.submit(lookup, server, host, timeout) for server in targets]
        missing = 0
        last_error: Exception | None = None
        try:
            for future in as_completed(futures, timeout=timeout + 1.0):
                try:
                    addresses = future.result()
                except BootstrapNameNotFound as exc:
                    missing += 1
                    last_error = exc
                    continue
                except Exception as exc:  # сеть, TLS, мусор в ответе — пробуем следующего
                    last_error = exc
                    continue
                if addresses:
                    return addresses
        except TimeoutError as exc:
            last_error = last_error or exc
        if missing and missing == len(targets):
            raise BootstrapNameNotFound(host)
        raise BootstrapDnsError(f"нет ответа доверенных резолверов: {last_error}")
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


class BootstrapCache:
    """Последние адреса серверов, полученные доверенным путём."""

    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time) -> None:
        self._path = Path(path)
        self._clock = clock
        self._lock = threading.Lock()

    def _load(self) -> dict[str, dict]:
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        entries = payload.get("hosts") if isinstance(payload, dict) else None
        return entries if isinstance(entries, dict) else {}

    def lookup(self, host: str) -> list[str]:
        host = _normalize_host(host)
        with self._lock:
            entry = self._load().get(host)
        if not isinstance(entry, dict):
            return []
        try:
            age = self._clock() - float(entry.get("saved_at", 0))
        except (TypeError, ValueError):
            return []
        if age < 0 or age > CACHE_MAX_AGE_SEC:
            return []
        result: list[str] = []
        for raw in entry.get("addresses") or []:
            try:
                address = str(ipaddress.ip_address(str(raw)))
            except ValueError:
                continue
            if _usable(address) and address not in result:
                result.append(address)
        return result

    def remember(self, host: str, addresses: Iterable[str]) -> None:
        host = _normalize_host(host)
        cleaned = sorted({str(ipaddress.ip_address(a)) for a in addresses}, key=lambda a: (":" in a, a))
        if not host or not cleaned:
            return
        with self._lock:
            entries = self._load()
            now = self._clock()
            entries = {
                name: entry
                for name, entry in entries.items()
                if isinstance(entry, dict) and 0 <= now - float(entry.get("saved_at", 0) or 0) <= CACHE_MAX_AGE_SEC
            }
            entries[host] = {"addresses": cleaned, "saved_at": now}
            temporary = self._path.with_suffix(self._path.suffix + ".tmp")
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                temporary.write_text(json.dumps({"version": 1, "hosts": entries}, indent=2), encoding="utf-8")
                os.replace(temporary, self._path)
            except OSError:
                # Кеш — подстраховка: невозможность записать его не должна
                # мешать подключению.
                pass


_cache: BootstrapCache | None = None
_session_snapshot: dict[str, tuple[str, ...]] = {}
_refresh_lock = threading.Lock()
_refreshed_at: dict[str, float] = {}


def configure_cache(path: Path | None) -> None:
    """Включить кеш (приложение) или выключить его (тесты, утилиты)."""

    global _cache
    _cache = BootstrapCache(path) if path is not None else None
    _session_snapshot.clear()
    with _refresh_lock:
        _refreshed_at.clear()


def _is_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def cached_addresses(host: str) -> list[str]:
    """Запомненные адреса имени, неизменные до конца сеанса приложения.

    Планировщик sing-box вызывает это при каждом построении конфига. Фоновое
    обновление кеша не должно менять уже построенный конфиг посреди сеанса,
    иначе совпадающие по смыслу планы различались бы и вызывали переподключение.
    Поэтому значение для имени читается с диска один раз.
    """

    host = _normalize_host(host)
    if _cache is None or not host or _is_literal(host):
        return []
    if host not in _session_snapshot:
        _session_snapshot[host] = tuple(_cache.lookup(host))
    return list(_session_snapshot[host])


def _system_lookup(host: str) -> set[str]:
    resolved: set[str] = set()
    for info in socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM):
        try:
            address = str(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
        if _usable(address):
            resolved.add(address)
    return resolved


def resolve_bootstrap(
    host: str,
    *,
    timeout: float = 3.0,
    doh: Callable[[str], set[str]] | None = None,
    system: Callable[[str], set[str]] = _system_lookup,
) -> BootstrapResolution:
    """Адреса сервера: доверенный DoH → системный резолвер → запомненный адрес.

    Блокирующий вызов, только для рабочих потоков. Бросает ``OSError``, когда
    адреса нет ни в одном из трёх источников.
    """

    host = _normalize_host(host)
    if not host:
        return BootstrapResolution(frozenset(), "literal")
    try:
        return BootstrapResolution(frozenset({str(ipaddress.ip_address(host))}), "literal")
    except ValueError:
        pass

    doh = doh or (lambda name: resolve_doh(name, timeout=timeout))
    trusted_error: Exception | None = None
    try:
        addresses = doh(host)
    except BootstrapNameNotFound:
        # Доверенный резолвер подтвердил отсутствие имени: провайдерскому
        # ответу и старому кешу здесь верить нечему.
        raise
    except Exception as exc:
        trusted_error = exc
        addresses = set()
    if addresses:
        if _cache is not None:
            _cache.remember(host, addresses)
        return BootstrapResolution(frozenset(addresses), "doh")

    system_error: Exception | None = None
    try:
        addresses = system(host)
    except OSError as exc:
        system_error = exc
        addresses = set()
    if addresses:
        # Не запоминаем: системный ответ мог быть подменён.
        return BootstrapResolution(frozenset(addresses), "system")

    cached = _cache.lookup(host) if _cache is not None else []
    if cached:
        return BootstrapResolution(frozenset(cached), "cache")
    raise system_error or BootstrapDnsError(f"имя сервера не разрешено: {trusted_error}")


_tampering_listener: Callable[[str], None] | None = None
_tampering_reported = False


def set_tampering_listener(listener: Callable[[str], None] | None) -> None:
    """Кому сообщить, что системный DNS отрицает существующее имя сервера."""

    global _tampering_listener, _tampering_reported
    _tampering_listener = listener
    _tampering_reported = False


def system_denies_name(host: str, lookup: Callable[..., object] = socket.getaddrinfo) -> bool:
    """Системный резолвер отвечает «имени нет» (а не просто недоступен)."""

    try:
        lookup(host, None, type=socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        # EAI_NONAME на POSIX, WSAHOST_NOT_FOUND (11001) на Windows.
        return exc.errno in (socket.EAI_NONAME, 11001)
    except OSError:
        return False
    return False


def _report_tampering(host: str) -> None:
    """Один раз за сеанс: доверенный DNS имя знает, системный — отрицает."""

    global _tampering_reported
    listener = _tampering_listener
    if listener is None or _tampering_reported:
        return
    _tampering_reported = True
    try:
        listener(host)
    except Exception:
        pass


def refresh_async(host: str) -> bool:
    """Обновить запомненный адрес в фоне; не чаще раза в десять минут на имя."""

    host = _normalize_host(host)
    if _cache is None or not host or _is_literal(host):
        return False
    now = time.monotonic()
    with _refresh_lock:
        last = _refreshed_at.get(host)
        if last is not None and now - last < _REFRESH_MIN_INTERVAL_SEC:
            return False
        _refreshed_at[host] = now

    def run() -> None:
        try:
            addresses = resolve_doh(host)
        except Exception:
            return
        cache = _cache
        if cache is not None and addresses:
            cache.remember(host, addresses)
        if addresses and system_denies_name(host):
            _report_tampering(host)

    threading.Thread(target=run, name="bootstrap-dns-refresh", daemon=True).start()
    return True
