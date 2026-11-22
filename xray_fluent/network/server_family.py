"""IPv6 к VPN-серверу первым: порядок семейств адресов и память о них.

Адрес IPv4 сервера часто блокируют по адресу, а IPv6 того же сервера проходит
(замер владельца 21.11.2026: IPv4 узла молчит, IPv6 отвечает). Поэтому
соединение к серверу начинается с IPv6, а IPv4 подхватывает его быстро.

Гонку делают сами ядра: sing-box (`domain_resolver.strategy: prefer_ipv6`,
его DialParallel и память `common/familymemory` из патча
`core-patches/address-family-memory.patch`). Здесь только то, что решает
приложение: включено ли это вообще (настройка и IPv6 на самой сети), и порядок
адресов там, где приложение само закрепляет один адрес (Hysteria, замер
задержки), с той же памятью, что у ядра: семейство, которое не ответило,
не ставится первым снова до истечения срока или смены сети.

Только локальные данные: никаких зондов в сеть.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
import threading
import time
from typing import Callable, Iterable

DEFAULT_TTL_SECONDS = 30 * 60
_MAX_ENTRIES = 256

# 2001::/32 — Teredo, 2002::/16 — 6to4: туннели поверх IPv4, не собственный IPv6 сети.
_NOT_NATIVE = (ipaddress.ip_network("2001::/32"), ipaddress.ip_network("2002::/16"))
_GLOBAL_UNICAST = ipaddress.ip_network("2000::/3")


def is_native_global_ipv6(value: str) -> bool:
    """Глобальный адрес IPv6 самой сети (не локальный, не ULA, не туннель поверх IPv4)."""

    try:
        address = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return False
    if address.version != 6 or address not in _GLOBAL_UNICAST:
        return False
    return not any(address in network for network in _NOT_NATIVE)


def uplink_has_ipv6(adapters: Iterable[object] | None = None) -> bool:
    """Есть ли у основного подключения ПК собственный глобальный IPv6.

    Основное подключение — то же, что выбирает ``select_physical_uplink``
    (работающий адаптер с IPv4, не туннель, наименьшая метрика). Без IPv6 на нём
    приложение ничего не меняет: попытка IPv6 только потеряла бы время.
    """

    try:
        from ..platform.windows import win_netinfo

        if adapters is None:
            if os.name != "nt":
                return False
            adapters = win_netinfo.list_adapters()
        uplink = win_netinfo.select_physical_uplink(list(adapters))
    except Exception:
        return False
    if uplink is None:
        return False
    return any(is_native_global_ipv6(address) for address in getattr(uplink, "ipv6_addresses", ()) or ())


def server_ipv6_first(setting_enabled: bool, *, has_ipv6: Callable[[], bool] = uplink_has_ipv6) -> bool:
    """Включить IPv6 первым для этого запуска: настройка включена и у сети есть IPv6."""

    return bool(setting_enabled) and bool(has_ipv6())


def _family(value: str) -> int:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return 0
    if address.version == 6 and address.ipv4_mapped is not None:
        return 4
    return address.version


@dataclass(slots=True)
class _Entry:
    worked: int = 0
    failed: int = 0
    at: float = 0.0


class FamilyMemory:
    """По имени сервера: какое семейство последним работало и какое не ответило.

    Та же логика, что ``common/familymemory`` в ядре (Android 0020): удача
    ставит своё семейство первым, неудача — другое; срок ``ttl``, ``reset`` при
    смене сети. Потокобезопасна.
    """

    def __init__(self, ttl: float = DEFAULT_TTL_SECONDS, clock: Callable[[], float] = time.monotonic) -> None:
        self._ttl = float(ttl)
        self._clock = clock
        self._entries: dict[str, _Entry] = {}
        self._lock = threading.Lock()

    def _fresh(self, name: str) -> _Entry | None:
        entry = self._entries.get(name)
        if entry is None:
            return None
        if self._clock() - entry.at > self._ttl:
            del self._entries[name]
            return None
        return entry

    def _store(self, name: str, entry: _Entry) -> None:
        if name not in self._entries and len(self._entries) >= _MAX_ENTRIES:
            oldest = min(self._entries, key=lambda key: self._entries[key].at)
            del self._entries[oldest]
        entry.at = self._clock()
        self._entries[name] = entry

    def prefer_ipv6(self, name: str, default: bool) -> bool:
        with self._lock:
            entry = self._fresh(name)
        if entry is None:
            return default
        if entry.worked:
            return entry.worked == 6
        if entry.failed == 6:
            return False
        if entry.failed == 4:
            return True
        return default

    def worked_ipv6(self, name: str) -> bool:
        with self._lock:
            entry = self._fresh(name)
        return entry is not None and entry.worked == 6

    def succeeded(self, name: str, address: str) -> None:
        self.succeeded_family(name, _family(address))

    def succeeded_family(self, name: str, family: int) -> None:
        """Сервер ответил по семейству ``family`` (4 или 6), адрес не известен (WG/AWG)."""

        if not name or family not in (4, 6):
            return
        with self._lock:
            self._store(name, _Entry(worked=family))

    def failed(self, name: str, address: str) -> None:
        family = _family(address)
        if not name or not family:
            return
        with self._lock:
            entry = self._fresh(name) or _Entry()
            if entry.worked == family:
                entry.worked = 0
            entry.failed = family
            self._store(name, entry)

    def reset(self) -> None:
        with self._lock:
            self._entries.clear()


#: Память процесса; сбрасывается при смене сети (controller).
MEMORY = FamilyMemory()

_UPLINK_CACHE_S = 30.0
_setting_enabled = True
_uplink_checked: tuple[float, bool] | None = None
_state_lock = threading.Lock()


def configure(setting_enabled: bool) -> None:
    """Значение настройки «IPv6 к серверу первым» для замеров (их зовут без настроек)."""

    global _setting_enabled, _uplink_checked
    with _state_lock:
        _setting_enabled = bool(setting_enabled)
        _uplink_checked = None


def probe_ipv6_first(*, clock: Callable[[], float] = time.monotonic, has_ipv6: Callable[[], bool] = uplink_has_ipv6) -> bool:
    """IPv6 первым для временных ядер замера; IPv6 сети перепроверяется не чаще раза в 30 с."""

    global _uplink_checked
    with _state_lock:
        if not _setting_enabled:
            return False
        cached = _uplink_checked
    now = clock()
    if cached is not None and now - cached[0] < _UPLINK_CACHE_S:
        return cached[1]
    value = bool(has_ipv6())
    with _state_lock:
        _uplink_checked = (now, value)
    return value


def order_addresses(
    name: str,
    addresses: Iterable[str],
    *,
    ipv6_first: bool,
    memory: FamilyMemory | None = None,
    proven_only: bool = False,
) -> list[str]:
    """Адреса сервера в порядке попыток: нужное семейство первым, внутри — как было.

    Выключено (``ipv6_first=False``) — прежний порядок приложения: IPv4 первым.
    Включено — IPv6 первым, если память не говорит, что для этого имени IPv6
    не ответил или работал IPv4. ``proven_only`` — для одного сокета без отката
    (временное ядро замера): IPv6 первым, только если он уже работал с этим именем.
    """

    values = [str(value) for value in addresses]
    prefer6 = bool(ipv6_first)
    if prefer6 and proven_only:
        prefer6 = memory is not None and memory.worked_ipv6(name)
    elif prefer6 and memory is not None:
        prefer6 = memory.prefer_ipv6(name, True)
    first, second = (6, 4) if prefer6 else (4, 6)
    ordered = [value for value in values if _family(value) == first]
    ordered += [value for value in values if _family(value) == second]
    ordered += [value for value in values if _family(value) not in (4, 6)]
    return ordered


def has_other_family(addresses: Iterable[str], tried: str) -> str | None:
    """Первый адрес другого семейства, чем ``tried``, или ``None``."""

    family = _family(tried)
    return next((str(value) for value in addresses if _family(value) not in (0, family)), None)
