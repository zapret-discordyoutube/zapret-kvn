"""Fast Windows network-adapter queries via ctypes GetAdaptersAddresses.

Replaces PowerShell polling (Get-NetIPAddress / netsh) in TUN readiness
checks: a single GetAdaptersAddresses call takes ~1ms instead of ~500ms
for a PowerShell process, which lets pollers use a 100ms step.

The module imports cleanly on any OS; the actual iphlpapi call is only
attempted on Windows. Any failure raises :class:`WinNetInfoError` (or the
underlying ctypes exception) so callers can fall back to their legacy
PowerShell/netsh paths (Wine and very old Windows builds may misbehave).
"""

from __future__ import annotations

import ctypes
import os
import socket
from ctypes import POINTER, Structure, c_char_p, c_int, c_ubyte, c_ulong, c_ushort, c_void_p, c_wchar_p
from dataclasses import dataclass

__all__ = [
    "AdapterInfo",
    "WinNetInfoError",
    "adapter_exists",
    "adapter_has_ipv4",
    "any_adapter_name_contains",
    "find_adapter",
    "is_available",
    "list_adapters",
]


class WinNetInfoError(RuntimeError):
    """Raised when adapter information cannot be obtained via iphlpapi."""


# Windows socket address families (values differ from Linux for AF_INET6).
_AF_UNSPEC = 0
_AF_INET = 2
_AF_INET6 = 23

_GAA_FLAG_SKIP_ANYCAST = 0x0002
_GAA_FLAG_SKIP_MULTICAST = 0x0004
_GAA_FLAG_SKIP_DNS_SERVER = 0x0008
_GAA_FLAG_INCLUDE_ALL_INTERFACES = 0x0100

_ERROR_SUCCESS = 0
_ERROR_BUFFER_OVERFLOW = 111
_ERROR_NO_DATA = 232


class _SOCKADDR(Structure):
    # sa_data is sized to cover sockaddr_in6 (28 bytes total).
    _fields_ = [("sa_family", c_ushort), ("sa_data", c_ubyte * 26)]


class _SOCKET_ADDRESS(Structure):
    _fields_ = [("lpSockaddr", POINTER(_SOCKADDR)), ("iSockaddrLength", c_int)]


class _IP_ADAPTER_UNICAST_ADDRESS(Structure):
    pass


# The leading {Length, Flags} pair mirrors the 8-byte alignment union of
# IP_ADAPTER_UNICAST_ADDRESS_LH. The structure is intentionally truncated
# after Address: entries are only ever read through API-allocated memory
# via Next pointers, never allocated or indexed by our sizeof.
_IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", c_ulong),
    ("Flags", c_ulong),
    ("Next", POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", _SOCKET_ADDRESS),
]


class _IP_ADAPTER_ADDRESSES(Structure):
    pass


# Truncated after FriendlyName for the same reason as above.
_IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", c_ulong),
    ("IfIndex", c_ulong),
    ("Next", POINTER(_IP_ADAPTER_ADDRESSES)),
    ("AdapterName", c_char_p),
    ("FirstUnicastAddress", POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress", c_void_p),
    ("FirstMulticastAddress", c_void_p),
    ("FirstDnsServerAddress", c_void_p),
    ("DnsSuffix", c_wchar_p),
    ("Description", c_wchar_p),
    ("FriendlyName", c_wchar_p),
]


@dataclass(slots=True)
class AdapterInfo:
    adapter_name: str
    friendly_name: str
    description: str
    if_index: int
    ipv4_addresses: list[str]
    ipv6_addresses: list[str]  # link-local (fe80::/10) excluded


def _sockaddr_to_ip(sockaddr_ptr) -> tuple[int, str] | None:
    if not sockaddr_ptr:
        return None
    sa = sockaddr_ptr.contents
    raw = bytes(sa.sa_data)
    family = int(sa.sa_family)
    try:
        if family == _AF_INET:
            # sockaddr_in: sa_data = port(2) + addr(4) + zero padding
            return _AF_INET, socket.inet_ntop(socket.AF_INET, raw[2:6])
        if family == _AF_INET6:
            # sockaddr_in6: sa_data = port(2) + flowinfo(4) + addr(16) + scope
            return _AF_INET6, socket.inet_ntop(socket.AF_INET6, raw[6:22])
    except (OSError, ValueError):
        return None
    return None


def _parse_adapter_chain(first) -> list[AdapterInfo]:
    adapters: list[AdapterInfo] = []
    current = first
    while current:
        entry = current.contents
        ipv4_addresses: list[str] = []
        ipv6_addresses: list[str] = []
        unicast = entry.FirstUnicastAddress
        while unicast:
            item = unicast.contents
            parsed = _sockaddr_to_ip(item.Address.lpSockaddr)
            if parsed is not None:
                family, text = parsed
                if family == _AF_INET:
                    if text != "0.0.0.0":
                        ipv4_addresses.append(text)
                elif not text.lower().startswith("fe80"):
                    ipv6_addresses.append(text)
            unicast = item.Next
        raw_name = entry.AdapterName
        adapters.append(
            AdapterInfo(
                adapter_name=(raw_name or b"").decode("ascii", errors="replace"),
                friendly_name=str(entry.FriendlyName or ""),
                description=str(entry.Description or ""),
                if_index=int(entry.IfIndex),
                ipv4_addresses=ipv4_addresses,
                ipv6_addresses=ipv6_addresses,
            )
        )
        current = entry.Next
    return adapters


_get_adapters_addresses = None


def _resolve_get_adapters_addresses():
    global _get_adapters_addresses
    if _get_adapters_addresses is None:
        iphlpapi = ctypes.WinDLL("iphlpapi")
        func = iphlpapi.GetAdaptersAddresses
        func.argtypes = [c_ulong, c_ulong, c_void_p, c_void_p, POINTER(c_ulong)]
        func.restype = c_ulong
        _get_adapters_addresses = func
    return _get_adapters_addresses


def list_adapters() -> list[AdapterInfo]:
    """Return all network adapters. Raises WinNetInfoError on any failure."""
    if os.name != "nt":
        raise WinNetInfoError("GetAdaptersAddresses is only available on Windows")
    try:
        func = _resolve_get_adapters_addresses()
    except Exception as exc:  # missing DLL/symbol (Wine, stripped systems)
        raise WinNetInfoError(f"iphlpapi is unavailable: {exc}") from exc
    # Wintun can briefly exist without being bound to either address family
    # while sing-box configures it.  Ask for every NDIS interface so a poll
    # started during that window does not keep overlooking the same adapter.
    flags = (
        _GAA_FLAG_SKIP_ANYCAST
        | _GAA_FLAG_SKIP_MULTICAST
        | _GAA_FLAG_SKIP_DNS_SERVER
        | _GAA_FLAG_INCLUDE_ALL_INTERFACES
    )
    size = c_ulong(16 * 1024)
    for _ in range(4):
        buffer = ctypes.create_string_buffer(size.value)
        result = func(_AF_UNSPEC, flags, None, ctypes.cast(buffer, c_void_p), ctypes.byref(size))
        if result == _ERROR_BUFFER_OVERFLOW:
            continue
        if result == _ERROR_NO_DATA:
            return []
        if result != _ERROR_SUCCESS:
            raise WinNetInfoError(f"GetAdaptersAddresses failed with code {result}")
        first = ctypes.cast(buffer, POINTER(_IP_ADAPTER_ADDRESSES))
        return _parse_adapter_chain(first)
    raise WinNetInfoError("GetAdaptersAddresses buffer negotiation failed")


def find_adapter(name: str) -> AdapterInfo | None:
    """Find an adapter whose friendly name, description or GUID matches ``name``."""
    needle = str(name or "").strip().lower()
    if not needle:
        return None
    for adapter in list_adapters():
        candidates = (adapter.friendly_name, adapter.description, adapter.adapter_name)
        if any(candidate.strip().lower() == needle for candidate in candidates):
            return adapter
    return None


def adapter_exists(name: str) -> bool:
    return find_adapter(name) is not None


def adapter_has_ipv4(name: str) -> bool:
    adapter = find_adapter(name)
    return adapter is not None and bool(adapter.ipv4_addresses)


def any_adapter_name_contains(substring: str) -> bool:
    needle = str(substring or "").strip().lower()
    if not needle:
        return False
    for adapter in list_adapters():
        candidates = (adapter.friendly_name, adapter.description, adapter.adapter_name)
        if any(needle in candidate.lower() for candidate in candidates):
            return True
    return False


_available: bool | None = None


def is_available() -> bool:
    """Whether the ctypes fast path works in this environment (cached probe)."""
    global _available
    if _available is None:
        if os.name != "nt":
            _available = False
        else:
            try:
                list_adapters()
                _available = True
            except Exception:
                _available = False
    return _available


def _reset_availability_cache_for_tests() -> None:
    global _available
    _available = None
