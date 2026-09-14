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
from ctypes import POINTER, Structure, c_char_p, c_int, c_ubyte, c_ulong, c_ulonglong, c_ushort, c_void_p, c_wchar_p
from dataclasses import dataclass, field

__all__ = [
    "AdapterInfo",
    "WinNetInfoError",
    "adapter_exists",
    "adapter_has_ipv4",
    "any_adapter_name_contains",
    "best_interface_for",
    "find_adapter",
    "is_available",
    "list_adapters",
    "resolve_physical_uplink",
    "select_physical_uplink",
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

# IF_OPER_STATUS: only IfOperStatusUp (1) carries traffic.
_IF_OPER_STATUS_UP = 1
# MAX_ADAPTER_ADDRESS_LENGTH from iptypes.h.
_MAX_ADAPTER_ADDRESS_LENGTH = 8
# IfType values (ipifcons.h) that can never be a physical uplink.
_IF_TYPE_SOFTWARE_LOOPBACK = 24
_IF_TYPE_TUNNEL = 131
# A public IPv4 used only to ask the OS which interface reaches the internet.
_DEFAULT_PROBE_DESTINATION = "8.8.8.8"


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


# The DNS-server and gateway lists share the {Length, Flags/Reserved, Next,
# Address} prologue with the unicast node, so the same truncated structure
# walks all three chains through API-allocated Next pointers.
#
# Fields through Ipv4Metric mirror IP_ADAPTER_ADDRESSES_LH exactly (iptypes.h);
# the layout is only extended, never reordered, so existing readers that stop
# at FriendlyName keep their offsets. Everything after Ipv4Metric is omitted
# because nothing here reads it. Entries are always API-allocated, so the
# omission is safe: we never allocate or index by our own sizeof.
_IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", c_ulong),
    ("IfIndex", c_ulong),
    ("Next", POINTER(_IP_ADAPTER_ADDRESSES)),
    ("AdapterName", c_char_p),
    ("FirstUnicastAddress", POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress", c_void_p),
    ("FirstMulticastAddress", c_void_p),
    ("FirstDnsServerAddress", POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("DnsSuffix", c_wchar_p),
    ("Description", c_wchar_p),
    ("FriendlyName", c_wchar_p),
    ("PhysicalAddress", c_ubyte * _MAX_ADAPTER_ADDRESS_LENGTH),
    ("PhysicalAddressLength", c_ulong),
    ("Flags", c_ulong),
    ("Mtu", c_ulong),
    ("IfType", c_ulong),
    ("OperStatus", c_int),
    ("Ipv6IfIndex", c_ulong),
    ("ZoneIndices", c_ulong * 16),
    ("FirstPrefix", c_void_p),
    ("TransmitLinkSpeed", c_ulonglong),
    ("ReceiveLinkSpeed", c_ulonglong),
    ("FirstWinsServerAddress", c_void_p),
    ("FirstGatewayAddress", POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("Ipv4Metric", c_ulong),
    ("Ipv6Metric", c_ulong),
]


@dataclass(slots=True)
class AdapterInfo:
    adapter_name: str
    friendly_name: str
    description: str
    if_index: int
    ipv4_addresses: list[str]
    ipv6_addresses: list[str]  # link-local (fe80::/10) excluded
    if_type: int = 0
    oper_status: int = 0
    ipv4_metric: int = 0
    ipv4_gateways: list[str] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)  # IPv4 then IPv6


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


def _walk_address_nodes(first) -> list[tuple[int, str]]:
    """Collect (family, ip) from a {Length, Flags, Next, Address} node chain."""
    collected: list[tuple[int, str]] = []
    node = first
    while node:
        item = node.contents
        parsed = _sockaddr_to_ip(item.Address.lpSockaddr)
        if parsed is not None:
            collected.append(parsed)
        node = item.Next
    return collected


def _parse_adapter_chain(first) -> list[AdapterInfo]:
    adapters: list[AdapterInfo] = []
    current = first
    while current:
        entry = current.contents
        ipv4_addresses: list[str] = []
        ipv6_addresses: list[str] = []
        for family, text in _walk_address_nodes(entry.FirstUnicastAddress):
            if family == _AF_INET:
                if text != "0.0.0.0":
                    ipv4_addresses.append(text)
            elif not text.lower().startswith("fe80"):
                ipv6_addresses.append(text)

        ipv4_gateways = [text for family, text in _walk_address_nodes(entry.FirstGatewayAddress)
                         if family == _AF_INET and text != "0.0.0.0"]
        # DNS servers: IPv4 first, then non-link-local IPv6, matching how the
        # bootstrap resolver prefers reachable servers.
        dns_v4 = [text for family, text in _walk_address_nodes(entry.FirstDnsServerAddress) if family == _AF_INET]
        dns_v6 = [text for family, text in _walk_address_nodes(entry.FirstDnsServerAddress)
                  if family == _AF_INET6 and not text.lower().startswith("fe80")]

        raw_name = entry.AdapterName
        adapters.append(
            AdapterInfo(
                adapter_name=(raw_name or b"").decode("ascii", errors="replace"),
                friendly_name=str(entry.FriendlyName or ""),
                description=str(entry.Description or ""),
                if_index=int(entry.IfIndex),
                ipv4_addresses=ipv4_addresses,
                ipv6_addresses=ipv6_addresses,
                if_type=int(entry.IfType),
                oper_status=int(entry.OperStatus),
                ipv4_metric=int(entry.Ipv4Metric),
                ipv4_gateways=ipv4_gateways,
                dns_servers=dns_v4 + dns_v6,
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


class _SOCKADDR_IN(Structure):
    _fields_ = [
        ("sin_family", c_ushort),
        ("sin_port", c_ushort),
        ("sin_addr", c_ubyte * 4),
        ("sin_zero", c_ubyte * 8),
    ]


_get_best_interface_ex = None


def _resolve_get_best_interface_ex():
    global _get_best_interface_ex
    if _get_best_interface_ex is None:
        iphlpapi = ctypes.WinDLL("iphlpapi")
        func = iphlpapi.GetBestInterfaceEx
        func.argtypes = [c_void_p, POINTER(c_ulong)]
        func.restype = c_ulong
        _get_best_interface_ex = func
    return _get_best_interface_ex


def best_interface_for(dest_ipv4: str) -> int:
    """Interface index the OS would use to reach ``dest_ipv4`` (0 on failure).

    This is the authoritative default-route decision (the same one sing-box
    logs as the ``default interface``). It does not depend on the unreliable
    per-adapter gateway list. Passing the AWG server's own IP returns the
    physical uplink even while a tunnel holds the default route, because
    WireGuard keeps a host route to the server endpoint off the tunnel.
    """
    if os.name != "nt":
        return 0
    try:
        func = _resolve_get_best_interface_ex()
    except Exception:  # missing DLL/symbol (Wine, stripped systems)
        return 0
    sockaddr = _SOCKADDR_IN()
    sockaddr.sin_family = _AF_INET
    try:
        sockaddr.sin_addr = (c_ubyte * 4)(*socket.inet_aton(dest_ipv4))
    except OSError:
        return 0
    index = c_ulong(0)
    if func(ctypes.byref(sockaddr), ctypes.byref(index)) != _ERROR_SUCCESS:
        return 0
    return int(index.value)


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
    # DNS servers are kept (no SKIP_DNS_SERVER): the physical-uplink resolver
    # needs them for bootstrap resolution, and the extra parsing is cheap.
    flags = (
        _GAA_FLAG_SKIP_ANYCAST
        | _GAA_FLAG_SKIP_MULTICAST
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


def _has_routable_ipv4(adapter: AdapterInfo) -> bool:
    return any(not addr.startswith("169.254.") for addr in adapter.ipv4_addresses)


def select_physical_uplink(adapters: list[AdapterInfo]) -> AdapterInfo | None:
    """Fallback uplink pick when GetBestInterfaceEx is unavailable.

    A candidate must be operationally up, carry a routable (non-APIPA) IPv4
    address, and not be a loopback or tunnel interface (so the AWG relay never
    binds onto its own tunnel). Ties break on the lowest ``Ipv4Metric`` (the OS
    route preference), then the lowest interface index for determinism. The
    per-adapter gateway list is deliberately NOT used: Windows leaves
    ``FirstGatewayAddress`` empty on many working uplinks (Hyper-V vEthernet,
    some DHCP setups), which previously rejected every adapter.
    """
    candidates = [
        adapter
        for adapter in adapters
        if adapter.if_index > 0
        and adapter.oper_status == _IF_OPER_STATUS_UP
        and adapter.if_type not in (_IF_TYPE_SOFTWARE_LOOPBACK, _IF_TYPE_TUNNEL)
        and _has_routable_ipv4(adapter)
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda a: (a.ipv4_metric, a.if_index))


def resolve_physical_uplink(dest_ipv4: str = _DEFAULT_PROBE_DESTINATION) -> tuple[int, list[str]] | None:
    """Return ``(interface_index, bootstrap_dns)`` for the physical uplink.

    Primary path: ask the OS which interface reaches ``dest_ipv4``
    (``GetBestInterfaceEx``) — the authoritative default-route decision, which
    does not depend on the unreliable per-adapter gateway list. Pass the AWG
    server's IP to get the physical uplink even while a tunnel holds the
    default route. Fallback: pick by route metric from the adapter list.

    Returns ``None`` only when neither path yields a usable index. Raises
    :class:`WinNetInfoError` when adapter enumeration itself is unavailable.
    """
    adapters = list_adapters()
    by_index = {adapter.if_index: adapter for adapter in adapters}
    index = best_interface_for(dest_ipv4)
    adapter = by_index.get(index) if index > 0 else None
    if index > 0 and (
        adapter is None
        or adapter.if_type not in (_IF_TYPE_SOFTWARE_LOOPBACK, _IF_TYPE_TUNNEL)
    ):
        return index, list(adapter.dns_servers) if adapter is not None else []
    uplink = select_physical_uplink(adapters)
    if uplink is not None:
        return uplink.if_index, list(uplink.dns_servers)
    return None


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
