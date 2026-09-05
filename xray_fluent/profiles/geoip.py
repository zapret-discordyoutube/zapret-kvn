"""Offline country lookup. Never resolve names or open sockets here."""
from __future__ import annotations

from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path

from ..constants import ASSETS_DIR

DATABASE_PATH = ASSETS_DIR / "geoip" / "country.mmdb"


def normalize_country(value: str) -> str:
    value = str(value or "").strip().upper()
    return value if value != "ZZ" and len(value) == 2 and value.isascii() and value.isalpha() else ""


def endpoint_hosts(node) -> tuple[str, ...]:
    """Use transport peers, never interface addresses or allowed network ranges."""
    if node.scheme.lower() in {"awg", "wireguard"}:
        peers = node.outbound.get("peers", [])
        hosts = tuple(str(p.get("address") or "") for p in peers if isinstance(p, dict))
        return hosts or (node.server,)
    return (node.server,)


class CountryDatabase:
    def __init__(self, path: Path = DATABASE_PATH):
        self.path = path
        self._reader = None

    def __enter__(self):
        import maxminddb
        self._reader = maxminddb.open_database(str(self.path))
        return self

    def __exit__(self, *_):
        if self._reader is not None:
            self._reader.close()
        self.country.cache_clear()

    @lru_cache(maxsize=32768)
    def country(self, address: str) -> str:
        try:
            ip = ip_address(address.strip().removeprefix("[").removesuffix("]"))
        except ValueError:
            return ""
        if not ip.is_global or self._reader is None:
            return ""
        record = self._reader.get(str(ip)) or {}
        return normalize_country((record.get("country") or {}).get("iso_code", ""))

    def countries(self, addresses: tuple[str, ...]) -> str:
        codes = {self.country(address) for address in addresses}
        return next(iter(codes)) if len(codes) == 1 else ""
