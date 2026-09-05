"""Worker for local MMDB reads; intentionally has no network capabilities."""
from __future__ import annotations

from PyQt6.QtCore import QThread, pyqtSignal

from ..profiles.geoip import CountryDatabase
from ..platform.windows.dns_cache import read_dns_cache, host_key
from ipaddress import ip_address


class CountryResolver(QThread):
    resolved = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, nodes, parent=None, *, database_factory=CountryDatabase, cache_provider=read_dns_cache):
        super().__init__(parent)
        # id, endpoint fingerprint, known addresses; unresolved names yield no country.
        self._nodes = tuple(nodes)
        self._database_factory = database_factory
        self._cache_provider = cache_provider

    def run(self) -> None:
        results = {}
        try:
            def literal(address):
                try:
                    ip_address(address.strip().removeprefix("[").removesuffix("]"))
                    return True
                except ValueError:
                    return False
            cache = self._cache_provider() if any(not literal(a) for _, _, addresses in self._nodes for a in addresses) else {}
            with self._database_factory() as database:
                for node_id, fingerprint, addresses in self._nodes:
                    if self.isInterruptionRequested():
                        return
                    known = tuple(ip for address in addresses for ip in
                                  ((address,) if literal(address) else cache.get(host_key(address), (address,))))
                    results[node_id] = (fingerprint, database.countries(known))
        except Exception:
            self.failed.emit("Локальная база стран недоступна")
        self.resolved.emit(results)
