"""Worker for local MMDB reads; intentionally has no network capabilities."""
from __future__ import annotations

from PyQt6.QtCore import QThread, pyqtSignal

from ..profiles.geoip import CountryDatabase


class CountryResolver(QThread):
    resolved = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, nodes, parent=None, *, database_factory=CountryDatabase):
        super().__init__(parent)
        # id, endpoint fingerprint, known addresses; unresolved names yield no country.
        self._nodes = tuple(nodes)
        self._database_factory = database_factory

    def run(self) -> None:
        results = {}
        try:
            with self._database_factory() as database:
                for node_id, fingerprint, addresses in self._nodes:
                    if self.isInterruptionRequested():
                        return
                    results[node_id] = (fingerprint, database.countries(addresses))
        except Exception:
            self.failed.emit("Локальная база стран недоступна")
        self.resolved.emit(results)
