"""Async IP-based country resolution (network I/O lives here, not in country_flags)."""

from __future__ import annotations

import json
import socket
import urllib.request

from PyQt6.QtCore import QThread, pyqtSignal

from .http_utils import urlopen as _urlopen


class CountryResolver(QThread):
    resolved = pyqtSignal(dict)  # {node_id: country_code}

    def __init__(self, nodes: list[tuple[str, str]], parent=None):
        super().__init__(parent)
        self._nodes = nodes  # [(node_id, server_address), ...]

    def run(self) -> None:
        results: dict[str, str] = {}
        ip_map: dict[str, list[str]] = {}  # ip → [node_ids]

        for node_id, server in self._nodes:
            try:
                infos = socket.getaddrinfo(server, None, socket.AF_INET, socket.SOCK_STREAM)
                if infos:
                    ip = infos[0][4][0]
                    ip_map.setdefault(ip, []).append(node_id)
            except Exception:
                pass

        if not ip_map:
            self.resolved.emit(results)
            return

        ips = list(ip_map.keys())
        for i in range(0, len(ips), 100):
            batch = ips[i : i + 100]
            try:
                payload = json.dumps(
                    [{"query": ip, "fields": "countryCode,query"} for ip in batch]
                ).encode()
                req = urllib.request.Request(
                    "http://ip-api.com/batch",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
                with _urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read())
                for item in data:
                    cc = item.get("countryCode", "")
                    ip = item.get("query", "")
                    if cc and ip in ip_map:
                        for nid in ip_map[ip]:
                            results[nid] = cc
            except Exception:
                pass

        self.resolved.emit(results)
