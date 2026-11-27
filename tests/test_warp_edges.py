"""The WARP edges the service sends in the subscription header (owner 2026-11-27).

The edges are real Cloudflare addresses: HTTP/2 MASQUE answers on 162.159.198.2-50 (checked against the real edge from the
host, where the patched core came up through 162.159.198.7 in 6 s with this very list) and WireGuard on 188.114.96-99.x.
"""

from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xray_fluent.network import warp_edges  # noqa: E402

GOOD = {
    "v": 1,
    "edges": [
        {"transport": "masque-http2", "address": "162.159.198.7", "sni": "www.cloudflare.com"},
        {"transport": "masque-quic", "address": "2606:4700:103::2", "port": 443},
        {"transport": "wireguard", "address": "188.114.97.5", "port": 2408},
    ],
}


def _header(document: object) -> str:
    return base64.b64encode(json.dumps(document).encode()).decode()


class EdgesTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.profile = self.dir / "warp-entry-profile.json"

    def test_a_good_list_is_kept_and_read_back(self) -> None:
        self.assertEqual("written", warp_edges.apply({"Zapret-Warp-Edges": _header(GOOD)}, self.dir))
        self.assertEqual(GOOD["edges"], warp_edges.load(self.profile))
        self.assertEqual("same", warp_edges.apply({"zapret-warp-edges": _header(GOOD)}, self.dir))

    def test_names_bad_transports_bad_names_and_the_excess_are_dropped(self) -> None:
        many = [{"transport": "wireguard", "address": f"188.114.96.{index}"} for index in range(1, 41)]
        edges = warp_edges.valid(
            [
                {"transport": "wireguard", "address": "engage.cloudflareclient.com"},
                {"transport": "carrier-pigeon", "address": "1.2.3.4"},
                {"transport": "masque-http2", "address": "162.159.198.9", "sni": "bad name!"},
                {"transport": "wireguard", "address": "1.2.3.4", "sni": "x.example"},
                {"transport": "wireguard", "address": "999.1.1.1"},
                {"transport": "wireguard", "address": "1.2.3.4", "port": 70000},
                "not an object",
                *many,
            ]
        )
        self.assertEqual(warp_edges.MAX_EDGES, len(edges))
        self.assertTrue(all(edge["address"].startswith("188.114.96.") for edge in edges))

    def test_garbage_writes_nothing_and_an_empty_list_removes_the_file(self) -> None:
        for value in ("%%%", _header("not a document"), _header({"v": 2, "edges": []}), _header({"v": 1}),
                      "A" * (warp_edges.MAX_HEADER_BYTES + 1)):
            self.assertEqual("invalid", warp_edges.apply({"zapret-warp-edges": value}, self.dir), value[:12])
        self.assertEqual([], list(self.dir.iterdir()))
        warp_edges.apply({"zapret-warp-edges": _header(GOOD)}, self.dir)
        self.assertEqual("written", warp_edges.apply({"zapret-warp-edges": _header({"v": 1, "edges": []})}, self.dir))
        self.assertFalse(warp_edges.edges_path(self.profile).exists())
        self.assertEqual("none", warp_edges.apply({"etag": "x"}, self.dir))

    def test_a_broken_file_is_no_list_at_all(self) -> None:
        warp_edges.edges_path(self.profile).write_text("{broken", encoding="utf-8")
        self.assertEqual([], warp_edges.load(self.profile))


if __name__ == "__main__":
    unittest.main()
