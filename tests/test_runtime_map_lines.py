"""[runtime-map] stays small so a big server list cannot push real events out of the diagnostics archive."""

from __future__ import annotations

import unittest

from xray_fluent.diagnostics.runtime_logging import (
    RUNTIME_MAP_FULL_LIMIT,
    RuntimeLogContext,
    RuntimeNodeIdentity,
    runtime_mapping_lines,
)


def _identity(index: int) -> RuntimeNodeIdentity:
    return RuntimeNodeIdentity(ref=f"{index:012x}", name=f"Server {index}", protocol="vless")


def _context(count: int) -> RuntimeLogContext:
    nodes = {f"__app_proxy_{index:04d}": _identity(index) for index in range(count)}
    return RuntimeLogContext(engine="xray", role="sidecar", mode="proxy", generation=4, selected=_identity(7),
                             outbound_nodes=nodes)


class RuntimeMapLinesTests(unittest.TestCase):
    def test_small_map_lists_every_outbound(self):
        lines = runtime_mapping_lines(_context(3))
        self.assertEqual(3, len(lines))
        self.assertIn("outbound=__app_proxy_0000", lines[0])
        self.assertIn('node="Server 0"', lines[0])

    def test_big_map_is_one_summary_line_with_the_selected_server(self):
        lines = runtime_mapping_lines(_context(1112))
        self.assertEqual(1, len(lines))
        self.assertIn("outbounds=1112", lines[0])
        self.assertIn("generation=4", lines[0])
        self.assertIn('node="Server 7"', lines[0])

    def test_limit_is_inclusive(self):
        self.assertEqual(RUNTIME_MAP_FULL_LIMIT, len(runtime_mapping_lines(_context(RUNTIME_MAP_FULL_LIMIT))))


if __name__ == "__main__":
    unittest.main()
