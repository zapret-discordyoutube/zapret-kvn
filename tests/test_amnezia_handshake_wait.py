"""How long the AmneziaWG helper waits for its first handshake (release gate 2026-11-27).

The numbers are the ones of the real gate runs: the real AmneziaWG server of the test person entered through the WARP hop and the
helper gave up at 12 s ("transition connect failed" at 14 s in the 0.8.132 and 0.8.133 full runs) while the same test passed
alone in 12 s.  Through the hop the wait is longer; without it the 12 s of the owner's report ("thinking for a very long time")
stay.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xray_fluent.engines.amnezia.manager import (  # noqa: E402
    HANDSHAKE_WAIT_S,
    HANDSHAKE_WAIT_THROUGH_HOP_S,
    AmneziaManager,
    handshake_wait_seconds,
)


class HandshakeWaitTests(unittest.TestCase):
    def test_without_the_hop_the_owners_12_seconds_stay(self) -> None:
        self.assertEqual(12.0, handshake_wait_seconds(False))
        self.assertEqual(HANDSHAKE_WAIT_S, AmneziaManager.handshake_wait_s)

    def test_through_the_hop_the_tunnel_gets_time_to_come_up_first(self) -> None:
        self.assertGreater(handshake_wait_seconds(True), 14.5, "the failed gate run gave up at 14.4 s")
        self.assertEqual(HANDSHAKE_WAIT_THROUGH_HOP_S, handshake_wait_seconds(True))


if __name__ == "__main__":
    unittest.main()
