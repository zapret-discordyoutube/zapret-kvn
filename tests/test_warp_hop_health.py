"""What the core says about the WARP hop, counted per connect (owner request 2026-11-26).

The lines below are REAL captures: the first from the real controller on win10 (2026-11-25 18:04), the others from the
owner's diagnostics of 0.8.112/0.8.113 (server names are already hashed by the app's own masking of reports).
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xray_fluent.network.warp_hop_health import HopHealth, LOOKUP_STUCK, TUNNEL_DOWN  # noqa: E402

PREFIX = "[sing-box][engine=sing-box role=front mode=proxy generation=1 outbound=kvn-warp-entry] "
RETRY_2408 = PREFIX + "-0400 2026-11-25 18:04:18 WARN endpoint/warp[kvn-warp-entry]: WARP handshake did not answer at 162.159.192.10:2408, trying the next address"
RETRY_500 = PREFIX + "-0400 2026-11-25 18:04:22 WARN endpoint/warp[kvn-warp-entry]: WARP handshake did not answer at 162.159.192.10:500, trying the next address"
NOT_READY = PREFIX + "+0300 2026-11-26 00:07:40 ERROR [1316337261 15ms] connection: open connection to [<сервер 17e86f8758cc>] using outbound/warp[kvn-warp-entry]: endpoint not initialized"
LOOKUP = PREFIX + "+0300 2026-11-26 00:07:40 ERROR [3405634934 6.45s] connection: open connection to <сервер 9cd8dfb20f14>:8443 using outbound/warp[kvn-warp-entry]: lookup <сервер 9cd8dfb20f14>: context deadline exceeded"
REGISTRATION = PREFIX + '+0300 2026-11-25 23:43:53 ERROR endpoint/warp[kvn-warp-entry]: Post "<URL скрыт>": read tcp 192.168.1.2:29054->8.6.112.0:443: wsarecv: An existing connection was forcibly closed by the remote host.'
UNRELATED = "[sing-box][engine=sing-box role=front mode=proxy generation=1] +0300 2026-11-26 00:49:40 ERROR [2452425249 8ms] connection: open connection to chatgpt.com:443 using outbound/selector[zapret-slot-ai]: dial tcp 127.0.0.1:0->127.0.0.1:11820: connectex: No connection could be made"


class HopHealthTests(unittest.TestCase):
    def test_real_lines_are_counted_and_ports_kept_without_addresses(self) -> None:
        health = HopHealth()
        for line in (RETRY_2408, RETRY_500, NOT_READY, LOOKUP, REGISTRATION, UNRELATED):
            health.observe(line)
        self.assertEqual(2, health.handshake_retries)
        self.assertEqual([2408, 500], health.ports_tried)
        self.assertEqual(1, health.not_initialized)
        self.assertEqual(1, health.lookup_timeouts)
        self.assertEqual(1, health.registration_errors)
        summary = health.summary(40)
        self.assertIn("порты 2408,500", summary)
        self.assertNotIn("162.159", summary)

    def test_the_user_is_told_once_when_the_tunnel_is_clearly_not_coming_up(self) -> None:
        health = HopHealth()
        notices = [health.observe(NOT_READY) for _ in range(12)]
        self.assertEqual([TUNNEL_DOWN], [n for n in notices if n])

    def test_repeated_handshake_failures_alone_tell_the_user(self) -> None:
        health = HopHealth()
        notices = [health.observe(line) for line in (RETRY_2408, RETRY_500, RETRY_2408)]
        self.assertEqual(TUNNEL_DOWN, notices[-1])

    def test_a_slow_start_is_not_a_warning(self) -> None:
        health = HopHealth()
        self.assertIsNone(health.observe(RETRY_2408))
        self.assertIsNone(health.observe(NOT_READY))

    def test_stuck_address_lookups_get_their_own_message(self) -> None:
        health = HopHealth()
        notices = [health.observe(LOOKUP) for _ in range(5)]
        self.assertEqual([LOOKUP_STUCK], [n for n in notices if n])


if __name__ == "__main__":
    unittest.main()
