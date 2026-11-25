"""The WARP entry hop's facts in connection reports (owner 2026-11-25: «make more logs and put them in the database»).

Agreed with the WARP chat: settings.warp_entry (bool), probes warp_register and warp_tunnel ({r, ms}) at the end of the
probe order, details warp_retries (int). Everything stays out of the report until vpnbot admits it (checks.WARP_LIVE):
a report with an unknown probe is refused whole. The facts are built from the REAL core lines and the real registration
error text captured in the field (tests/test_warp_hop_health.py), by the app's own functions, and go through the real
reporter to a local ingest.
"""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import json
import tempfile
import threading
import unittest
from http.server import HTTPServer
from pathlib import Path
from unittest.mock import patch

from tests import test_client_reports as base
from tests.test_warp_hop_health import LOOKUP, NOT_READY, REGISTRATION, RETRY_2408, RETRY_500
from xray_fluent.client_reports import checks as k
from xray_fluent.client_reports import contract as c
from xray_fluent.client_reports import reporter as r
from xray_fluent.network.warp_hop_health import HopHealth, WarpFacts, registration_result, tunnel_result

REGISTRATION_TEXT = REGISTRATION.split("ERROR ", 1)[1]


def facts_after(lines: tuple[str, ...], *, registered: bool | None = None) -> WarpFacts:
    """What the controller would hand over after these real core lines (the same functions it uses)."""
    health = HopHealth()
    for line in lines:
        health.observe(line)
    register = None if registered is None else (registration_result(registered, "" if registered else REGISTRATION_TEXT), 640)
    return WarpFacts(enabled=True, register=register, retries=health.handshake_retries,
                     tunnel=(tunnel_result(health), 2300))


class WarpContractTests(unittest.TestCase):
    def test_nothing_of_the_hop_is_sent_while_vpnbot_has_not_admitted_it(self) -> None:
        facts = facts_after((RETRY_2408, RETRY_500, NOT_READY), registered=False)
        self.assertFalse(k.WARP_LIVE)
        self.assertEqual({}, k.warp_checks(facts))
        details = c.AttemptDetails(settings=c.ReportSettings(mode="tun", warp_entry=True), warp_retries=2).cleaned()
        self.assertEqual(c.ReportSettings(mode="tun"), details.settings)
        self.assertIsNone(details.warp_retries)
        self.assertNotIn("warp_tunnel", k.PROBES)

    def test_the_probes_stand_last_in_the_agreed_order_once_live(self) -> None:
        with patch.object(k, "WARP_LIVE", True):
            order = tuple(probe for probe in (
                "control_front", "control_neutral", "dns_system", "dns_doh", "tcp_preflight", "tcp_target", "tcp_443",
                "tls_real", "tls_neutral", "tls_front", "quic_neutral", "quic_target", "tunnel_a", "tunnel_b",
                "direct_a", "direct_b", "flow",
            )) + (("health",) if k.HEALTH_LIVE else ()) + k.WARP_PROBES
        self.assertEqual(("warp_register", "warp_tunnel"), k.WARP_PROBES)
        self.assertEqual(order[-2:], k.WARP_PROBES)

    def test_real_facts_become_probes_and_a_step_that_did_not_run_sends_none(self) -> None:
        failing = facts_after((RETRY_2408, RETRY_500, NOT_READY, LOOKUP), registered=False)
        self.assertEqual(("reset", 640), failing.register)
        self.assertEqual("timeout", failing.tunnel[0])
        healthy = facts_after((), registered=None)
        with patch.object(k, "WARP_LIVE", True), patch.object(k, "PROBES", k.PROBES + k.WARP_PROBES):
            self.assertEqual({"warp_register": k.Check("reset", 640), "warp_tunnel": k.Check("timeout", 2300)},
                             k.warp_checks(failing))
            # The account already existed: no registration ran, so no warp_register at all (not «unknown»).
            self.assertEqual(["warp_tunnel"], list(k.warp_checks(healthy)))
            self.assertEqual({}, k.warp_checks(WarpFacts(False, None, None, None)))
            self.assertEqual({}, k.warp_checks(None))

    def test_queue_line_round_trips_the_hop_fields(self) -> None:
        with patch.object(k, "WARP_LIVE", True), patch.object(k, "PROBES", k.PROBES + k.WARP_PROBES):
            record = c.AttemptRecord(
                "hiphopgen", "vless", c.Outcome.FAILED, "", "", 4200, base.NOW - 1000, "tok",
                details=c.AttemptDetails(settings=c.ReportSettings(mode="tun", warp_entry=True), warp_retries=2).cleaned(),
                carrier="tcp", core_code="TARGET_NETWORK_TIMEOUT",
                checks=k.ordered({"warp_tunnel": k.Check("timeout", 2300), "warp_register": k.Check("reset", 640)}),
            )
            line = c._queue_line(record)
            again = c._parse_queue_line(line)
            body = json.loads(c.batch_json("0123456789abcdef0123456789abcdef", c.AppIdentity("zapret-kvn", "0.8.115", "windows"),
                                           [record], c.SENT_DIRECT))["reports"][0]
        self.assertEqual(record, again)
        self.assertEqual(["warp_register", "warp_tunnel"], list(body["checks"]))
        self.assertEqual({"mode": "tun", "warp_entry": True}, body["settings"])
        self.assertEqual(2, body["warp_retries"])


class WarpReporterTests(unittest.TestCase):
    """The real reporter to a local ingest, with the facts of a failed and of a good connect."""

    setUp = base.ReporterTests.setUp
    _opener = base.ReporterTests._opener
    _reporter = base.ReporterTests._reporter

    def _failed(self, warp: WarpFacts | None) -> dict:
        reporter = self._reporter()
        with patch.object(r, "probe_relay", return_value="timeout"):
            reporter._attempt(c.ServerRef("hipnl", "vless"), "vless", c.AttemptFacts(core_code="TARGET_NETWORK_TIMEOUT"),
                              4200, base.NOW - 5000, None, None, 0, "", warp)
        return base._Ingest.received[0]["reports"][0]

    def test_a_failed_connect_carries_the_hop_start_once_live(self) -> None:
        warp = facts_after((RETRY_2408, RETRY_500, NOT_READY), registered=False)
        with patch.object(k, "WARP_LIVE", True), patch.object(k, "PROBES", k.PROBES + k.WARP_PROBES):
            report = self._failed(warp)
        self.assertEqual({"warp_register": {"r": "reset", "ms": 640}, "warp_tunnel": {"r": "timeout", "ms": 2300}},
                         report["checks"])
        self.assertEqual(2, report["warp_retries"])
        self.assertTrue(report["settings"]["warp_entry"])

    def test_the_same_connect_says_nothing_of_the_hop_until_live(self) -> None:
        report = self._failed(facts_after((RETRY_2408, RETRY_500, NOT_READY), registered=False))
        self.assertNotIn("checks", report)
        self.assertNotIn("warp_retries", report)
        self.assertNotIn("warp_entry", report.get("settings", {}))


if __name__ == "__main__":
    unittest.main()
