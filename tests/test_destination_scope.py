"""A destination refused by an authenticated server never tears down the tunnel.

Regression for 0.6.11 (2026-09-25): VPnBot nodes reject public DoH resolvers
and IP-discovery services by network policy. The app probed exactly those
resolvers, and the official Hysteria client reports every such refusal as a
relayed-connection error. That error was classified as a transport failure,
started automatic recovery and stopped sing-box with all live connections.
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from PyQt6.QtCore import QCoreApplication

from xray_fluent.application.controller import AppController
from xray_fluent.diagnostics import runtime_errors
from xray_fluent.diagnostics.runtime_errors import (
    DESTINATION_UNREACHABLE_CODE,
    classify_core_error,
    core_failure,
)
from xray_fluent.engines.amnezia import manager as amnezia_manager
from xray_fluent.engines.hysteria import manager as hysteria_manager
from xray_fluent.engines.hysteria.manager import HysteriaManager
from xray_fluent.engines.hysteria.runtime_contract import HysteriaFailureCode, classify_hysteria_failure
from xray_fluent.engines.socks_probe import HTTPS_ENDPOINTS

_APP = QCoreApplication.instance() or QCoreApplication([])

# Mirror of vpnbot_node_services network-policy-v3.json: blocked_doh_domain_suffixes
# and the public-ip-discovery entries of blocked_vpn_detection_domain_suffixes.
POLICY_BLOCKED_SUFFIXES = (
    "cloudflare-dns.com", "dns.adguard-dns.com", "dns.alidns.com", "dns.google",
    "dns.nextdns.io", "dns.quad9.net", "dns.sb", "dns10.quad9.net", "dns11.quad9.net",
    "dns9.quad9.net", "doh.opendns.com", "doh.pub", "family.cloudflare-dns.com",
    "freedns.controld.com", "mozilla.cloudflare-dns.com", "one.one.one.one",
    "security.cloudflare-dns.com",
    "api.ipify.org", "checkip.amazonaws.com", "ifconfig.me", "ip.mail.ru",
    "ipv4-internet.yandex.net", "ipv6-internet.yandex.net",
)
# Classes the policy blocks even when a new domain is not listed yet.
FORBIDDEN_MARKERS = re.compile(r"(?:^|[.-])(?:doh|dns|ipify|checkip|ifconfig|myip|whatismyip)(?:[.-]|$)")

SERVER_REFUSAL = ('2026-09-25T10:00:00+03:00\tWARN\tSOCKS5 TCP error\t'
                  '{"addr": "127.0.0.1:52001", "reqAddr": "dns.google:443", '
                  '"error": "dial error: dial tcp4 8.8.8.8:443: connect: connection refused"}')
TRANSPORT_TIMEOUT = ('2026-09-25T10:00:00+03:00\tWARN\tSOCKS5 TCP error\t'
                     '{"addr": "127.0.0.1:52002", "reqAddr": "example.com:443", '
                     '"error": "connect error: timeout: no recent network activity"}')


class HealthProbePolicyTests(unittest.TestCase):
    def test_every_transport_uses_one_shared_policy_allowed_list(self):
        self.assertIs(hysteria_manager._FUNCTIONAL_HTTPS_ENDPOINTS, HTTPS_ENDPOINTS)
        self.assertIs(amnezia_manager.PROBES, HTTPS_ENDPOINTS)
        self.assertGreaterEqual(len(HTTPS_ENDPOINTS), 2, "one blocked endpoint must not fail the check")

    def test_endpoints_are_connectivity_checks_not_doh_or_ip_discovery(self):
        for destination, name, path in HTTPS_ENDPOINTS:
            with self.subTest(name=name):
                self.assertEqual(destination, name)
                with self.assertRaises(ValueError, msg="literal IPs bypass the node resolver"):
                    ipaddress.ip_address(destination)
                for suffix in POLICY_BLOCKED_SUFFIXES:
                    self.assertFalse(name == suffix or name.endswith("." + suffix), suffix)
                self.assertIsNone(FORBIDDEN_MARKERS.search(name))
                self.assertEqual(path, "/generate_204")


class DestinationScopeCatalogTests(unittest.TestCase):
    def test_server_reported_destination_failures_are_record_only(self):
        for line in (
            SERVER_REFUSAL,
            SERVER_REFUSAL.replace("SOCKS5 TCP error", "SOCKS5 UDP error"),
            SERVER_REFUSAL.replace('"error": "dial error: dial tcp4 8.8.8.8:443: connect: connection refused"',
                                   '"error":"dial error: blocked by ACL"'),
            # sing-box/sing-quic hysteria2 outbound (Android and native sing-box).
            "outbound/hysteria2[hy]: remote error: dial tcp4 8.8.8.8:443: connect: connection refused",
            "outbound/hysteria2[hy]: remote error: access denied by policy",
        ):
            with self.subTest(line=line[-70:]):
                self.assertEqual(classify_core_error(line), (DESTINATION_UNREACHABLE_CODE, "record_only"))
                self.assertIsNone(classify_hysteria_failure(line))
                self.assertEqual(core_failure("hysteria", "runtime", line).action, "record_only")

    def test_transport_and_security_failures_keep_their_recovery_policy(self):
        for line, expected in (
            (TRANSPORT_TIMEOUT, HysteriaFailureCode.TARGET_NETWORK_TIMEOUT),
            ('{"error": "connect error: dial udp 192.0.2.1:443: connection refused"}',
             HysteriaFailureCode.TARGET_CONNECTION_REFUSED),
            ("remote error: tls: bad certificate", HysteriaFailureCode.TARGET_TLS_REJECTED),
            ("connect error: CRYPTO_ERROR 0x150 (remote): tls: internal error",
             HysteriaFailureCode.TARGET_TLS_INTERNAL),
        ):
            with self.subTest(line=line[-60:]):
                self.assertEqual(classify_hysteria_failure(line), expected)

    def test_destination_rule_precedes_every_recovering_rule(self):
        catalog = json.loads(Path(runtime_errors.__file__).with_name("runtime-errors.json").read_text("utf-8"))
        self.assertEqual(catalog["rules"][0]["code"], DESTINATION_UNREACHABLE_CODE)
        self.assertEqual(catalog["rules"][0]["action"], "record_only")


class HysteriaDestinationRefusalTests(unittest.TestCase):
    def setUp(self):
        self.manager = HysteriaManager()
        self.addCleanup(self.manager.deleteLater)
        self.manager._begin_attempt(None, {})
        self.errors, self.failures, self.logs = [], [], []
        self.manager.error.connect(self.errors.append)
        self.manager.failure.connect(lambda *args: self.failures.append(args))
        self.manager.log_received.connect(self.logs.append)

    def test_refusal_on_running_session_is_evidence_only(self):
        self.manager._starting = False
        self.manager._mark_running()
        for request in ("dns.google:443", "api.ipify.org:443", "gosuslugi.ru:443"):
            self.manager._emit_process_line(SERVER_REFUSAL.replace("dns.google:443", request))
        self.assertEqual(self.errors, [])
        self.assertEqual(self.failures, [])
        self.assertIsNone(self.manager.last_failure_code)
        self.assertFalse(self.manager._failure_reported)
        refusals = [line for line in self.logs if "SOCKS5 TCP error" in line]
        self.assertEqual(len(refusals), 3)
        self.assertTrue(all("stage=destination" in line for line in refusals))

    def test_refusal_during_startup_does_not_become_the_start_verdict(self):
        self.manager._starting = True
        self.manager._emit_process_line(SERVER_REFUSAL)
        self.assertIsNone(self.manager.last_failure_code)
        self.assertEqual(self.errors, [])

    def test_real_transport_failure_still_reaches_recovery(self):
        self.manager._starting = False
        self.manager._mark_running()
        self.manager._emit_process_line(TRANSPORT_TIMEOUT)
        self.assertEqual([args[0] for args in self.failures], [HysteriaFailureCode.TARGET_NETWORK_TIMEOUT.value])

    def test_controller_keeps_front_running_after_policy_refusals(self):
        self.manager._starting = False
        self.manager._mark_running()
        self.manager._process_generation = 3
        controller = Mock()
        controller.hysteria = self.manager
        controller._hysteria_active_generation = 3
        self.manager.failure.connect(lambda code, message, generation:
            AppController._on_hysteria_failure(controller, self.manager, code, message, generation))
        self.manager._emit_process_line(SERVER_REFUSAL)
        controller.singbox.stop.assert_not_called()
        controller._request_transition.assert_not_called()

    def test_destination_log_is_not_recorded_as_core_failure(self):
        ctrl = SimpleNamespace(_core_log_contexts={}, _transition_generation=1,
            state=SimpleNamespace(settings=SimpleNamespace(tun_mode=False)),
            _record_core_failure=Mock(), _log=Mock())
        self.manager._emit_process_line(SERVER_REFUSAL)
        AppController._on_core_log(ctrl, "hysteria", self.logs[-1])
        ctrl._record_core_failure.assert_not_called()
        ctrl._log.assert_called_once()


class PlannedFullTransitionLogTests(unittest.TestCase):
    def _precheck(self, session):
        ctrl = SimpleNamespace(selected_node=SimpleNamespace(id="next", server="next.example"),
                               _active_session=session, connected=True, _log=Mock())
        self.assertIsNone(AppController._hot_switch_precheck(ctrl))
        return ctrl._log.call_args.args[0]

    def test_sidecar_session_reports_planned_transition_not_a_broken_pool(self):
        message = self._precheck(SimpleNamespace(outbound_pool_tags={}, active_core="singbox",
                                                 sidecar_kind="hysteria"))
        self.assertIn("full transition to node next", message)
        self.assertIn("hysteria sidecar session serves one server", message)
        self.assertNotIn("fallback", message)

    def test_node_outside_running_pool_names_the_pool(self):
        message = self._precheck(SimpleNamespace(outbound_pool_tags={"other": "t"}, active_core="singbox",
                                                 sidecar_kind=""))
        self.assertIn("outside the running singbox pool (1 tags)", message)


if __name__ == "__main__":
    unittest.main()
