"""Hysteria2: адрес сервера — из доверенного DoH, а не от DNS провайдера (жалоба 0.8.47)."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from PyQt6.QtCore import QCoreApplication

from tests.step_fakes import drive
from xray_fluent.engines.hysteria.manager import HysteriaManager
from xray_fluent.network.bootstrap_dns import BootstrapDnsError, BootstrapResolution

_APP = QCoreApplication.instance() or QCoreApplication([])

_CONFIG = {
    "server": "hy2://secret@hy.example:443,5000-6000/?obfs=salamander",
    "tls": {"sni": "hy.example"},
    "socks5": {"listen": "127.0.0.1:11809"},
}


class TrustedServerAddressTests(unittest.TestCase):
    def _pin(self, resolve):
        manager = HysteriaManager()
        with patch("xray_fluent.engines.hysteria.manager.resolve_bootstrap", resolve):
            return drive(manager._trusted_server_address_steps(_CONFIG))

    def test_doh_answer_is_pinned_and_name_stays_in_sni(self) -> None:
        pinned = self._pin(lambda host: BootstrapResolution(frozenset({"203.0.113.7", "2001:db8::7"}), "doh"))
        self.assertEqual(pinned["server"], "hy2://secret@203.0.113.7:443,5000-6000/?obfs=salamander")
        self.assertEqual(pinned["tls"]["sni"], "hy.example")
        self.assertEqual(_CONFIG["server"], "hy2://secret@hy.example:443,5000-6000/?obfs=salamander")

    def test_remembered_address_is_used_when_doh_is_unreachable(self) -> None:
        pinned = self._pin(lambda host: BootstrapResolution(frozenset({"203.0.113.8"}), "cache"))
        self.assertIn("@203.0.113.8:", pinned["server"])

    def test_system_answer_or_failure_leaves_the_name(self) -> None:
        self.assertEqual(self._pin(lambda host: BootstrapResolution(frozenset({"198.51.100.1"}), "system")), _CONFIG)

        def offline(host):
            raise BootstrapDnsError("нет сети")

        self.assertEqual(self._pin(offline), _CONFIG)

    def test_ip_literal_is_not_looked_up(self) -> None:
        config = dict(_CONFIG, server="hy2://secret@198.51.100.2:443/")

        def forbidden(host):
            raise AssertionError("IP не разрешается")

        manager = HysteriaManager()
        with patch("xray_fluent.engines.hysteria.manager.resolve_bootstrap", forbidden):
            self.assertEqual(drive(manager._trusted_server_address_steps(config)), config)


if __name__ == "__main__":
    unittest.main()
