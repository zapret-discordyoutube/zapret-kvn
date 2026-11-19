"""Schema 3 facts: checks, carrier, core code (the same rules as vpnbot client_reports/contract.py)."""

from __future__ import annotations

import unittest


from xray_fluent.client_reports import checks as k


class CheckRulesTests(unittest.TestCase):
    def test_probe_names_and_results_follow_the_contract(self) -> None:
        self.assertEqual(17, len(k.PROBES))
        self.assertTrue(k.is_valid_check("tcp_target", k.Check("refused", 120)))
        self.assertFalse(k.is_valid_check("tcp_target", k.Check("nxdomain", 120)))   # nxdomain only for DNS
        self.assertTrue(k.is_valid_check("dns_doh", k.Check("nxdomain", 300)))
        self.assertFalse(k.is_valid_check("tcp_target", k.Check("answered", 60_001)))
        self.assertFalse(k.is_valid_check("tls_real", k.Check("answered", 10, b=5)))   # bytes only on flow probes
        self.assertTrue(k.is_valid_check("flow", k.Check("timeout", 5000, b=16_000)))
        self.assertTrue(k.is_valid_check("dns_system", k.Check("answered", 30, same=False)))
        self.assertFalse(k.is_valid_check("dns_system", k.Check("timeout", 30, same=False)))
        self.assertFalse(k.is_valid_check("dns_doh", k.Check("answered", 30, same=True)))
        self.assertFalse(k.is_valid_check("ping", k.Check("answered", 1)))

    def test_checks_are_ordered_and_a_bad_one_drops_out(self) -> None:
        got = k.ordered({"tls_real": k.Check("timeout", 5000), "control_front": k.Check("answered", 40),
                         "tcp_target": k.Check("answered", 50, b=1)})
        self.assertEqual(["control_front", "tls_real"], [probe for probe, _ in got])

    def test_core_code_only_in_the_contract_shape(self) -> None:
        self.assertEqual("TARGET_NETWORK_TIMEOUT", k.core_code_of("TARGET_NETWORK_TIMEOUT"))
        self.assertEqual("LOCAL_BIND_COLLISION", k.core_code_of("LOCAL_BIND_COLLISION"))
        self.assertEqual("NETWORK_LOST", k.core_code_of("NETWORK_LOST"))
        for other in ("CORE_UNCLASSIFIED", "TRANSITION_DEADLINE_EXCEEDED", "target_x", "", None):
            self.assertEqual("", k.core_code_of(other))

    def test_carrier_is_what_the_first_hop_runs_over(self) -> None:
        self.assertEqual("udp", k.carrier_of("hysteria2"))
        self.assertEqual("udp", k.carrier_of("awg"))
        self.assertEqual("udp", k.carrier_of("vless", "kcp"))
        self.assertEqual("udp", k.carrier_of("vless", "xhttp", ["h3"]))
        self.assertEqual("tcp", k.carrier_of("vless", "xhttp", ["h2", "http/1.1"]))
        self.assertEqual("tcp", k.carrier_of("vless", "grpc"))
        self.assertEqual("tcp", k.carrier_of("trojan", None))


if __name__ == "__main__":
    unittest.main()
