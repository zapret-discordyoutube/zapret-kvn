"""Шлюз проверок (xray_fluent/network/probe_gate.py): бюджет и журнал."""

from __future__ import annotations

import random
import unittest

from xray_fluent.network import probe_gate


class ProbeGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 1000.0
        self.gate = probe_gate.ProbeGate(clock=lambda: self.now)

    def test_candidate_budget_is_a_sliding_hour(self) -> None:
        for _ in range(probe_gate.CANDIDATE_PROBES_PER_HOUR):
            self.assertTrue(self.gate.try_candidate("a.example"))
        self.assertFalse(self.gate.try_candidate("b.example"))
        self.now += 3599.0
        self.assertFalse(self.gate.try_candidate("b.example"))
        self.now += 2.0
        self.assertTrue(self.gate.try_candidate("b.example"))

    def test_refused_candidate_is_not_journaled(self) -> None:
        for _ in range(probe_gate.CANDIDATE_PROBES_PER_HOUR + 2):
            self.gate.try_candidate("a.example")
        kinds = [record.kind for record in self.gate.journal()]
        self.assertEqual(kinds, [probe_gate.CANDIDATE] * probe_gate.CANDIDATE_PROBES_PER_HOUR)

    def test_sweep_pause_stays_in_range(self) -> None:
        rng = random.Random(7)
        low, high = probe_gate.SWEEP_PAUSE_SEC
        self.assertGreaterEqual(low, 10.0)
        pauses = [probe_gate.sweep_pause(rng) for _ in range(200)]
        self.assertTrue(all(low <= pause <= high for pause in pauses))
        self.assertGreater(max(pauses) - min(pauses), 5.0)  # разброс, не ровный ритм


if __name__ == "__main__":
    unittest.main()
