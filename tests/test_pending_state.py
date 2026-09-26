"""Намерение пользователя поверх наблюдаемого состояния (ui/pending_state.py)."""

from __future__ import annotations

import unittest

from xray_fluent.ui.pending_state import PendingValue


class _Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


class PendingValueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = _Clock()
        self.value: PendingValue[bool] = PendingValue(timeout_s=10, clock=self.clock)

    def test_shows_intent_until_observed_catches_up(self) -> None:
        self.value.request(False)
        self.assertFalse(self.value.display(True))  # факт ещё «вкл» — показываем выбор
        self.assertTrue(self.value.pending)
        self.assertFalse(self.value.display(False))  # догнал
        self.assertFalse(self.value.pending)
        self.assertTrue(self.value.display(True))  # дальше — чистый факт

    def test_timeout_falls_back_to_truth(self) -> None:
        self.value.request(False)
        self.clock.now += 11
        self.assertTrue(self.value.display(True))
        self.assertFalse(self.value.pending)

    def test_new_request_replaces_old(self) -> None:
        self.value.request(False)
        self.value.request(True)
        self.assertTrue(self.value.display(False))
        self.assertTrue(self.value.display(True))
        self.assertFalse(self.value.pending)


if __name__ == "__main__":
    unittest.main()
