from __future__ import annotations

import unittest

from xray_fluent.application.transition_engine import (
    proxy_resolution_is_current,
    transition_request_delay_ms,
)


class TransitionResponsivenessTests(unittest.TestCase):
    def test_manual_node_switch_is_debounced_before_runtime_work(self) -> None:
        self.assertEqual(transition_request_delay_ms("node switched"), 180)

    def test_non_selection_transition_is_scheduled_immediately(self) -> None:
        self.assertEqual(transition_request_delay_ms("toggle connection"), 0)

    def test_stale_dns_result_cannot_switch_the_new_selection(self) -> None:
        self.assertFalse(
            proxy_resolution_is_current(
                result_generation=1,
                current_generation=2,
                desired_connected=True,
                result_server="old.example.com",
                current_server="new.example.com",
            )
        )

    def test_current_dns_result_can_resume_the_transition(self) -> None:
        self.assertTrue(
            proxy_resolution_is_current(
                result_generation=2,
                current_generation=2,
                desired_connected=True,
                result_server="new.example.com",
                current_server="new.example.com",
            )
        )


if __name__ == "__main__":
    unittest.main()
