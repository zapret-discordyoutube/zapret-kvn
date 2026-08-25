"""Startup / subscription auto-update settings tests (startup-subscription-settings).

Covers AC1-AC6 of .agent/tasks/startup-subscription-settings/spec.md:

- AC1: additive AppSettings fields, defaults, legacy from_dict, round-trip;
- AC2: auto_connect_last toggle card + auto_connect_if_needed() no-op;
- AC3: global subscriptions_auto_update gate over per-subscription auto_update;
- AC4: subscriptions_check_on_startup gates the one-shot startup check only;
- AC5: subscription timer interval from settings, clamped, applied on the fly;
- AC6: startup_connect_order immediate/after_subscriptions with <=30 s fallback.

Keep the ``test_app_*`` prefix: widget test modules must sort before
``tests/test_engine_process_stop.py`` which creates a bare QCoreApplication
at import time (see tests/test_app_nodes_page_view.py).

Widget/controller lifecycle note (Windows crash guard): the SettingsPage and
AppController instances are created ONCE per module and shared between tests,
and are intentionally never destroyed while tests run (see the docstring of
tests/test_app_scrollable_page.py for the underlying qfluentwidgets /
deleteLater crash). Do NOT re-introduce per-test creation with deleteLater.

All checks are deterministic offscreen: timers are asserted via intervals and
direct slot calls, never by waiting for real time to pass (spec C8).
"""

from __future__ import annotations

import inspect
import os
import unittest
from copy import deepcopy

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError(
        "A bare QCoreApplication was created before "
        "test_app_startup_subscription_settings was imported; "
        "widget tests need a QApplication."
    )
app = _existing or QApplication([])

from qfluentwidgets import SettingCardGroup, SwitchSettingCard

from xray_fluent.app_controller import AppController, STARTUP_CONNECT_FALLBACK_MS
from xray_fluent.constants import STATE_SCHEMA_VERSION
from xray_fluent.models import (
    AppSettings,
    AppState,
    Node,
    SecuritySettings,
    Subscription,
    clamp_subscriptions_check_interval,
    normalize_startup_connect_order,
)
from xray_fluent.ui.base_page import ScrollablePage
from xray_fluent.ui.settings_page import SettingsPage, _ComboCard, _SpinCard

#: Shared instances, created lazily and kept alive for the whole process.
_shared: dict[str, object] = {}


def _get_controller() -> AppController:
    controller = _shared.get("controller")
    if controller is None:
        controller = AppController()
        # Never write real state from tests: neutralise persistence on this
        # shared instance (instance attributes shadow the bound methods).
        controller.schedule_save = lambda: None  # type: ignore[method-assign]
        controller.save = lambda: None  # type: ignore[method-assign]
        _shared["controller"] = controller
    return controller  # type: ignore[return-value]


def _get_settings_page() -> SettingsPage:
    page = _shared.get("settings_page")
    if page is None:
        page = SettingsPage()
        _shared["settings_page"] = page
    return page  # type: ignore[return-value]


def _reset_controller(controller: AppController) -> None:
    """Bring the shared controller back to a known baseline between tests."""
    controller.state = AppState()
    controller.locked = False
    controller.connected = False
    controller._desired_connected = False
    controller._startup_connect_pending = False
    controller._startup_connect_timer.stop()
    controller._subscription_timer.stop()
    controller._subscription_update_queue.clear()
    controller._subscription_queued_ids.clear()
    controller._subscription_workers.clear()
    # Drop per-test instance overrides so the real bound methods are back.
    for name in ("_request_transition", "_drain_subscription_update_queue"):
        controller.__dict__.pop(name, None)


def _select_node(controller: AppController) -> Node:
    node = Node(name="node", scheme="vless", server="node.example", port=443)
    controller.state.nodes = [node]
    controller.state.selected_node_id = node.id
    return node


def _due_subscription() -> Subscription:
    # No last_success_at and no backoff -> subscription_due() is True.
    return Subscription(name="Sub", url="https://example.com/sub", auto_update=True)


class Ac1ModelTests(unittest.TestCase):
    def test_defaults_match_current_behaviour(self) -> None:
        settings = AppSettings()
        self.assertTrue(settings.subscriptions_auto_update)
        self.assertTrue(settings.subscriptions_check_on_startup)
        self.assertEqual(settings.subscriptions_check_interval_min, 15)
        self.assertEqual(settings.startup_connect_order, "immediate")
        self.assertTrue(settings.auto_connect_last)

    def test_to_dict_contains_new_keys(self) -> None:
        data = AppSettings().to_dict()
        self.assertIs(data["subscriptions_auto_update"], True)
        self.assertIs(data["subscriptions_check_on_startup"], True)
        self.assertEqual(data["subscriptions_check_interval_min"], 15)
        self.assertEqual(data["startup_connect_order"], "immediate")

    def test_legacy_state_without_new_keys_gets_defaults(self) -> None:
        legacy = AppSettings().to_dict()
        for key in (
            "subscriptions_auto_update",
            "subscriptions_check_on_startup",
            "subscriptions_check_interval_min",
            "startup_connect_order",
        ):
            legacy.pop(key)
        restored = AppSettings.from_dict(legacy)
        self.assertEqual(restored, AppSettings())

    def test_round_trip_with_nontrivial_values(self) -> None:
        original = AppSettings(
            subscriptions_auto_update=False,
            subscriptions_check_on_startup=False,
            subscriptions_check_interval_min=240,
            startup_connect_order="after_subscriptions",
        )
        self.assertEqual(AppSettings.from_dict(original.to_dict()), original)

    def test_garbage_values_do_not_raise_and_are_normalised(self) -> None:
        data = AppSettings().to_dict()
        data["subscriptions_check_interval_min"] = "garbage"
        data["startup_connect_order"] = "weird-mode"
        restored = AppSettings.from_dict(data)
        self.assertEqual(restored.subscriptions_check_interval_min, 15)
        self.assertEqual(restored.startup_connect_order, "immediate")
        self.assertEqual(
            AppSettings.from_dict({"subscriptions_check_interval_min": 0}).subscriptions_check_interval_min,
            5,
        )
        self.assertEqual(
            AppSettings.from_dict({"subscriptions_check_interval_min": -1}).subscriptions_check_interval_min,
            5,
        )
        self.assertEqual(
            AppSettings.from_dict(
                {"subscriptions_check_interval_min": 100000}
            ).subscriptions_check_interval_min,
            1440,
        )

    def test_schema_version_includes_subscription_parser_revision(self) -> None:
        self.assertEqual(STATE_SCHEMA_VERSION, 4)

    def test_helpers(self) -> None:
        self.assertEqual(clamp_subscriptions_check_interval(None), 15)
        self.assertEqual(clamp_subscriptions_check_interval(4), 5)
        self.assertEqual(clamp_subscriptions_check_interval(5), 5)
        self.assertEqual(clamp_subscriptions_check_interval(1440), 1440)
        self.assertEqual(clamp_subscriptions_check_interval(1441), 1440)
        self.assertEqual(normalize_startup_connect_order(None), "immediate")
        self.assertEqual(normalize_startup_connect_order("after_subscriptions"), "after_subscriptions")
        self.assertEqual(normalize_startup_connect_order("nope"), "immediate")


class Ac2AutoConnectToggleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = _get_controller()
        _reset_controller(self.controller)
        self.transitions: list[str] = []
        self.controller._request_transition = self.transitions.append  # type: ignore[method-assign]

    def tearDown(self) -> None:
        _reset_controller(self.controller)

    def test_auto_connect_disabled_is_noop(self) -> None:
        _select_node(self.controller)
        self.controller.state.settings.auto_connect_last = False
        self.controller.auto_connect_if_needed()
        self.assertEqual(self.transitions, [])
        self.assertFalse(self.controller._desired_connected)

    def test_auto_connect_enabled_connects(self) -> None:
        _select_node(self.controller)
        self.controller.state.settings.auto_connect_last = True
        self.controller.auto_connect_if_needed()
        self.assertEqual(self.transitions, ["auto connect"])
        self.assertTrue(self.controller._desired_connected)

    def test_settings_page_card_round_trip(self) -> None:
        page = _get_settings_page()
        self.assertIsInstance(page, ScrollablePage)
        self.assertIsInstance(page.auto_connect_card, SwitchSettingCard)
        settings = AppSettings(auto_connect_last=False)
        page.set_values(settings, SecuritySettings())
        self.assertFalse(page.auto_connect_card.isChecked())

        received: list[AppSettings] = []
        page.save_requested.connect(received.append)
        try:
            page.auto_connect_card.setChecked(True)  # checkedChanged -> _auto_save
        finally:
            page.save_requested.disconnect(received.append)
        self.assertTrue(received)
        self.assertTrue(received[-1].auto_connect_last)


class Ac3GlobalSubscriptionToggleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = _get_controller()
        _reset_controller(self.controller)
        # Keep queued items observable: never start real network workers.
        self.controller._drain_subscription_update_queue = lambda: None  # type: ignore[method-assign]

    def tearDown(self) -> None:
        _reset_controller(self.controller)

    def test_global_off_blocks_due_subscription(self) -> None:
        self.controller.state.subscriptions = [_due_subscription()]
        self.controller.state.settings.subscriptions_auto_update = False
        self.controller._check_due_subscriptions()
        self.assertEqual(self.controller._subscription_update_queue, [])
        self.assertEqual(self.controller._subscription_workers, {})

    def test_global_on_enqueues_due_subscription(self) -> None:
        subscription = _due_subscription()
        self.controller.state.subscriptions = [subscription]
        self.controller.state.settings.subscriptions_auto_update = True
        self.controller._check_due_subscriptions()
        self.assertEqual(
            [item[0].id for item in self.controller._subscription_update_queue],
            [subscription.id],
        )

    def test_per_subscription_auto_update_still_applies(self) -> None:
        subscription = _due_subscription()
        subscription.auto_update = False
        self.controller.state.subscriptions = [subscription]
        self.controller.state.settings.subscriptions_auto_update = True
        self.controller._check_due_subscriptions()
        self.assertEqual(self.controller._subscription_update_queue, [])

    def test_manual_update_ignores_global_toggle(self) -> None:
        subscription = _due_subscription()
        self.controller.state.subscriptions = [subscription]
        self.controller.state.settings.subscriptions_auto_update = False
        self.assertTrue(self.controller.update_subscription(subscription.id, mode="manual"))
        self.assertEqual(
            [item[0].id for item in self.controller._subscription_update_queue],
            [subscription.id],
        )

    def test_force_refresh_is_request_scoped_and_preserves_live_validators(self) -> None:
        subscription = _due_subscription()
        subscription.etag = '"old"'
        subscription.last_modified = "Mon, 01 Jan 2024 00:00:00 GMT"
        self.controller.state.subscriptions = [subscription]

        self.assertTrue(
            self.controller.update_subscription(
                subscription.id,
                mode="auto",
                force_refresh=True,
            )
        )

        queued = self.controller._subscription_update_queue[0]
        self.assertEqual(queued[0].id, subscription.id)
        self.assertTrue(queued[4])
        self.assertEqual(subscription.etag, '"old"')
        self.assertEqual(
            subscription.last_modified,
            "Mon, 01 Jan 2024 00:00:00 GMT",
        )


class Ac4StartupCheckFlagTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = _get_controller()
        _reset_controller(self.controller)
        self.controller._drain_subscription_update_queue = lambda: None  # type: ignore[method-assign]

    def tearDown(self) -> None:
        _reset_controller(self.controller)

    def test_startup_check_predicate(self) -> None:
        settings = self.controller.state.settings
        for auto_update, on_startup, expected in (
            (True, True, True),
            (True, False, False),
            (False, True, False),
            (False, False, False),
        ):
            settings.subscriptions_auto_update = auto_update
            settings.subscriptions_check_on_startup = on_startup
            self.assertIs(
                self.controller._startup_subscription_check_enabled(),
                expected,
                (auto_update, on_startup),
            )

    def test_load_and_unlock_gate_the_one_shot_check(self) -> None:
        # The decision is a pure predicate (spec AC4 allows this); statically
        # confirm both one-shot call sites are behind it.
        load_source = inspect.getsource(AppController.load)
        self.assertIn("if self._startup_subscription_check_enabled():", load_source)
        self.assertIn("QTimer.singleShot(30_000, self._check_due_subscriptions)", load_source)
        self.assertLess(
            load_source.index("_startup_subscription_check_enabled"),
            load_source.index("singleShot(30_000"),
        )
        unlock_source = inspect.getsource(AppController.unlock)
        self.assertEqual(unlock_source.count("QTimer.singleShot(0, self._check_due_subscriptions)"), 2)
        self.assertEqual(unlock_source.count("if self._startup_subscription_check_enabled():"), 2)

    def test_periodic_timer_path_survives_startup_flag_off(self) -> None:
        # The periodic timer fires _check_due_subscriptions, which only obeys
        # the global toggle, not the startup flag.
        subscription = _due_subscription()
        self.controller.state.subscriptions = [subscription]
        self.controller.state.settings.subscriptions_auto_update = True
        self.controller.state.settings.subscriptions_check_on_startup = False
        self.controller._check_due_subscriptions()
        self.assertEqual(
            [item[0].id for item in self.controller._subscription_update_queue],
            [subscription.id],
        )


class Ac5IntervalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = _get_controller()
        _reset_controller(self.controller)

    def tearDown(self) -> None:
        _reset_controller(self.controller)

    def _updated_settings(self, minutes) -> AppSettings:
        settings = deepcopy(self.controller.state.settings)
        settings.subscriptions_check_interval_min = minutes
        return settings

    def test_update_settings_applies_interval_to_running_timer(self) -> None:
        self.controller._subscription_timer.start()
        try:
            self.controller.update_settings(self._updated_settings(30))
            self.assertEqual(self.controller._subscription_timer.interval(), 30 * 60_000)
            self.assertTrue(self.controller._subscription_timer.isActive())
        finally:
            self.controller._subscription_timer.stop()

    def test_out_of_range_values_are_clamped_without_exceptions(self) -> None:
        for minutes, expected_ms in ((0, 5 * 60_000), (-1, 5 * 60_000), (100000, 1440 * 60_000)):
            self.controller.update_settings(self._updated_settings(minutes))
            self.assertEqual(self.controller._subscription_timer.interval(), expected_ms, minutes)

    def test_garbage_state_value_falls_back_to_default(self) -> None:
        self.controller.state.settings.subscriptions_check_interval_min = "junk"  # type: ignore[assignment]
        self.controller._apply_subscription_timer_interval()
        self.assertEqual(self.controller._subscription_timer.interval(), 15 * 60_000)

    def test_settings_page_spin_card_range_and_round_trip(self) -> None:
        page = _get_settings_page()
        self.assertIsInstance(page.subscriptions_interval_card, _SpinCard)
        spin = page.subscriptions_interval_card.spin
        self.assertEqual((spin.minimum(), spin.maximum()), (5, 1440))

        settings = AppSettings(
            subscriptions_auto_update=False,
            subscriptions_check_on_startup=False,
            subscriptions_check_interval_min=120,
            startup_connect_order="after_subscriptions",
        )
        page.set_values(settings, SecuritySettings())
        self.assertFalse(page.subscriptions_auto_update_card.isChecked())
        self.assertFalse(page.subscriptions_startup_check_card.isChecked())
        self.assertEqual(spin.value(), 120)
        self.assertEqual(page.startup_order_card.combo.currentData(), "after_subscriptions")

        received: list[AppSettings] = []
        page.save_requested.connect(received.append)
        try:
            page._auto_save()
        finally:
            page.save_requested.disconnect(received.append)
        self.assertTrue(received)
        saved = received[-1]
        self.assertFalse(saved.subscriptions_auto_update)
        self.assertFalse(saved.subscriptions_check_on_startup)
        self.assertEqual(saved.subscriptions_check_interval_min, 120)
        self.assertEqual(saved.startup_connect_order, "after_subscriptions")


class Ac6StartupOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = _get_controller()
        _reset_controller(self.controller)
        self.transitions: list[str] = []
        self.controller._request_transition = self.transitions.append  # type: ignore[method-assign]
        self.controller._drain_subscription_update_queue = lambda: None  # type: ignore[method-assign]
        _select_node(self.controller)

    def tearDown(self) -> None:
        _reset_controller(self.controller)

    def _arm_deferred_start(self) -> None:
        self.controller.state.subscriptions = [_due_subscription()]
        self.controller.state.settings.startup_connect_order = "after_subscriptions"
        self.controller.auto_connect_if_needed()

    def test_fallback_constant_is_at_most_30_seconds(self) -> None:
        self.assertLessEqual(STARTUP_CONNECT_FALLBACK_MS, 30_000)
        self.assertEqual(
            self.controller._startup_connect_timer.interval(), STARTUP_CONNECT_FALLBACK_MS
        )

    def test_immediate_order_connects_without_waiting(self) -> None:
        self.controller.state.subscriptions = [_due_subscription()]
        self.controller.state.settings.startup_connect_order = "immediate"
        self.controller.auto_connect_if_needed()
        self.assertEqual(self.transitions, ["auto connect"])
        self.assertFalse(self.controller._startup_connect_pending)

    def test_after_subscriptions_waits_then_connects_on_completion(self) -> None:
        self._arm_deferred_start()
        self.assertEqual(self.transitions, [])
        self.assertFalse(self.controller._desired_connected)
        self.assertTrue(self.controller._startup_connect_pending)
        self.assertTrue(self.controller._startup_connect_timer.isActive())
        # Startup refresh finished (success or failure — same completion path).
        self.controller._subscription_update_queue.clear()
        self.controller._subscription_queued_ids.clear()
        self.controller._maybe_finish_startup_connect()
        self.assertEqual(self.transitions, ["auto connect"])
        self.assertTrue(self.controller._desired_connected)
        self.assertFalse(self.controller._startup_connect_pending)
        self.assertFalse(self.controller._startup_connect_timer.isActive())

    def test_after_subscriptions_timeout_fallback_connects_anyway(self) -> None:
        self._arm_deferred_start()
        self.assertEqual(self.transitions, [])
        # Simulate a hanging update: the fallback timer slot fires (no real wait).
        self.controller._finish_startup_connect()
        self.assertEqual(self.transitions, ["auto connect"])
        self.assertTrue(self.controller._desired_connected)
        self.assertFalse(self.controller._startup_connect_pending)
        # Queue is still busy, but the connection was not blocked.
        self.assertTrue(self.controller._subscription_update_queue)
        # A late completion never double-connects.
        self.controller._subscription_update_queue.clear()
        self.controller._subscription_queued_ids.clear()
        self.controller._maybe_finish_startup_connect()
        self.assertEqual(self.transitions, ["auto connect"])

    def test_after_subscriptions_with_nothing_due_connects_immediately(self) -> None:
        self.controller.state.subscriptions = []
        self.controller.state.settings.startup_connect_order = "after_subscriptions"
        self.controller.auto_connect_if_needed()
        self.assertEqual(self.transitions, ["auto connect"])
        self.assertFalse(self.controller._startup_connect_pending)

    def test_after_subscriptions_with_gates_off_connects_immediately(self) -> None:
        self.controller.state.subscriptions = [_due_subscription()]
        self.controller.state.settings.startup_connect_order = "after_subscriptions"
        self.controller.state.settings.subscriptions_auto_update = False
        self.controller.auto_connect_if_needed()
        self.assertEqual(self.transitions, ["auto connect"])
        self.assertFalse(self.controller._startup_connect_pending)
        self.assertEqual(self.controller._subscription_update_queue, [])


class Ac7UiInvariantTests(unittest.TestCase):
    def test_new_cards_are_stock_components_inside_groups(self) -> None:
        page = _get_settings_page()
        self.assertIsInstance(page.auto_connect_card, SwitchSettingCard)
        self.assertIsInstance(page.subscriptions_auto_update_card, SwitchSettingCard)
        self.assertIsInstance(page.subscriptions_startup_check_card, SwitchSettingCard)
        self.assertIsInstance(page.subscriptions_interval_card, _SpinCard)
        self.assertIsInstance(page.startup_order_card, _ComboCard)
        for card in (
            page.auto_connect_card,
            page.startup_order_card,
            page.subscriptions_auto_update_card,
            page.subscriptions_startup_check_card,
            page.subscriptions_interval_card,
        ):
            group = card.parent()
            while group is not None and not isinstance(group, SettingCardGroup):
                group = group.parent()
            self.assertIsInstance(group, SettingCardGroup, card)

    def test_startup_order_combo_items(self) -> None:
        combo = _get_settings_page().startup_order_card.combo
        values = [combo.itemData(index) for index in range(combo.count())]
        self.assertEqual(values, ["immediate", "after_subscriptions"])


if __name__ == "__main__":
    unittest.main()
