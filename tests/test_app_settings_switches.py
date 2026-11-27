"""Every switch of the settings page really turns a setting on and off (owner request 2026-11-27).

"Let's fix it so everything that can be toggled can actually be turned on and off": the check is generic, so a new switch
that does nothing, a setting that does not survive a save and a restart, or a setting nobody reads fails here.
Keep the ``test_app_*`` prefix: widget tests must sort before tests that create a bare QCoreApplication.
"""

from __future__ import annotations

import dataclasses
import os
import re
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError("A bare QCoreApplication was created before this module; widget tests need a QApplication.")
_APP = _existing or QApplication([])

from qfluentwidgets import SwitchSettingCard

from xray_fluent.profiles.models import AppSettings, SecuritySettings, Subscription
from xray_fluent.ui.settings_page import SettingsPage

PACKAGE = Path(__file__).resolve().parent.parent / "xray_fluent"

#: Boolean settings that no switch of the settings page controls, each with the reason (a new one fails the test until a
#: decision is written here).
BOOLEANS_WITHOUT_A_SETTINGS_SWITCH = {
    "start_minimized": "legacy: the page forces it to False, the app always starts in the normal window",
    "enable_system_proxy": "the Proxy/TUN mode switch of the dashboard",
    "tun_mode": "the Proxy/TUN mode switch of the dashboard",
    "system_proxy_before_tun": "internal: remembers the system-proxy choice around a TUN-mode switch",
    "nav_expanded": "view state of the side menu",
    "tour_done": "state: the tour was shown",
    "nodes_sort_desc": "view state of the server list",
    "nodes_favorites_only": "view state of the server list",
    "zapret_autostart": "the autostart switch of the Zapret page",
}

#: Boolean flags of a subscription: the user's own switches have a checkbox in the subscription editor, the rest is state.
SUBSCRIPTION_FLAGS = {
    "send_hwid": "checkbox «Передавать стабильный HWID»",
    "auto_update": "checkbox «Автоматически обновлять»",
    "retry_via_tunnel": "state: a failed fetch is retried through the tunnel (set and cleared by the app)",
    "service": "state: the last answer carried the Zapret VPN service header",
}

#: Settings that live in a nested dict and are checked by their own test (``test_app_masking_settings``).
NESTED_SETTINGS_PREFIX = "masking."


def _build(settings: AppSettings) -> tuple[SettingsPage, list[AppSettings]]:
    page = SettingsPage()
    saves: list[AppSettings] = []
    page.save_requested.connect(saves.append)
    page.set_values(settings, SecuritySettings())
    return page, saves


def _normalized() -> tuple[SettingsPage, list[AppSettings]]:
    """A page whose first saved state is the baseline: loading normalizes paths and masking, a toggle must add nothing."""
    page, saves = _build(AppSettings())
    page._auto_save()
    return page, saves


def _switch_names() -> list[str]:
    page, _ = _build(AppSettings())
    return [name for name, widget in vars(page).items() if isinstance(widget, SwitchSettingCard)]


def _diff(before, after, path: str = "") -> list[str]:
    if isinstance(before, dict) and isinstance(after, dict):
        changed: list[str] = []
        for key in sorted(set(before) | set(after)):
            changed += _diff(before.get(key), after.get(key), f"{path}{key}.")
        return changed
    return [path.rstrip(".")] if before != after else []


class SettingsSwitchesTests(unittest.TestCase):
    def test_the_page_has_its_switches(self) -> None:
        # a guard against the discovery silently finding nothing (a renamed widget class would empty the other tests)
        self.assertGreaterEqual(len(_switch_names()), 20)

    def test_every_switch_changes_exactly_one_setting_and_turning_it_back_restores_it(self) -> None:
        for name in _switch_names():
            with self.subTest(switch=name):
                page, saves = _normalized()
                baseline = saves[-1].to_dict()
                card = getattr(page, name)
                start = card.isChecked()
                card.setChecked(not start)
                changed = _diff(baseline, saves[-1].to_dict())
                self.assertEqual(1, len(changed), f"{name} changed {changed}: a dead switch changes nothing, a leaky one several")
                card.setChecked(start)
                self.assertEqual([], _diff(baseline, saves[-1].to_dict()), f"{name} does not restore its setting")

    def test_a_switch_survives_a_save_and_a_restart(self) -> None:
        for name in _switch_names():
            with self.subTest(switch=name):
                page, saves = _normalized()
                card = getattr(page, name)
                flipped = not card.isChecked()
                card.setChecked(flipped)
                stored = AppSettings.from_dict(saves[-1].to_dict())  # what the file holds after the restart
                reopened, _ = _build(stored)
                self.assertEqual(flipped, getattr(reopened, name).isChecked(), f"{name} does not come back after a restart")

    def test_every_setting_a_switch_controls_is_read_by_the_app(self) -> None:
        fields: dict[str, str] = {}
        for name in _switch_names():
            page, saves = _normalized()
            baseline = saves[-1].to_dict()
            card = getattr(page, name)
            card.setChecked(not card.isChecked())
            for key in _diff(baseline, saves[-1].to_dict()):
                if not key.startswith(NESTED_SETTINGS_PREFIX):
                    fields[key] = name
        self.assertGreaterEqual(len(fields), 15)
        skipped = {"ui/settings_page.py", "profiles/models.py"}
        for field, name in sorted(fields.items()):
            with self.subTest(setting=field, switch=name):
                readers = [
                    path.relative_to(PACKAGE).as_posix()
                    for path in PACKAGE.rglob("*.py")
                    if path.relative_to(PACKAGE).as_posix() not in skipped
                    and re.search(rf"\b{re.escape(field)}\b", path.read_text(encoding="utf-8", errors="replace"))
                ]
                self.assertTrue(readers, f"{field} is switchable (card {name}) but nothing in the app reads it")

    def test_boolean_settings_without_a_switch_are_decided(self) -> None:
        page, _ = _normalized()
        controlled: set[str] = set()
        for name in _switch_names():
            page, saves = _normalized()
            baseline = saves[-1].to_dict()
            card = getattr(page, name)
            card.setChecked(not card.isChecked())
            controlled.update(_diff(baseline, saves[-1].to_dict()))
        uncovered = {
            item.name
            for item in dataclasses.fields(AppSettings)
            if item.type in (bool, "bool") and item.name not in controlled
        }
        self.assertEqual(
            set(BOOLEANS_WITHOUT_A_SETTINGS_SWITCH), uncovered,
            "a boolean setting appeared (or lost its switch): give it a switch or record why it has none",
        )


class SubscriptionFlagsTests(unittest.TestCase):
    def test_every_boolean_flag_of_a_subscription_is_a_switch_or_declared_state(self) -> None:
        flags = {item.name for item in dataclasses.fields(Subscription) if item.type in (bool, "bool")}
        self.assertEqual(
            set(SUBSCRIPTION_FLAGS), flags,
            "a boolean subscription flag appeared: give it a checkbox or record that it is state",
        )

    def test_the_user_switches_of_a_subscription_have_a_checkbox_and_a_reader(self) -> None:
        page_source = (PACKAGE / "ui" / "subscriptions_page.py").read_text(encoding="utf-8")
        for name, how in SUBSCRIPTION_FLAGS.items():
            if not how.startswith("checkbox"):
                continue
            with self.subTest(flag=name):
                self.assertIn(f"subscription.{name}", page_source, f"{name} has no checkbox that loads and saves it")
                readers = [
                    path.relative_to(PACKAGE).as_posix()
                    for path in PACKAGE.rglob("*.py")
                    if path.relative_to(PACKAGE).parts[0] != "ui" and path.name != "models.py"
                    and re.search(rf"\b{name}\b", path.read_text(encoding="utf-8", errors="replace"))
                ]
                self.assertTrue(readers, f"{name} can be switched but nothing outside the UI reads it")


if __name__ == "__main__":
    unittest.main()
