"""«Маскировка» group of the settings page: the controls load the stored document and save it
back through the pure package. Widget module: keep the ``test_app_*`` prefix (it must sort
before modules that create a bare QCoreApplication) and create the page once, never
destroyed (see tests/test_app_startup_subscription_settings.py for the crash guard)."""

from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError("widget tests need a QApplication")
app = _existing or QApplication([])

from xray_fluent.masking import codec, presets
from xray_fluent.masking.model import OFF, Masking, MaskingSettings, WireGuardMasking
from xray_fluent.profiles.models import AppSettings, SecuritySettings
from xray_fluent.ui.masking_dialog import parse_custom
from xray_fluent.ui.settings_page import SettingsPage

_shared: dict[str, SettingsPage] = {}


def _page() -> SettingsPage:
    page = _shared.get("page")
    if page is None:
        page = SettingsPage()
        _shared["page"] = page
    return page


class MaskingSettingsGroupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.saved: list[AppSettings] = []
        self.page = _page()
        self.page.save_requested.connect(self.saved.append)

    def tearDown(self) -> None:
        self.page.save_requested.disconnect(self.saved.append)

    def load(self, settings: MaskingSettings) -> None:
        self.page.set_values(AppSettings(masking=codec.encode(settings)), SecuritySettings())

    def test_controls_show_the_stored_presets(self) -> None:
        stored = MaskingSettings(True, Masking(wireguard=presets.WIREGUARD_JUNK_ONLY.masking.wireguard,
                                               xray=presets.XMUX_ROTATE.masking.xray))
        self.load(stored)
        self.assertTrue(self.page.masking_card.isChecked())
        self.assertEqual("wg-junk-only", self.page.masking_wg_card.combo.currentData())
        self.assertEqual("xmux-rotate", self.page.masking_xmux_card.combo.currentData())
        self.assertFalse(self.page.masking_mux_card.isChecked())

    def test_changing_a_control_saves_the_document_and_keeps_overrides(self) -> None:
        self.load(MaskingSettings(False, Masking(), {"node-1": OFF}))
        self.page.masking_card.setChecked(True)
        combo = self.page.masking_wg_card.combo
        combo.setCurrentIndex(combo.findData("wg-dns"))
        saved = codec.decode(self.saved[-1].masking)
        self.assertTrue(saved.enabled)
        self.assertEqual(presets.wireguard_dns().masking.wireguard, saved.global_masking.wireguard)
        self.assertEqual({"node-1": OFF}, saved.overrides)

    def test_a_tuned_section_reads_custom_and_survives_other_changes(self) -> None:
        tuned = WireGuardMasking(jc=5, jmin=20, jmax=40)
        self.load(MaskingSettings(True, Masking(wireguard=tuned)))
        self.assertEqual("custom", self.page.masking_wg_card.combo.currentData())
        self.page.masking_mux_card.setChecked(True)
        saved = codec.decode(self.saved[-1].masking)
        self.assertEqual(tuned, saved.global_masking.wireguard)
        self.assertIsNotNone(saved.global_masking.xray.mux)

    def test_custom_editor_refuses_what_a_core_would_refuse(self) -> None:
        masking, problems = parse_custom('{"wireguard": {"jc": 3, "jmin": 50, "jmax": 10}}')
        self.assertIsNone(masking)
        self.assertIn("Jmin не может быть больше Jmax.", problems)
        self.assertEqual(["Неизвестные разделы: sockopt."], parse_custom('{"sockopt": {}}')[1])
        self.assertTrue(parse_custom("not json")[1][0].startswith("Это не JSON"))
        ok, problems = parse_custom('{"xray": {"xmux": {"maxConnections": "2"}}}')
        self.assertEqual([], problems)
        self.assertEqual("2", str(ok.xray.xmux.max_connections))


if __name__ == "__main__":
    unittest.main()
