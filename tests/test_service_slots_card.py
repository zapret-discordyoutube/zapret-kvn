"""«Серверы по сервисам» card on the main page (docs/SERVICE_SLOTS.md, phase 5)."""

from __future__ import annotations

import unittest

from PyQt6.QtWidgets import QApplication

from xray_fluent.profiles.models import Node
from xray_fluent.ui.service_slots_card import ServiceSlotsCard

_app = QApplication.instance() or QApplication([])

NODES = [Node(id="a", name="Alpha"), Node(id="b", name="Beta")]


class ServiceSlotsCardTests(unittest.TestCase):
    def setUp(self):
        self.card = ServiceSlotsCard()
        self.wanted: list[set[str]] = []
        self.pins: list[tuple[str, str]] = []
        self.card.slots_changed.connect(self.wanted.append)
        self.card.pin_changed.connect(lambda slot, node: self.pins.append((slot, node)))

    def fill(self, **overrides):
        args = dict(available=True, enabled={"youtube"}, pins={"youtube": "b"}, nodes=NODES, live={"youtube": NODES[1]},
                    connected=True)
        args.update(overrides)
        self.card.set_state(**args)

    def test_filling_the_card_emits_nothing_and_shows_the_state(self):
        self.fill()
        self.assertEqual([], self.wanted)
        self.assertEqual([], self.pins)
        self.assertTrue(self.card._switches["youtube"].isChecked())
        self.assertFalse(self.card._switches["ai"].isChecked())
        self.assertEqual(2, self.card._combos["youtube"].currentIndex(), "«Авто» is index 0, Beta is 2")
        self.assertFalse(self.card._combos["ai"].isEnabled())
        self.assertEqual("сейчас: Beta", self.card._states["youtube"].text())

    def test_switch_emits_the_whole_wanted_set_and_pins_emit_ids(self):
        self.fill()
        self.card._switches["telegram"].setChecked(True)
        self.assertEqual([{"youtube", "telegram"}], self.wanted)
        self.card._combos["youtube"].setCurrentIndex(0)
        self.assertEqual([("youtube", "")], self.pins)
        self.card._combos["youtube"].setCurrentIndex(1)
        self.assertEqual(("youtube", "a"), self.pins[-1])

    def test_unavailable_disables_and_shows_why(self):
        self.fill(available=False, note="нет outbound «proxy»")
        self.assertFalse(self.card._switches["youtube"].isEnabled())
        self.assertEqual("нет outbound «proxy»", self.card._note.text())

    def test_live_text_when_following_main_or_not_connected(self):
        self.fill(live={"youtube": None})
        self.assertEqual("сейчас: как основной", self.card._states["youtube"].text())
        self.fill(connected=False)
        self.assertEqual("", self.card._states["youtube"].text())


if __name__ == "__main__":
    unittest.main()
