"""«Сервисы» page with a full-page server picker (docs/SERVICE_SLOTS.md; owner 2026-11-17)."""

from __future__ import annotations

import unittest

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication

from xray_fluent.profiles.models import Node
from xray_fluent.ui.services_page import ServicesPage

_app = QApplication.instance() or QApplication([])

NODES = [
    Node(id="a", name="Alpha", is_alive=True, ping_ms=80, scheme="vless"),
    Node(id="b", name="Beta", is_alive=True, speed_mbps=50, ping_ms=40, scheme="hysteria2"),
    Node(id="c", name="Gamma", is_alive=False, scheme="vless"),
]


class ServicesPageTests(unittest.TestCase):
    def setUp(self):
        self.page = ServicesPage()
        self.wanted: list[set[str]] = []
        self.pins: list[tuple[str, str]] = []
        self.page.slots_changed.connect(self.wanted.append)
        self.page.pin_changed.connect(lambda slot, node: self.pins.append((slot, node)))

    def fill(self, **overrides):
        args = dict(available=True, enabled={"youtube"}, pins={"youtube": "b"}, nodes=NODES, live={"youtube": NODES[1]},
                    connected=True)
        args.update(overrides)
        self.page.set_state(**args)

    def ids(self):
        lst = self.page._list
        return [lst.item(i).data(Qt.ItemDataRole.UserRole) for i in range(lst.count()) if not lst.item(i).isHidden()]

    def test_filling_emits_nothing_and_builds_no_server_list(self):
        self.fill()
        self.assertEqual([], self.wanted)
        self.assertEqual([], self.pins)
        row = self.page._rows["youtube"]
        self.assertTrue(row.switch.isChecked())
        self.assertEqual("Закреплён: Beta", row.server.text())
        self.assertEqual("сейчас: Beta", row.state.text())
        self.assertFalse(self.page._rows["ai"].choose.isEnabled())
        self.assertEqual(0, self.page._list.count(), "the list is built only when the picker opens")

    def test_picker_lists_auto_first_then_servers_best_first_and_marks_the_pin(self):
        self.fill()
        self.page.open_picker("youtube")
        self.assertTrue(self.page.picker_open())
        self.assertEqual(["", "b", "a", "c"], self.ids())
        self.assertTrue(self.page._list.item(1).text().startswith("✓  Beta"))
        self.assertIn("не отвечал", self.page._list.item(3).text())

    def test_search_filters_by_name_and_a_pick_emits_and_closes(self):
        self.fill()
        self.page.open_picker("youtube")
        self.page._search.setText("alp")
        self.assertEqual(["a"], self.ids())
        self.page._on_pick(self.page._list.item(2))
        self.assertEqual([("youtube", "a")], self.pins)
        self.assertFalse(self.page.picker_open())
        self.page.open_picker("youtube")
        self.page._on_pick(self.page._list.item(0))
        self.assertEqual(("youtube", ""), self.pins[-1])

    def test_switch_emits_the_whole_wanted_set(self):
        self.fill()
        self.page._rows["telegram"].switch.setChecked(True)
        self.assertEqual([{"youtube", "telegram"}], self.wanted)
        self.assertTrue(self.page._rows["telegram"].choose.isEnabled())

    def test_unavailable_disables_and_shows_why_and_live_texts(self):
        self.fill(available=False, note="нет outbound «proxy»")
        self.assertFalse(self.page._rows["youtube"].switch.isEnabled())
        self.assertEqual("нет outbound «proxy»", self.page._note.text())
        self.fill(live={"youtube": None})
        self.assertEqual("сейчас: как основной", self.page._rows["youtube"].state.text())
        self.fill(connected=False, pins={})
        self.assertEqual("", self.page._rows["youtube"].state.text())
        self.assertEqual("Сервер: Авто", self.page._rows["youtube"].server.text())

    def test_hundred_servers_fill_fast(self):
        import time
        many = [Node(id=f"n{i}", name=f"Server {i}", is_alive=True, ping_ms=i + 1) for i in range(300)]
        self.fill(nodes=many, pins={})
        started = time.perf_counter()
        for _ in range(20):
            self.fill(nodes=many, pins={})  # runtime refreshes while the picker is closed: no list work
        self.assertLess(time.perf_counter() - started, 0.5)
        self.page.open_picker("youtube")
        self.assertEqual(301, self.page._list.count())


if __name__ == "__main__":
    unittest.main()
