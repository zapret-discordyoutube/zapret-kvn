"""«Сервисы» page with a full-page server picker (docs/SERVICE_SLOTS.md; owner 2026-11-17)."""

from __future__ import annotations

import unittest

from PyQt6.QtWidgets import QApplication

from xray_fluent.profiles.models import Node
from xray_fluent.ui.nodes_table_model import COLUMN_KEYS, COLUMN_SPECS
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
        model = self.page._model
        nodes = (model.node_at_row(row) for row in range(model.rowCount()))
        return [node.id for node in nodes if node is not None]

    def select(self, node_id):
        self.page._table.select_row(self.page._model.row_of_node(node_id))

    def test_filling_emits_nothing_and_builds_no_server_table(self):
        self.fill()
        self.assertEqual([], self.wanted)
        self.assertEqual([], self.pins)
        row = self.page._rows["youtube"]
        self.assertTrue(row.switch.isChecked())
        self.assertEqual("Закреплён: Beta", row.server.text())
        self.assertEqual("сейчас: Beta", row.state.text())
        self.assertFalse(self.page._rows["ai"].choose.isEnabled())
        self.assertEqual(0, self.page._model.rowCount(), "the table is filled only when the picker opens")

    def test_picker_is_the_servers_table_sorted_by_ping_with_the_pin_active(self):
        self.fill()
        self.page.open_picker("youtube")
        self.assertTrue(self.page.picker_open())
        self.assertEqual(["b", "a", "c"], self.ids(), "lower ping first, unknown ping last")
        self.assertEqual("b", self.page._model.active_node_id())
        self.assertTrue(self.page._auto_button.isEnabled())
        self.assertFalse(self.page._pin_button.isEnabled(), "nothing selected yet")
        visible = [spec.key for i, spec in enumerate(COLUMN_SPECS) if not self.page._table.isColumnHidden(i)]
        self.assertEqual(["name", "type", "ping", "speed"], visible)
        self.page._on_header_clicked(COLUMN_KEYS.index("speed"))
        self.assertEqual("b", self.ids()[0], "speed sorts fastest first")

    def test_search_filters_and_pinning_the_selection_emits_and_closes(self):
        self.fill()
        self.page.open_picker("youtube")
        self.page._search.setText("alp")
        self.assertEqual(["a"], self.ids())
        self.select("a")
        self.assertTrue(self.page._pin_button.isEnabled())
        self.page._pin_button.click()
        self.assertEqual([("youtube", "a")], self.pins)
        self.assertFalse(self.page.picker_open())
        self.page.open_picker("youtube")
        self.assertEqual("", self.page._search.text())
        self.assertEqual(["b", "a", "c"], self.ids())
        self.page._auto_button.click()
        self.assertEqual(("youtube", ""), self.pins[-1])

    def test_double_click_pins_and_auto_is_disabled_without_a_pin(self):
        self.fill(pins={})
        self.page.open_picker("youtube")
        self.assertIsNone(self.page._model.active_node_id())
        self.assertFalse(self.page._auto_button.isEnabled())
        self.page._table.node_activated.emit("c", None)
        self.assertEqual([("youtube", "c")], self.pins)

    def test_open_picker_refreshes_rows_in_place(self):
        self.fill()
        self.page.open_picker("youtube")
        faster = [Node(id="a", name="Alpha", is_alive=True, ping_ms=10, scheme="vless")] + NODES[1:]
        self.fill(nodes=faster, pins={"youtube": "a"})
        self.assertTrue(self.page.picker_open())
        self.assertEqual(["a", "b", "c"], self.ids())
        self.assertEqual("a", self.page._model.active_node_id())

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
        started = time.perf_counter()
        self.page.open_picker("youtube")
        self.assertLess(time.perf_counter() - started, 0.5)
        self.assertEqual(300, len(self.ids()))


if __name__ == "__main__":
    unittest.main()
