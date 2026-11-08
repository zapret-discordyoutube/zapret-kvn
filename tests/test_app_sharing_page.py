from __future__ import annotations

"""Вкладка «Кто подключается»: что видно человеку о раздаче обновлений (Zapret KVN).

Keep the ``test_app_*`` prefix (QApplication before tests/test_engine_process_stop.py).
"""

import os
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError("widget tests need a QApplication")
app = _existing or QApplication([])

from xray_fluent.ui.sharing_page import SharingPage
from xray_fluent.updates import share_wiring
from zapret_update.share_activity import ActivityLog


#: Страницы живут до конца процесса (как в test_app_dashboard_layout): deleteLater + processEvents роняют Python на Windows.
_KEEP_ALIVE: list = []


def snapshot_of(events, **extra):
    log = ActivityLog()
    for item in events:
        log.add(*item)
    return {
        "available": True, "lan_port": 51298, "internet_running": False, "internet_address": "", "notes": [],
        "events": log.snapshot(), "summary": log.summary(), **extra,
    }


class SharingPageTests(unittest.TestCase):
    def _page(self, snapshot):
        state = {"snapshot": snapshot, "cleared": 0}

        def clear():
            state["cleared"] += 1
            state["snapshot"] = snapshot_of([])

        page = SharingPage(snapshot=lambda: state["snapshot"], clear=clear)
        _KEEP_ALIVE.append(page)  # не уничтожаем: удаление виджетов посреди прогона роняет Windows-тесты
        return page, state

    def test_rows_show_who_connected_and_where_from(self) -> None:
        page, _ = self._page(snapshot_of([
            ("in", "lan", "10.0.0.5", "file", "ZapretKVN.exe", 2_500_000, "ok"),
            ("in", "internet", "93.184.216.34", "peers", "", 120, "ok"),
        ]))
        self.assertEqual(page.table.rowCount(), 2)
        row0 = [page.table.item(0, c).text() for c in range(page.table.columnCount())]
        row1 = [page.table.item(1, c).text() for c in range(page.table.columnCount())]
        self.assertEqual((row0[1], row0[2], row0[3]), ("К вам", "Интернет", "93.184.216.34"))  # новые сверху
        self.assertEqual((row1[2], row1[3], row1[4], row1[6]), ("Локальная сеть", "10.0.0.5", "Файл ZapretKVN.exe", "отдано"))
        self.assertTrue(page.table.item(0, 0).data(Qt.ItemDataRole.AccessibleTextRole))
        self.assertIn("порт 51298", page.status_labels[0].text())

    def test_empty_journal_explains_itself(self) -> None:
        page, _ = self._page(snapshot_of([]))
        self.assertFalse(page.empty_label.isHidden())
        self.assertIn("Пока никто не подключался", page.empty_label.text())
        off, _ = self._page({"available": False})
        self.assertIn("включите её", off.empty_label.text())

    def test_notes_explain_why_internet_sharing_is_off(self) -> None:
        page, _ = self._page(snapshot_of([], notes=["Раздача по интернету недоступна: роутер с UPnP не нашёлся"]))
        self.assertFalse(page.notes_label.isHidden())
        self.assertIn("UPnP", page.notes_label.text())

    def test_page_does_not_rebuild_without_changes_and_follows_new_events(self) -> None:
        page, state = self._page(snapshot_of([("in", "lan", "10.0.0.5", "file", "a", 10, "ok")]))
        item = page.table.item(0, 0)
        page.refresh()
        self.assertIs(page.table.item(0, 0), item)
        state["snapshot"] = snapshot_of([("in", "lan", "10.0.0.5", "file", "a", 10, "ok"), ("in", "lan", "10.0.0.6", "file", "b", 20, "ok")])
        page.refresh()
        self.assertEqual(page.table.rowCount(), 2)

    def test_clear_button_empties_the_journal(self) -> None:
        page, state = self._page(snapshot_of([("in", "lan", "10.0.0.5", "file", "a", 10, "ok")]))
        page.clear_button.click()
        self.assertEqual((state["cleared"], page.table.rowCount()), (1, 0))

    def test_broken_source_does_not_break_the_page(self) -> None:
        def boom():
            raise RuntimeError("no service")

        page = SharingPage(snapshot=boom, clear=lambda: None)
        _KEEP_ALIVE.append(page)  # не уничтожаем: удаление виджетов посреди прогона роняет Windows-тесты
        self.assertEqual(page.table.rowCount(), 0)

    def test_empty_page_stays_compact_at_the_top_instead_of_spreading_over_the_window(self) -> None:
        from PyQt6.QtCore import QPoint

        page, _ = self._page(snapshot_of([], notes=["Раздача по интернету недоступна: роутер с UPnP не нашёлся"]))
        page.resize(1100, 1000)
        page.show()
        for _ in range(5):
            app.processEvents()

        def top(widget):
            return widget.mapTo(page, QPoint(0, 0)).y()

        def bottom(widget):
            return top(widget) + widget.height()

        # Раньше свободное место делилось между надписями поровну, и подпись внизу уезжала к краю окна.
        self.assertLess(top(page.empty_label) - bottom(page.summary_label), 80)
        self.assertLess(top(page.hint_label) - bottom(page.empty_label), 60)
        self.assertLess(bottom(page.hint_label), 700)

    def test_timer_runs_only_while_the_page_is_shown(self) -> None:
        page, _ = self._page({"available": False})
        self.assertFalse(page._timer.isActive())
        page.show()
        self.assertTrue(page._timer.isActive())
        page.hide()
        self.assertFalse(page._timer.isActive())


class SnapshotTests(unittest.TestCase):
    def test_nothing_before_the_service_exists_and_a_full_picture_after(self) -> None:
        with patch.object(share_wiring, "_service", None):
            self.assertEqual(share_wiring.activity_snapshot(), {"available": False})
            share_wiring.clear_activity()  # без службы не падает
        with patch.object(share_wiring, "_service", None), patch.object(share_wiring, "_internet", False):
            service = share_wiring.default_service()
            service.activity.add("in", "lan", "10.0.0.5", "file", "a", 10)
            service.notes.append((1.0, "сеть не частная"))
            shot = share_wiring.activity_snapshot()
            self.assertTrue(shot["available"])
            self.assertEqual((shot["events"][0].peer, shot["notes"], shot["lan_port"]), ("10.0.0.5", ["сеть не частная"], None))
            self.assertEqual(shot["summary"]["events"], 1)
            share_wiring.clear_activity()
            self.assertEqual(share_wiring.activity_snapshot()["events"], [])

    def test_main_window_registers_the_tab_in_the_sidebar(self) -> None:
        from pathlib import Path

        source = (Path(__file__).resolve().parents[1] / "xray_fluent" / "ui" / "main_window.py").read_text(encoding="utf-8")
        self.assertIn('self.addSubInterface(self.sharing_page, FIF.SHARE, "Кто подключается"', source)


if __name__ == "__main__":
    unittest.main()
