"""In-page breadcrumb sub-pages replacing the old modal form dialogs.

NOTE on the module name: unittest discover imports test modules in
alphabetical order, and ``tests/test_engine_process_stop.py`` (and others)
create a bare ``QCoreApplication`` at import time, which cannot host widgets
and cannot be upgraded in-process.  Keep the ``test_app_*`` prefix so widget
test modules sort before any ``QCoreApplication``-creating module.

Widget lifetime: pages are created once per module and never destroyed —
``deleteLater()`` on several qfluentwidgets scroll pages races the cyclic GC
and crashes on Windows (see tests/test_app_scrollable_page.py).
"""

from __future__ import annotations

import importlib
import os
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QLineEdit

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError(
        "A bare QCoreApplication was created before test_app_detail_pages "
        "was imported; widget tests need a QApplication."
    )
app = _existing or QApplication([])

from xray_fluent.profiles.models import Node, Subscription
from xray_fluent.ui.detail_page import DetailPage, StackedSection
from xray_fluent.ui.nodes_page import NodesPage
from xray_fluent.ui.subscriptions_page import SubscriptionsPage, _subscription_status

UI_DIR = Path(__file__).resolve().parent.parent / "xray_fluent" / "ui"

_shared: dict[str, object] = {}


def _page(name: str, factory):
    if name not in _shared:
        _shared[name] = factory()
    return _shared[name]


def _nodes_page() -> NodesPage:
    return _page("nodes", NodesPage)  # type: ignore[return-value]


def _subscriptions_page() -> SubscriptionsPage:
    return _page("subscriptions", SubscriptionsPage)  # type: ignore[return-value]


def _node(node_id: str = "n1") -> Node:
    return Node(
        id=node_id,
        name="Berlin",
        server="example.com",
        port=443,
        scheme="vless",
        group="EU",
        tags=["fast"],
    )


class DetailPageBaseTest(unittest.TestCase):
    def test_breadcrumb_is_a_two_item_trail(self) -> None:
        page = _page("plain", lambda: DetailPage("Корень", "Деталь", root_key="root", page_key="leaf"))
        self.assertEqual(page.breadcrumb.count(), 2)
        self.assertEqual(page.breadcrumb.itemAt(0).routeKey, "root")
        self.assertEqual(page.breadcrumb.itemAt(1).routeKey, "leaf")

    def test_root_crumb_requests_back(self) -> None:
        page = _page("plain", lambda: DetailPage("Корень", "Деталь", root_key="root", page_key="leaf"))
        seen: list[int] = []
        page.back_requested.connect(lambda: seen.append(1))
        page.breadcrumb.setCurrentItem("root")
        self.assertEqual(len(seen), 1)
        # The bar pops the tail on click; the trail must be restored for reuse.
        page.reset_breadcrumb()
        self.assertEqual(page.breadcrumb.count(), 2)

    def test_dirty_page_asks_before_leaving(self) -> None:
        class _DirtyPage(DetailPage):
            def is_dirty(self) -> bool:
                return True

        page = _page("dirty", lambda: _DirtyPage("Корень", "Деталь"))
        seen: list[int] = []
        page.back_requested.connect(lambda: seen.append(1))
        page.confirm_back = lambda: False  # stand in for the user cancelling
        page.request_back()
        self.assertEqual(seen, [])
        page.confirm_back = lambda: True
        page.request_back()
        self.assertEqual(seen, [1])


class NodesPageSubPagesTest(unittest.TestCase):
    def test_node_editor_opens_as_sub_page_and_emits_fields(self) -> None:
        page = _nodes_page()
        page.show_root()
        self.assertTrue(page.is_root_visible())

        page.open_node_editor(_node(), ["EU", "US"])
        self.assertFalse(page.is_root_visible())
        self.assertIs(page._stack.currentWidget(), page._edit_page)
        self.assertEqual(page._edit_page.name_edit.text(), "Berlin")
        self.assertEqual(page._edit_page.tags_edit.text(), "fast")
        self.assertEqual(page._edit_page.endpoint_label.text(), "********  (VLESS)")
        self.assertNotIn("example.com", page._edit_page.endpoint_label.text())

        QTest.keyPress(page._edit_page.reveal_address_btn, Qt.Key.Key_Enter)
        self.assertEqual(page._edit_page.endpoint_label.text(), "example.com:443  (VLESS)")
        QTest.keyRelease(page._edit_page.reveal_address_btn, Qt.Key.Key_Enter)
        self.assertEqual(page._edit_page.endpoint_label.text(), "********  (VLESS)")

        saved: list[tuple[str, dict]] = []
        page.node_edit_saved.connect(lambda nid, fields: saved.append((nid, fields)))
        page._edit_page.name_edit.setText("Frankfurt")
        page._edit_page.tags_edit.setText("fast, eu")
        page._edit_page.save_btn.click()

        self.assertEqual(len(saved), 1)
        node_id, fields = saved[0]
        self.assertEqual(node_id, "n1")
        self.assertEqual(fields["name"], "Frankfurt")
        self.assertEqual(fields["tags"], ["fast", "eu"])

        page.close_editor()
        self.assertTrue(page.is_root_visible())

    def test_node_editor_tracks_dirty_state(self) -> None:
        page = _nodes_page()
        page.open_node_editor(_node("n2"), [])
        self.assertFalse(page._edit_page.is_dirty())
        page._edit_page.name_edit.setText("changed")
        self.assertTrue(page._edit_page.is_dirty())
        page.close_editor()
        self.assertFalse(page._edit_page.is_dirty())

    def test_bulk_editor_opens_as_sub_page_and_emits_operations(self) -> None:
        page = _nodes_page()
        page.open_bulk_editor({"a", "b"}, ["EU"])
        self.assertIs(page._stack.currentWidget(), page._bulk_edit_page)

        applied: list[tuple[set, dict]] = []
        page.bulk_edit_applied.connect(lambda ids, ops: applied.append((ids, ops)))
        page._bulk_edit_page.group_combo.setText("US")
        page._bulk_edit_page.add_tags_edit.setText("new")
        page._bulk_edit_page.apply_btn.click()

        self.assertEqual(len(applied), 1)
        ids, ops = applied[0]
        self.assertEqual(ids, {"a", "b"})
        self.assertEqual(ops["group"], "US")
        self.assertEqual(ops["add_tags"], ["new"])
        self.assertEqual(ops["remove_tags"], [])
        page.show_root()

    def test_detail_sub_page_is_reachable(self) -> None:
        page = _nodes_page()
        page._show_detail(_node("n3"))
        self.assertIs(page._stack.currentWidget(), page._detail_widget)
        self.assertEqual(page._detail_widget.breadcrumb.count(), 2)
        self.assertEqual(page._detail_widget.endpoint_label.text(), "********  (VLESS)")
        self.assertNotIn("example.com", page._detail_widget.endpoint_label.text())
        QTest.keyPress(page._detail_widget.reveal_address_btn, Qt.Key.Key_Space)
        self.assertEqual(
            page._detail_widget.endpoint_label.text(), "example.com:443  (VLESS)"
        )
        QTest.keyRelease(page._detail_widget.reveal_address_btn, Qt.Key.Key_Space)
        self.assertEqual(page._detail_widget.endpoint_label.text(), "********  (VLESS)")
        page.show_root()


class SubscriptionsPageSubPageTest(unittest.TestCase):
    def test_persistent_subscription_status_and_force_refresh_signal(self) -> None:
        subscription = Subscription(
            id="s-warning",
            skipped_count=4,
            warnings=["Строка 39: Gecko не поддержан"],
        )
        text, tooltip = _subscription_status(subscription, updating=False)
        self.assertIn("Предупреждений: 1", text)
        self.assertIn("пропущено: 4", text)
        self.assertIn("Gecko", tooltip)

        subscription.last_error = "Сетевая ошибка"
        text, tooltip = _subscription_status(subscription, updating=False)
        self.assertEqual(text, "Сетевая ошибка")
        self.assertIn("Последний успешно применённый снимок", tooltip)

        page = _subscriptions_page()
        page.set_data([subscription], [])
        page.table.selectRow(0)
        emitted: list[tuple[str, str]] = []
        page.force_update_requested.connect(
            lambda sid, mode: emitted.append((sid, mode))
        )
        page.force_update_btn.click()
        self.assertEqual(emitted, [(subscription.id, "auto")])

    def test_new_subscription_form_opens_as_sub_page(self) -> None:
        page = _subscriptions_page()
        page.open_editor(None)
        self.assertIs(page._stack.currentWidget(), page.editor)
        self.assertEqual(page.editor.save_btn.text(), "Проверить и добавить")
        self.assertEqual(page.editor.url_edit.text(), "")
        page.show_root()

    def test_existing_subscription_form_prefills_and_emits_id(self) -> None:
        page = _subscriptions_page()
        subscription = Subscription(id="s1", name="Provider", url="https://example.com/sub/token")
        page.open_editor(subscription, ["DE-1", "NL-1"])
        self.assertEqual(page.editor.name_edit.text(), "Provider")
        self.assertEqual(page.editor.save_btn.text(), "Сохранить")
        self.assertEqual(page.editor.url_edit.echoMode(), QLineEdit.EchoMode.Password)

        emitted: list[str] = []
        page.editor_save_requested.connect(emitted.append)
        page.editor.save_btn.click()
        self.assertEqual(emitted, ["s1"])

        page.close_editor()
        self.assertTrue(page.is_root_visible())
        self.assertFalse(page.editor.is_dirty())

    def test_invalid_url_keeps_the_form_open(self) -> None:
        page = _subscriptions_page()
        page.open_editor(None)
        emitted: list[str] = []
        page.editor_save_requested.connect(emitted.append)
        page.editor.url_edit.setText("not a url")
        page.editor.save_btn.click()
        self.assertEqual(emitted, [])
        self.assertIs(page._stack.currentWidget(), page.editor)
        self.assertEqual(page.editor.url_edit.text(), "not a url")
        page.show_root()


class NoModalFormDialogsLeftTest(unittest.TestCase):
    def test_large_form_dialog_modules_are_gone(self) -> None:
        for name in ("node_edit_dialog", "bulk_edit_dialog"):
            with self.subTest(module=name):
                self.assertFalse((UI_DIR / f"{name}.py").exists())
                with self.assertRaises(ModuleNotFoundError):
                    importlib.import_module(f"xray_fluent.ui.{name}")

    def test_subscription_form_is_not_a_dialog(self) -> None:
        module = importlib.import_module("xray_fluent.ui.subscriptions_page")
        self.assertFalse(hasattr(module, "SubscriptionDialog"))
        self.assertTrue(issubclass(module.SubscriptionEditPage, DetailPage))

    def test_form_sections_host_their_sub_pages(self) -> None:
        for page in (_nodes_page(), _subscriptions_page()):
            with self.subTest(page=type(page).__name__):
                self.assertIsInstance(page, StackedSection)


if __name__ == "__main__":
    unittest.main()
