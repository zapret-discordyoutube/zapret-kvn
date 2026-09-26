"""Exercise user actions against the virtual table and stable node identities.

Keep the ``test_app_*`` prefix: widget test modules must sort before
``tests/test_engine_process_stop.py`` which creates a bare QCoreApplication
at import time (see tests/test_app_nodes_page_view.py).
"""
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import unittest
from unittest.mock import patch

from PyQt6.QtCore import Qt, QPersistentModelIndex
from PyQt6.QtTest import QTest, QAbstractItemModelTester
from PyQt6.QtWidgets import QApplication
from xray_fluent.profiles.models import AppSettings, Node
from xray_fluent.profiles.node_presentation import display_name, node_country
from xray_fluent.ui.nodes_page import NodesPage
from xray_fluent.ui.nodes_table_model import GROUP_MODES, NODE_ID_ROLE, SORT_KEYS

_APP = QApplication.instance() or QApplication([])

_GROUP = 'source:local'
# Окно троттлинга пересортировки по метрикам (300 мс) плюс запас.
_AFTER_RELAYOUT_WINDOW_MS = 400

# Одна страница (и один тестер модели) на модуль: пачка deleteLater полных
# страниц в одном процессе роняет Windows-прогон.
_shared_page: NodesPage | None = None
_shared_tester: QAbstractItemModelTester | None = None


def _stop_timers(page: NodesPage) -> None:
    for timer in (page._column_layout_timer, page._viewport_layout_timer, page._search_timer,
                  page._ping_batch_timer, page._speed_progress_timer, page._table_model._relayout_timer):
        timer.stop()


def _reset_page(nodes: list[Node]) -> NodesPage:
    global _shared_page, _shared_tester
    if _shared_page is None:
        _shared_page = NodesPage()
        # Проверка контракта QAbstractItemModel на каждом сигнале модели
        # (в т.ч. перенос персистентных индексов при layoutChanged).
        _shared_tester = QAbstractItemModelTester(
            _shared_page._table_model, QAbstractItemModelTester.FailureReportingMode.Fatal
        )
    page = _shared_page
    _stop_timers(page)
    page.search_edit.clear()
    page.search_edit.hide()
    page.set_subscriptions([])
    page.apply_view_settings(AppSettings())
    page._clear_filters()
    page.table.clearSelection()
    page.set_active_node(None)
    page.set_nodes(nodes)
    page.resize(1100, 550)
    page.show()
    page.activateWindow()
    _APP.processEvents()
    _stop_timers(page)
    return page


class NodesInteractionTests(unittest.TestCase):
    def setUp(self):
        self.nodes = [Node(id=str(i), name=f'🇳🇱 Server {i}', link=f'vless://test{i}', ping_ms=i) for i in range(8)]
        self.page = _reset_page(self.nodes)
        self.table = self.page.table
        self.model = self.page._table_model

    def tearDown(self):
        _stop_timers(self.page)

    def connect(self, signal, slot):
        signal.connect(slot)
        self.addCleanup(signal.disconnect, slot)

    def index(self, node_id):
        row = self.model.row_of_node(node_id)
        self.assertIsNotNone(row, f'node {node_id} has no visible row')
        return self.model.index(row, 0)

    def click(self, node_id, modifiers=Qt.KeyboardModifier.NoModifier):
        QTest.mouseClick(self.table.viewport(), Qt.MouseButton.LeftButton, modifiers,
                         self.table.visualRect(self.index(node_id)).center())

    def set_sort(self, key):
        self.page.sort_combo.setCurrentIndex(SORT_KEYS.index(key))

    def test_row_texts_are_cached_and_one_node_change_rebuilds_one_row(self):
        # Сброс кэша текстов всех строк публичным путём (маскировка адресов).
        self.model.set_endpoints_revealed(True)
        self.model.set_endpoints_revealed(False)
        first, other = self.index('1'), self.index('2')
        with patch.object(self.model, '_build_texts', wraps=self.model._build_texts) as build:
            for _ in range(100):
                self.assertEqual(first.data(), 'Server 1')
                self.assertEqual(other.data(), 'Server 2')
            self.assertEqual(build.call_count, 2)
            changes = []
            self.connect(self.model.dataChanged,
                         lambda top, bottom, roles=None: changes.append((top.row(), bottom.row())))
            self.nodes[1].name = '🇩🇪 Changed'
            self.page._table_model.refresh_countries({'1'})
            self.assertEqual(changes, [(first.row(), first.row())])
            self.assertEqual(first.data(), 'Changed')
            reads_after_update = build.call_count
            self.assertEqual(other.data(), 'Server 2')
            self.assertEqual(build.call_count, reads_after_update)
            self.assertEqual(sum(call.args[0].id == '2' for call in build.call_args_list), 1)
            self.assertEqual(sum(call.args[0].id == '1' for call in build.call_args_list), 2)

    def test_collapsed_node_shows_fresh_data_after_expansion(self):
        self.assertEqual(self.index('1').data(), 'Server 1')
        self.table.set_group_expanded(_GROUP, False)
        self.assertIsNone(self.model.row_of_node('1'))
        self.nodes[1].name = '🇫🇮 New name'
        self.page._table_model.refresh_countries({'1'})
        self.table.set_group_expanded(_GROUP, True)
        self.assertEqual(self.index('1').data(), 'New name')

    def test_resize_events_share_one_layout_and_keep_final_widths(self):
        self.page._viewport_layout_timer.stop()
        with patch.object(self.page, '_relayout_flex_column') as layout:
            for _ in range(50):
                self.page._queue_viewport_layout()
            self.assertEqual(layout.call_count, 0)
            for _ in range(50):
                QTest.qWait(10)
                if layout.call_count:
                    break
            self.assertEqual(layout.call_count, 1)
        self.page.resize(1500, 550)
        QTest.qWait(50)
        header = self.table.horizontalHeader()
        width = sum(header.sectionSize(i) for i in range(header.count()) if not header.isSectionHidden(i))
        self.assertEqual(width, self.table.viewport().width())

    def test_mouse_multiselection_keyboard_navigation_and_copy_links(self):
        self.click('1')
        self.click('3', Qt.KeyboardModifier.ControlModifier)
        self.assertEqual(self.page._selected_ids(), {'1', '3'})
        QTest.keyClick(self.table, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
        self.assertEqual(set(_APP.clipboard().text().splitlines()), {'vless://test1', 'vless://test3'})
        QTest.keyClick(self.table, Qt.Key.Key_Down)
        self.assertEqual(self.page._selected_ids(), {'4'})
        QTest.keyClick(self.table, Qt.Key.Key_Down, Qt.KeyboardModifier.ShiftModifier)
        self.assertEqual(self.page._selected_ids(), {'4', '5'})

    # ── Выбор ≠ подключение ──

    def context_menu(self, node_id):
        """Открыть контекстное меню строки; вернуть пункты меню."""
        menus = []
        with patch('xray_fluent.ui.nodes_page.RoundMenu.exec', autospec=True,
                   side_effect=lambda menu, *args, **kwargs: menus.append(menu)):
            pos = self.table.visualRect(self.index(node_id)).center()
            QTest.mouseClick(self.table.viewport(), Qt.MouseButton.RightButton, pos=pos)
            self.page._on_context_menu(pos)
        self.assertTrue(menus)
        return {action.text(): action for action in menus[-1].menuActions()}

    def test_double_click_connects_once_and_does_not_open_details(self):
        self.click('2')
        switches = []
        self.connect(self.page.selected_node_changed, switches.append)
        pos = self.table.visualRect(self.index('2')).center()
        with patch.object(self.page, '_show_detail') as detail:
            # Первое нажатие двойного клика — просто выделение.
            QTest.mouseClick(self.table.viewport(), Qt.MouseButton.LeftButton, pos=pos)
            self.assertEqual(switches, [])
            QTest.mouseDClick(self.table.viewport(), Qt.MouseButton.LeftButton, pos=pos)
            detail.assert_not_called()
        self.assertEqual(switches, ['2'])
        self.assertEqual(self.page._selected_ids(), {'2'})

    def test_context_menu_keeps_multiselection_and_offers_no_connect_for_many(self):
        self.click('2')
        self.click('4', Qt.KeyboardModifier.ControlModifier)
        switches = []
        self.connect(self.page.selected_node_changed, switches.append)
        actions = self.context_menu('2')
        self.assertEqual(self.page._selected_ids(), {'2', '4'})
        self.assertNotIn('Подключить к этому серверу', actions)
        self.assertEqual(switches, [])

    def test_right_click_on_other_row_only_selects_and_menu_connects(self):
        self.click('1')
        switches = []
        self.connect(self.page.selected_node_changed, switches.append)
        actions = self.context_menu('3')
        self.assertEqual(self.page._selected_ids(), {'3'})
        self.assertEqual(switches, [])
        self.assertEqual(list(actions)[:2], ['Подключить к этому серверу', 'Подробности'])
        with patch.object(self.page, '_show_detail') as detail:
            actions['Подробности'].trigger()
            detail.assert_called_once_with(self.nodes[3])
        self.assertEqual(switches, [])
        actions['Подключить к этому серверу'].trigger()
        self.assertEqual(switches, ['3'])

    def test_arrow_keys_and_modifier_selection_do_not_connect(self):
        self.click('1')
        switches = []
        self.connect(self.page.selected_node_changed, switches.append)
        QTest.keyClick(self.table, Qt.Key.Key_Down)
        QTest.keyClick(self.table, Qt.Key.Key_Down)
        self.assertEqual(self.page._selected_ids(), {'3'})
        QTest.keyClick(self.table, Qt.Key.Key_Up, Qt.KeyboardModifier.ShiftModifier)
        self.assertEqual(self.page._selected_ids(), {'2', '3'})
        self.click('5', Qt.KeyboardModifier.ControlModifier)
        self.click('6')
        self.click('7', Qt.KeyboardModifier.ShiftModifier)
        self.assertEqual(self.page._selected_ids(), {'6', '7'})
        self.assertEqual(switches, [])

    def test_enter_connects_current_server_and_toggles_group_header(self):
        self.click('3')
        switches = []
        self.connect(self.page.selected_node_changed, switches.append)
        QTest.keyClick(self.table, Qt.Key.Key_Return)
        self.assertEqual(switches, ['3'])
        QTest.keyClick(self.table, Qt.Key.Key_Enter, Qt.KeyboardModifier.KeypadModifier)
        self.assertEqual(switches, ['3', '3'])
        QTest.keyClick(self.table, Qt.Key.Key_Return, Qt.KeyboardModifier.ControlModifier)
        self.assertEqual(switches, ['3', '3'])
        # Enter на заголовке группы сворачивает/разворачивает её и не подключает.
        QTest.keyClick(self.table, Qt.Key.Key_Left)
        QTest.keyClick(self.table, Qt.Key.Key_Return)
        self.assertFalse(self.table.is_group_expanded(_GROUP))
        QTest.keyClick(self.table, Qt.Key.Key_Return)
        self.assertTrue(self.table.is_group_expanded(_GROUP))
        self.assertEqual(switches, ['3', '3'])

    def test_double_click_on_group_header_toggles_without_connecting(self):
        switches = []
        self.connect(self.page.selected_node_changed, switches.append)
        pos = self.table.visualRect(self.model.index(self.model.row_of_key(_GROUP), 0)).center()
        # Настоящий двойной клик: нажатие/отпускание, затем DblClick (QTest.mouseDClick
        # в Qt 6 шлёт только DblClick). Итог — одно переключение группы.
        QTest.mouseClick(self.table.viewport(), Qt.MouseButton.LeftButton, pos=pos)
        QTest.mouseDClick(self.table.viewport(), Qt.MouseButton.LeftButton, pos=pos)
        self.assertFalse(self.table.is_group_expanded(_GROUP))
        QTest.mouseClick(self.table.viewport(), Qt.MouseButton.LeftButton, pos=pos)
        QTest.mouseDClick(self.table.viewport(), Qt.MouseButton.LeftButton, pos=pos)
        self.assertTrue(self.table.is_group_expanded(_GROUP))
        self.assertEqual(switches, [])

    def test_groups_collapse_with_mouse_and_keyboard_without_switching_server(self):
        self.click('2')
        switches = []
        self.connect(self.page.selected_node_changed, switches.append)
        group = self.model.index(self.model.row_of_key(_GROUP), 0)
        QTest.mouseClick(self.table.viewport(), Qt.MouseButton.LeftButton,
                         pos=self.table.visualRect(group).center())
        self.assertFalse(self.table.is_group_expanded(_GROUP))
        self.assertIsNone(self.model.row_of_node('2'))
        self.assertEqual(self.page._selected_ids(), {'2'})
        QTest.keyClick(self.table, Qt.Key.Key_Right)
        self.assertTrue(self.table.is_group_expanded(_GROUP))
        self.assertIsNotNone(self.model.row_of_node('2'))
        self.assertTrue(self.table.selectionModel().isRowSelected(self.model.row_of_node('2')))
        QTest.keyClick(self.table, Qt.Key.Key_Left)
        self.assertFalse(self.table.is_group_expanded(_GROUP))
        self.assertIsNone(self.model.row_of_node('2'))
        self.assertEqual(self.page._selected_ids(), {'2'})
        self.assertEqual(switches, [])

    def test_left_on_server_moves_to_its_group_header(self):
        self.click('5')
        QTest.keyClick(self.table, Qt.Key.Key_Left)
        self.assertEqual(self.table.currentIndex().row(), self.model.row_of_key(_GROUP))
        self.assertTrue(self.table.is_group_expanded(_GROUP))
        QTest.keyClick(self.table, Qt.Key.Key_Space)
        self.assertFalse(self.table.is_group_expanded(_GROUP))
        self.assertEqual(self.page._selected_ids(), {'5'})

    def test_plain_click_after_collapse_replaces_hidden_selection(self):
        self.page.set_subscriptions([])
        remote = [Node(id=f'r{i}', name=f'Remote {i}', subscription_id='sub', link=f'vless://r{i}') for i in range(2)]
        self.page.set_nodes(self.nodes + remote)
        self.click('2')
        self.table.set_group_expanded(_GROUP, False)
        self.assertEqual(self.page._selected_ids(), {'2'})
        self.click('r0', Qt.KeyboardModifier.ControlModifier)
        self.assertEqual(self.page._selected_ids(), {'2', 'r0'})
        self.click('r1')
        self.assertEqual(self.page._selected_ids(), {'r1'})
        self.table.set_group_expanded(_GROUP, True)
        self.assertEqual(self.page._selected_ids(), {'r1'})

    def test_removal_and_filter_preserve_surviving_selection_and_header_count(self):
        self.click('2')
        self.click('4', Qt.KeyboardModifier.ControlModifier)
        self.page.set_nodes(self.nodes[1:])
        self.assertEqual(self.page._selected_ids(), {'2', '4'})
        self.assertEqual(self.table.verticalHeader().count(), self.model.rowCount())
        self.page._table_model.set_query('Server 4')
        self.assertEqual(self.page._selected_ids(), {'4'})
        self.assertEqual(self.model.rowCount(), 2)  # заголовок группы + сервер
        self.assertTrue(self.page.bulk_edit_btn.isHidden())
        self.page._table_model.set_query('')
        self.assertEqual(self.table.verticalHeader().count(), self.model.rowCount())
        self.assertEqual(self.page._selected_ids(), {'4'})

    def test_deleting_selected_node_inside_collapsed_group_drops_it(self):
        self.click('2')
        self.click('4', Qt.KeyboardModifier.ControlModifier)
        self.table.collapseAll()
        self.assertEqual(self.page._selected_ids(), {'2', '4'})
        self.page.set_nodes([node for node in self.nodes if node.id != '4'])
        self.assertEqual(self.page._selected_ids(), {'2'})
        self.table.expandAll()
        self.assertEqual(self.page._selected_ids(), {'2'})

    def test_metric_sort_preserves_persistent_index_selection_and_collapse(self):
        self.click('2')
        self.click('4', Qt.KeyboardModifier.ControlModifier)
        self.set_sort('ping')
        persistent = QPersistentModelIndex(self.index('2'))
        resets, layouts = [], []
        self.connect(self.model.modelReset, lambda: resets.append(True))
        self.connect(self.model.layoutChanged, lambda *args: layouts.append(True))
        self.nodes[2].ping_ms = 100
        self.page._table_model.finish_ping_batch({'2'})
        # Пересортировка отложена на окно троттлинга и происходит один раз.
        self.assertEqual(layouts, [])
        QTest.qWait(_AFTER_RELAYOUT_WINDOW_MS)
        self.assertEqual(len(layouts), 1)
        self.assertEqual(resets, [])
        self.assertEqual(persistent.data(NODE_ID_ROLE), '2')
        self.assertEqual(persistent.row(), self.model.rowCount() - 1)
        self.assertEqual(self.page._selected_ids(), {'2', '4'})
        self.table.collapseAll()
        self.assertIsNone(self.model.row_of_node('2'))
        self.assertEqual(self.page._selected_ids(), {'2', '4'})
        self.table.expandAll()
        self.assertEqual(self.model.row_of_node('2'), self.model.rowCount() - 1)
        self.assertEqual(self.page._selected_ids(), {'2', '4'})

    def test_editing_recreated_profile_regroups_same_id_and_preserves_selection(self):
        self.click('2')
        self.page.group_by_combo.setCurrentIndex(list(GROUP_MODES).index('group'))
        self.assertEqual(self.model.group_mode(), 'group')
        self.assertEqual(self.page._selected_ids(), {'2'})
        replacement = Node(id='2', name='Edited server', group='New group')
        self.page.set_nodes([replacement if n.id == '2' else n for n in self.nodes])
        row = self.model.row_of_node('2')
        header = next(r for r in range(row - 1, -1, -1) if self.model.row_at(r).is_group)
        self.assertEqual(self.model.row_at(header).key, 'group:New group')
        self.assertEqual(self.page._selected_ids(), {'2'})
        self.assertEqual(self.index('2').data(), 'Edited server')

    def test_country_batch_does_not_resort_or_rebuild(self):
        resets, layouts, changes = [], [], []
        self.connect(self.model.modelReset, lambda: resets.append(True))
        self.connect(self.model.layoutChanged, lambda *args: layouts.append(True))
        self.connect(self.model.dataChanged,
                     lambda top, bottom, roles=None: changes.append((top.row(), bottom.row())))
        for node in self.nodes:
            node.country_code = 'DE'
        with patch.object(self.model, '_accepts', wraps=self.model._accepts) as filters, \
             patch.object(self.model, '_sorted', wraps=self.model._sorted) as sorts:
            self.page.update_countries({node.id for node in self.nodes})
            QTest.qWait(_AFTER_RELAYOUT_WINDOW_MS)
            filters.assert_not_called()
            sorts.assert_not_called()
        self.assertEqual((resets, layouts), ([], []))
        rows = {row for top, bottom in changes for row in range(top, bottom + 1)}
        self.assertEqual(rows, {self.model.row_of_node(node.id) for node in self.nodes})

    def test_collapsed_group_metrics_do_not_notify_or_sort_until_expansion(self):
        self.set_sort('ping')
        self.click('2')
        self.table.collapseAll()
        _APP.processEvents()
        changes, layouts, resets = [], [], []
        self.connect(self.model.dataChanged,
                     lambda top, bottom, roles=None: changes.append((top.row(), bottom.row())))
        self.connect(self.model.layoutChanged, lambda *args: layouts.append(True))
        self.connect(self.model.modelReset, lambda: resets.append(True))
        self.nodes[2].ping_ms = 999
        self.page._table_model.finish_ping_batch({'2'})
        QTest.qWait(_AFTER_RELAYOUT_WINDOW_MS)
        # Строк серверов в модели нет — нечего и перерисовывать; допустима
        # лишь перерисовка заголовков групп.
        for top, bottom in changes:
            for row in range(top, bottom + 1):
                self.assertTrue(self.model.row_at(row).is_group)
        self.assertEqual((layouts, resets), ([], []))
        self.assertEqual(self.page._selected_ids(), {'2'})
        self.table.expandAll()
        _APP.processEvents()
        self.assertEqual(self.model.visible_node_ids()[-1], '2')
        self.assertEqual(self.model.row_of_node('2'), self.model.rowCount() - 1)
        self.assertEqual(self.page._selected_ids(), {'2'})
        self.assertEqual(len(resets), 1)
        self.assertEqual(layouts, [])

    def test_provider_flag_is_graphical_only_and_does_not_modify_profile(self):
        node = self.nodes[0]
        node.country_code = 'US'
        index = self.index(node.id)
        self.assertEqual(index.data(), 'Server 0')
        self.assertFalse(index.data(Qt.ItemDataRole.DecorationRole).isNull())
        self.assertEqual(node_country(node), 'NL')
        self.assertEqual(node.name, '🇳🇱 Server 0')
        self.assertEqual(node.link, 'vless://test0')
        node.country_override = 'DE'
        self.assertEqual(node_country(node), 'DE')
        self.assertEqual(display_name('DE Server'), 'DE Server')
        node.name = 'No flag'
        node.country_override = ''
        self.assertEqual(node_country(node), 'US')


if __name__ == '__main__':
    unittest.main()
