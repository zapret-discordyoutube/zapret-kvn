"""Exercise user actions against the virtual table and stable node identities."""
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import unittest
from unittest.mock import patch

from PyQt6.QtCore import Qt, QPersistentModelIndex, QItemSelectionModel
from PyQt6.QtTest import QTest, QAbstractItemModelTester
from PyQt6.QtWidgets import QApplication
from xray_fluent.profiles.models import Node
from xray_fluent.profiles.node_presentation import display_name, node_country
from xray_fluent.ui.nodes_page import NodesPage
from xray_fluent.ui.nodes_table_model import NODE_ID_ROLE

_APP = QApplication.instance() or QApplication([])


class NodesInteractionTests(unittest.TestCase):
    def setUp(self):
        self.page = NodesPage()
        self.nodes = [Node(id=str(i), name=f'🇳🇱 Server {i}', link=f'vless://test{i}', ping_ms=i) for i in range(8)]
        self.page.set_nodes(self.nodes)
        self.page.resize(1100, 550)
        self.page.show()
        self.page.activateWindow()
        _APP.processEvents()
        self.table = self.page.table
        self.model = self.page._group_model
        self.tester = QAbstractItemModelTester(self.model, QAbstractItemModelTester.FailureReportingMode.Fatal)

    def tearDown(self):
        self.page.close()
        self.page.deleteLater()
        _APP.processEvents()

    def index(self, node_id):
        source = self.page._table_model.index(self.page._table_model.row_for_node(node_id), 0)
        return self.model.mapFromSource(self.page._proxy.mapFromSource(source))

    def click(self, node_id, modifiers=Qt.KeyboardModifier.NoModifier):
        QTest.mouseClick(self.table.viewport(), Qt.MouseButton.LeftButton, modifiers,
                         self.table.visualRect(self.index(node_id)).center())

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

    def test_double_click_opens_correct_server_and_context_keeps_multiselection(self):
        self.click('2')
        with patch.object(self.page, '_show_detail') as detail:
            QTest.mouseDClick(self.table.viewport(), Qt.MouseButton.LeftButton,
                             pos=self.table.visualRect(self.index('2')).center())
            detail.assert_called_once_with(self.nodes[2])
        self.click('4', Qt.KeyboardModifier.ControlModifier)
        with patch('xray_fluent.ui.nodes_page.RoundMenu.exec') as menu:
            self.page._on_context_menu(self.table.visualRect(self.index('2')).center())
            menu.assert_called_once()
        self.assertEqual(self.page._selected_ids(), {'2', '4'})

    def test_groups_collapse_with_mouse_and_keyboard_without_switching_server(self):
        self.click('2')
        switches = []
        self.page.selected_node_changed.connect(switches.append)
        group = self.model.group_indexes()[0]
        QTest.mouseClick(self.table.viewport(), Qt.MouseButton.LeftButton,
                         pos=self.table.visualRect(group).center())
        self.assertTrue(self.table.isRowHidden(self.index('2').row()))
        QTest.keyClick(self.table, Qt.Key.Key_Right)
        self.assertFalse(self.table.isRowHidden(self.index('2').row()))
        QTest.keyClick(self.table, Qt.Key.Key_Left)
        self.assertTrue(self.table.isRowHidden(self.index('2').row()))
        self.assertEqual(self.page._selected_ids(), {'2'})
        self.assertEqual(switches, [])

    def test_removal_and_filter_preserve_surviving_selection_and_header_count(self):
        self.click('2')
        self.click('4', Qt.KeyboardModifier.ControlModifier)
        self.page.set_nodes(self.nodes[1:])
        self.assertEqual(self.page._selected_ids(), {'2', '4'})
        self.assertEqual(self.table.verticalHeader().count(), self.model.rowCount())
        self.page._proxy.set_query('Server 4')
        self.assertEqual(self.page._selected_ids(), {'4'})
        self.assertEqual(self.model.rowCount(), 2)
        self.assertTrue(self.page.bulk_edit_btn.isHidden())
        self.page._proxy.set_query('')
        self.assertEqual(self.table.verticalHeader().count(), self.model.rowCount())
        self.assertEqual(self.page._selected_ids(), {'4'})

    def test_metric_sort_preserves_persistent_index_selection_and_collapse(self):
        self.click('2')
        self.click('4', Qt.KeyboardModifier.ControlModifier)
        persistent = QPersistentModelIndex(self.index('2'))
        self.page._proxy.set_sort_key('ping')
        self.table.collapseAll()
        self.nodes[2].ping_ms = 100
        self.page._table_model.finish_ping_batch({'2'})
        self.assertEqual(persistent.data(NODE_ID_ROLE), '2')
        self.assertEqual(self.page._selected_ids(), {'2', '4'})
        self.assertTrue(self.table.isRowHidden(persistent.row()))
        self.table.expandAll()
        self.assertFalse(self.table.isRowHidden(persistent.row()))

    def test_editing_recreated_profile_regroups_same_id_and_preserves_selection(self):
        self.click('2')
        self.model.set_group_mode('group')
        replacement = Node(id='2', name='Edited server', group='New group')
        self.page.set_nodes([replacement if n.id == '2' else n for n in self.nodes])
        self.assertEqual(self.index('2').internalPointer().parent.key, 'group:New group')
        self.assertEqual(self.page._selected_ids(), {'2'})
        self.assertEqual(self.index('2').data(), 'Edited server')

    def test_country_batch_does_not_resort_or_rebuild(self):
        with patch.object(self.page._proxy, 'filterAcceptsRow', wraps=self.page._proxy.filterAcceptsRow) as filters, \
             patch.object(self.page._proxy, 'lessThan', wraps=self.page._proxy.lessThan) as sorts, \
             patch.object(self.model, 'rebuild', wraps=self.model.rebuild) as rebuild:
            self.page.update_countries({node.id for node in self.nodes})
            _APP.processEvents()
            filters.assert_not_called()
            sorts.assert_not_called()
            rebuild.assert_not_called()

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
