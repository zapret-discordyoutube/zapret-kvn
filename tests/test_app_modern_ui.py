"""Behavioral regressions for grouped servers, offline countries and startup."""
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import time
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, Mock, MagicMock

from PyQt6.QtCore import QRect, QPersistentModelIndex, Qt, QTimer, QEventLoop
from PyQt6.QtWidgets import QApplication, QWidget
_APP = QApplication.instance() or QApplication([])

from xray_fluent.profiles.models import Node, AppSettings, Subscription
from xray_fluent.profiles.geoip import CountryDatabase, endpoint_hosts
from xray_fluent.network.country_resolver import CountryResolver
from xray_fluent.ui.nodes_page import NodesPage
from xray_fluent.ui.nodes_group_model import GROUP_KEY_ROLE
from xray_fluent.ui.nodes_table_model import NODE_ID_ROLE, COL_PING
from xray_fluent.ui.window_geometry import fitted_geometry
from xray_fluent.ui.deferred_page import DeferredPage
from xray_fluent.application.startup_service import StartupWorker


class GroupedServersTests(unittest.TestCase):
    def setUp(self):
        self.page = NodesPage()
        self.addCleanup(self.page.deleteLater)

    def test_duplicate_subscription_names_still_have_distinct_groups(self):
        self.page.set_subscriptions([Subscription(id="one", name="Provider", url=""), Subscription(id="two", name="Provider", url="")])
        self.page.set_nodes([Node(id="a", subscription_id="one"), Node(id="b", subscription_id="two"), Node(id="c")])
        model = self.page._group_model
        self.assertEqual(model.rowCount(), 3)
        keys = {model.index(row, 0).data(GROUP_KEY_ROLE) for row in range(3)}
        self.assertEqual(keys, {"source:one", "source:two", "source:local"})

    def test_persistent_selection_and_expansion_survive_metric_sort(self):
        nodes = [Node(id="a", name="A", ping_ms=10), Node(id="b", name="B", ping_ms=20)]
        self.page.set_nodes(nodes, "a")
        model = self.page._group_model
        group = model.index(0, 0)
        persistent = QPersistentModelIndex(model.index(0, 0, group))
        self.page._proxy.set_sort_key("ping")
        self.page.table.collapse(group)
        resets = []
        model.modelReset.connect(lambda: resets.append(True))
        nodes[0].ping_ms = 90
        self.page._table_model.refresh_ping("a")
        self.assertEqual(persistent.data(NODE_ID_ROLE), "a")
        self.assertEqual(self.page._selected_ids(), {"a"})
        self.assertFalse(self.page.table.isExpanded(model.index(0, 0)))
        self.assertEqual(resets, [])

    def test_favorites_filter_and_settings_roundtrip(self):
        nodes = [Node(id="a", is_favorite=True), Node(id="b")]
        self.page.set_nodes(nodes)
        self.page.favorites_filter.setChecked(True)
        self.assertEqual(self.page._proxy.rowCount(), 1)
        prefs=[]
        self.page.view_prefs_changed.connect(prefs.append)
        self.page.table.header().resizeSection(0, 480)
        self.page._emit_view_prefs()
        restored = AppSettings.from_dict(prefs[-1])
        self.assertTrue(restored.nodes_favorites_only)
        self.assertEqual(restored.nodes_column_widths['name'], 480)
        self.assertTrue(Node.from_dict(nodes[0].to_dict()).is_favorite)

    def test_large_list_point_update_does_not_reset_or_resize(self):
        nodes=[Node(id=str(i), name=f"Server {i}", subscription_id=str(i%20)) for i in range(10000)]
        self.page.set_nodes(nodes)
        model=self.page._group_model
        self.assertEqual(model.rowCount(),20)
        resets=[]
        model.modelReset.connect(lambda:resets.append(True))
        self.page._table_model.refresh_ping('5000')
        self.assertEqual(resets,[])
        self.assertEqual(self.page.table.header().sectionSize(0),360)


class OfflineCountryTests(unittest.TestCase):
    def test_no_network_calls_even_for_domains_and_ipv6(self):
        factory=MagicMock()
        reader=CountryDatabase()
        reader._reader=Mock()
        reader._reader.get.return_value={'country':{'iso_code':'US'}}
        factory.return_value.__enter__.return_value=reader
        results=[]
        worker=CountryResolver([('a',('vpn.example',),('vpn.example',)),('b',('8.8.8.8',),('8.8.8.8',)),('c',('v6',),('2606:4700:4700::1111',))],database_factory=factory)
        worker.resolved.connect(results.append)
        with patch('socket.getaddrinfo',side_effect=AssertionError('DNS forbidden')), patch('socket.socket',side_effect=AssertionError('socket forbidden')), patch('urllib.request.urlopen',side_effect=AssertionError('HTTP forbidden')):
            worker.run()
        self.assertEqual(results[0]['a'][1], '')
        self.assertEqual(results[0]['b'][1], 'US')
        self.assertEqual(results[0]['c'][1], 'US')
        self.assertEqual(reader._reader.get.call_count,2)
        reader.country.cache_clear()

    def test_awg_uses_peers_not_interface_or_routes(self):
        node=Node(scheme='awg',server='8.8.8.8',outbound={'address':['10.0.0.2/32'],'peers':[{'address':'8.8.8.8','allowed_ips':['0.0.0.0/0']}]})
        self.assertEqual(endpoint_hosts(node),('8.8.8.8',))

    def test_old_country_is_discarded_but_manual_choice_is_persisted(self):
        node=Node.from_dict({'country_code':'NL','country_override':'US','is_favorite':True})
        self.assertEqual(node.country_code,'')
        self.assertEqual(node.country_override,'US')
        self.assertNotIn('country_code',node.to_dict())

    def test_late_result_cannot_override_changed_endpoint_or_manual_country(self):
        from xray_fluent.application.node_runtime_service import on_countries_resolved
        node=Node(id='a',server='new.example')
        ctrl=SimpleNamespace(state=SimpleNamespace(nodes=[node]),nodes_changed=Mock())
        on_countries_resolved(ctrl,{'a':(('old.example',),'NL')})
        self.assertEqual(node.country_code,'')
        node.country_override='US'
        on_countries_resolved(ctrl,{'a':(('new.example',),'NL')})
        self.assertEqual(node.country_override,'US')
        ctrl.nodes_changed.emit.assert_not_called()


class GeometryTests(unittest.TestCase):
    def test_secondary_negative_coordinates(self):
        settings=AppSettings(window_x=-1500,window_y=50,window_width=1000,window_height=720)
        rect, minimum=fitted_geometry(settings,[QRect(0,0,1920,1080),QRect(-1920,0,1920,1080)])
        self.assertEqual(rect.x(),-1500)
        self.assertEqual(minimum.width(),860)

    def test_disconnected_screen_and_small_desktop(self):
        rect,minimum=fitted_geometry(AppSettings(window_x=3000,window_y=3000,window_width=3000,window_height=2000),[QRect(0,0,800,500)])
        self.assertEqual(rect,QRect(0,0,800,500))
        self.assertEqual(minimum.width(),800)


class StartupTests(unittest.TestCase):
    def test_slow_preparation_leaves_qt_event_loop_running(self):
        storage=SimpleNamespace(_startup_raw='',load_payload=lambda raw:{},passphrase='',_normalize_state_paths=lambda s:s)
        release = threading.Event()
        observed = []
        worker=StartupWorker(storage,prepare=lambda:observed.append(release.wait(2)))
        loop=QEventLoop();worker.finished.connect(loop.quit)
        with patch('xray_fluent.application.startup_service.TrafficHistoryStorage',return_value=object()):
            QTimer.singleShot(20, release.set)
            worker.start();loop.exec();worker.wait()
        self.assertEqual(observed, [True], "GUI must service the timer while startup is waiting")

    def test_deferred_page_constructs_once_and_replays_latest_snapshot(self):
        class Page(QWidget):
            count=0
            def __init__(self,parent=None):
                super().__init__(parent);Page.count+=1;self.value=None
            def set_values(self,value):self.value=value
        host=DeferredPage(Page,'test');host.set_values(1);host.set_values(2)
        self.assertEqual(Page.count,0)
        page=host.ensure_page();self.assertEqual(page.value,2)
        self.assertIs(host.ensure_page(),page);self.assertEqual(Page.count,1)
        host.deleteLater()


class StartupCancellationTests(unittest.TestCase):
    def test_cancel_before_load_never_saves_default_state(self):
        from xray_fluent.ui.main_window import MainWindow
        controller=Mock()
        window=SimpleNamespace(_startup_loader=Mock(),_state_loaded=False,controller=controller)
        MainWindow._shutdown_controller(window)
        controller.shutdown.assert_not_called()
        controller.save.assert_not_called()
        window._startup_loader.cancel.assert_called_once()

    def test_initialize_is_idempotent(self):
        from xray_fluent.ui.main_window import MainWindow
        MainWindow.initialize(SimpleNamespace(_initialized=True))
