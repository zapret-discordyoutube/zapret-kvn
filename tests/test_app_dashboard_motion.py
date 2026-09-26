"""Главная панель: бюджет CPU анимаций, плитки режима, приложения, боковое меню.

Keep the ``test_app_*`` prefix: widget test modules must sort before
``tests/test_engine_process_stop.py`` which creates a bare QCoreApplication
at import time (see tests/test_app_nodes_page_view.py).

Общая страница создаётся один раз на модуль и не уничтожается (см.
предупреждение про крэш Windows в tests/test_app_scrollable_page.py);
единственное исключение — LifecycleTest, который проверяет именно
синхронное разрушение одной страницы.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError(
        "A bare QCoreApplication was created before test_app_dashboard_motion "
        "was imported; widget tests need a QApplication."
    )
app = _existing or QApplication([])

from qfluentwidgets import NavigationDisplayMode

from xray_fluent.profiles.models import AppSettings, Node
from xray_fluent.ui.connection_orb import CONNECTED, CONNECTING, ERROR, IDLE
from xray_fluent.ui.dashboard_page import DashboardPage
from xray_fluent.ui.dashboard_widgets import latency_bars
from xray_fluent.ui.main_window import _WINDOW_OWNED_SETTINGS, MainWindow

_page: DashboardPage | None = None
_nav_window_ref = None


def _shared_page() -> DashboardPage:
    global _page
    if _page is None:
        _page = DashboardPage()
        _page.resize(1200, 900)
    return _page


def _reset(page: DashboardPage) -> None:
    page.set_transition_busy(False)
    page.set_runtime_status("idle", "")
    page.set_connection(False)
    page.set_settings_snapshot(AppSettings(tun_mode=True))
    page._do_refresh_dashboard()


class SceneCpuBudgetTest(unittest.TestCase):
    """Таймер кадров только в подключении/подключено и только пока сцена видна."""

    def setUp(self) -> None:
        self.page = _shared_page()
        _reset(self.page)
        self.page.show()
        QApplication.processEvents()
        self.scene = self.page.connection_scene

    def tearDown(self) -> None:
        self.page.hide()
        _reset(self.page)
        QApplication.processEvents()

    def test_idle_has_no_frame_timers(self) -> None:
        self.assertEqual(self.scene.state(), IDLE)
        self.assertFalse(self.scene.is_animating())
        self.assertFalse(self.page.connection_orb.is_animating())

    def test_connected_animates_and_stops_on_hide(self) -> None:
        self.page.set_connection(True)
        self.page._do_refresh_dashboard()
        self.assertEqual(self.scene.state(), CONNECTED)
        self.assertTrue(self.scene.is_animating())
        self.page.hide()
        QApplication.processEvents()
        self.assertFalse(self.scene.is_animating())
        self.assertFalse(self.page.connection_orb.is_animating())

    def test_connected_without_traffic_rests_and_wakes_on_traffic(self) -> None:
        self.page.set_connection(True)
        self.page._do_refresh_dashboard()
        self.assertTrue(self.scene.is_animating())
        self.scene._burst_started = None
        self.scene.set_traffic(0.0, 0.0)
        self.scene._tick()  # первый тихий кадр запоминает начало покоя
        self.scene._quiet_since -= 10.0
        self.scene._tick()
        self.assertFalse(self.scene.is_animating())
        self.assertTrue(self.scene.is_resting())
        self.page.set_live_metrics(2e6, 1e5, 40)
        self.assertTrue(self.scene.is_animating())

    def test_error_is_static(self) -> None:
        self.page.set_runtime_status("error", "Не удалось запустить sing-box")
        self.page._do_refresh_dashboard()
        self.assertEqual(self.scene.state(), ERROR)
        self.assertFalse(self.scene.is_animating())
        self.assertEqual(self.page.connection_state_label.text(), "Ошибка подключения")
        self.assertFalse(self.page.logs_btn.isHidden())

    def test_starting_runs_probe_animation(self) -> None:
        self.page.set_runtime_status("starting", "Запуск")
        self.page._do_refresh_dashboard()
        self.assertEqual(self.scene.state(), CONNECTING)
        self.assertTrue(self.scene.is_animating())

    def test_frame_dirty_region_skips_orb_centre(self) -> None:
        self.page.set_connection(True)
        self.page._do_refresh_dashboard()
        self.scene._burst_started = None
        self.scene.grab()  # строит кэш и выборку пути
        region = self.scene._dirty_region()
        self.assertFalse(region.contains(self.page.connection_orb.geometry().center()))
        self.assertLess(region.boundingRect().height(), self.scene.height() + 1)


class DashboardHonestStatusTest(unittest.TestCase):
    def setUp(self) -> None:
        self.page = _shared_page()
        _reset(self.page)

    def tearDown(self) -> None:
        _reset(self.page)

    def test_only_tun_is_called_protected(self) -> None:
        cases = (
            (AppSettings(tun_mode=True), "Защищено"),
            (AppSettings(tun_mode=False, enable_system_proxy=True), "Подключено"),
            (AppSettings(tun_mode=False, enable_system_proxy=False), "Прокси запущен"),
        )
        for settings, title in cases:
            with self.subTest(title=title):
                self.page.set_settings_snapshot(settings)
                self.page.set_connection(True)
                self.page._do_refresh_dashboard()
                self.assertEqual(self.page.connection_state_label.text(), title)
                self.page.set_connection(False)

    def test_idle_invites_to_connect(self) -> None:
        self.page._do_refresh_dashboard()
        self.assertEqual(self.page.connection_state_label.text(), "Не подключено")
        self.assertIn("кнопку питания", self.page.connection_status_label.text())


class ModeTilesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.page = _shared_page()
        _reset(self.page)
        self.emitted: list[bool] = []
        self.page.tun_toggled.connect(self.emitted.append)

    def tearDown(self) -> None:
        self.page.tun_toggled.disconnect(self.emitted.append)
        _reset(self.page)

    def test_tiles_follow_settings(self) -> None:
        self.assertTrue(self.page.vpn_tile.isChecked())
        self.assertFalse(self.page.proxy_tile.isChecked())
        self.assertTrue(self.page.proxy_options.isHidden())
        self.page.set_settings_snapshot(AppSettings(tun_mode=False))
        self.page._do_refresh_dashboard()
        self.assertFalse(self.page.vpn_tile.isChecked())
        self.assertTrue(self.page.proxy_tile.isChecked())
        self.assertFalse(self.page.proxy_options.isHidden())

    def test_clicking_other_mode_emits_once_and_current_mode_is_noop(self) -> None:
        self.page.vpn_tile.clicked.emit()
        self.assertEqual(self.emitted, [])
        self.page.proxy_tile.clicked.emit()
        self.assertEqual(self.emitted, [False])

    def test_tiles_disabled_while_busy(self) -> None:
        self.page.set_transition_busy(True)
        self.assertFalse(self.page.vpn_tile.isEnabled())
        self.assertFalse(self.page.proxy_tile.isEnabled())
        self.assertFalse(self.page.toggle_btn.isEnabled())


class ProcessesAndServerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.page = _shared_page()
        _reset(self.page)

    def tearDown(self) -> None:
        _reset(self.page)

    @staticmethod
    def _stat(exe: str, up: int, down: int, proxy: int):
        return SimpleNamespace(
            exe=exe, upload=up, download=down, proxy_bytes=proxy, direct_bytes=up + down - proxy,
            down_speed=0.0, up_speed=0.0, connections=1, total_connections=1, top_host="example.org",
        )

    def test_top_apps_ranked_and_session_total_is_cumulative_proxy_bytes(self) -> None:
        self.page.set_connection(True)
        stats = [
            self._stat("small.exe", 10, 10, 20),
            self._stat("chrome.exe", 1000, 3000, 4000),
            self._stat("game.exe", 500, 500, 0),
        ]
        self.page.set_process_stats(stats)
        self.page._do_refresh_dashboard()
        names = [name for name, _value, _share in self.page.process_bars.items()]
        self.assertEqual(names, ["chrome.exe", "game.exe", "small.exe"])
        self.assertEqual(self.page.process_bars.items()[0][2], 1.0)
        self.assertEqual(self.page.traffic_session_label.text(), self.page._format_bytes(4020))

    def test_unavailable_stats_are_shown_honestly(self) -> None:
        self.page.set_connection(True)
        self.page.set_process_stats(None)
        self.page._do_refresh_dashboard()
        self.assertEqual(self.page.traffic_session_label.text(), "--")
        self.assertIn("недоступна", self.page.process_summary_label.text())
        self.assertEqual(self.page.process_bars.items(), [])

    def test_next_server_needs_more_than_one_node(self) -> None:
        nodes = [Node(name="A", scheme="vless", server="a.example", port=1)]
        self.page.set_nodes(nodes, nodes[0].id)
        self.page._do_refresh_dashboard()
        self.assertFalse(self.page.next_server_btn.isEnabled())
        nodes.append(Node(name="B", scheme="vless", server="b.example", port=1))
        self.page.set_nodes(nodes, nodes[0].id)
        self.page._do_refresh_dashboard()
        self.assertTrue(self.page.next_server_btn.isEnabled())
        self.page.set_nodes([], None)

    def test_signal_bars_scale(self) -> None:
        self.assertEqual([latency_bars(v) for v in (None, 40, 120, 250, 900)], [0, 4, 3, 2, 1])


def _nav_window(mode, expanding: bool, *, width: int = 1400, saved: bool = False):
    panel = SimpleNamespace(
        displayMode=mode,
        expandAni=Mock(property=Mock(return_value=expanding)),
        minimumExpandWidth=1100,
        expand=Mock(),
    )
    settings = AppSettings(nav_expanded=saved)
    controller = Mock()
    controller.state.settings = settings
    window = SimpleNamespace(
        navigationInterface=SimpleNamespace(panel=panel),
        controller=controller,
        _geometry_persistence_ready=True,
        _nav_expanded_pref=saved,
        width=lambda: width,
    )
    window._sync_nav_to_preference = lambda: MainWindow._sync_nav_to_preference(window)
    return window, panel, settings, controller


class NavPreferenceTest(unittest.TestCase):
    def test_click_expand_is_saved(self) -> None:
        window, _panel, settings, controller = _nav_window(NavigationDisplayMode.EXPAND, True)
        MainWindow._on_nav_menu_clicked(window)
        self.assertTrue(settings.nav_expanded)
        controller.schedule_save.assert_called_once()

    def test_click_collapse_is_saved(self) -> None:
        window, _panel, settings, _controller = _nav_window(NavigationDisplayMode.EXPAND, False, saved=True)
        MainWindow._on_nav_menu_clicked(window)
        self.assertFalse(settings.nav_expanded)
        self.assertFalse(window._nav_expanded_pref)

    def test_overlay_menu_is_not_a_preference(self) -> None:
        for expanding in (True, False):
            with self.subTest(expanding=expanding):
                window, _panel, settings, controller = _nav_window(NavigationDisplayMode.MENU, expanding, saved=True)
                MainWindow._on_nav_menu_clicked(window)
                self.assertTrue(settings.nav_expanded)
                controller.schedule_save.assert_not_called()

    def test_restore_expands_only_on_wide_window(self) -> None:
        window, panel, settings, _controller = _nav_window(NavigationDisplayMode.COMPACT, False, saved=True)
        MainWindow._restore_nav_preference(window, settings)
        panel.expand.assert_called_once_with(useAni=False)

        window, panel, settings, _controller = _nav_window(
            NavigationDisplayMode.COMPACT, False, width=1000, saved=True
        )
        MainWindow._restore_nav_preference(window, settings)
        panel.expand.assert_not_called()

    def test_collapsed_preference_never_expands(self) -> None:
        window, panel, settings, _controller = _nav_window(NavigationDisplayMode.COMPACT, False, saved=False)
        MainWindow._restore_nav_preference(window, settings)
        MainWindow._sync_nav_to_preference(window)
        panel.expand.assert_not_called()

    def test_auto_collapse_keeps_preference_and_widening_restores(self) -> None:
        # Библиотека свернула меню на узком окне: клика не было, предпочтение живо.
        window, panel, settings, _controller = _nav_window(
            NavigationDisplayMode.COMPACT, False, width=1000, saved=True
        )
        MainWindow._sync_nav_to_preference(window)
        panel.expand.assert_not_called()
        window.width = lambda: 1300
        MainWindow._sync_nav_to_preference(window)
        panel.expand.assert_called_once_with(useAni=False)
        self.assertTrue(settings.nav_expanded)

    def test_real_navigation_panel_click_order(self) -> None:
        """На настоящей панели qfluentwidgets: toggle() панели срабатывает раньше нашего слота."""
        from PyQt6.QtCore import QEventLoop, QTimer
        from qfluentwidgets import FluentWindow

        global _nav_window_ref
        window = FluentWindow()
        _nav_window_ref = window  # общий на процесс, не уничтожаем (см. докстринг модуля)
        window.resize(1400, 800)
        window.show()
        QApplication.processEvents()
        # Экран может ужать окно (у отключённой сессии Windows ~1036 px):
        # порог развёртывания считаем от фактической ширины, иначе панель
        # уходит во всплывающий режим MENU, который предпочтением не считается.
        window.navigationInterface.setMinimumExpandWidth(max(1, window.width() - 100))
        settings = AppSettings(nav_expanded=False)
        controller = Mock()
        controller.state.settings = settings
        facade = SimpleNamespace(
            navigationInterface=window.navigationInterface,
            controller=controller,
            _geometry_persistence_ready=True,
            _nav_expanded_pref=False,
        )
        button = window.navigationInterface.panel.menuButton
        button.clicked.connect(lambda: MainWindow._on_nav_menu_clicked(facade))

        def settle() -> None:
            loop = QEventLoop()
            QTimer.singleShot(300, loop.quit)
            loop.exec()

        button.click()
        settle()
        self.assertTrue(settings.nav_expanded)
        button.click()
        settle()
        self.assertFalse(settings.nav_expanded)
        window.hide()

    def test_setting_roundtrip(self) -> None:
        self.assertTrue(AppSettings.from_dict(AppSettings(nav_expanded=True).to_dict()).nav_expanded)
        self.assertFalse(AppSettings.from_dict({}).nav_expanded)


class SettingsPageSaveGuardTest(unittest.TestCase):
    def test_window_owned_fields_survive_settings_page_snapshot(self) -> None:
        self.assertIn("nav_expanded", _WINDOW_OWNED_SETTINGS)
        self.assertIn("nodes_column_widths", _WINDOW_OWNED_SETTINGS)
        self.assertIn("window_width", _WINDOW_OWNED_SETTINGS)
        current = AppSettings(nav_expanded=True, window_width=1500, nodes_column_widths={"name": 240})
        controller = Mock()
        controller.state.settings = current
        window = SimpleNamespace(controller=controller)
        stale = AppSettings(nav_expanded=False, window_width=1000, theme="dark")

        MainWindow._on_settings_page_saved(window, stale)

        saved = controller.update_settings.call_args.args[0]
        self.assertTrue(saved.nav_expanded)
        self.assertEqual(saved.window_width, 1500)
        self.assertEqual(saved.nodes_column_widths, {"name": 240})
        self.assertEqual(saved.theme, "dark")
        self.assertIsNot(saved.nodes_column_widths, current.nodes_column_widths)


class LifecycleTest(unittest.TestCase):
    """Нет циклов «C++-владение ↔ __dict__»: окно разрушается сразу, пока жив QApplication."""

    def test_frame_gate_holds_no_strong_reference_to_window(self) -> None:
        import gc
        import weakref

        from PyQt6.QtWidgets import QWidget

        from xray_fluent.ui.motion import FrameGate

        window = QWidget()
        child = QWidget(window)
        gate = FrameGate(child)
        gate.set_interval(40)
        window.show()
        QApplication.processEvents()
        self.assertTrue(gate.is_running())
        destroyed = []
        window.destroyed.connect(lambda *_: destroyed.append(True))
        ref = weakref.ref(window)
        del window, child, gate
        gc.collect()
        self.assertIsNone(ref())
        self.assertEqual(destroyed, [True])

    def test_connected_dashboard_is_freed_without_gc(self) -> None:
        import gc
        import weakref

        page = DashboardPage()
        page.resize(1000, 800)
        page.show()
        page.set_connection(True)
        page._do_refresh_dashboard()
        QApplication.processEvents()
        self.assertTrue(page.connection_scene.is_animating())
        ref = weakref.ref(page)
        gc.disable()
        try:
            del page
            self.assertIsNone(ref(), "dashboard page is kept alive by a reference cycle")
        finally:
            gc.enable()

    def test_dispose_windows_deletes_idle_windows_and_keeps_running_threads(self) -> None:
        import threading

        from PyQt6 import sip
        from PyQt6.QtCore import QThread
        from PyQt6.QtWidgets import QWidget

        from xray_fluent.ui.qt_lifecycle import dispose_windows

        release = threading.Event()

        class _Blocker(QThread):
            def run(self) -> None:
                release.wait(5)

        idle = QWidget()
        busy = QWidget()
        thread = _Blocker(busy)
        thread.start()
        try:
            windows = [idle, busy]
            kept = dispose_windows(windows)
            self.assertTrue(sip.isdeleted(idle))
            self.assertFalse(sip.isdeleted(busy))
            self.assertEqual(kept, [busy])
            self.assertEqual(windows, [busy])
        finally:
            release.set()
            thread.wait(5000)
        dispose_windows(windows)
        self.assertTrue(sip.isdeleted(busy))

    def test_dispose_all_widgets_sweeps_orphan_top_levels(self) -> None:
        from PyQt6 import sip
        from PyQt6.QtWidgets import QMenu, QWidget

        from xray_fluent.ui.qt_lifecycle import dispose_all_widgets

        from unittest.mock import patch

        from xray_fluent.ui import qt_lifecycle

        window = QWidget()
        orphan_menu = QMenu()  # как меню трея без родителя
        # Подменяем список окон верхнего уровня: настоящий снёс бы общие
        # страницы других тестовых модулей в этом процессе.
        fake_app = SimpleNamespace(topLevelWidgets=lambda: [orphan_menu])
        with patch.object(qt_lifecycle.QApplication, "instance", return_value=fake_app):
            dispose_all_widgets([window])
        self.assertTrue(sip.isdeleted(window))
        self.assertTrue(sip.isdeleted(orphan_menu))



class TunnelLoadScaleTest(unittest.TestCase):
    """Огоньки следуют реальной скорости до 1 Гбит/с; полоса меняется только под нагрузкой."""

    def test_level_scale_distinguishes_high_speeds(self) -> None:
        from xray_fluent.ui.dashboard_widgets import ConnectionScene

        level = ConnectionScene._traffic_level
        mbit = 125_000.0
        points = [level(v) for v in (1_000.0, 1_000_000.0, 50 * mbit, 100 * mbit, 500 * mbit, 1000 * mbit)]
        self.assertEqual(points, sorted(points))
        self.assertAlmostEqual(level(1000 * mbit), 1.0, places=3)
        self.assertEqual(level(5000 * mbit), 1.0)  # потолок — 1 Гбит/с
        self.assertGreater(level(500 * mbit) - level(50 * mbit), 0.2)  # 500 и 50 Мбит заметно различаются
        self.assertEqual(level(0), 0.0)

    def test_background_traffic_does_not_thicken_the_tunnel(self) -> None:
        from xray_fluent.ui.dashboard_widgets import ConnectionScene

        scene = ConnectionScene()
        try:
            for bps, expect_load in ((20_000.0, False), (1_000_000.0, False), (60_000_000.0, True)):
                scene._level = ConnectionScene._traffic_level(bps)
                self.assertEqual(scene.load_level() > 0.05, expect_load, bps)
            scene._level = 1.0
            self.assertEqual(scene.load_level(), 1.0)
        finally:
            _KEEP_SCENES.append(scene)


_KEEP_SCENES: list = []


if __name__ == "__main__":
    unittest.main()
