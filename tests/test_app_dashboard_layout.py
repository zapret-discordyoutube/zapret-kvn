"""Dashboard layout tests: wordWrap invariant (AC8) and adaptive grid (AC10).

Keep the ``test_app_*`` prefix: widget test modules must sort before
``tests/test_engine_process_stop.py`` which creates a bare QCoreApplication
at import time (see tests/test_app_nodes_page_view.py).
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
        "A bare QCoreApplication was created before test_app_dashboard_layout "
        "was imported; widget tests need a QApplication."
    )
app = _existing or QApplication([])

from xray_fluent.profiles.models import AppSettings, Node
from xray_fluent.ui.dashboard_page import DashboardPage
from xray_fluent.ui.main_window import MainWindow


def _routing_card_position(page: DashboardPage) -> tuple[int, int, int, int]:
    grid = page._cards_grid
    index = grid.indexOf(page.routing_card)
    assert index >= 0, "routing_card is not in the cards grid"
    return grid.getItemPosition(index)


class DashboardWordWrapTest(unittest.TestCase):
    """AC8: variable-length labels of the connection/routing cards wrap."""

    LABELS = (
        "connection_status_label",
        "connection_target_label",
        "connection_engine_label",
        "connection_ports_label",
        "routing_mode_label",
        "routing_dns_label",
        "routing_rules_label",
        "routing_bypass_label",
    )

    def test_labels_have_word_wrap(self) -> None:
        page = DashboardPage()
        for name in self.LABELS:
            with self.subTest(label=name):
                label = getattr(page, name)
                self.assertTrue(label.wordWrap(), f"{name} must have wordWrap")
        page.deleteLater()
        QApplication.processEvents()

    def test_minimum_size_hint_with_typical_texts(self) -> None:
        # AC9 companion: with the (long) default TUN/proxy explanation texts
        # rendered, the page minimum must still fit the 860px window minimum.
        page = DashboardPage()
        page.set_settings_snapshot(AppSettings())
        page._do_refresh_dashboard()
        self.assertLessEqual(page.minimumSizeHint().width(), 860)
        page.deleteLater()
        QApplication.processEvents()

    def test_selected_server_endpoint_is_masked(self) -> None:
        page = DashboardPage()
        page.set_selected_node(
            Node(name="Server", scheme="vless", server="secret.example", port=443)
        )
        page._do_refresh_dashboard()
        self.assertEqual(page.connection_target_label.text(), "VLESS · ********")
        self.assertEqual(page.server_name_label.text(), "Server")
        for label in (page.connection_target_label, page.server_name_label, page.connection_status_label):
            self.assertNotIn("secret.example", label.text())
        self.assertNotIn("secret.example", page.connection_scene._server_caption)
        page.deleteLater()
        QApplication.processEvents()

    def test_generated_awg_name_does_not_reveal_endpoint_on_dashboard(self):
        page = DashboardPage()
        page.set_selected_node(Node(name="awg-203.0.113.8:443", scheme="awg", server="203.0.113.8", port=443))
        page._do_refresh_dashboard()
        self.assertNotIn("203.0.113.8", page.connection_target_label.text())
        self.assertNotIn("203.0.113.8", page.server_name_label.text())
        self.assertNotIn("203.0.113.8", page.connection_scene._server_caption)
        page.deleteLater()
        QApplication.processEvents()

    def test_connected_proxy_shows_effective_ports_and_mixed_compatibility(self) -> None:
        page = DashboardPage()
        settings = AppSettings(tun_mode=False, proxy_engine="singbox")
        page.set_settings_snapshot(settings)
        page.set_proxy_ports(1392, 1393)
        page.set_connection(True)
        page._do_refresh_dashboard()

        self.assertFalse(page.connection_ports_label.isHidden())
        self.assertEqual(
            page.connection_ports_label.text(),
            "Mixed (SOCKS5 + HTTP): 127.0.0.1:1392  ·  HTTP: 127.0.0.1:1393",
        )

        page.set_tun_mode(True)
        page._do_refresh_dashboard()
        self.assertTrue(page.connection_ports_label.isHidden())
        page.deleteLater()
        QApplication.processEvents()


class DashboardAdaptiveGridTest(unittest.TestCase):
    """AC10: routing card moves to row 1 below 900px, back at >= 900px;
    the four traffic tiles fold into a 2×2 grid on the narrow layout."""

    def test_routing_card_reflows_on_resize(self) -> None:
        page = DashboardPage()
        try:
            page.resize(850, 600)
            page.show()
            QApplication.processEvents()
            row, col, _rspan, cspan = _routing_card_position(page)
            self.assertEqual((row, col), (1, 0), "narrow: routing card in second row")
            self.assertEqual(cspan, 2, "narrow: routing card spans both columns")
            stats = page._stats_grid
            self.assertEqual(stats.getItemPosition(stats.indexOf(page.session_tile))[:2], (1, 1))

            page.resize(1200, 700)
            QApplication.processEvents()
            row, col, _rspan, cspan = _routing_card_position(page)
            self.assertEqual((row, col), (0, 1), "wide: routing card back in first row")
            self.assertEqual(cspan, 1)

            self.assertEqual(stats.getItemPosition(stats.indexOf(page.session_tile))[:2], (0, 3))

            # Reflow must not recreate widgets: same processes card position.
            grid = page._cards_grid
            conn_row, conn_col, _r, _c = grid.getItemPosition(
                grid.indexOf(page.processes_card)
            )
            self.assertEqual((conn_row, conn_col), (0, 0))
        finally:
            page.hide()
            page.deleteLater()
            QApplication.processEvents()

    def test_resize_around_threshold_is_stable(self) -> None:
        page = DashboardPage()
        try:
            page.resize(1000, 700)
            page.show()
            QApplication.processEvents()
            self.assertEqual(_routing_card_position(page)[:2], (0, 1))

            for width, expected in ((899, (1, 0)), (900, (0, 1)), (850, (1, 0)), (1200, (0, 1))):
                page.resize(width, 700)
                QApplication.processEvents()
                self.assertEqual(
                    _routing_card_position(page)[:2], expected, f"width={width}"
                )
        finally:
            page.hide()
            page.deleteLater()
            QApplication.processEvents()


class DashboardEffectivePortsWiringTest(unittest.TestCase):
    def test_connection_event_forwards_active_session_ports(self) -> None:
        dashboard = Mock()
        controller = Mock()
        controller.state.settings.tun_mode = False
        controller.get_effective_proxy_ports.return_value = (1392, 1393)
        window = SimpleNamespace(
            dashboard_page=dashboard,
            controller=controller,
            tray_connect_action=None,
            _deferred_dashboard_metrics=None,
            _deferred_process_stats=None,
            _has_deferred_process_stats=False,
            _refresh_tray_tooltip=Mock(),
        )

        MainWindow._on_connection_changed(window, True)

        dashboard.set_connection.assert_called_once_with(True)
        dashboard.set_proxy_ports.assert_called_once_with(1392, 1393)

    def test_tun_connection_never_advertises_proxy_ports(self) -> None:
        dashboard = Mock()
        controller = Mock()
        controller.state.settings.tun_mode = True
        window = SimpleNamespace(
            dashboard_page=dashboard,
            controller=controller,
            tray_connect_action=None,
            _deferred_dashboard_metrics=None,
            _deferred_process_stats=None,
            _has_deferred_process_stats=False,
            _refresh_tray_tooltip=Mock(),
        )

        MainWindow._on_connection_changed(window, True)

        dashboard.set_proxy_ports.assert_called_once_with(0, 0)
        controller.get_effective_proxy_ports.assert_not_called()


class DashboardDensityTests(unittest.TestCase):
    """Графика панели плавно следует окну, текст — только две плотности."""

    def test_hero_scales_smoothly_within_bounds(self) -> None:
        from xray_fluent.ui.dashboard_page import hero_sizes

        sizes = [hero_sizes(h) for h in range(300, 1600, 50)]
        orbs = [orb for orb, _pad, _graph in sizes]
        self.assertEqual(orbs, sorted(orbs))  # монотонно растёт с окном
        self.assertGreaterEqual(min(orbs), 96)
        self.assertLessEqual(max(orbs), 156)
        mid = hero_sizes(700)[0]
        self.assertTrue(96 < mid < 156)  # между пределами — плавно, не ступенькой

    def test_page_applies_sizes_and_keeps_orb_inside_scene(self) -> None:
        from xray_fluent.ui.dashboard_page import DashboardPage, hero_sizes

        page = DashboardPage()
        for height in (480, 700, 1100):
            page._apply_hero_size(height)
            orb, padding, graph = hero_sizes(height)
            self.assertEqual(page.connection_orb.width(), orb)
            self.assertEqual(page.connection_scene.height(), orb + padding)
            self.assertEqual(page.traffic_graph.height(), graph)
        page._apply_density(True)
        page._apply_density(False)
        # Страницу не удаляем: пакетный deleteLater страниц на Windows падает
        # (см. память ui-theme-architecture) — держим до конца процесса.
        _KEEP_ALIVE.append(page)


_KEEP_ALIVE: list = []


if __name__ == "__main__":
    unittest.main()
