"""Боковое меню на низком окне: пункты прокручиваются, а не наезжают друг на друга.

Верхняя область панели qfluentwidgets (NavigationItemPosition.TOP) не
прокручивается: раскрытая «Маршрутизация» с подпунктами сжимала её, и пункты
фиксированной высоты рисовались поверх соседних. Основные пункты живут в
прокручиваемой области (SCROLL).
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import unittest

from PyQt6.QtCore import QEventLoop, QPoint, QTimer
from PyQt6.QtWidgets import QApplication, QWidget

_app = QApplication.instance() or QApplication([])

from qfluentwidgets import FluentWindow  # noqa: E402
from qfluentwidgets.components.navigation.navigation_widget import NavigationTreeWidget  # noqa: E402

from xray_fluent.ui.main_window import MainWindow  # noqa: E402

_PAGES = (
    "dashboard_page", "nodes_page", "subscriptions_page", "zapret_page", "logs_page",
    "history_page", "about_page", "updates_page", "settings_page",
)
#: Окно общее на процесс и не уничтожается: удаление виджетов посреди прогона
#: роняет Windows-тесты (см. test_app_detail_pages).
_shared: dict[str, FluentWindow] = {}


def _settle(ms: int = 250) -> None:
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def _window() -> FluentWindow:
    if "window" not in _shared:
        window = FluentWindow()
        for name in _PAGES:
            page = QWidget()
            page.setObjectName(name)
            setattr(window, name, page)
        window.configs_page = QWidget()
        window.configs_page.setObjectName("configs")
        window._on_nav_menu_clicked = lambda *_args: None
        window._reveal_nav_item = lambda item: MainWindow._reveal_nav_item(window, item)
        MainWindow._create_navigation(window)
        window.navigationInterface.setMinimumExpandWidth(100)
        _shared["window"] = window
    return _shared["window"]


def _visible_spans(panel) -> list[tuple[int, int, str]]:
    """Видимые полосы пунктов в координатах панели (прокрученные — по окну прокрутки)."""
    view = panel.scrollArea.viewport()
    view_top = view.mapTo(panel, QPoint(0, 0)).y()
    spans = []
    for item in panel.items.values():
        widget = item.widget
        if not widget.isVisible():
            continue
        target = widget.itemWidget if isinstance(widget, NavigationTreeWidget) else widget
        top = target.mapTo(panel, QPoint(0, 0)).y()
        bottom = top + target.height()
        if view.isAncestorOf(target):
            top, bottom = max(top, view_top), min(bottom, view_top + view.height())
            if bottom <= top:
                continue
        spans.append((top, bottom, item.routeKey))
    return sorted(spans)


class NavigationLayoutTests(unittest.TestCase):
    def test_main_items_live_in_the_scroll_area(self) -> None:
        panel = _window().navigationInterface.panel
        for name in ("dashboard_page", "configs", "history_page"):
            self.assertTrue(panel.scrollWidget.isAncestorOf(panel.widget(name)), name)
        self.assertFalse(panel.scrollWidget.isAncestorOf(panel.widget("settings_page")))

    def test_expanded_routing_never_overlaps_on_a_short_window(self) -> None:
        window = _window()
        panel = window.navigationInterface.panel
        routing = panel.widget("configs")
        window.show()
        try:
            for height in (400, 560, 900):
                window.resize(900, height)
                panel.expand(useAni=False)
                routing.setExpanded(True, ani=True)
                _settle()
                spans = _visible_spans(panel)
                overlaps = [(a[2], b[2]) for a, b in zip(spans, spans[1:]) if b[0] < a[1]]
                self.assertEqual(overlaps, [], height)
                # Раскрытый пункт докручен в видимую область.
                view = panel.scrollArea.viewport()
                header_top = routing.itemWidget.mapTo(view, QPoint(0, 0)).y()
                self.assertGreaterEqual(header_top, 0, height)
                last = routing.treeChildren[-1]
                last_bottom = last.mapTo(view, QPoint(0, 0)).y() + last.height()
                # Подпункты видны целиком, либо их больше окна — тогда пункт у верхнего края.
                self.assertTrue(last_bottom <= view.height() or header_top == 0, (height, header_top, last_bottom))
                routing.setExpanded(False)
                _settle(50)
        finally:
            window.hide()


if __name__ == "__main__":
    unittest.main()
