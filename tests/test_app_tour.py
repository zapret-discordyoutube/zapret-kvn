"""Обучающая экскурсия: шаги, размещение карточки и поведение оверлея.

Keep the ``test_app_*`` prefix (QApplication before tests/test_engine_process_stop.py).
"""

from __future__ import annotations

import os
import re
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6 import sip
from PyQt6.QtCore import QEvent, QEventLoop, QPoint, QRect, QSize, Qt, QTimer
from PyQt6.QtGui import QKeyEvent
from PyQt6.QtWidgets import QApplication, QPushButton, QScrollArea, QVBoxLayout, QWidget

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError("widget tests need a QApplication")
app = _existing or QApplication([])

from dataclasses import fields

from xray_fluent.profiles.models import AppSettings
from xray_fluent.ui.tour import TOUR_STEPS, TourOverlay, TourStep, active_tour
from xray_fluent.ui.tour.overlay import (
    CARD_GAP,
    CARD_MARGIN,
    PULSE_CYCLES,
    PULSE_PERIOD_MS,
    place_card,
)
from xray_fluent.ui.tour.steps import on_page

UI_DIR = Path(__file__).resolve().parents[1] / "xray_fluent" / "ui"

#: Где объявлен первый атрибут пути ``on_page`` для каждой страницы.
PAGE_SOURCES = {
    "dashboard_page": "dashboard_page.py",
    "nodes_page": "nodes_page.py",
    "subscriptions_page": "subscriptions_page.py",
    "configs_page": "configs_page.py",
    "zapret_page": "zapret_page.py",
    "logs_page": "logs_page.py",
    "settings_page": "settings_page.py",
    "updates_page": "updates_page.py",
    "about_page": "about_page.py",
}


def _spin(ms: int) -> None:
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def _key(overlay: TourOverlay, key: Qt.Key) -> None:
    overlay.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, key, Qt.KeyboardModifier.NoModifier))


class StepsTests(unittest.TestCase):
    def test_keys_are_unique_and_texts_filled(self) -> None:
        keys = [step.key for step in TOUR_STEPS]
        self.assertEqual(len(keys), len(set(keys)))
        for step in TOUR_STEPS:
            self.assertTrue(step.title.strip(), step.key)
            self.assertGreater(len(step.body), 60, step.key)

    def test_tour_starts_with_intro_and_ends_on_restart_item(self) -> None:
        self.assertTrue(TOUR_STEPS[0].hero)
        last = TOUR_STEPS[-1]
        self.assertIsNotNone(last.target)
        self.assertEqual(last.target.__closure__[0].cell_contents, ("tour",))

    def test_restart_item_is_registered_in_navigation(self) -> None:
        """Повторный запуск — пункт «Обучение» в меню, а не спрятанная кнопка."""
        source = (UI_DIR / "main_window.py").read_text(encoding="utf-8")
        block = source[source.index('routeKey="tour"'):]
        block = block[: block.index(")\n")]
        self.assertIn("selectable=False", block)
        self.assertIn("NavigationItemPosition.BOTTOM", block)
        # clicked(bool) не должен попасть в automatic: лямбда отбрасывает аргумент.
        self.assertIn("onClick=lambda *_args: self._on_tour_nav_clicked()", block)

    def test_menu_item_collapses_overlay_menu_before_tour(self) -> None:
        from types import SimpleNamespace
        from unittest.mock import Mock

        from qfluentwidgets import NavigationDisplayMode

        MainWindow = _main_window_class()
        for mode, collapsed in ((NavigationDisplayMode.MENU, 1), (NavigationDisplayMode.EXPAND, 0)):
            panel = SimpleNamespace(displayMode=mode, collapse=Mock())
            window = SimpleNamespace(navigationInterface=SimpleNamespace(panel=panel), _start_tour=Mock())
            MainWindow._on_tour_nav_clicked(window)
            self.assertEqual(panel.collapse.call_count, collapsed, mode)
            window._start_tour.assert_called_once_with()

    def test_pages_are_main_window_pages(self) -> None:
        source = (UI_DIR / "main_window.py").read_text(encoding="utf-8")
        for step in TOUR_STEPS:
            if step.page is None:
                continue
            self.assertIn(step.page, PAGE_SOURCES, step.key)
            self.assertRegex(source, rf"self\.{step.page} = ", step.key)

    def test_routing_sections_exist(self) -> None:
        from xray_fluent.ui.configs_page import SECTIONS

        known = {key for key, _title, _icon in SECTIONS}
        for step in TOUR_STEPS:
            if step.section is not None:
                self.assertEqual(step.page, "configs_page", step.key)
                self.assertIn(step.section, known, step.key)

    def test_page_anchors_exist_in_page_source(self) -> None:
        """Переименовали кнопку на странице — шаг не должен молча потерять подсветку."""
        sources = {name: (UI_DIR / file).read_text(encoding="utf-8") for name, file in PAGE_SOURCES.items()}
        sections = (UI_DIR / "singbox" / "sections.py").read_text(encoding="utf-8")
        lists = (UI_DIR / "singbox" / "lists.py").read_text(encoding="utf-8")
        checked = 0
        for step in TOUR_STEPS:
            if step.target is None or step.target.__closure__ is None:
                continue
            cells = [cell.cell_contents for cell in step.target.__closure__]
            page = next((c for c in cells if isinstance(c, str)), None)
            paths = next((c for c in cells if isinstance(c, tuple)), ())
            if page not in sources:
                continue  # nav_item: проверяется маршрутами ниже
            for path in paths:
                first = path.split(".")[0]
                self.assertRegex(sources[page], rf"self\.{re.escape(first)}\b[^=\n]*=", f"{step.key}: {path}")
                checked += 1
        self.assertGreater(checked, 15)
        # Вложенные звенья маршрутизации живут в других файлах.
        self.assertRegex(sections, r"self\.check_row = ")
        self.assertRegex(sections, r"self\.rules = ")
        self.assertRegex(lists, r"self\.add_button = ")

    def test_nav_routes_match_page_object_names(self) -> None:
        source = (UI_DIR / "main_window.py").read_text(encoding="utf-8")
        for route in ("subscriptions", "configs", "zapret", "updates"):
            self.assertRegex(source, rf'DeferredPage\(\w+, "{route}", self\)')

    def test_on_page_walks_attributes_and_dict_keys(self) -> None:
        window = QWidget()
        page = QWidget(window)
        page.button = QPushButton(page)
        page.rows = {"tcp": QPushButton(page)}
        window.some_page = page
        found = on_page("some_page", "button", "rows.tcp", "rows.missing", "nope.deeper")(window)
        self.assertEqual(found, [page.button, page.rows["tcp"]])


class SettingsTests(unittest.TestCase):
    def test_banner_flag_round_trips_and_defaults_to_false(self) -> None:
        self.assertFalse(AppSettings.from_dict({}).tour_banner_closed)
        # Старый флаг v0.8.10 ставился при показе, без действия пользователя, —
        # он не должен прятать плашку.
        self.assertFalse(AppSettings.from_dict({"tour_seen": True}).tour_banner_closed)
        settings = AppSettings()
        settings.tour_banner_closed = True
        self.assertTrue(AppSettings.from_dict(settings.to_dict()).tour_banner_closed)

    def test_settings_page_cannot_roll_the_flag_back(self) -> None:
        source = (UI_DIR / "main_window.py").read_text(encoding="utf-8")
        block = source[source.index("_WINDOW_OWNED_SETTINGS = tuple("):]
        self.assertIn('"tour_banner_closed"', block[: block.index(")\n\n")])
        self.assertIn("tour_banner_closed", {item.name for item in fields(AppSettings)})


class PlaceCardTests(unittest.TestCase):
    BOUNDS = QRect(16, 16, 968, 640)
    SIZE = QSize(440, 300)

    def test_centres_without_target(self) -> None:
        rect = place_card(self.BOUNDS, None, self.SIZE)
        self.assertEqual(rect.center(), self.BOUNDS.center())

    def test_prefers_right_of_target(self) -> None:
        hole = QRect(40, 100, 200, 60)
        rect = place_card(self.BOUNDS, hole, self.SIZE)
        self.assertEqual(rect.left(), hole.right() + 1 + CARD_GAP)
        self.assertFalse(rect.intersects(hole))

    def test_goes_below_when_right_does_not_fit(self) -> None:
        hole = QRect(700, 40, 260, 60)
        rect = place_card(self.BOUNDS, hole, self.SIZE)
        self.assertGreater(rect.top(), hole.bottom())
        self.assertTrue(self.BOUNDS.contains(rect))

    def test_goes_left_of_target_in_bottom_right_corner(self) -> None:
        hole = QRect(700, 420, 260, 200)
        rect = place_card(self.BOUNDS, hole, self.SIZE)
        self.assertFalse(rect.intersects(hole))
        self.assertTrue(self.BOUNDS.contains(rect))

    def test_huge_target_keeps_card_inside_window(self) -> None:
        hole = QRect(20, 20, 960, 630)
        rect = place_card(self.BOUNDS, hole, self.SIZE)
        self.assertTrue(self.BOUNDS.contains(rect))

    def test_card_larger_than_window_is_shrunk(self) -> None:
        bounds = QRect(16, 16, 300, 200)
        rect = place_card(bounds, None, self.SIZE)
        self.assertTrue(bounds.contains(rect))


class _FakeWindow(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.resize(900, 600)
        self.opened: list[str] = []
        layout = QVBoxLayout(self)
        self.first = QPushButton("first", self)
        self.area = QScrollArea(self)
        self.area.setWidgetResizable(True)
        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.addSpacing(2000)
        self.deep = QPushButton("deep", body)
        body_layout.addWidget(self.deep)
        self.area.setWidget(body)
        self.hidden = QPushButton("hidden", self)
        self.hidden.hide()
        layout.addWidget(self.first)
        layout.addWidget(self.area)


def _steps() -> tuple[TourStep, ...]:
    return (
        TourStep("intro", "Вступление", "Текст вступления", hero=True),
        TourStep("first", "Первая", "Текст первой", page="a", target=lambda w: [w.first]),
        TourStep("deep", "Глубокая", "Текст глубокой", page="b", target=lambda w: [w.deep]),
        TourStep("hidden", "Скрытая", "Текст скрытой", target=lambda w: [w.hidden]),
        TourStep("broken", "Сломанная", "Текст сломанной", target=lambda w: [w.no_such_widget]),
    )


class OverlayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.window = _FakeWindow()
        self.window.show()
        app.processEvents()
        self.reasons: list[str] = []
        self.overlay = TourOverlay(self.window, _steps())
        self.overlay.step_opening.connect(lambda step: self.window.opened.append(step.key))
        self.overlay.finished.connect(self.reasons.append)
        self.overlay.start()
        _spin(30)

    def tearDown(self) -> None:
        if not sip.isdeleted(self.overlay):
            self.overlay.finish("interrupted")
        _spin(10)
        self.window.hide()
        self.window.deleteLater()
        app.processEvents()

    def _settle(self) -> None:
        _spin(700)

    def test_covers_window_and_shows_intro_without_spotlight(self) -> None:
        self.assertEqual(self.overlay.geometry(), self.window.rect())
        self.assertIs(active_tour(self.window), self.overlay)
        self.assertIsNone(self.overlay._hole)
        self.assertEqual(self.overlay.card.title_label.text(), "Вступление")
        self.assertEqual(self.overlay.card.counter_label.text(), "Шаг 1 из 5")
        self.assertEqual(self.overlay.card.next_btn.text(), "Начнём")
        self.assertFalse(self.overlay.card.back_btn.isVisibleTo(self.overlay.card))
        self._settle()
        self.assertEqual(self.overlay.card.geometry().center(), self.overlay.rect().center())

    def test_step_opens_its_page_and_spotlights_target(self) -> None:
        self.overlay.go_next()
        self._settle()
        self.assertEqual(self.window.opened, ["intro", "first"])
        hole = self.overlay._hole.toRect()
        target = QRect(self.overlay.mapFromGlobal(self.window.first.mapToGlobal(self.window.first.rect().topLeft())), self.window.first.size())
        self.assertTrue(hole.contains(target))
        self.assertLessEqual(hole.width(), target.width() + 20)
        card = self.overlay.card.geometry()
        self.assertFalse(card.intersects(hole))
        inner = self.overlay.rect().adjusted(CARD_MARGIN, CARD_MARGIN, -CARD_MARGIN, -CARD_MARGIN)
        self.assertTrue(inner.contains(card))

    def test_scrolls_to_target_below_the_fold(self) -> None:
        self.overlay.go_next()
        self.overlay.go_next()
        self._settle()
        self.assertGreater(self.window.area.verticalScrollBar().value(), 0)
        self.assertIsNotNone(self.overlay._hole)

    def test_spotlight_follows_window_resize(self) -> None:
        self.overlay.go_next()
        self._settle()
        before = self.overlay._hole.toRect()
        self.window.resize(1200, 700)
        self._settle()
        self.assertEqual(self.overlay.geometry(), self.window.rect())
        self.assertGreater(self.overlay._hole.toRect().width(), before.width())

    def test_hidden_or_broken_target_falls_back_to_centred_card(self) -> None:
        for _ in range(3):
            self.overlay.go_next()
        self._settle()
        self.assertEqual(self.overlay.step.key, "hidden")
        self.assertIsNone(self.overlay._hole)
        with self.assertLogs("xray_fluent.ui.tour.overlay", level="ERROR") as logs:
            self.overlay.go_next()
            self._settle()
        self.assertEqual(len(logs.records), 1)  # не на каждом кадре
        self.assertIsNone(self.overlay._hole)
        self.assertEqual(self.overlay.card.counter_label.text(), "Шаг 5 из 5")

    def test_keyboard_navigation_and_finish(self) -> None:
        _key(self.overlay, Qt.Key.Key_Right)
        self.assertEqual(self.overlay.index, 1)
        _key(self.overlay, Qt.Key.Key_Left)
        self.assertEqual(self.overlay.index, 0)
        _key(self.overlay, Qt.Key.Key_Left)
        self.assertEqual(self.overlay.index, 0)
        with self.assertLogs("xray_fluent.ui.tour.overlay", level="ERROR"):
            for _ in range(4):
                _key(self.overlay, Qt.Key.Key_Return)
        self.assertEqual(self.overlay.card.next_btn.text(), "Готово")
        self.assertFalse(self.overlay.card.skip_btn.isVisibleTo(self.overlay.card))
        _key(self.overlay, Qt.Key.Key_Return)
        self.assertEqual(self.reasons, ["done"])
        _spin(20)
        self.assertIsNone(active_tour(self.window))

    def test_escape_skips_once(self) -> None:
        _key(self.overlay, Qt.Key.Key_Escape)
        self.overlay.go_next()
        self.overlay.finish("done")
        self.assertEqual(self.reasons, ["skipped"])

    def test_hiding_window_ends_tour(self) -> None:
        self.window.hide()
        _spin(200)
        self.assertEqual(self.reasons, ["hidden"])

    def test_idle_tour_does_not_repaint(self) -> None:
        self.overlay.go_next()
        _spin(int(PULSE_CYCLES * PULSE_PERIOD_MS) + 900)  # кольцо отыграло и замерло
        paints = 0
        original = self.overlay.paintEvent

        def counting(event) -> None:
            nonlocal paints
            paints += 1
            original(event)

        self.overlay.paintEvent = counting
        _spin(400)
        self.assertEqual(paints, 0)

    def test_card_takes_final_size_at_once_so_text_is_not_rewrapped(self) -> None:
        """Карточка едет, но не растягивается: иначе текст «плывёт» на каждом кадре."""
        self._settle()
        self.overlay.go_next()
        sizes = set()
        for _ in range(12):
            sizes.add((self.overlay.card.width(), self.overlay.card.height()))
            _spin(20)
        self.assertEqual(len(sizes), 1, sizes)
        self._settle()
        self.assertIn((self.overlay.card.width(), self.overlay.card.height()), sizes)

    def test_step_change_repaints_only_changed_areas(self) -> None:
        """Полная перерисовка оверлея перерисовывает всю страницу под ним — это и есть лаги."""
        self._settle()  # затемнение проявилось — дальше полных перерисовок быть не должно
        # Точка в стороне и от подсветки (вверху окна), и от карточки (по центру и слева).
        untouched = QPoint(self.overlay.width() - 6, self.overlay.height() // 2)
        hits: list[bool] = []
        original = self.overlay.paintEvent

        def recording(event) -> None:
            hits.append(event.region().contains(untouched))
            original(event)

        self.overlay.paintEvent = recording
        self.overlay.go_next()
        self._settle()
        self.assertGreater(len(hits), 3)
        self.assertFalse(any(hits))

    def test_content_fades_in_and_effect_is_off_at_rest(self) -> None:
        self._settle()
        self.overlay.go_next()
        _spin(40)
        self.assertTrue(self.overlay.card.content_effect.isEnabled())
        self._settle()
        self.assertFalse(self.overlay.card.content_effect.isEnabled())

    def test_announces_next_step_for_prewarming(self) -> None:
        upcoming: list[str] = []
        self.overlay.step_upcoming.connect(lambda step: upcoming.append(step.key))
        self._settle()
        self.assertEqual(upcoming, ["first"])

    def test_dim_fades_out_after_finish(self) -> None:
        self._settle()
        self.overlay.skip()
        self.assertEqual(self.reasons, ["skipped"])
        self.assertIsNone(active_tour(self.window))
        self.assertFalse(self.overlay.card.isVisible())
        self.assertTrue(self.overlay.isVisible())
        _spin(400)
        self.assertTrue(sip.isdeleted(self.overlay) or not self.overlay.isVisible())

    def test_overlay_holds_no_strong_reference_to_window(self) -> None:
        for value in vars(self.overlay).values():
            self.assertIsNot(value, self.window)


def _main_window_class():
    import ctypes
    import sys
    from types import SimpleNamespace

    if sys.platform == "win32":
        from xray_fluent.ui.main_window import MainWindow
        return MainWindow

    class _FakeWindll:
        def __getattr__(self, name):
            library = SimpleNamespace()
            setattr(self, name, library)
            return library

    original = getattr(ctypes, "windll", None)
    ctypes.windll = _FakeWindll()
    try:
        from xray_fluent.ui.main_window import MainWindow
    finally:
        if original is None:
            del ctypes.windll
        else:
            ctypes.windll = original
    return MainWindow


class TourBannerTests(unittest.TestCase):
    """Плашка внизу окна: экскурсия стартует только по кнопке."""

    def setUp(self) -> None:
        from types import SimpleNamespace
        from unittest.mock import Mock

        MainWindow = _main_window_class()
        names = (
            "_start_tour", "_open_tour_step", "_prewarm_tour_step", "_on_tour_finished", "_set_tour_banner_closed",
            "_schedule_tour_banner", "_try_show_tour_banner", "_show_tour_banner",
            "_on_tour_banner_closed", "_close_tour_banner",
        )
        host_cls = type("Host", (QWidget,), {name: getattr(MainWindow, name) for name in names})
        self.window = host_cls()
        self.window.resize(900, 600)
        self.window._quitting = False
        self.window._geometry_persistence_ready = True
        self.window._tour_automatic = False
        self.window._tour_banner = None
        self.window._tour_banner_tries = 0
        self.window._tour_banner_timer = QTimer(self.window)
        self.window._tour_banner_timer.setSingleShot(True)
        self.window._tour_banner_timer.timeout.connect(self.window._try_show_tour_banner)
        self.window.controller = SimpleNamespace(
            state=SimpleNamespace(settings=AppSettings()), locked=False, schedule_save=Mock()
        )
        self.window.switchTo = Mock()
        self.window.stackedWidget = Mock()
        self.window.stackedWidget.isAnimationEnabled.return_value = True
        self.window.dashboard_page = QWidget(self.window)
        self.window.show()

    def tearDown(self) -> None:
        tour = active_tour(self.window)
        if tour is not None:
            tour.finish("skipped")
        self.window.hide()
        self.window.deleteLater()
        _spin(10)

    @property
    def settings(self) -> AppSettings:
        return self.window.controller.state.settings

    def _show_banner(self):
        self.window._try_show_tour_banner()
        banner = self.window._tour_banner
        self.assertIsNotNone(banner)
        return banner

    def test_banner_does_not_start_tour_or_set_flag(self) -> None:
        self._show_banner()
        self.assertIsNone(active_tour(self.window))
        self.assertFalse(self.settings.tour_banner_closed)
        # Повторный вызов (showEvent + controls-ready) не плодит вторую плашку.
        banner = self.window._tour_banner
        self.window._try_show_tour_banner()
        self.window._schedule_tour_banner()
        self.assertIs(self.window._tour_banner, banner)
        self.assertFalse(self.window._tour_banner_timer.isActive())

    def test_start_button_closes_banner_and_starts_tour(self) -> None:
        from qfluentwidgets import PrimaryPushButton

        banner = self._show_banner()
        banner.findChild(PrimaryPushButton).click()
        self.assertIsNone(self.window._tour_banner)
        self.assertIsNotNone(active_tour(self.window))
        self.assertTrue(self.window._tour_automatic)
        self.assertTrue(self.settings.tour_banner_closed)

    def test_close_button_hides_banner_for_good(self) -> None:
        banner = self._show_banner()
        banner.closeButton.click()
        _spin(10)
        self.assertIsNone(self.window._tour_banner)
        self.assertIsNone(active_tour(self.window))
        self.assertTrue(self.settings.tour_banner_closed)
        self.window._schedule_tour_banner()
        self.assertFalse(self.window._tour_banner_timer.isActive())

    def test_interrupted_banner_tour_offers_banner_again(self) -> None:
        from qfluentwidgets import PrimaryPushButton

        self._show_banner().findChild(PrimaryPushButton).click()
        active_tour(self.window).finish("interrupted")
        self.assertFalse(self.settings.tour_banner_closed)

    def test_menu_tour_is_not_automatic(self) -> None:
        self.settings.tour_banner_closed = True
        self.window._start_tour()
        self.assertFalse(self.window._tour_automatic)
        active_tour(self.window).finish("interrupted")
        self.assertTrue(self.settings.tour_banner_closed)

    def test_busy_window_postpones_banner(self) -> None:
        self.window.controller.locked = True
        self.window._try_show_tour_banner()
        self.assertIsNone(self.window._tour_banner)
        self.assertTrue(self.window._tour_banner_timer.isActive())


class RealStepsFitTests(unittest.TestCase):
    def test_every_card_fits_the_minimum_window(self) -> None:
        """Самый длинный текст должен помещаться в окно 860×560 под заголовком."""
        window = QWidget()
        window.resize(860, 560 - 48)
        window.show()
        overlay = TourOverlay(window, TOUR_STEPS)
        try:
            available = window.height() - 2 * CARD_MARGIN
            for index, step in enumerate(TOUR_STEPS):
                overlay.card.set_step(step, index, len(TOUR_STEPS))
                width = 560 if step.hero else 440
                self.assertLessEqual(overlay.card.height_for(width), available, step.key)
        finally:
            overlay.finish("interrupted")
            _spin(10)
            window.hide()
            window.deleteLater()


if __name__ == "__main__":
    unittest.main()
