"""«Маршрутизация»: structured and raw editing of the active sing-box JSON.

One container page owns one :class:`SingboxSession` and shows its sub-pages
(overview, rules, rule-sets, DNS, outbounds, system, JSON). The main window's
navigation lists the sub-pages as child items and calls :meth:`show_section`.
The public API towards the main window (signals carrying the JSON text,
``set_document``/``mark_saved``/``is_dirty``…) is unchanged from the former raw
editor, so load/save/apply/reset keep their proven paths.
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QEasingCurve, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QHBoxLayout, QSizePolicy, QVBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    ComboBox,
    FluentIcon as FIF,
    MessageBox,
    PlainTextEdit,
    PopUpAniStackedWidget,
    PrimaryPushButton,
    PushButton,
    StrongBodyLabel,
    SubtitleLabel,
)

from ..singbox_config import catalog
from ..singbox_config.document import differing_sections
from .adaptive_buttons import AdaptiveButtonRow
from .elided_label import ElidedCaptionLabel
from .motion import reduced_motion
from .base_page import BODY_MARGINS, ScrollablePage
from .singbox.sections import (
    DnsSection,
    OutboundsSection,
    RuleSetsSection,
    RulesSection,
    SystemSection,
)
from .singbox.art import JsonArt, KindBadge, PulseDot, RouteMapArt
from .singbox.lists import popup_menu
from .singbox.session import SingboxSession
from .singbox.visuals import PROXY, Visual, rule_outcomes


def _expand_horizontally(widget) -> None:
    """Let the widget stretch horizontally on wide windows (AC9)."""
    policy = widget.sizePolicy()
    policy.setHorizontalPolicy(QSizePolicy.Policy.Expanding)
    widget.setSizePolicy(policy)


#: (key, title, icon) of the sub-pages, in navigation order.
SECTIONS: tuple[tuple[str, str, object], ...] = (
    ("overview", "Обзор", FIF.HOME),
    ("rules", "Правила", FIF.FILTER),
    ("rule_sets", "Наборы правил", FIF.LIBRARY),
    ("dns", "DNS", FIF.GLOBE),
    ("outbounds", "Исходящие", FIF.SEND),
    ("system", "Система", FIF.DEVELOPER_TOOLS),
    ("json", "JSON", FIF.CODE),
)


def _confirm(parent: QWidget, title: str, text: str, confirm: str) -> bool:
    box = MessageBox(title, text, parent.window())
    box.yesButton.setText(confirm)
    box.cancelButton.setText("Отмена")
    return bool(box.exec())


class _OverviewPanel(ScrollablePage):
    """Config/template choice, stock state and status of the session."""

    open_requested = pyqtSignal()
    reset_requested = pyqtSignal()
    config_selected = pyqtSignal(str)
    template_selected = pyqtSignal(str)

    def __init__(self, session: SingboxSession, parent: QWidget | None = None):
        super().__init__(parent)
        self.session = session
        self._selector_updating = False
        self._selected_config_key = ""
        self._selected_template_key = ""
        root = self.body_layout

        title_row = QHBoxLayout()
        title_row.setSpacing(10)
        badge = KindBadge(self.body, size=32)
        badge.set_visual(Visual(FIF.IOT, PROXY), vivid=True)
        title_row.addWidget(badge)
        title_row.addWidget(SubtitleLabel("Маршрутизация sing-box", self.body))
        title_row.addStretch(1)
        root.addLayout(title_row)
        self.route_map = RouteMapArt(self.body)
        root.addWidget(self.route_map)
        intro = CaptionLabel(
            "Все разделы редактируют один native JSON ядра sing-box: маршрутизация и DNS работают "
            "одинаково в TUN и в системном прокси. Обновление приложения ваши правки не перезаписывает: "
            "разделы, которые вы не меняли, сами следуют за новым стоковым шаблоном.",
            self.body,
        )
        intro.setWordWrap(True)
        root.addWidget(intro)

        selectors = QHBoxLayout()
        selectors.setSpacing(8)
        selectors.addWidget(BodyLabel("Конфиг", self.body))
        self.config_combo = ComboBox(self.body)
        self.config_combo.setMinimumWidth(200)
        _expand_horizontally(self.config_combo)
        selectors.addWidget(self.config_combo, 1)
        selectors.addSpacing(12)
        selectors.addWidget(BodyLabel("Шаблон", self.body))
        self.template_combo = ComboBox(self.body)
        self.template_combo.setMinimumWidth(200)
        _expand_horizontally(self.template_combo)
        selectors.addWidget(self.template_combo, 1)
        root.addLayout(selectors)

        self.file_label = CaptionLabel("Файл: --", self.body)
        self.file_label.setWordWrap(True)
        root.addWidget(self.file_label)
        self.template_label = CaptionLabel("Шаблон: --", self.body)
        self.template_label.setWordWrap(True)
        root.addWidget(self.template_label)

        root.addWidget(StrongBodyLabel("Сравнение со стоком", self.body))
        self.stock_label = CaptionLabel("", self.body)
        self.stock_label.setWordWrap(True)
        root.addWidget(self.stock_label)
        stock_row = QHBoxLayout()
        stock_row.setSpacing(8)
        self.reset_section_btn = PushButton(FIF.HISTORY, "Сбросить раздел к стоку…", self.body)
        self.reset_section_btn.clicked.connect(self._show_reset_section_menu)
        self.reset_btn = PushButton(FIF.RETURN, "Сбросить всё к стоку", self.body)
        self.open_btn = PushButton(FIF.FOLDER, "Импорт шаблона", self.body)
        stock_row.addWidget(self.reset_section_btn)
        stock_row.addWidget(self.reset_btn)
        stock_row.addWidget(self.open_btn)
        stock_row.addStretch(1)
        root.addLayout(stock_row)

        root.addWidget(StrongBodyLabel("Статус", self.body))
        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.status_box = PlainTextEdit(self.body)
        self.status_box.setReadOnly(True)
        self.status_box.setFixedHeight(110)
        self.status_box.setFont(font)
        root.addWidget(self.status_box)
        root.addStretch(1)

        self.open_btn.clicked.connect(self._on_open_clicked)
        self.reset_btn.clicked.connect(self._on_reset_clicked)
        self.config_combo.currentIndexChanged.connect(lambda _index: self._on_config_combo_changed())
        self.template_combo.currentIndexChanged.connect(lambda _index: self._on_template_combo_changed())
        session.state_changed.connect(self.refresh_state)
        self.set_template_source(None)
        self.refresh_state()

    # -- state ------------------------------------------------------------------

    def refresh_state(self) -> None:
        if self.session.document is not None:
            self.route_map.set_counts(*rule_outcomes(self.session.document))
        path = self.session.path.as_posix() if self.session.path else "--"
        self.file_label.setText(f"Файл: {path}{' *' if self.session.is_dirty() else ''}")
        if self.session.document is None:
            self.stock_label.setText("Конфиг сейчас не разбирается как JSON — сравнение недоступно.")
            self.reset_section_btn.setEnabled(False)
            return
        if self.session.stock is None:
            self.stock_label.setText("Стоковый шаблон для этого конфига не найден.")
            self.reset_section_btn.setEnabled(False)
            return
        changed = differing_sections(self.session.document, self.session.stock)
        if not changed:
            self.stock_label.setText("Конфиг совпадает со стоковым шаблоном.")
        else:
            names = ", ".join(catalog.SECTION_LABELS.get(key, key) for key in changed)
            self.stock_label.setText(
                f"Отличаются от стока: {names}. При обновлении эти разделы останутся вашими, "
                "остальные подтянут новый сток."
            )
        self.reset_section_btn.setEnabled(bool(changed))

    def _show_reset_section_menu(self) -> None:
        if self.session.document is None:
            return
        changed = differing_sections(self.session.document, self.session.stock)
        popup_menu(
            self.reset_section_btn,
            [
                (f"{catalog.SECTION_LABELS.get(key, key)} · {key}", lambda section=key: self._reset_section(section), "")
                for key in changed
            ],
        )

    def _reset_section(self, key: str) -> None:
        label = catalog.SECTION_LABELS.get(key, key)
        if _confirm(
            self,
            "Сбросить раздел",
            f"Заменить раздел «{label}» стоковой версией? Изменение нужно будет сохранить.",
            "Сбросить",
        ):
            self.session.reset_section(key)

    def set_template_source(self, path: Path | None) -> None:
        if path is None:
            self.template_label.setText("Шаблон: --")
            self.reset_btn.setEnabled(False)
        else:
            self.template_label.setText(f"Шаблон: {path.as_posix()}")
            self.reset_btn.setEnabled(True)
        self.session.set_template(path)

    def set_status(self, level: str, message: str) -> None:
        prefix = {
            "success": "OK",
            "warning": "Внимание",
            "error": "Ошибка",
            "info": "Инфо",
        }.get(level.strip().lower(), "Статус")
        self.status_box.setPlainText(f"{prefix}: {message}".strip())

    # -- selectors (unchanged behaviour of the former raw editor) ---------------

    def set_available_configs(self, items: list[tuple[str, str]], selected: str | None = None) -> None:
        self._set_combo_items(self.config_combo, items, selected or "", placeholder="Нет конфигов")
        self._selected_config_key = self._current_combo_value(self.config_combo)

    def set_available_templates(self, items: list[tuple[str, str]], selected: str | None = None) -> None:
        self._set_combo_items(
            self.template_combo,
            items,
            selected or "",
            placeholder="Нет шаблонов",
            empty_label="Шаблон не выбран",
        )
        self._selected_template_key = self._current_combo_value(self.template_combo)

    def _set_combo_items(self, combo, items, selected, *, placeholder, empty_label="") -> None:
        self._selector_updating = True
        try:
            combo.clear()
            if not items:
                combo.addItem(placeholder, userData="")
                combo.setEnabled(False)
                combo.setCurrentIndex(0)
                return
            combo.setEnabled(True)
            if empty_label:
                combo.addItem(empty_label, userData="")
            for label, data in items:
                combo.addItem(label, userData=data)
            match_index = 0
            for index in range(combo.count()):
                if combo.itemData(index) == selected:
                    match_index = index
                    break
            combo.setCurrentIndex(match_index)
        finally:
            self._selector_updating = False

    @staticmethod
    def _current_combo_value(combo: ComboBox) -> str:
        return str(combo.currentData() or "").strip()

    def _restore_combo_selection(self, combo: ComboBox, value: str) -> None:
        self._selector_updating = True
        try:
            for index in range(combo.count()):
                if str(combo.itemData(index) or "").strip() == value:
                    combo.setCurrentIndex(index)
                    return
            if combo.count() > 0:
                combo.setCurrentIndex(0)
        finally:
            self._selector_updating = False

    def _confirm_discard(self, text: str, confirm: str) -> bool:
        if not self.session.is_dirty():
            return True
        return _confirm(self, "Несохранённые изменения", text, confirm)

    def _on_config_combo_changed(self) -> None:
        if self._selector_updating:
            return
        value = self._current_combo_value(self.config_combo)
        if not value or value == self._selected_config_key:
            return
        if not self._confirm_discard("Открыть другой конфиг без сохранения текущих правок?", "Открыть"):
            self._restore_combo_selection(self.config_combo, self._selected_config_key)
            return
        self._selected_config_key = value
        self.config_selected.emit(value)

    def _on_template_combo_changed(self) -> None:
        if self._selector_updating:
            return
        value = self._current_combo_value(self.template_combo)
        if not value or value == self._selected_template_key:
            return
        if not self._confirm_discard("Применить другой шаблон без сохранения текущих правок?", "Применить"):
            self._restore_combo_selection(self.template_combo, self._selected_template_key)
            return
        self._selected_template_key = value
        self.template_selected.emit(value)

    def _on_open_clicked(self) -> None:
        if self._confirm_discard("Импортировать другой шаблон без сохранения текущих правок?", "Импортировать"):
            self.open_requested.emit()

    def _on_reset_clicked(self) -> None:
        if _confirm(
            self,
            "Сбросить к стоку",
            "Заменить весь активный конфиг стоковым шаблоном? Ваши правила, DNS и остальные правки пропадут.",
            "Сбросить",
        ):
            self.reset_requested.emit()


class _JsonPanel(ScrollablePage):
    """The same document as raw native JSON."""

    def __init__(self, session: SingboxSession, parent: QWidget | None = None):
        super().__init__(parent)
        self.session = session
        self._syncing = False
        self._pending = False
        root = self.body_layout
        title_row = QHBoxLayout()
        title_row.setSpacing(10)
        badge = KindBadge(self.body, size=32)
        badge.set_visual(Visual(FIF.CODE, PROXY), vivid=True)
        title_row.addWidget(badge)
        title_row.addWidget(SubtitleLabel("JSON", self.body))
        title_row.addStretch(1)
        title_row.addWidget(JsonArt(self.body), 1)
        root.addLayout(title_row)
        hint = CaptionLabel(
            "Полный текст конфига. Правки здесь и в разделах — одно и то же; разделы обновятся, "
            "когда вы уйдёте с этой страницы. Если в outbounds есть тег proxy, при запуске туда "
            "подставляется выбранный сервер.",
            self.body,
        )
        hint.setWordWrap(True)
        root.addWidget(hint)
        self.editor = PlainTextEdit(self.body)
        self.editor.setPlaceholderText("Raw sing-box.json")
        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.editor.setFont(font)
        self.editor.setMinimumHeight(420)
        root.addWidget(self.editor, 1)
        self.editor.textChanged.connect(self._on_text_changed)

    def load_from_session(self) -> None:
        self._syncing = True
        try:
            self.editor.setPlainText(self.session.text())
        finally:
            self._syncing = False
        self._pending = False

    def _on_text_changed(self) -> None:
        if not self._syncing:
            self._pending = True

    def commit_to_session(self) -> None:
        if self._pending:
            self._pending = False
            self.session.replace_text(self.editor.toPlainText())


class ConfigsPage(QWidget):
    open_requested = pyqtSignal(str)
    reset_requested = pyqtSignal(str)
    save_requested = pyqtSignal(str, str)
    validate_requested = pyqtSignal(str, str)
    apply_requested = pyqtSignal(str, str)
    config_selected = pyqtSignal(str, str)
    template_selected = pyqtSignal(str, str)
    section_changed = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("configs")
        self.session = SingboxSession(self)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        left, top, right, _bottom = BODY_MARGINS
        bar = QHBoxLayout()
        bar.setContentsMargins(left, top, right, 4)
        bar.setSpacing(8)
        self.dirty_dot = PulseDot(self)
        bar.addWidget(self.dirty_dot)
        # Одна строка: на узком окне сокращается многоточием, полный текст —
        # в подсказке (раньше переносилась на две строки и раздувала панель).
        self.state_label = ElidedCaptionLabel("", self)
        bar.addWidget(self.state_label, 1)
        self.revert_btn = PushButton(FIF.CANCEL, "Отменить изменения", self)
        self.validate_btn = PushButton(FIF.ACCEPT, "Проверить", self)
        self.validate_btn.setToolTip("Проверить конфиг ядром sing-box (sing-box check)")
        self.save_btn = PushButton(FIF.SAVE, "Сохранить", self)
        self.apply_btn = PrimaryPushButton(FIF.PLAY, "Применить", self)
        for button in (self.revert_btn, self.validate_btn, self.save_btn, self.apply_btn):
            bar.addWidget(button)
        outer.addLayout(bar)
        self._bar_fit = AdaptiveButtonRow(bar, [self.apply_btn, self.save_btn, self.validate_btn, self.revert_btn])

        self.stack = PopUpAniStackedWidget(self)
        outer.addWidget(self.stack, 1)

        self.overview = _OverviewPanel(self.session, self)
        self.json_panel = _JsonPanel(self.session, self)
        self._sections: dict[str, QWidget] = {
            "overview": self.overview,
            "rules": RulesSection(self.session, self),
            "rule_sets": RuleSetsSection(self.session, self),
            "dns": DnsSection(self.session, self),
            "outbounds": OutboundsSection(self.session, self),
            "system": SystemSection(self.session, self),
            "json": self.json_panel,
        }
        for widget in self._sections.values():
            self.stack.addWidget(widget, deltaX=0, deltaY=36)
        self._current = "overview"
        # Kept for callers/tests that address the editor per core.
        self._editors = {"singbox": self.overview}

        self.overview.open_requested.connect(lambda: self.open_requested.emit("singbox"))
        self.overview.reset_requested.connect(lambda: self.reset_requested.emit("singbox"))
        self.overview.config_selected.connect(lambda value: self.config_selected.emit("singbox", value))
        self.overview.template_selected.connect(lambda value: self.template_selected.emit("singbox", value))
        self.revert_btn.clicked.connect(self._on_revert)
        self.validate_btn.clicked.connect(lambda: self._emit_with_text(self.validate_requested))
        self.save_btn.clicked.connect(lambda: self._emit_with_text(self.save_requested))
        self.apply_btn.clicked.connect(lambda: self._emit_with_text(self.apply_requested))
        self.session.state_changed.connect(self._refresh_bar)
        self._refresh_bar()

    # -- sections ---------------------------------------------------------------

    def flush(self) -> None:
        """Commit pending input of the visible page into the session."""
        if self._current == "json":
            self.json_panel.commit_to_session()
            return
        flush = getattr(self._sections[self._current], "flush", None)
        if flush is not None:
            flush()

    def show_section(self, key: str) -> None:
        if key not in self._sections:
            return
        if self._current != "json" and key != self._current:
            self.flush()
        if self._current == "json" and key != "json":
            self.json_panel.commit_to_session()
        if key == "json":
            self.json_panel.load_from_session()
        for name, widget in self._sections.items():
            set_active = getattr(widget, "set_active", None)
            if set_active is not None and name != key:
                set_active(False)
        self._current = key
        activate = getattr(self._sections[key], "set_active", None)
        if activate is not None:
            activate(True)
        self.stack.setAnimationEnabled(not reduced_motion())
        self.stack.setCurrentWidget(self._sections[key], duration=240, easingCurve=QEasingCurve.Type.OutCubic)
        self.section_changed.emit(key)

    def current_section(self) -> str:
        return self._current

    def scroll_areas(self) -> list:
        areas = [self.overview.scroll_area, self.json_panel.scroll_area]
        for key in ("rules", "rule_sets", "dns", "outbounds", "system"):
            areas.append(self._sections[key].scroll_area)
        return areas

    def _emit_with_text(self, signal) -> None:
        self.flush()
        signal.emit("singbox", self.session.text())

    def _on_revert(self) -> None:
        self.flush()
        if not self.session.is_dirty():
            return
        if _confirm(self, "Отменить изменения", "Вернуть конфиг к последнему сохранённому состоянию?", "Вернуть"):
            self.session.revert()
            if self._current == "json":
                self.json_panel.load_from_session()

    def _refresh_bar(self) -> None:
        dirty = self.session.is_dirty()
        if self.session.document is None:
            self.state_label.setText("В конфиге ошибка JSON — исправьте её на странице «JSON».")
        elif dirty:
            self.state_label.setText("Есть несохранённые изменения")
        else:
            self.state_label.setText("Сохранено")
        self.revert_btn.setEnabled(dirty)
        self.dirty_dot.set_active(dirty and self.session.document is not None)

    # -- API used by the main window (unchanged) --------------------------------

    def set_current_core(self, core: str) -> None:
        """Only sing-box has a routing editor; kept for callers."""

    def set_document(self, core: str, path: Path, text: str) -> None:
        self.session.load(path, text)
        if self._current == "json":
            self.json_panel.load_from_session()

    def replace_editor_text(self, core: str, text: str) -> None:
        self.session.replace_text(text)
        if self._current == "json":
            self.json_panel.load_from_session()

    def set_template_source(self, core: str, path: Path | None) -> None:
        self.overview.set_template_source(path)

    def set_available_configs(self, core: str, items: list[tuple[str, str]], selected: str | None = None) -> None:
        self.overview.set_available_configs(items, selected)

    def set_available_templates(self, core: str, items: list[tuple[str, str]], selected: str | None = None) -> None:
        self.overview.set_available_templates(items, selected)

    def set_status(self, core: str, level: str, message: str) -> None:
        self.overview.set_status(level, message)
        self.state_label.setText(message.splitlines()[0] if message else self.state_label.text())

    def mark_saved(self, core: str, path: Path | None = None, text: str | None = None) -> None:
        self.session.mark_saved(path, text)
        if self._current == "json":
            self.json_panel.load_from_session()

    def is_dirty(self, core: str) -> bool:
        self.flush()
        return self.session.is_dirty()
