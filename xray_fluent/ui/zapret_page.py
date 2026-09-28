"""Zapret section: an overview and two list ↔ card pages.

Overview (root)
    Status card: is winws2 running, which preset (a link to the preset page),
    one start/stop button, autostart.  The selected VPN server and what Zapret
    does with it.  One row per server kind — TCP / QUIC / WireGuard.
Kind page
    Bypass switch in the header; strategy browser (``zapret_browser``).
Presets page
    Preset browser; the file editor is one level deeper.

Choices apply at once — the button in a card, the switch in a header; there
is no separate «Применить».  Only titles and data live on the pages; the
explanation for newcomers is the «Как это б#&^ь работает?» window.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QFileDialog, QHBoxLayout, QVBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    CardWidget,
    FluentIcon as FIF,
    HyperlinkButton,
    IconWidget,
    MessageBox,
    PrimaryPushButton,
    PushButton,
    StrongBodyLabel,
    SubtitleLabel,
    SwitchButton,
)

from ..engines.zapret import presets
from ..engines.zapret.command import ServerRule
from ..engines.zapret.endpoint import KIND_PROTOCOLS, KIND_TITLES, endpoint_for_node
from ..engines.zapret.presets import PresetInfo
from ..engines.zapret.strategies import chosen_strategy, load_strategy_catalog
from ..profiles.models import ZAPRET_SERVER_KINDS, Node, ZapretTargetSettings
from .base_page import ScrollablePage
from .detail_page import DetailPage, StackedSection
from .preset_edit_widget import PresetEditWidget
from .singbox.art import KindBadge
from .singbox.guide import help_link, open_guide
from .singbox.lists import section_header
from .singbox.visuals import BLOCK, NEUTRAL, PROXY, SPECIAL, Visual
from .theme import on_theme_or_accent_changed
from .zapret_browser import PresetBrowser, StrategyBrowser

_KIND_ICONS = {"tcp": FIF.CONNECT, "quic": FIF.SPEED_HIGH, "wireguard": FIF.VPN}


@dataclass(frozen=True)
class ZapretStatus:
    """What the status card shows: ``stopped`` | ``starting`` | ``running`` | ``error``."""

    state: str = "stopped"
    preset: str = ""
    message: str = ""

    @property
    def active(self) -> bool:
        return self.state in ("running", "starting")


def off_meaning(kind: str) -> str:
    """What «bypass off» does for a kind — the preset for TCP, hands off for UDP."""
    return "по пресету" if kind == "tcp" else "не трогать"


def off_explained(kind: str) -> str:
    if kind == "tcp":
        return "Трафик к таким серверам обрабатывается пресетом, как и все сайты."
    return "Zapret не трогает трафик к таким серверам, даже если пресет обрабатывает UDP."


def strategy_title(settings: ZapretTargetSettings, kind: str) -> str:
    try:
        return chosen_strategy(settings, kind).name
    except ValueError:
        return "стратегия не найдена"


def _switch(parent: QWidget) -> SwitchButton:
    switch = SwitchButton(parent)
    # SwitchButton(text) fills only the «off» caption; the state is spelled
    # out by a label next to it instead.
    switch.setOnText("")
    switch.setOffText("")
    return switch


# ── overview rows ────────────────────────────────────────────────────────────


class KindRow(CardWidget):
    """One server kind: badge, title, protocols, current choice and a chevron."""

    def __init__(self, kind: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.kind = kind
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 12, 10)
        layout.setSpacing(12)
        self.badge = KindBadge(self)
        layout.addWidget(self.badge, 0, Qt.AlignmentFlag.AlignVCenter)
        column = QVBoxLayout()
        column.setSpacing(1)
        title_row = QHBoxLayout()
        title_row.setSpacing(8)
        title_row.addWidget(BodyLabel(KIND_TITLES[kind], self))
        self.current_mark = CaptionLabel("выбранный сервер", self)
        self.current_mark.hide()
        title_row.addWidget(self.current_mark)
        title_row.addStretch(1)
        column.addLayout(title_row)
        column.addWidget(CaptionLabel(KIND_PROTOCOLS[kind], self))
        layout.addLayout(column, 1)
        self.value = BodyLabel("", self)
        self.value.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.value)
        chevron = IconWidget(FIF.CHEVRON_RIGHT, self)
        chevron.setFixedSize(12, 12)
        layout.addWidget(chevron, 0, Qt.AlignmentFlag.AlignVCenter)

    def show_state(self, settings: ZapretTargetSettings, current: bool) -> None:
        enabled = settings.enabled(self.kind)
        self.badge.set_visual(
            Visual(_KIND_ICONS[self.kind], PROXY if enabled else NEUTRAL),
            vivid=enabled and current,
        )
        self.value.setText(
            strategy_title(settings, self.kind) if enabled else f"выкл · {off_meaning(self.kind)}"
        )
        self.current_mark.setVisible(current)


# ── kind page ────────────────────────────────────────────────────────────────


class KindPage(DetailPage):
    """Bypass switch and strategy for one server kind; every choice applies at once."""

    settings_changed = pyqtSignal(object)  # ZapretTargetSettings

    def __init__(self, parent: QWidget | None = None):
        super().__init__("Zapret", KIND_TITLES["tcp"], parent, root_key="zapret", page_key="kind")
        self.kind = "tcp"
        self._settings = ZapretTargetSettings()
        self._loaded_transport = ""

        self.state_label = CaptionLabel("", self)
        self.switch = _switch(self)
        self.add_header_action(self.state_label)
        self.add_header_action(self.switch)

        self.off_card = CardWidget(self)
        off_layout = QHBoxLayout(self.off_card)
        off_layout.setContentsMargins(16, 14, 16, 14)
        off_layout.setSpacing(12)
        self.off_badge = KindBadge(self.off_card)
        off_layout.addWidget(self.off_badge, 0, Qt.AlignmentFlag.AlignVCenter)
        off_text = QVBoxLayout()
        off_text.setSpacing(2)
        self.off_title = BodyLabel("", self.off_card)
        self.off_detail = CaptionLabel("", self.off_card)
        self.off_detail.setWordWrap(True)
        off_text.addWidget(self.off_title)
        off_text.addWidget(self.off_detail)
        off_layout.addLayout(off_text, 1)
        self.content_layout.addWidget(self.off_card)

        self.browser = StrategyBrowser(self)
        self.content_layout.addWidget(self.browser, 1)
        self.off_stretch = QWidget(self)
        self.content_layout.addWidget(self.off_stretch, 1)

        self.switch.checkedChanged.connect(self._on_switch)
        self.browser.chosen.connect(self._on_chosen)

    def open_kind(self, kind: str, settings: ZapretTargetSettings) -> None:
        self.kind = kind
        self._settings = settings
        self.set_page_label(KIND_TITLES[kind])
        transport = "tcp" if kind == "tcp" else "udp"
        if transport != self._loaded_transport:
            self.browser.set_entries(load_strategy_catalog(transport))
            self._loaded_transport = transport
        self.browser.set_chosen(settings.strategy_id(kind), settings.custom_args(kind))
        self._render()

    def set_settings(self, settings: ZapretTargetSettings) -> None:
        """Stored settings changed elsewhere; a hidden page reloads on its next visit."""

        self._settings = settings
        if self.isVisible():
            self.browser.set_chosen(settings.strategy_id(self.kind), settings.custom_args(self.kind))
            self._render()

    def _render(self) -> None:
        enabled = self._settings.enabled(self.kind)
        self.switch.blockSignals(True)
        self.switch.setChecked(enabled)
        self.switch.blockSignals(False)
        self.state_label.setText("Обход включён" if enabled else "Обход выключен")
        self.off_badge.set_visual(Visual(_KIND_ICONS[self.kind], NEUTRAL))
        self.off_title.setText(f"Выключено · {off_meaning(self.kind)}")
        self.off_detail.setText(
            off_explained(self.kind) + " Включите переключатель вверху, чтобы выбрать стратегию."
        )
        self.off_card.setVisible(not enabled)
        self.off_stretch.setVisible(not enabled)
        self.browser.setVisible(enabled)

    def _emit(self, **changes) -> None:
        settings = self._settings
        values = {
            "enabled": settings.enabled(self.kind),
            "strategy_id": settings.strategy_id(self.kind),
            "custom_args": settings.custom_args(self.kind),
            **changes,
        }
        self._settings = settings.with_kind(self.kind, **values)
        self._render()
        self.settings_changed.emit(self._settings)

    def _on_switch(self, checked: bool) -> None:
        self._emit(enabled=bool(checked))

    def _on_chosen(self, strategy_id: str, custom_text: str) -> None:
        self._emit(strategy_id=strategy_id, custom_args=custom_text)


# ── presets page ─────────────────────────────────────────────────────────────


class PresetsPage(DetailPage):
    def __init__(self, parent: QWidget | None = None):
        super().__init__("Zapret", "Пресеты", parent, root_key="zapret", page_key="presets")
        self.import_btn = PushButton(FIF.FOLDER, "Импорт", self)
        self.add_header_action(self.import_btn)
        self.create_btn = PrimaryPushButton(FIF.ADD, "Создать", self)
        self.add_header_action(self.create_btn)
        self.browser = PresetBrowser(self)
        self.content_layout.addWidget(self.browser, 1)


# ── section ──────────────────────────────────────────────────────────────────


class ZapretPage(StackedSection):
    start_requested = pyqtSignal(str)  # preset name
    stop_requested = pyqtSignal()
    target_settings_changed = pyqtSignal(object)  # ZapretTargetSettings
    preset_selected = pyqtSignal(str)
    autostart_changed = pyqtSignal(bool)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("zapret")
        self._presets: list[PresetInfo] = []
        self._selected_preset = ""
        self._status = ZapretStatus()
        self._settings = ZapretTargetSettings()
        self._node: Node | None = None
        self._rule: ServerRule | None = None
        self._server_status = ""

        overview = ScrollablePage()
        body, root = overview.body, overview.body_layout

        title_row = QHBoxLayout()
        title_row.setSpacing(10)
        title_badge = KindBadge(body, size=32)
        title_badge.set_visual(Visual(FIF.COMMAND_PROMPT, PROXY), vivid=True)
        title_row.addWidget(title_badge)
        title_row.addWidget(SubtitleLabel("Zapret", body))
        title_row.addStretch(1)
        self.help_link = help_link(body)
        self.help_link.clicked.connect(lambda: open_guide("zapret", self))
        title_row.addWidget(self.help_link)
        root.addLayout(title_row)

        # ── status card ──
        status_card = CardWidget(body)
        status_layout = QVBoxLayout(status_card)
        status_layout.setContentsMargins(16, 14, 16, 14)
        status_layout.setSpacing(10)
        head = QHBoxLayout()
        head.setSpacing(12)
        self.status_badge = KindBadge(status_card, size=40)
        head.addWidget(self.status_badge, 0, Qt.AlignmentFlag.AlignVCenter)
        status_text = QVBoxLayout()
        status_text.setSpacing(1)
        self.status_title = StrongBodyLabel("", status_card)
        self.status_detail = CaptionLabel("", status_card)
        self.status_detail.setWordWrap(True)
        status_text.addWidget(self.status_title)
        status_text.addWidget(self.status_detail)
        head.addLayout(status_text, 1)
        self.toggle_btn = PrimaryPushButton(FIF.PLAY, "Запустить", status_card)
        self.toggle_btn.clicked.connect(self._on_toggle)
        head.addWidget(self.toggle_btn, 0, Qt.AlignmentFlag.AlignVCenter)
        status_layout.addLayout(head)

        preset_row = QHBoxLayout()
        preset_row.setSpacing(6)
        preset_row.addWidget(BodyLabel("Пресет", status_card))
        self.preset_link = HyperlinkButton(status_card)
        self.preset_link.setToolTip("Выбрать пресет")
        self.preset_link.clicked.connect(self._open_presets)
        preset_row.addWidget(self.preset_link)
        self.preset_summary = CaptionLabel("", status_card)
        preset_row.addWidget(self.preset_summary, 1)
        status_layout.addLayout(preset_row)

        autostart_row = QHBoxLayout()
        autostart_row.addWidget(BodyLabel("Запускать вместе с приложением", status_card))
        autostart_row.addStretch(1)
        self.autostart_switch = _switch(status_card)
        autostart_row.addWidget(self.autostart_switch)
        status_layout.addLayout(autostart_row)
        root.addWidget(status_card)

        # ── selected server ──
        root.addWidget(section_header("Выбранный VPN-сервер", body))
        server_card = CardWidget(body)
        server_layout = QHBoxLayout(server_card)
        server_layout.setContentsMargins(14, 10, 14, 10)
        server_layout.setSpacing(12)
        self.server_badge = KindBadge(server_card)
        server_layout.addWidget(self.server_badge, 0, Qt.AlignmentFlag.AlignVCenter)
        server_text = QVBoxLayout()
        server_text.setSpacing(1)
        self.server_title = BodyLabel("Сервер не выбран", server_card)
        self.server_endpoint = CaptionLabel("", server_card)
        self.server_endpoint.setWordWrap(True)
        self.server_rule = CaptionLabel("", server_card)
        self.server_rule.setWordWrap(True)
        for label in (self.server_title, self.server_endpoint, self.server_rule):
            server_text.addWidget(label)
        server_layout.addLayout(server_text, 1)
        self.server_setup_btn = PushButton(FIF.SETTING, "Настроить", server_card)
        self.server_setup_btn.clicked.connect(self._open_current_kind)
        server_layout.addWidget(self.server_setup_btn, 0, Qt.AlignmentFlag.AlignVCenter)
        root.addWidget(server_card)

        # ── server kinds ──
        root.addWidget(section_header("Обход по видам серверов", body))
        self.kind_rows = {kind: KindRow(kind, body) for kind in ZAPRET_SERVER_KINDS}
        for row in self.kind_rows.values():
            row.clicked.connect(lambda row=row: self._open_kind(row.kind))
            root.addWidget(row)
        root.addStretch(1)

        self.set_root_page(overview)
        self._kind_page = KindPage(self)
        self.add_sub_page(self._kind_page)
        self._presets_page = PresetsPage(self)
        self.add_sub_page(self._presets_page)
        self._editor = PresetEditWidget(self)
        self.add_sub_page(self._editor)
        # The editor is reached from the preset page and returns there.
        self._editor.back_requested.disconnect(self.show_root)
        self._editor.back_requested.connect(lambda: self.show_sub_page(self._presets_page))

        self.autostart_switch.checkedChanged.connect(
            lambda checked: self.autostart_changed.emit(bool(checked))
        )
        self._kind_page.settings_changed.connect(self._on_kind_changed)
        browser = self._presets_page.browser
        browser.chosen.connect(self._choose_preset)
        browser.edit_requested.connect(self._open_editor)
        browser.delete_requested.connect(self._on_delete)
        self._presets_page.create_btn.clicked.connect(self._on_create)
        self._presets_page.import_btn.clicked.connect(self._on_import)
        self._editor.save_requested.connect(self._on_save_preset)
        on_theme_or_accent_changed(self._on_theme_changed)
        self._render()

    def _on_theme_changed(self, *_args) -> None:
        # List delegates read the theme at paint time; a repaint picks it up.
        self._presets_page.browser.list.viewport().update()
        self._kind_page.browser.list.viewport().update()

    # ── state from the application ──

    def set_presets(self, infos: list[PresetInfo], selected: str = "") -> None:
        self._presets = list(infos)
        if selected:
            self._selected_preset = selected
        self._sync_presets()
        self._render()

    def set_status(self, status: ZapretStatus) -> None:
        running_changed = status.active != self._status.active or status.preset != self._status.preset
        self._status = status
        if status.preset and status.active:
            self._selected_preset = status.preset
        if running_changed:
            self._sync_presets()  # the «Работает» chip follows the process
        self._render()

    def set_target_settings(self, settings: ZapretTargetSettings) -> None:
        self._settings = settings
        self._kind_page.set_settings(settings)
        self._render()

    def set_selected_node(self, node: Node | None) -> None:
        self._node = node
        self._render()

    def set_rule(self, rule: ServerRule | None) -> None:
        self._rule = rule
        self._render()

    def set_server_status(self, busy: bool, text: str = "") -> None:
        """Connection-transition text («DNS выбранного VPN-сервера…»)."""
        self._server_status = text if busy else ""
        self._render_server()

    def set_autostart(self, enabled: bool) -> None:
        self.autostart_switch.blockSignals(True)
        self.autostart_switch.setChecked(bool(enabled))
        self.autostart_switch.blockSignals(False)

    def current_preset(self) -> str:
        return self._selected_preset

    # ── rendering ──

    def _render(self) -> None:
        self._render_status()
        self._render_server()
        endpoint = endpoint_for_node(self._node)
        for kind, row in self.kind_rows.items():
            row.show_state(self._settings, current=endpoint is not None and endpoint.kind == kind)

    def _render_status(self) -> None:
        status = self._status
        if status.state == "running":
            visual, title, detail = Visual(FIF.PLAY_SOLID, PROXY), "Zapret работает", ""
        elif status.state == "starting":
            visual, title, detail = Visual(FIF.SYNC, SPECIAL), "Zapret запускается…", ""
        elif status.state == "error":
            visual, title, detail = Visual(FIF.CLOSE, BLOCK), "Zapret остановлен из-за ошибки", status.message
        else:
            visual, title, detail = Visual(FIF.PAUSE_BOLD, NEUTRAL), "Zapret выключен", ""
            endpoint = endpoint_for_node(self._node)
            if endpoint is not None and self._settings.enabled(endpoint.kind):
                detail = f"Включится сам при подключении к «{self._node.name}»"
        self.status_badge.set_visual(visual, vivid=status.state == "running")
        self.status_title.setText(title)
        self.status_detail.setText(detail)
        self.status_detail.setVisible(bool(detail))
        self.toggle_btn.setText("Остановить" if status.active else "Запустить")
        self.toggle_btn.setIcon(FIF.PAUSE_BOLD if status.active else FIF.PLAY)
        self.toggle_btn.setEnabled(status.active or bool(self._selected_preset))

        preset = next((item for item in self._presets if item.name == self._selected_preset), None)
        self.preset_link.setText(self._selected_preset or "выбрать")
        self.preset_summary.setText(preset.summary.short() if preset is not None else "")

    def _render_server(self) -> None:
        node = self._node
        endpoint = endpoint_for_node(node)
        self.server_setup_btn.setVisible(endpoint is not None)
        if node is None:
            self.server_badge.set_visual(Visual(FIF.VPN, NEUTRAL))
            self.server_title.setText("Сервер не выбран")
            self.server_endpoint.setText("")
            self.server_rule.setText("")
            return
        self.server_title.setText(node.name)
        if endpoint is None:
            self.server_badge.set_visual(Visual(FIF.VPN, NEUTRAL))
            self.server_endpoint.setText("Этот вид сервера Zapret не обрабатывает")
            self.server_rule.setText("")
            return
        enabled = self._settings.enabled(endpoint.kind)
        self.server_badge.set_visual(Visual(_KIND_ICONS[endpoint.kind], PROXY if enabled else NEUTRAL))
        self.server_endpoint.setText(
            f"{KIND_TITLES[endpoint.kind]} · {endpoint.transport.upper()} {endpoint.port_filter} · "
            f"{', '.join(endpoint.hosts)}"
        )
        if enabled:
            text = f"Обход: {strategy_title(self._settings, endpoint.kind)}"
        else:
            text = f"Обход выключен · {off_meaning(endpoint.kind)}"
        rule = self._rule
        if self._server_status:
            text += f" · {self._server_status}"
        elif rule is not None and rule.target.endpoint == endpoint and self._status.state == "running":
            text += f" · работает для {', '.join(rule.target.ips)}"
        elif enabled:
            text += " · применится при подключении"
        self.server_rule.setText(text)

    def _sync_presets(self) -> None:
        running = self._status.preset if self._status.active else ""
        self._presets_page.browser.set_presets(self._presets, self._selected_preset, running)

    # ── user actions ──

    def _on_toggle(self) -> None:
        if self._status.active:
            self.stop_requested.emit()
        elif self._selected_preset:
            self.start_requested.emit(self._selected_preset)

    def _open_presets(self) -> None:
        self._presets_page.browser.highlight(self._selected_preset)
        self.show_sub_page(self._presets_page)

    def _choose_preset(self, name: str) -> None:
        if not name:
            return
        self._selected_preset = name
        self.preset_selected.emit(name)
        if self._status.active:
            # What runs is what is chosen: switching restarts on that preset.
            self.start_requested.emit(name)
        self._sync_presets()
        self._render()

    def _open_kind(self, kind: str) -> None:
        self._kind_page.open_kind(kind, self._settings)
        self.show_sub_page(self._kind_page)

    def _open_current_kind(self) -> None:
        endpoint = endpoint_for_node(self._node)
        if endpoint is not None:
            self._open_kind(endpoint.kind)

    def _on_kind_changed(self, settings: ZapretTargetSettings) -> None:
        self._settings = settings
        self._render()
        self.target_settings_changed.emit(settings)

    def _reload_presets(self) -> None:
        self.set_presets(presets.list_preset_infos())

    def _open_editor(self, name: str) -> None:
        info = next((preset for preset in self._presets if preset.name == name), None)
        if info is None:
            return
        self._editor.set_preset(
            info.name, info.description, presets.read_preset(info.name), info.created, info.modified,
        )
        self.show_sub_page(self._editor)

    def _on_create(self) -> None:
        self._editor.set_preset("", "", "")
        self.show_sub_page(self._editor)

    def _on_import(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Импорт пресета", "", "Текстовые файлы (*.txt);;Все файлы (*)"
        )
        if not path:
            return
        info = presets.import_preset(Path(path))
        self._reload_presets()
        if info is None:
            MessageBox("Импорт пресета", "Не удалось импортировать файл.", self.window()).exec()
        else:
            self._presets_page.browser.highlight(info.name)

    def _on_delete(self, name: str) -> None:
        box = MessageBox("Удаление пресета", f"Удалить «{name}»?", self.window())
        box.yesButton.setText("Удалить")
        box.cancelButton.setText("Отмена")
        if not box.exec():
            return
        if name == self._status.preset and self._status.active:
            self.stop_requested.emit()
        presets.delete_preset(name)
        if name == self._selected_preset:
            self._selected_preset = ""
        self._reload_presets()

    def _on_save_preset(self, original: str, name: str, description: str, content: str) -> None:
        if name != original and presets.preset_path(name).exists():
            self._editor.show_error(f"Пресет «{name}» уже есть")
            return
        try:
            if original and name != original:
                if presets.rename_preset(original, name) is None:
                    self._editor.show_error("Не удалось переименовать пресет")
                    return
                if self._selected_preset == original:
                    self._selected_preset = name
                    self.preset_selected.emit(name)
            presets.save_preset(name, content, description)
        except OSError as exc:
            self._editor.show_error(f"Не удалось сохранить: {exc}")
            return
        self._editor.mark_saved(name, description, content)
        self._reload_presets()
        self._presets_page.browser.highlight(name)
        self.show_sub_page(self._presets_page)
        if self._status.active and self._status.preset in (original, name):
            # winws2 reads the file at launch: restart it on what was saved.
            self._selected_preset = name
            self.start_requested.emit(name)
