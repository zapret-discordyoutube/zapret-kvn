"""Zapret section: one overview, one page per server kind, the preset list.

Overview (root)
    Status card — is winws2 running, on which preset, one start/stop button,
    autostart.  Selected server — what Zapret does with its traffic right now.
    Three rows — TCP / QUIC / WireGuard servers: bypass on (strategy) or off.
Kind page
    Bypass switch and the strategy catalog for that kind; «Применить».
Presets page
    The winws2 preset files: create, import, edit, delete, start.

Only titles and data live on these pages; the explanation for newcomers is in
the «Как это б#&^ь работает?» window (``singbox.guide``, key ``zapret``).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QModelIndex, QRect, QSize, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QCursor, QFont, QPainter
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QListWidgetItem,
    QSizePolicy,
    QStyleOptionViewItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    Action,
    BodyLabel,
    CaptionLabel,
    CardWidget,
    ComboBox,
    FluentIcon as FIF,
    IconWidget,
    ListWidget,
    MessageBox,
    PlainTextEdit,
    PrimaryPushButton,
    PushButton,
    RoundMenu,
    StrongBodyLabel,
    SubtitleLabel,
    SwitchButton,
    TransparentPushButton,
)
from qfluentwidgets.components.widgets.list_view import ListItemDelegate

from ..engines.zapret import presets
from ..engines.zapret.command import ServerRule
from ..engines.zapret.endpoint import KIND_PROTOCOLS, KIND_TITLES, endpoint_for_node
from ..engines.zapret.presets import PresetInfo
from ..engines.zapret.strategies import (
    CUSTOM_STRATEGY_ID,
    chosen_strategy,
    load_strategy_catalog,
    validate_custom_strategy,
)
from ..profiles.models import ZAPRET_SERVER_KINDS, Node, ZapretTargetSettings
from .base_page import ScrollablePage
from .detail_page import DetailPage, StackedSection
from .preset_edit_widget import PresetEditWidget
from .singbox.art import KindBadge
from .singbox.guide import help_link, open_guide
from .singbox.lists import section_header
from .singbox.visuals import BLOCK, NEUTRAL, PROXY, SPECIAL, Visual
from .strategy_picker import StrategyPicker
from .theme import accent_color, on_theme_or_accent_changed, text_muted_color

_KIND_ICONS = {"tcp": FIF.CONNECT, "quic": FIF.SPEED_HIGH, "wireguard": FIF.VPN}
_PRESET_ROW_HEIGHT = 32


@dataclass(frozen=True)
class ZapretStatus:
    """What the status card shows: ``stopped`` | ``starting`` | ``running`` | ``error``."""

    state: str = "stopped"
    preset: str = ""
    message: str = ""


def off_meaning(kind: str) -> str:
    """What «bypass off» does for a kind — the preset for TCP, hands off for UDP."""
    return "по пресету" if kind == "tcp" else "не трогать"


def strategy_title(settings: ZapretTargetSettings, kind: str) -> str:
    try:
        return chosen_strategy(settings, kind).name
    except ValueError:
        return "стратегия не найдена"


def _expanding(widget: QWidget) -> QWidget:
    widget.setSizePolicy(QSizePolicy.Policy.Expanding, widget.sizePolicy().verticalPolicy())
    return widget


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
    """Bypass switch and strategy for one server kind."""

    apply_requested = pyqtSignal(object)  # ZapretTargetSettings

    def __init__(self, parent: QWidget | None = None):
        super().__init__("Zapret", KIND_TITLES["tcp"], parent, root_key="zapret", page_key="kind")
        self.kind = "tcp"
        self._settings = ZapretTargetSettings()
        self._original: tuple = ()

        self.validation_label = CaptionLabel("", self)
        self.apply_btn = PrimaryPushButton(FIF.ACCEPT, "Применить", self)
        self.apply_btn.clicked.connect(self._apply)
        self.add_header_action(self.validation_label)
        self.add_header_action(self.apply_btn)

        switch_card = CardWidget(self)
        switch_layout = QHBoxLayout(switch_card)
        switch_layout.setContentsMargins(14, 10, 14, 10)
        switch_layout.setSpacing(12)
        self.badge = KindBadge(switch_card)
        switch_layout.addWidget(self.badge, 0, Qt.AlignmentFlag.AlignVCenter)
        column = QVBoxLayout()
        column.setSpacing(1)
        column.addWidget(BodyLabel("Обход DPI до сервера", switch_card))
        self.protocols_label = CaptionLabel("", switch_card)
        column.addWidget(self.protocols_label)
        switch_layout.addLayout(column, 1)
        self.state_label = CaptionLabel("", switch_card)
        switch_layout.addWidget(self.state_label)
        self.switch = SwitchButton(switch_card)
        # SwitchButton(text) fills only the «off» caption; the state is spelled
        # out by state_label instead.
        self.switch.setOnText("")
        self.switch.setOffText("")
        switch_layout.addWidget(self.switch)
        self.content_layout.addWidget(switch_card)

        self.strategy_card = CardWidget(self)
        strategy_layout = QVBoxLayout(self.strategy_card)
        strategy_layout.setContentsMargins(16, 12, 16, 12)
        strategy_layout.setSpacing(8)
        self.picker = StrategyPicker(self.strategy_card)
        strategy_layout.addWidget(self.picker)
        self.custom_edit = PlainTextEdit(self.strategy_card)
        self.custom_edit.setPlaceholderText("# комментарий\n--lua-desync=...")
        self.custom_edit.setMaximumHeight(96)
        self.custom_edit.hide()
        strategy_layout.addWidget(self.custom_edit)
        self.content_layout.addWidget(self.strategy_card)
        self.content_layout.addStretch(1)

        self.switch.checkedChanged.connect(lambda _checked: self._on_edited())
        self.picker.selection_changed.connect(lambda _id: self._on_edited())
        self.custom_edit.textChanged.connect(self._on_edited)

    # ── public API ──

    def open_kind(self, kind: str, settings: ZapretTargetSettings) -> None:
        """Load one kind's stored choice; this is the page's clean state."""

        self.kind = kind
        self._settings = settings
        self.set_page_label(KIND_TITLES[kind])
        self.protocols_label.setText(KIND_PROTOCOLS[kind])
        transport = "tcp" if kind == "tcp" else "udp"
        self.picker.set_entries(
            "TCP-стратегия" if transport == "tcp" else "UDP-стратегия",
            load_strategy_catalog(transport),
        )
        self.picker.set_selected(settings.strategy_id(kind))
        self.custom_edit.blockSignals(True)
        self.custom_edit.setPlainText(settings.custom_args(kind))
        self.custom_edit.blockSignals(False)
        self.switch.blockSignals(True)
        self.switch.setChecked(settings.enabled(kind))
        self.switch.blockSignals(False)
        self.validation_label.setText("")
        self._sync()
        self._original = self._snapshot()

    def set_settings(self, settings: ZapretTargetSettings) -> None:
        """Stored settings changed elsewhere; unapplied edits on screen win.

        A hidden page only remembers them: ``open_kind`` reloads on the next
        visit, and rebuilding a ~470-row catalog nobody sees is wasted work.
        """

        if self.is_dirty() or not self.isVisible():
            self._settings = settings
            return
        self.open_kind(self.kind, settings)

    def is_dirty(self) -> bool:
        return bool(self._original) and self._snapshot() != self._original

    # ── internals ──

    def _snapshot(self) -> tuple:
        return (self.switch.isChecked(), self.picker.selected_id(), self.custom_edit.toPlainText())

    def _on_edited(self) -> None:
        self.validation_label.setText("")
        self._sync()

    def _sync(self) -> None:
        enabled = self.switch.isChecked()
        self.badge.set_visual(Visual(_KIND_ICONS[self.kind], PROXY if enabled else NEUTRAL), vivid=enabled)
        self.state_label.setText("включён" if enabled else f"выключен · {off_meaning(self.kind)}")
        self.strategy_card.setVisible(enabled)
        self.custom_edit.setVisible(enabled and self.picker.selected_id() == CUSTOM_STRATEGY_ID)

    def _apply(self) -> None:
        strategy_id = self.picker.selected_id()
        custom = self.custom_edit.toPlainText()
        if self.switch.isChecked():
            if not strategy_id:
                self.validation_label.setText("Выберите стратегию")
                return
            if strategy_id == CUSTOM_STRATEGY_ID:
                try:
                    validate_custom_strategy(custom)
                except ValueError as exc:
                    self.validation_label.setText(str(exc))
                    return
        updated = self._settings.with_kind(
            self.kind,
            enabled=self.switch.isChecked(),
            strategy_id=strategy_id,
            custom_args=custom,
        )
        self._settings = updated
        self._original = self._snapshot()
        self.apply_requested.emit(updated)


# ── presets page ─────────────────────────────────────────────────────────────


class PresetItemDelegate(ListItemDelegate):
    """Thin one-line preset row: name, then meta and an «active» badge."""

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex) -> QSize:
        return QSize(super().sizeHint(option, index).width(), _PRESET_ROW_HEIGHT)

    def initStyleOption(self, option: QStyleOptionViewItem, index: QModelIndex) -> None:
        # The base delegate re-reads DisplayRole here; the text is drawn below.
        super().initStyleOption(option, index)
        option.text = ""

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex) -> None:
        name = str(index.data(Qt.ItemDataRole.DisplayRole) or "")
        meta = str(index.data(Qt.ItemDataRole.UserRole + 1) or "")
        badge = str(index.data(Qt.ItemDataRole.UserRole + 2) or "")
        super().paint(painter, option, index)

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        small = QFont(option.font)
        small.setPointSizeF(max(7.5, option.font.pointSizeF() - 1.5))
        right = option.rect.right() - 12
        if badge:
            painter.setFont(small)
            width = painter.fontMetrics().horizontalAdvance(badge) + 16
            rect = QRect(right - width, option.rect.center().y() - 9, width, 18)
            fill = QColor(accent_color())
            fill.setAlpha(38)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(fill)
            painter.drawRoundedRect(rect, 9, 9)
            painter.setPen(accent_color())
            painter.drawText(rect, int(Qt.AlignmentFlag.AlignCenter), badge)
            right -= width + 8
        if meta:
            painter.setFont(small)
            painter.setPen(text_muted_color())
            width = min(260, painter.fontMetrics().horizontalAdvance(meta) + 8)
            rect = QRect(right - width, option.rect.y(), width, option.rect.height())
            painter.drawText(
                rect,
                int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
                painter.fontMetrics().elidedText(meta, Qt.TextElideMode.ElideRight, width),
            )
            right -= width + 8
        left = option.rect.left() + 14
        text_width = max(40, right - left)
        painter.setFont(option.font)
        painter.setPen(accent_color() if badge else option.palette.text().color())
        painter.drawText(
            QRect(left, option.rect.y(), text_width, option.rect.height()),
            int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
            painter.fontMetrics().elidedText(name, Qt.TextElideMode.ElideRight, text_width),
        )
        painter.restore()


class PresetsPage(DetailPage):
    """The preset files; double click edits, the context menu does the rest."""

    edit_requested = pyqtSignal(str)
    start_requested = pyqtSignal(str)
    create_requested = pyqtSignal()
    import_requested = pyqtSignal()
    delete_requested = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__("Zapret", "Пресеты", parent, root_key="zapret", page_key="presets")
        self._presets: list[PresetInfo] = []
        self._active = ""

        self.import_btn = PushButton(FIF.FOLDER, "Импорт", self)
        self.import_btn.clicked.connect(lambda: self.import_requested.emit())
        self.add_header_action(self.import_btn)
        self.create_btn = PrimaryPushButton(FIF.ADD, "Создать", self)
        self.create_btn.clicked.connect(lambda: self.create_requested.emit())
        self.add_header_action(self.create_btn)

        self.empty_label = CaptionLabel("Пресетов нет", self)
        self.empty_label.hide()
        self.content_layout.addWidget(self.empty_label)
        self.list = ListWidget(self)
        self.list.setItemDelegate(PresetItemDelegate(self.list))
        self.list.setUniformItemSizes(True)
        self.list.setVerticalScrollMode(ListWidget.ScrollMode.ScrollPerItem)
        self.list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.list.doubleClicked.connect(lambda index: self._emit_for_row(index.row(), self.edit_requested))
        self.list.customContextMenuRequested.connect(self._on_context_menu)
        self.content_layout.addWidget(self.list, 1)

    def show_presets(self, infos: list[PresetInfo], active: str) -> None:
        self._presets = list(infos)
        self._active = active
        self.list.clear()
        for preset in self._presets:
            item = QListWidgetItem(preset.name)
            item.setData(Qt.ItemDataRole.UserRole + 1, preset.description or f"{preset.arg_count} арг.")
            if preset.name == active:
                item.setData(Qt.ItemDataRole.UserRole + 2, "Работает")
            item.setSizeHint(QSize(0, _PRESET_ROW_HEIGHT))
            item.setToolTip(
                f"{preset.name}\nАргументов: {preset.arg_count}\nИзменён: {_format_date(preset.modified)}"
            )
            self.list.addItem(item)
        self.empty_label.setVisible(not self._presets)
        # Size the list to its rows: the page itself scrolls.
        self.list.setFixedHeight(max(1, len(self._presets)) * _PRESET_ROW_HEIGHT + 8)

    def _emit_for_row(self, row: int, signal) -> None:
        if 0 <= row < len(self._presets):
            signal.emit(self._presets[row].name)

    def _on_context_menu(self, pos) -> None:
        item = self.list.itemAt(pos)
        if item is None:
            return
        row = self.list.row(item)
        self.list.setCurrentRow(row)
        menu = RoundMenu(parent=self)
        for text, icon, signal in (
            ("Изменить", FIF.EDIT, self.edit_requested),
            ("Запустить", FIF.PLAY, self.start_requested),
            ("Удалить", FIF.DELETE, self.delete_requested),
        ):
            action = Action(icon, text, self)
            action.triggered.connect(lambda _checked=False, s=signal: self._emit_for_row(row, s))
            menu.addAction(action)
        menu.exec(QCursor.pos())


def _format_date(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M") if iso else ""
    except (ValueError, TypeError):
        return iso


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
        self._list_key: tuple = ()

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
        status_layout.setSpacing(12)
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
        preset_row.setSpacing(8)
        preset_row.addWidget(BodyLabel("Пресет", status_card))
        self.preset_combo = _expanding(ComboBox(status_card))
        self.preset_combo.setMinimumWidth(220)
        preset_row.addWidget(self.preset_combo, 1)
        self.presets_btn = TransparentPushButton(FIF.LIBRARY, "Все пресеты", status_card)
        preset_row.addWidget(self.presets_btn)
        status_layout.addLayout(preset_row)

        autostart_row = QHBoxLayout()
        autostart_row.addWidget(BodyLabel("Запускать вместе с приложением", status_card))
        autostart_row.addStretch(1)
        self.autostart_switch = SwitchButton(status_card)
        self.autostart_switch.setOnText("")
        self.autostart_switch.setOffText("")
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
        # The editor is reached from the preset list and returns there.
        self._editor.back_requested.disconnect(self.show_root)
        self._editor.back_requested.connect(lambda: self.show_sub_page(self._presets_page))

        self.presets_btn.clicked.connect(lambda: self.show_sub_page(self._presets_page))
        self.preset_combo.currentIndexChanged.connect(self._on_preset_chosen)
        self.autostart_switch.checkedChanged.connect(lambda checked: self.autostart_changed.emit(bool(checked)))
        self._kind_page.apply_requested.connect(self._on_kind_applied)
        self._presets_page.edit_requested.connect(self._open_editor)
        self._presets_page.start_requested.connect(self.start_requested)
        self._presets_page.create_requested.connect(self._on_create)
        self._presets_page.import_requested.connect(self._on_import)
        self._presets_page.delete_requested.connect(self._on_delete)
        self._editor.save_requested.connect(self._on_save_preset)
        on_theme_or_accent_changed(self._on_theme_changed)
        self._render()

    def _on_theme_changed(self, *_args) -> None:
        # Delegates read the accent at paint time; a repaint picks up a new one.
        self._presets_page.list.viewport().update()

    # ── state from the application ──

    def set_presets(self, infos: list[PresetInfo], selected: str = "") -> None:
        self._presets = list(infos)
        if selected:
            self._selected_preset = selected
        self._fill_preset_combo()
        self._render()

    def set_status(self, status: ZapretStatus) -> None:
        self._status = status
        if status.preset and status.state in ("running", "starting"):
            self._selected_preset = status.preset
        self._fill_preset_combo()  # the «Работает» badge follows the process
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
        self._render()

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
        running = status.state in ("running", "starting")
        preset = status.preset or self._selected_preset
        if status.state == "running":
            visual, title = Visual(FIF.PLAY_SOLID, PROXY), "Zapret работает"
            detail = f"Пресет «{preset}»"
        elif status.state == "starting":
            visual, title = Visual(FIF.SYNC, SPECIAL), "Zapret запускается…"
            detail = f"Пресет «{preset}»"
        elif status.state == "error":
            visual, title = Visual(FIF.CLOSE, BLOCK), "Zapret остановлен из-за ошибки"
            detail = status.message
        else:
            visual, title = Visual(FIF.PAUSE_BOLD, NEUTRAL), "Zapret выключен"
            endpoint = endpoint_for_node(self._node)
            if endpoint is not None and self._settings.enabled(endpoint.kind):
                detail = f"Включится сам при подключении к «{self._node.name}»"
            else:
                detail = ""
        self.status_badge.set_visual(visual, vivid=status.state == "running")
        self.status_title.setText(title)
        self.status_detail.setText(detail)
        self.status_detail.setVisible(bool(detail))
        self.toggle_btn.setText("Остановить" if running else "Запустить")
        self.toggle_btn.setIcon(FIF.PAUSE_BOLD if running else FIF.PLAY)
        self.toggle_btn.setEnabled(running or bool(self._selected_preset))

    def _render_server(self) -> None:
        node = self._node
        endpoint = endpoint_for_node(node)
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

    def _fill_preset_combo(self) -> None:
        names = [preset.name for preset in self._presets]
        if self._selected_preset and self._selected_preset not in names:
            names.insert(0, self._selected_preset)
        active = self._status.preset if self._status.state in ("running", "starting") else ""
        key = (tuple(self._presets), self._selected_preset, active)
        if key == self._list_key:
            return  # status ticks (every transition step) change nothing here
        self._list_key = key
        self.preset_combo.blockSignals(True)
        self.preset_combo.clear()
        for name in names:
            self.preset_combo.addItem(name, userData=name)
        if self._selected_preset in names:
            self.preset_combo.setCurrentIndex(names.index(self._selected_preset))
        else:
            self.preset_combo.setCurrentIndex(-1)
        self.preset_combo.blockSignals(False)
        self._presets_page.show_presets(self._presets, active)

    # ── user actions ──

    def _on_toggle(self) -> None:
        if self._status.state in ("running", "starting"):
            self.stop_requested.emit()
        elif self._selected_preset:
            self.start_requested.emit(self._selected_preset)

    def _on_preset_chosen(self, index: int) -> None:
        name = str(self.preset_combo.itemData(index) or "")
        if not name or name == self._selected_preset:
            return
        self._selected_preset = name
        self.preset_selected.emit(name)
        if self._status.state in ("running", "starting"):
            # The combo shows what runs: switching it restarts on that preset.
            self.start_requested.emit(name)
        self._render()

    def _open_kind(self, kind: str) -> None:
        self._kind_page.open_kind(kind, self._settings)
        self.show_sub_page(self._kind_page)

    def _on_kind_applied(self, settings: ZapretTargetSettings) -> None:
        self._settings = settings
        self._render()
        self.show_root()
        self.target_settings_changed.emit(settings)

    def _reload_presets(self, select: str = "") -> None:
        self.set_presets(presets.list_preset_infos(), select)

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

    def _on_delete(self, name: str) -> None:
        box = MessageBox("Удаление пресета", f"Удалить «{name}»?", self.window())
        box.yesButton.setText("Удалить")
        box.cancelButton.setText("Отмена")
        if not box.exec():
            return
        if name == self._status.preset and self._status.state in ("running", "starting"):
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
        running = self._status.state in ("running", "starting")
        self._reload_presets()
        self.show_sub_page(self._presets_page)
        if running and self._status.preset in (original, name):
            # winws2 reads the file at launch: restart it on what was saved.
            self._selected_preset = name
            self.start_requested.emit(name)
