"""Zapret (DPI bypass) page — compact preset list + selected-server subpage."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from PyQt6.QtCore import QModelIndex, QRect, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QCursor, QFont, QPainter
from PyQt6.QtWidgets import (
    QFileDialog, QHBoxLayout, QListWidgetItem, QStyleOptionViewItem,
    QVBoxLayout, QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    CardWidget,
    FluentIcon as FIF,
    IndeterminateProgressBar,
    ListWidget,
    PlainTextEdit,
    PrimaryPushButton,
    PrimaryToolButton,
    StrongBodyLabel,
    SubtitleLabel,
    SwitchButton,
    TransparentToolButton,
    VerticalSeparator,
    setCustomStyleSheet,
)
from qfluentwidgets import RoundMenu, Action
from qfluentwidgets.components.widgets.list_view import ListItemDelegate

from ..models import Node, ZapretTargetSettings
from ..zapret_manager import PresetInfo, ZapretManager
from ..zapret_target import (
    ResolvedZapretEndpoint,
    endpoint_spec_for_node,
    load_strategy_catalog,
    strategy_for_target,
    validate_custom_strategy,
)
from .detail_page import DetailPage, StackedSection
from .preset_edit_widget import PresetEditWidget
from .strategy_picker import CUSTOM_STRATEGY_ID, StrategyPicker
from .theme import (
    accent_color,
    on_theme_or_accent_changed,
    text_muted_color,
    token_pair,
)

#: Fallback strategies so a group can never be enabled without a runnable body.
DEFAULT_TCP_STRATEGY = "alt9"
DEFAULT_UDP_STRATEGY = "general_bf_32"

_GROUP_TITLES = {
    "tcp_proxy": "TCP-прокси",
    "quic_proxy": "QUIC-прокси",
    "wireguard": "WireGuard",
}
_PRESET_ROW_HEIGHT = 32


def _status_qss(token: str) -> tuple[str, str]:
    light, dark = token_pair(token)
    return (
        f"BodyLabel {{ color: {light}; }}",
        f"BodyLabel {{ color: {dark}; }}",
    )


class SelectedServerZapretPage(DetailPage):
    """Bypass policy for the currently selected VPN endpoint.

    Only the transport the selected server actually uses gets a strategy
    section: a TCP node never needs the 66-entry UDP catalog on screen, and the
    page is rebuilt on every visit, so there is nothing to keep in sync.
    """

    apply_requested = pyqtSignal(object)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(
            "Zapret",
            "Выбранный сервер",
            parent,
            root_key="zapret",
            page_key="selected-server",
        )
        self._settings = ZapretTargetSettings()
        self._node: Node | None = None
        self._resolved: ResolvedZapretEndpoint | None = None
        self._transport = "tcp"
        self._group = ""
        self._original: tuple = ()

        self.validation_label = CaptionLabel("", self)
        self.apply_btn = PrimaryPushButton(FIF.ACCEPT, "Применить", self)
        self.apply_btn.clicked.connect(self._apply)
        self.add_header_action(self.validation_label)
        self.add_header_action(self.apply_btn)

        # ── server card ──
        live = CardWidget(self)
        live_layout = QVBoxLayout(live)
        live_layout.setContentsMargins(16, 12, 16, 12)
        live_layout.setSpacing(3)
        self.live_title = StrongBodyLabel("Сервер не выбран", live)
        self.live_details = CaptionLabel("—", live)
        self.live_details.setWordWrap(True)
        self.live_state = CaptionLabel("Профиль не подготовлен", live)
        live_layout.addWidget(self.live_title)
        live_layout.addWidget(self.live_details)
        live_layout.addWidget(self.live_state)
        self.content_layout.addWidget(live)

        # ── protocol groups ──
        groups = CardWidget(self)
        groups_layout = QVBoxLayout(groups)
        groups_layout.setContentsMargins(16, 12, 16, 12)
        groups_layout.setSpacing(6)
        groups_layout.addWidget(StrongBodyLabel("Для каких серверов включён обход", groups))
        self.tcp_switch, self._tcp_mark = self._group_row(
            groups_layout, groups, "TCP-прокси", "VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP",
        )
        self.quic_switch, self._quic_mark = self._group_row(
            groups_layout, groups, "QUIC-прокси", "Hysteria, Hysteria2, TUIC, QUIC/KCP",
        )
        self.wg_switch, self._wg_mark = self._group_row(
            groups_layout, groups, "WireGuard", "WireGuard и AmneziaWG",
        )
        self.content_layout.addWidget(groups)

        # ── strategy section (single transport) ──
        strategy_card = CardWidget(self)
        strategy_layout = QVBoxLayout(strategy_card)
        strategy_layout.setContentsMargins(16, 12, 16, 12)
        strategy_layout.setSpacing(8)
        self.strategy_card = strategy_card
        self.disabled_hint = BodyLabel("", strategy_card)
        self.disabled_hint.setWordWrap(True)
        self.disabled_hint.hide()
        strategy_layout.addWidget(self.disabled_hint)
        self.picker = StrategyPicker(strategy_card)
        strategy_layout.addWidget(self.picker)
        self.custom_edit = PlainTextEdit(strategy_card)
        self.custom_edit.setPlaceholderText("# комментарий\n--lua-desync=...")
        self.custom_edit.setMaximumHeight(84)
        self.custom_edit.hide()
        strategy_layout.addWidget(self.custom_edit)
        self.content_layout.addWidget(strategy_card)
        self.content_layout.addStretch(1)

        self.picker.selection_changed.connect(self._on_strategy_selected)
        self.custom_edit.textChanged.connect(self._on_form_edited)
        self._load_transport("tcp")
        self.mark_clean()

    # ── construction helpers ──

    def _group_row(
        self, layout: QVBoxLayout, parent: QWidget, title: str, hint: str,
    ) -> tuple[SwitchButton, CaptionLabel]:
        """One switch row whose caption survives being switched on.

        ``SwitchButton(text)`` only fills the *off* caption, so an enabled
        switch used to replace the whole protocol list with the word "On".
        """

        row = QWidget(parent)
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(8)
        text_layout = QVBoxLayout()
        text_layout.setSpacing(0)
        text_layout.addWidget(BodyLabel(title, row))
        hint_label = CaptionLabel(hint, row)
        text_layout.addWidget(hint_label)
        row_layout.addLayout(text_layout, 1)
        mark = CaptionLabel("", row)
        row_layout.addWidget(mark)
        switch = SwitchButton(row)
        switch.setOnText("")
        switch.setOffText("")
        row_layout.addWidget(switch)
        layout.addWidget(row)
        switch.checkedChanged.connect(lambda _checked: self._on_form_edited())
        return switch, mark

    # ── transport handling ──

    def _load_transport(self, transport: str) -> None:
        self._transport = transport if transport in ("tcp", "udp") else "tcp"
        title = "TCP-стратегия" if self._transport == "tcp" else "UDP-стратегия"
        self.picker.set_entries(title, load_strategy_catalog(self._transport))
        self.picker.set_selected(self._settings_strategy_id())
        self._set_custom_text(
            self._settings.tcp_custom_args
            if self._transport == "tcp"
            else self._settings.udp_custom_args
        )
        self._sync_custom_editor()
        # Rebuilding the form for another node is not an unsaved edit, but the
        # group switches belong to the user, not to the node: keep their baseline
        # so real edits still count as dirty across a node switch.  An unapplied
        # custom body is transport-bound and does not survive the switch.
        switches = self._original[:3] if self._original else None
        self.mark_clean()
        if switches is not None:
            self._original = switches + self._original[3:]

    def _settings_strategy_id(self) -> str:
        if self._transport == "tcp":
            return self._settings.tcp_strategy_id or DEFAULT_TCP_STRATEGY
        # A UDP node ships with an empty id, so without a default the picker
        # would open with nothing selected and refuse to apply.
        return self._settings.udp_strategy_id or DEFAULT_UDP_STRATEGY

    def _set_custom_text(self, text: str) -> None:
        """Fill the editor programmatically without reporting a user edit."""

        if self.custom_edit.toPlainText() == text:
            return
        self.custom_edit.blockSignals(True)
        self.custom_edit.setPlainText(text)
        self.custom_edit.blockSignals(False)

    def _sync_custom_editor(self) -> None:
        is_custom = self.picker.selected_id() == CUSTOM_STRATEGY_ID
        self.custom_edit.setVisible(is_custom)

    def _on_strategy_selected(self, _strategy_id: str) -> None:
        self._sync_custom_editor()
        self._on_form_edited()

    def _on_form_edited(self) -> None:
        """A fresh edit invalidates whatever the last apply reported."""

        self.validation_label.setText("")
        self._refresh_summary()
        self._sync_strategy_section()

    def _group_switch(self, group: str) -> SwitchButton:
        if group == "tcp_proxy":
            return self.tcp_switch
        if group == "quic_proxy":
            return self.quic_switch
        return self.wg_switch

    def _sync_strategy_section(self) -> None:
        """Hide the catalog while the bypass is off — the choice changes nothing."""

        if not self._group:
            enabled = True
        else:
            enabled = self._group_switch(self._group).isChecked()
        self.picker.setVisible(enabled)
        self.custom_edit.setVisible(
            enabled and self.picker.selected_id() == CUSTOM_STRATEGY_ID
        )
        self.disabled_hint.setVisible(not enabled)
        if not enabled:
            title = _GROUP_TITLES.get(self._group, self._group)
            self.disabled_hint.setText(
                f"Обход для этого сервера выключен. Включите «{title}» выше, "
                "чтобы выбрать стратегию."
            )

    # ── dirty tracking ──

    def _snapshot(self) -> tuple:
        return (
            self.tcp_switch.isChecked(),
            self.quic_switch.isChecked(),
            self.wg_switch.isChecked(),
            self.picker.selected_id(),
            self.custom_edit.toPlainText(),
        )

    def mark_clean(self) -> None:
        self._original = self._snapshot()

    def is_dirty(self) -> bool:
        return bool(self._original) and self._snapshot() != self._original

    # ── public API ──

    def set_settings(self, settings: ZapretTargetSettings, *, force: bool = False) -> None:
        """Push stored settings into the form.

        Any settings change in the app used to reach this page and overwrite
        edits in progress, so an unapplied form now wins unless forced.
        """

        if self.is_dirty() and not force:
            # Keep the user's on-screen edits, but still track the stored values:
            # apply() reads the other transport's fields from here, and a stale
            # copy would silently roll that transport back.
            self._settings = replace(settings)
            return
        self._settings = replace(settings)
        self.tcp_switch.setChecked(settings.tcp_proxy_enabled)
        self.quic_switch.setChecked(settings.quic_proxy_enabled)
        self.wg_switch.setChecked(settings.wireguard_enabled)
        self._set_custom_text(
            settings.tcp_custom_args if self._transport == "tcp" else settings.udp_custom_args
        )
        self.picker.set_selected(self._settings_strategy_id())
        self._sync_custom_editor()
        self._sync_strategy_section()
        self.mark_clean()

    def set_target(
        self,
        node: Node | None,
        resolved: ResolvedZapretEndpoint | None = None,
        state: str = "",
    ) -> None:
        self._node = node
        self._resolved = resolved
        spec = endpoint_spec_for_node(node)
        self._group = spec.group if spec else ""
        if spec is not None and spec.transport != self._transport:
            self._load_transport(spec.transport)
        self.live_title.setText(node.name if node else "Сервер не выбран")
        self._refresh_summary()
        self.live_state.setText(state or ("Готов" if resolved else "Профиль не подготовлен"))
        self._mark_active_group()
        self._sync_strategy_section()

    def _mark_active_group(self) -> None:
        for group, mark in (
            ("tcp_proxy", self._tcp_mark),
            ("quic_proxy", self._quic_mark),
            ("wireguard", self._wg_mark),
        ):
            active = group == self._group
            mark.setText("этот сервер" if active else "")
            mark.setVisible(active)

    def _refresh_summary(self) -> None:
        spec = endpoint_spec_for_node(self._node)
        if spec is None:
            self.live_details.setText("Для выбранной ноды точечный профиль не применяется")
            return
        resolved = self._resolved
        ips = ", ".join(resolved.ips) if resolved and resolved.spec == spec else "DNS ещё не выполнен"
        entry = self.picker.selected_entry()
        if self.picker.selected_id() == CUSTOM_STRATEGY_ID:
            strategy_name = "своя стратегия"
        elif entry is not None:
            strategy_name = entry.name
        else:
            strategy_name = "не выбрана"
        group_title = _GROUP_TITLES.get(spec.group, spec.group)
        self.live_details.setText(
            f"{group_title} · {spec.transport.upper()} · "
            f"{', '.join(spec.hosts)}:{spec.port_filter}\n"
            f"IP: {ips} · Стратегия: {strategy_name}"
        )

    def set_runtime_state(self, text: str) -> None:
        self.live_state.setText(text or "Профиль не подготовлен")
        if "сохранен" in text.casefold():
            self.validation_label.setText("Сохранено")

    # ── apply ──

    def _apply(self) -> None:
        strategy_id = self.picker.selected_id()
        custom_text = self.custom_edit.toPlainText()
        if not strategy_id:
            self.validation_label.setText("Выберите стратегию из каталога")
            return
        if strategy_id == CUSTOM_STRATEGY_ID:
            try:
                validate_custom_strategy(custom_text)
            except ValueError as exc:
                self.validation_label.setText(str(exc))
                return
        settings = self._settings
        if self._transport == "tcp":
            tcp_id, udp_id = strategy_id, settings.udp_strategy_id
            tcp_custom, udp_custom = custom_text, settings.udp_custom_args
        else:
            tcp_id, udp_id = settings.tcp_strategy_id or DEFAULT_TCP_STRATEGY, strategy_id
            tcp_custom, udp_custom = settings.tcp_custom_args, custom_text
        if (self.quic_switch.isChecked() or self.wg_switch.isChecked()) and not udp_id:
            # A UDP group without a body used to refuse the whole save; fall back
            # to the shipped default instead of trapping the user.
            udp_id = DEFAULT_UDP_STRATEGY
        updated = ZapretTargetSettings(
            tcp_proxy_enabled=self.tcp_switch.isChecked(),
            quic_proxy_enabled=self.quic_switch.isChecked(),
            wireguard_enabled=self.wg_switch.isChecked(),
            tcp_strategy_id=tcp_id or DEFAULT_TCP_STRATEGY,
            udp_strategy_id=udp_id,
            tcp_custom_args=tcp_custom,
            udp_custom_args=udp_custom,
        )
        self._settings = replace(updated)
        self.validation_label.setText("Применяется…")
        self.mark_clean()
        self.apply_requested.emit(updated)


class PresetItemDelegate(ListItemDelegate):
    """Thin one-line preset row: name, then meta and an "active" badge."""

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex) -> QSize:
        size = super().sizeHint(option, index)
        return QSize(size.width(), _PRESET_ROW_HEIGHT)

    def initStyleOption(self, option: QStyleOptionViewItem, index: QModelIndex) -> None:
        # The base delegate re-reads DisplayRole here, so clearing the text in
        # paint() is too late — both lines are drawn by this delegate instead.
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
            width = min(200, painter.fontMetrics().horizontalAdvance(meta) + 8)
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


class ZapretPage(StackedSection):
    start_requested = pyqtSignal(str)   # preset name
    stop_requested = pyqtSignal()
    target_settings_changed = pyqtSignal(object)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("zapret")

        self._presets: list[PresetInfo] = []
        self._running = False
        self._active_preset = ""
        self._target_settings = ZapretTargetSettings()

        list_page = QWidget()
        root = QVBoxLayout(list_page)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(SubtitleLabel("Обход блокировок (zapret)", list_page))

        # ── selected-server entry point ──
        self.target_card = CardWidget(list_page)
        target_layout = QHBoxLayout(self.target_card)
        target_layout.setContentsMargins(16, 12, 16, 12)
        target_text = QVBoxLayout()
        target_text.setSpacing(3)
        target_text.addWidget(StrongBodyLabel("Обход выбранного сервера", self.target_card))
        self.target_summary = CaptionLabel("Сервер не выбран", self.target_card)
        self.target_summary.setWordWrap(True)
        target_text.addWidget(self.target_summary)
        target_layout.addLayout(target_text, 1)
        self.target_open_btn = PrimaryPushButton(FIF.SETTING, "Настроить", self.target_card)
        target_layout.addWidget(self.target_open_btn)
        root.addWidget(self.target_card)

        # ── preset toolbar + status on one thin row ──
        toolbar = QHBoxLayout()
        toolbar.setSpacing(4)
        toolbar.addWidget(BodyLabel("Пресеты", list_page))
        self.count_label = CaptionLabel("", list_page)
        toolbar.addWidget(self.count_label)
        toolbar.addSpacing(8)
        self.add_btn = PrimaryToolButton(FIF.ADD, list_page)
        self.add_btn.setToolTip("Создать новый пресет")
        toolbar.addWidget(self.add_btn)
        self.import_btn = TransparentToolButton(FIF.FOLDER, list_page)
        self.import_btn.setToolTip("Импорт из файла")
        toolbar.addWidget(self.import_btn)
        self.delete_btn = TransparentToolButton(FIF.DELETE, list_page)
        self.delete_btn.setToolTip("Удалить пресет")
        toolbar.addWidget(self.delete_btn)
        self.refresh_btn = TransparentToolButton(FIF.SYNC, list_page)
        self.refresh_btn.setToolTip("Обновить список")
        toolbar.addWidget(self.refresh_btn)
        toolbar.addStretch(1)
        self.status_label = BodyLabel("Остановлен", list_page)
        toolbar.addWidget(self.status_label)
        self.progress = IndeterminateProgressBar(list_page)
        self.progress.setFixedHeight(3)
        self.progress.setFixedWidth(90)
        self.progress.hide()
        toolbar.addWidget(self.progress)
        toolbar.addWidget(VerticalSeparator(list_page))
        self.start_btn = TransparentToolButton(FIF.PLAY_SOLID, list_page)
        self.start_btn.setToolTip("Запустить выбранный пресет")
        toolbar.addWidget(self.start_btn)
        self.stop_btn = TransparentToolButton(FIF.PAUSE_BOLD, list_page)
        self.stop_btn.setToolTip("Остановить zapret")
        self.stop_btn.setEnabled(False)
        toolbar.addWidget(self.stop_btn)
        root.addLayout(toolbar)

        # ── thin preset list ──
        self.preset_list = ListWidget(list_page)
        self.preset_list.setItemDelegate(PresetItemDelegate(self.preset_list))
        self.preset_list.setUniformItemSizes(True)
        self.preset_list.setVerticalScrollMode(ListWidget.ScrollMode.ScrollPerItem)
        self.preset_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        root.addWidget(self.preset_list, 1)

        self.hint_label = CaptionLabel(
            "winws2 работает независимо от VPN и требует прав администратора. "
            "Двойной клик — редактирование пресета.",
            list_page,
        )
        self.hint_label.setWordWrap(True)
        root.addWidget(self.hint_label)

        self.set_root_page(list_page)

        self._editor = PresetEditWidget(self)
        self.add_sub_page(self._editor)
        self._target_page = SelectedServerZapretPage(self)
        self.add_sub_page(self._target_page)

        self.add_btn.clicked.connect(self._on_create)
        self.import_btn.clicked.connect(self._on_import)
        self.delete_btn.clicked.connect(self._on_delete)
        self.refresh_btn.clicked.connect(self.refresh_presets)
        self.start_btn.clicked.connect(self._on_start)
        self.stop_btn.clicked.connect(self._on_stop)
        self.preset_list.doubleClicked.connect(self._on_double_click)
        self.preset_list.customContextMenuRequested.connect(self._on_context_menu)
        self._editor.save_requested.connect(self._on_save_preset)
        self.target_open_btn.clicked.connect(lambda: self.show_sub_page(self._target_page))
        self._target_page.apply_requested.connect(self.target_settings_changed)
        on_theme_or_accent_changed(self._on_theme_changed)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        # The layout has not settled while the resize is still being delivered,
        # so the row fit is deferred to the end of the event loop turn.
        QTimer.singleShot(0, self._fit_preset_list)

    def _fit_preset_list(self) -> None:
        """Show whole preset rows only — a sliced last row reads as a glitch."""

        if not self.preset_list.isVisible():
            return
        overhead = self.preset_list.height() - self.preset_list.viewport().height()
        available = self.preset_list.height() - overhead
        rows = max(3, available // _PRESET_ROW_HEIGHT)
        wanted = rows * _PRESET_ROW_HEIGHT + overhead
        if self.preset_list.maximumHeight() != wanted:
            self.preset_list.setMaximumHeight(wanted)

    def _on_theme_changed(self, *args) -> None:
        self._reload_list(self.current_preset())

    # ── Public API ──

    def set_presets(self, infos: list[PresetInfo], selected: str = "") -> None:
        self._presets = list(infos)
        self._reload_list(selected)

    def set_running(self, running: bool, preset_name: str = "") -> None:
        self._running = running
        if running:
            self._active_preset = preset_name
            self.status_label.setText(f"Работает: {preset_name}")
            setCustomStyleSheet(self.status_label, *_status_qss("success"))
            self.progress.show()
            self.progress.start()
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
        else:
            self._active_preset = ""
            self.status_label.setText("Остановлен")
            setCustomStyleSheet(self.status_label, "", "")
            self.progress.stop()
            self.progress.hide()
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
        self._reload_list(self.current_preset())

    def set_error(self, message: str) -> None:
        self.set_running(False)
        self.status_label.setText(f"Ошибка: {message}")
        setCustomStyleSheet(self.status_label, *_status_qss("error"))

    def set_target_settings(self, settings: ZapretTargetSettings) -> None:
        self._target_settings = replace(settings)
        self._target_page.set_settings(settings)

    def set_target(
        self,
        node: Node | None,
        resolved: ResolvedZapretEndpoint | None = None,
        state: str = "",
    ) -> None:
        self._target_page.set_target(node, resolved, state)
        spec = endpoint_spec_for_node(node)
        if spec is None:
            summary = f"{node.name}: профиль не применяется" if node else "Сервер не выбран"
        else:
            ips = ", ".join(resolved.ips) if resolved and resolved.spec == spec else "DNS ожидается"
            try:
                strategy = strategy_for_target(self._target_settings, spec)
                strategy_name = strategy.name if strategy else "обход выключен"
                if strategy is not None and strategy.strategy_id == "pass":
                    strategy_name = "обход выключен"
            except ValueError:
                strategy_name = "не выбрана"
            summary = (
                f"{node.name} · {spec.transport.upper()} {spec.port_filter} · "
                f"{', '.join(spec.hosts)} · {ips} · {strategy_name}"
            )
        if state:
            summary += f" · {state}"
        self.target_summary.setText(summary)

    def set_target_runtime_state(self, text: str) -> None:
        self._target_page.set_runtime_state(text)

    def current_preset(self) -> str:
        row = self.preset_list.currentRow()
        if 0 <= row < len(self._presets):
            return self._presets[row].name
        return ""

    def refresh_presets(self) -> None:
        selected = self.current_preset()
        self._presets = ZapretManager.list_preset_infos()
        self._reload_list(selected)

    # ── list ──

    def _reload_list(self, select_name: str = "") -> None:
        self.preset_list.blockSignals(True)
        self.preset_list.clear()
        select_row = -1
        for row, preset in enumerate(self._presets):
            item = QListWidgetItem(preset.name)
            item.setData(
                Qt.ItemDataRole.UserRole + 1,
                preset.description or f"{preset.arg_count} арг.",
            )
            if self._running and preset.name == self._active_preset:
                item.setData(Qt.ItemDataRole.UserRole + 2, "Активен")
            item.setSizeHint(QSize(0, _PRESET_ROW_HEIGHT))
            item.setToolTip(
                f"{preset.name}\nАргументов: {preset.arg_count}\n"
                f"Изменён: {self._format_date(preset.modified)}"
            )
            self.preset_list.addItem(item)
            if preset.name == select_name:
                select_row = row
        self.preset_list.blockSignals(False)
        self.count_label.setText(f"{len(self._presets)}")
        if select_row >= 0:
            self.preset_list.setCurrentRow(select_row)

    @staticmethod
    def _format_date(iso: str) -> str:
        if not iso:
            return ""
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(iso)
            return dt.strftime("%Y-%m-%d %H:%M")
        except (ValueError, TypeError):
            return iso

    # ── Handlers ──

    def _on_start(self) -> None:
        name = self.current_preset()
        if name:
            self.start_requested.emit(name)

    def _on_stop(self) -> None:
        self.stop_requested.emit()

    def _on_double_click(self, index) -> None:
        row = index.row()
        if 0 <= row < len(self._presets):
            self._open_editor(self._presets[row])

    def _on_create(self) -> None:
        self._editor.set_preset("", "", "")
        self.show_sub_page(self._editor)

    def _on_import(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Импорт пресета", "", "Текстовые файлы (*.txt);;Все файлы (*)"
        )
        if not path:
            return
        info = ZapretManager.import_preset(Path(path))
        if info:
            self.refresh_presets()
            self._reload_list(info.name)
        else:
            self.status_label.setText("Не удалось импортировать пресет")
            setCustomStyleSheet(self.status_label, *_status_qss("error"))

    def _on_delete(self) -> None:
        name = self.current_preset()
        if not name:
            return
        from qfluentwidgets import MessageBox
        box = MessageBox("Удаление пресета", f"Удалить «{name}»?", self.window())
        box.yesButton.setText("Удалить")
        box.cancelButton.setText("Отмена")
        if box.exec():
            if self._running and name == self._active_preset:
                self.stop_requested.emit()
            ZapretManager.delete_preset(name)
            self.refresh_presets()

    def _on_save_preset(self, name: str, description: str, content: str) -> None:
        ZapretManager.save_preset(name, content, description)
        self.refresh_presets()
        self._reload_list(name)
        self.show_root()

    def _open_editor(self, info: PresetInfo) -> None:
        content = ZapretManager.read_preset(info.name)
        self._editor.set_preset(info.name, info.description, content,
                                info.created, info.modified)
        self.show_sub_page(self._editor)

    def _on_context_menu(self, pos) -> None:
        item = self.preset_list.itemAt(pos)
        if item is None:
            return
        row = self.preset_list.row(item)
        if not (0 <= row < len(self._presets)):
            return
        preset = self._presets[row]
        self.preset_list.setCurrentRow(row)

        menu = RoundMenu(parent=self)
        edit_action = Action("Редактировать", self)
        edit_action.triggered.connect(lambda: self._open_editor(preset))
        menu.addAction(edit_action)
        start_action = Action("Запустить", self)
        start_action.triggered.connect(lambda: self.start_requested.emit(preset.name))
        menu.addAction(start_action)
        menu.addSeparator()
        delete_action = Action("Удалить", self)
        delete_action.triggered.connect(self._on_delete)
        menu.addAction(delete_action)
        menu.exec(QCursor.pos())
