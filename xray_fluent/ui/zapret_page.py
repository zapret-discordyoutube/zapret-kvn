"""Zapret (DPI bypass) management page — preset table + editor subpage."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import cast

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QBrush, QCursor
from PyQt6.QtWidgets import (
    QAbstractItemView, QFileDialog, QHBoxLayout, QHeaderView,
    QTableWidgetItem, QVBoxLayout, QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    CardWidget,
    ComboBox,
    FluentIcon as FIF,
    IndeterminateProgressBar,
    PlainTextEdit,
    PrimaryPushButton,
    PrimaryToolButton,
    SearchLineEdit,
    SubtitleLabel,
    SwitchButton,
    TableWidget,
    TransparentPushButton,
    TransparentToolButton,
    VerticalSeparator,
    setCustomStyleSheet,
)
from qfluentwidgets import RoundMenu, Action

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
from .theme import accent_color, accent_soft_bg, on_theme_or_accent_changed, token_pair


def _status_qss(token: str) -> tuple[str, str]:
    light, dark = token_pair(token)
    return (
        f"BodyLabel {{ color: {light}; }}",
        f"BodyLabel {{ color: {dark}; }}",
    )


class SelectedServerZapretPage(DetailPage):
    """TCP/UDP strategy policy for the currently selected VPN endpoint."""

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
        self._catalogs = {
            "tcp": load_strategy_catalog("tcp"),
            "udp": load_strategy_catalog("udp"),
        }

        self.apply_btn = PrimaryPushButton(FIF.ACCEPT, "Применить", self)
        self.apply_btn.clicked.connect(self._apply)
        self.add_header_action(self.apply_btn)

        live = CardWidget(self)
        live_layout = QVBoxLayout(live)
        live_layout.setContentsMargins(16, 12, 16, 12)
        self.live_title = BodyLabel("Сервер не выбран", live)
        self.live_details = CaptionLabel("—", live)
        self.live_details.setWordWrap(True)
        self.live_state = CaptionLabel("Профиль не подготовлен", live)
        live_layout.addWidget(self.live_title)
        live_layout.addWidget(self.live_details)
        live_layout.addWidget(self.live_state)
        self.content_layout.addWidget(live)

        groups = CardWidget(self)
        groups_layout = QVBoxLayout(groups)
        groups_layout.setContentsMargins(16, 12, 16, 12)
        groups_layout.addWidget(BodyLabel("Группы протоколов", groups))
        self.tcp_switch = SwitchButton("TCP-прокси: VLESS, VMess, Trojan, SS, SOCKS, HTTP", groups)
        self.quic_switch = SwitchButton("QUIC-прокси: Hysteria, Hysteria2, TUIC, QUIC/KCP", groups)
        self.wg_switch = SwitchButton("WireGuard / AmneziaWG", groups)
        groups_layout.addWidget(self.tcp_switch)
        groups_layout.addWidget(self.quic_switch)
        groups_layout.addWidget(self.wg_switch)
        self.content_layout.addWidget(groups)

        self.tcp_search, self.tcp_combo, self.tcp_desc, self.tcp_preview, self.tcp_custom = \
            self._strategy_card("TCP", "tcp")
        self.udp_search, self.udp_combo, self.udp_desc, self.udp_preview, self.udp_custom = \
            self._strategy_card("UDP", "udp")
        self.validation_label = CaptionLabel("", self)
        self.validation_label.setWordWrap(True)
        self.content_layout.addWidget(self.validation_label)
        self.content_layout.addStretch(1)

        self.tcp_search.textChanged.connect(lambda text: self._fill_combo("tcp", text))
        self.udp_search.textChanged.connect(lambda text: self._fill_combo("udp", text))
        self.tcp_combo.currentIndexChanged.connect(lambda _i: self._show_strategy("tcp"))
        self.udp_combo.currentIndexChanged.connect(lambda _i: self._show_strategy("udp"))
        self._fill_combo("tcp")
        self._fill_combo("udp")

    def _strategy_card(self, title: str, transport: str):
        card = CardWidget(self)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)
        layout.addWidget(BodyLabel(f"{title}-стратегия", card))
        search = SearchLineEdit(card)
        search.setPlaceholderText("Поиск по каталогу")
        combo = ComboBox(card)
        description = CaptionLabel("", card)
        description.setWordWrap(True)
        preview = PlainTextEdit(card)
        preview.setReadOnly(True)
        preview.setMaximumHeight(94)
        custom = PlainTextEdit(card)
        custom.setPlaceholderText("# комментарий\n--lua-desync=...")
        custom.setMaximumHeight(120)
        custom.hide()
        layout.addWidget(search)
        layout.addWidget(combo)
        layout.addWidget(description)
        layout.addWidget(preview)
        layout.addWidget(custom)
        self.content_layout.addWidget(card)
        return search, combo, description, preview, custom

    def _controls(self, transport: str):
        if transport == "tcp":
            return self.tcp_combo, self.tcp_desc, self.tcp_preview, self.tcp_custom
        return self.udp_combo, self.udp_desc, self.udp_preview, self.udp_custom

    def _fill_combo(self, transport: str, query: str = "") -> None:
        combo, _desc, _preview, _custom = self._controls(transport)
        selected = combo.currentData() if combo.count() else ""
        query = str(query or "").casefold()
        combo.blockSignals(True)
        combo.clear()
        for strategy_id, entry in self._catalogs[transport].items():
            haystack = f"{entry.name} {entry.description} {' '.join(entry.args)}".casefold()
            if not query or query in haystack:
                combo.addItem(entry.name, userData=strategy_id)
        combo.addItem("Своя стратегия", userData="custom")
        for index in range(combo.count()):
            if combo.itemData(index) == selected:
                combo.setCurrentIndex(index)
                break
        combo.blockSignals(False)
        self._show_strategy(transport)

    def _show_strategy(self, transport: str) -> None:
        combo, desc, preview, custom = self._controls(transport)
        strategy_id = str(combo.currentData() or "")
        is_custom = strategy_id == "custom"
        custom.setVisible(is_custom)
        if is_custom:
            desc.setText("Разрешены только комментарии и строки --lua-desync=...")
            preview.setPlainText(custom.toPlainText())
            return
        entry = self._catalogs[transport].get(strategy_id)
        desc.setText(entry.description if entry else "Стратегия не выбрана")
        preview.setPlainText("\n".join(entry.args) if entry else "")

    @staticmethod
    def _select(combo: ComboBox, value: str) -> None:
        for index in range(combo.count()):
            if combo.itemData(index) == value:
                combo.setCurrentIndex(index)
                return

    def set_settings(self, settings: ZapretTargetSettings) -> None:
        self._settings = replace(settings)
        self.tcp_switch.setChecked(settings.tcp_proxy_enabled)
        self.quic_switch.setChecked(settings.quic_proxy_enabled)
        self.wg_switch.setChecked(settings.wireguard_enabled)
        self.tcp_custom.setPlainText(settings.tcp_custom_args)
        self.udp_custom.setPlainText(settings.udp_custom_args)
        self._select(self.tcp_combo, settings.tcp_strategy_id)
        if settings.udp_strategy_id:
            self._select(self.udp_combo, settings.udp_strategy_id)
        else:
            self.udp_combo.setCurrentIndex(-1)
            self._show_strategy("udp")
        self.validation_label.setText("")

    def set_target(
        self,
        node: Node | None,
        resolved: ResolvedZapretEndpoint | None = None,
        state: str = "",
    ) -> None:
        self._node = node
        self._resolved = resolved
        spec = endpoint_spec_for_node(node)
        self.live_title.setText(node.name if node else "Сервер не выбран")
        if spec is None:
            self.live_details.setText("Для выбранной ноды точечный профиль не применяется")
        else:
            ips = ", ".join(resolved.ips) if resolved and resolved.spec == spec else "DNS ещё не выполнен"
            try:
                strategy = strategy_for_target(self._settings, spec)
                strategy_name = strategy.name if strategy else "отключена"
            except ValueError:
                strategy_name = "не выбрана"
            self.live_details.setText(
                f"Группа: {spec.group} · {spec.transport.upper()} · "
                f"{', '.join(spec.hosts)}:{spec.port_filter}\n"
                f"IP: {ips} · Стратегия: {strategy_name}"
            )
        self.live_state.setText(state or ("Готов" if resolved else "Профиль не подготовлен"))

    def _apply(self) -> None:
        tcp_id = str(self.tcp_combo.currentData() or "")
        udp_id = str(self.udp_combo.currentData() or "")
        if (self.quic_switch.isChecked() or self.wg_switch.isChecked()) and not udp_id:
            self.validation_label.setText("Для включённой UDP-группы выберите UDP-стратегию")
            return
        try:
            if tcp_id == "custom":
                validate_custom_strategy(self.tcp_custom.toPlainText())
            if udp_id == "custom":
                validate_custom_strategy(self.udp_custom.toPlainText())
        except ValueError as exc:
            self.validation_label.setText(str(exc))
            return
        updated = ZapretTargetSettings(
            tcp_proxy_enabled=self.tcp_switch.isChecked(),
            quic_proxy_enabled=self.quic_switch.isChecked(),
            wireguard_enabled=self.wg_switch.isChecked(),
            tcp_strategy_id=tcp_id or "alt9",
            udp_strategy_id=udp_id,
            tcp_custom_args=self.tcp_custom.toPlainText(),
            udp_custom_args=self.udp_custom.toPlainText(),
        )
        self._settings = replace(updated)
        self.validation_label.setText("Настройки применяются…")
        self.apply_requested.emit(updated)

    def set_runtime_state(self, text: str) -> None:
        self.live_state.setText(text or "Профиль не подготовлен")

    def is_dirty(self) -> bool:
        return False


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

        # ══════════════ Root view: preset list ══════════════
        list_page = QWidget()
        root = QVBoxLayout(list_page)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        root.addWidget(SubtitleLabel("Обход блокировок (zapret)", list_page))

        self.target_card = CardWidget(list_page)
        target_layout = QHBoxLayout(self.target_card)
        target_layout.setContentsMargins(16, 12, 16, 12)
        target_text = QVBoxLayout()
        target_text.setSpacing(3)
        target_text.addWidget(BodyLabel("Обход выбранного сервера", self.target_card))
        self.target_summary = CaptionLabel("Сервер не выбран", self.target_card)
        self.target_summary.setWordWrap(True)
        target_text.addWidget(self.target_summary)
        target_layout.addLayout(target_text, 1)
        self.target_open_btn = TransparentPushButton("Настроить", self.target_card)
        target_layout.addWidget(self.target_open_btn)
        root.addWidget(self.target_card)

        # Info card
        info_card = CardWidget(list_page)
        info_lay = QVBoxLayout(info_card)
        info_lay.setContentsMargins(16, 12, 16, 12)
        info_lay.setSpacing(4)
        info_lay.addWidget(BodyLabel(
            "Zapret (winws2) — инструмент обхода DPI-блокировок.\n"
            "Выберите пресет и нажмите «Запустить». Работает независимо от VPN/прокси.",
            info_card,
        ))
        info_lay.addWidget(CaptionLabel(
            "Требуются права администратора. Файлы zapret должны находиться в папке zapret/ рядом с приложением.",
            info_card,
        ))
        root.addWidget(info_card)

        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(4)

        self.add_btn = PrimaryToolButton(FIF.ADD, list_page)
        self.add_btn.setToolTip("Создать новый пресет")
        toolbar.addWidget(self.add_btn)

        self.import_btn = TransparentToolButton(FIF.FOLDER, list_page)
        self.import_btn.setToolTip("Импорт из файла")
        toolbar.addWidget(self.import_btn)

        toolbar.addWidget(VerticalSeparator(list_page))

        self.delete_btn = TransparentToolButton(FIF.DELETE, list_page)
        self.delete_btn.setToolTip("Удалить пресет")
        toolbar.addWidget(self.delete_btn)

        self.refresh_btn = TransparentToolButton(FIF.SYNC, list_page)
        self.refresh_btn.setToolTip("Обновить список")
        toolbar.addWidget(self.refresh_btn)

        toolbar.addStretch()

        toolbar.addWidget(VerticalSeparator(list_page))

        self.start_btn = TransparentToolButton(FIF.PLAY_SOLID, list_page)
        self.start_btn.setToolTip("Запустить выбранный пресет")
        toolbar.addWidget(self.start_btn)

        self.stop_btn = TransparentToolButton(FIF.PAUSE_BOLD, list_page)
        self.stop_btn.setToolTip("Остановить zapret")
        self.stop_btn.setEnabled(False)
        toolbar.addWidget(self.stop_btn)

        root.addLayout(toolbar)

        # Status bar
        status_card = CardWidget(list_page)
        status_lay = QHBoxLayout(status_card)
        status_lay.setContentsMargins(16, 8, 16, 8)
        self.status_label = BodyLabel("Остановлен", status_card)
        status_lay.addWidget(self.status_label, 1)
        self.progress = IndeterminateProgressBar(status_card)
        self.progress.setFixedHeight(3)
        self.progress.hide()
        status_lay.addWidget(self.progress)
        root.addWidget(status_card)

        # Table
        self.table = TableWidget(list_page)
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Имя", "Описание", "Аргументов", "Изменён"])
        v_header = cast(QHeaderView, self.table.verticalHeader())
        v_header.setVisible(False)
        h_header = cast(QHeaderView, self.table.horizontalHeader())
        h_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        h_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        h_header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        h_header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        root.addWidget(self.table, 1)

        self.set_root_page(list_page)

        # ══════════════ Sub-page: preset editor ══════════════
        self._editor = PresetEditWidget(self)
        self.add_sub_page(self._editor)
        self._target_page = SelectedServerZapretPage(self)
        self.add_sub_page(self._target_page)

        # ── Signals ──
        self.add_btn.clicked.connect(self._on_create)
        self.import_btn.clicked.connect(self._on_import)
        self.delete_btn.clicked.connect(self._on_delete)
        self.refresh_btn.clicked.connect(self.refresh_presets)
        self.start_btn.clicked.connect(self._on_start)
        self.stop_btn.clicked.connect(self._on_stop)
        self.table.doubleClicked.connect(self._on_double_click)
        self.table.customContextMenuRequested.connect(self._on_context_menu)
        self._editor.save_requested.connect(self._on_save_preset)
        self.target_open_btn.clicked.connect(lambda: self.show_sub_page(self._target_page))
        self._target_page.apply_requested.connect(self.target_settings_changed)
        # Re-resolve the theme/accent-dependent row brushes on any change (AC6).
        on_theme_or_accent_changed(self._on_theme_changed)

    def _on_theme_changed(self, *args) -> None:
        self._reload_table(self.current_preset())

    # ── Public API ──

    def set_presets(self, infos: list[PresetInfo], selected: str = "") -> None:
        self._presets = list(infos)
        self._reload_table(selected)

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
        self._reload_table()

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
                strategy_name = strategy.name if strategy else "отключена"
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
        row = self.table.currentRow()
        if 0 <= row < len(self._presets):
            return self._presets[row].name
        return ""

    def refresh_presets(self) -> None:
        selected = self.current_preset()
        self._presets = ZapretManager.list_preset_infos()
        self._reload_table(selected)

    # ── Table ──

    def _reload_table(self, select_name: str = "") -> None:
        self.table.setUpdatesEnabled(False)
        self.table.blockSignals(True)
        self.table.setRowCount(len(self._presets))

        select_row = -1
        for row, p in enumerate(self._presets):
            name_item = QTableWidgetItem(p.name)
            desc_item = QTableWidgetItem(p.description)
            args_item = QTableWidgetItem(str(p.arg_count))
            mod_item = QTableWidgetItem(self._format_date(p.modified))

            # Highlight active preset: soft accent fill on the whole row,
            # solid accent on the name cell (active state, not "success"; D4).
            if self._running and p.name == self._active_preset:
                soft = QBrush(accent_soft_bg())
                for item in (name_item, desc_item, args_item, mod_item):
                    item.setBackground(soft)
                name_item.setForeground(QBrush(accent_color()))

            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, desc_item)
            self.table.setItem(row, 2, args_item)
            self.table.setItem(row, 3, mod_item)

            if p.name == select_name:
                select_row = row

        self.table.blockSignals(False)
        self.table.setUpdatesEnabled(True)

        if select_row >= 0:
            self.table.selectRow(select_row)

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
        if path:
            info = ZapretManager.import_preset(Path(path))
            if info:
                self.refresh_presets()
                self._reload_table(info.name)

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
        self._reload_table(name)
        self.show_root()

    def _open_editor(self, info: PresetInfo) -> None:
        content = ZapretManager.read_preset(info.name)
        self._editor.set_preset(info.name, info.description, content,
                                info.created, info.modified)
        self.show_sub_page(self._editor)

    def _on_context_menu(self, pos) -> None:
        item = self.table.itemAt(pos)
        if item is None:
            return
        row = item.row()
        if row < 0 or row >= len(self._presets):
            return

        preset = self._presets[row]
        self.table.selectRow(row)

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
