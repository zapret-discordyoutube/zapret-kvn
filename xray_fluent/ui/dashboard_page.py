"""Главная панель: статус защиты, сервер, режим, трафик, приложения, маршрутизация.

Экран читается сверху вниз так же, как в привычных VPN-клиентах:

1. **Статус** — сцена «Этот ПК ⟷ сфера ⟷ сервер» (сфера — кнопка питания),
   крупный заголовок состояния, одна понятная строка пояснения, кнопка и
   строка текущего сервера со сменой сервера;
2. **Режим работы** — две плитки «VPN (TUN)» / «Прокси» и системный прокси;
3. **Трафик** — плитки скорости/пинга/объёма и график;
4. **Приложения** и **Маршрутизация** — рядом на широком окне, друг под
   другом на узком.

Живая графика (``dashboard_widgets``) экономит CPU: таймер кадров работает
только у сцены и только пока идёт подключение или трафик, при этом страница
видна, а окно не свёрнуто.
"""

from __future__ import annotations

import math
import time
from collections import deque
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer, QEvent, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QSizePolicy,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets.common.font import getFont
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    CardWidget,
    ComboBox,
    FluentIcon as FIF,
    IndeterminateProgressBar,
    PrimaryPushButton,
    PushButton,
    StrongBodyLabel,
    SubtitleLabel,
    SwitchButton,
    TableWidget,
    TitleLabel,
    TransparentPushButton,
)

from ..diagnostics.connection_message import connection_message
from ..profiles.models import AppSettings, Node, RoutingSettings
from ..platform.windows.proxy_manager import SystemProxyState
from .base_page import BODY_MARGINS, ScrollablePage
from .connection_orb import CONNECTED, CONNECTING, ERROR, IDLE
from .dashboard_widgets import ConnectionScene, FlagBadge, ModeTile, ProcessBars, SignalBars, StatTile, latency_color
from .detail_page import DetailPage, StackedSection
from .privacy import masked_endpoint, node_name_text
from .theme import error_color, graph_down_color, graph_up_color, on_theme_or_accent_changed, positive_color
from .traffic_graph import DetailTrafficGraphWidget, TrafficGraphWidget
from .adaptive_buttons import AdaptiveButtonRow
from .pending_state import PendingValue

#: Ширина области прокрутки, ниже которой карточки встают в одну колонку.
NARROW_WIDTH = 900
# Компактная плотность: маленький экран или ноутбук с масштабом 125–150 %.
COMPACT_HEIGHT = 780
COMPACT_WIDTH = 980
# Графика тянется под окно плавно: доля высоты области просмотра с пределами.
# Текст и кнопки не масштабируются (читаемость и масштаб Windows важнее) —
# у них только две плотности.
_ORB_SHARE, _ORB_MIN, _ORB_MAX = 0.18, 96, 156
_GRAPH_SHARE, _GRAPH_MIN, _GRAPH_MAX = 0.16, 64, 170
_TITLE_PX = {True: 20, False: 24}


def hero_sizes(viewport_height: int) -> tuple[int, int, int]:
    """(диаметр сферы, поле сцены, высота графика) для высоты области просмотра."""
    orb = int(max(_ORB_MIN, min(_ORB_MAX, viewport_height * _ORB_SHARE)))
    padding = int(18 + (orb - _ORB_MIN) * 0.3)
    graph = int(max(_GRAPH_MIN, min(_GRAPH_MAX, viewport_height * _GRAPH_SHARE)))
    return orb, padding, graph


def _format_speed(value_bps: float) -> str:
    value = 0.0 if not math.isfinite(value_bps) else max(0.0, value_bps)
    units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s", "PB/s", "EB/s"]
    unit_index = 0
    while value >= 1024.0 and unit_index < len(units) - 1:
        value /= 1024.0
        unit_index += 1
    if unit_index == 0:
        return f"{int(value)} {units[unit_index]}"
    return f"{value:.2f} {units[unit_index]}"


def _format_latency(value_ms: int | None) -> str:
    if value_ms is None:
        return "--"
    return f"{value_ms} ms"


def _latency_quality(value_ms: int | None) -> str:
    if value_ms is None:
        return "Нет замера"
    if value_ms < 80:
        return "Отличная связь"
    if value_ms < 150:
        return "Хорошая связь"
    if value_ms < 300:
        return "Средняя связь"
    return "Слабая связь"


def _mode_title(mode: str) -> str:
    mapping = {
        "global": "Глобальный",
        "rule": "Правила",
        "direct": "Прямой",
    }
    return mapping.get(mode, mode.title() or "Неизвестно")


def _card_header(parent: QWidget, title: str) -> tuple[QHBoxLayout, StrongBodyLabel]:
    row = QHBoxLayout()
    row.setSpacing(8)
    label = StrongBodyLabel(title, parent)
    row.addWidget(label)
    row.addStretch(1)
    return row, label


class DashboardPage(StackedSection):
    logs_requested = pyqtSignal()
    toggle_connection_requested = pyqtSignal()
    mode_changed = pyqtSignal(str)
    tun_toggled = pyqtSignal(bool)
    proxy_toggled = pyqtSignal(bool)
    servers_requested = pyqtSignal()
    next_node_requested = pyqtSignal()
    configs_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("dashboard")

        self._node_count = 0
        self._selected_node: Node | None = None
        self._connected = False
        self._connection_phase = "idle"
        self._connection_message = "Прокси остановлен"
        self._mode = "rule"
        self._settings = AppSettings()
        self._routing = RoutingSettings()
        self._system_proxy_state: SystemProxyState | None = None
        self._selected_latency_ms: int | None = None
        self._live_rtt_ms: int | None = None
        self._proxy_socks_port = 0
        self._proxy_http_port = 0
        self._transition_busy = False
        self._initializing = False
        self._last_down_bps = 0.0
        self._last_up_bps = 0.0
        self._peak_bps = 0.0
        self._session_proxy_bytes: int | None = None
        self._down_history: deque[float] = deque(maxlen=300)
        self._up_history: deque[float] = deque(maxlen=300)
        self._last_process_stats: list | None = None
        self._connected_since: float | None = None
        self._grid_narrow = False
        self._compact: bool | None = None
        self._proxy_intent: PendingValue[bool] = PendingValue()
        self._in_grid_relayout = False
        self._title_state = IDLE

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.setInterval(30)
        self._refresh_timer.timeout.connect(self._do_refresh_dashboard)

        # ── Root view: main dashboard (scrollable, AC7) ────────
        self._main_page = ScrollablePage()
        self.set_root_page(self._main_page)

        container = self._main_page.body
        root = self._main_page.body_layout
        root.addWidget(SubtitleLabel("Панель управления", container))
        self._main_page.scroll_area.viewport().installEventFilter(self)

        self._build_connection_card(container)
        self._build_mode_card(container)
        self._build_traffic_card(container)
        self._build_processes_card(container)
        self._build_routing_card(container)

        for card in (
            self.connection_card,
            self.mode_card,
            self.traffic_card,
            self.processes_card,
            self.routing_card,
        ):
            card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        grid.addWidget(self.processes_card, 0, 0)
        grid.addWidget(self.routing_card, 0, 1)
        self._cards_grid = grid

        root.addWidget(self.connection_card)
        root.addWidget(self.mode_card)
        root.addWidget(self.traffic_card)
        root.addLayout(grid)
        root.addStretch(1)

        self._build_sub_pages()

        on_theme_or_accent_changed(self._color_traffic_captions)
        on_theme_or_accent_changed(self._color_state_title)
        self._color_traffic_captions()

        self.show_root()
        self._sync_switches()
        self._refresh_dashboard()

    # ── Построение карточек ───────────────────────────────────

    def _build_connection_card(self, container: QWidget) -> None:
        card = CardWidget(container)
        self.connection_card = card
        layout = QVBoxLayout(card)
        self._connection_layout = layout
        layout.setContentsMargins(16, 8, 16, 14)
        layout.setSpacing(4)

        # Сцена туннеля; сфера в её центре — кнопка питания.
        self.connection_scene = ConnectionScene(card, orb_diameter=_ORB_MAX)
        self.connection_orb = self.connection_scene.orb
        self.connection_orb.clicked.connect(self._on_orb_clicked)
        layout.addWidget(self.connection_scene)

        center = Qt.AlignmentFlag.AlignHCenter
        self.connection_state_label = TitleLabel("Не подключено", card)
        self.connection_state_label.setAlignment(center)
        self.connection_state_label.setWordWrap(True)
        self.connection_uptime_label = CaptionLabel("", card)
        self.connection_uptime_label.setAlignment(center)
        self.connection_uptime_label.setWordWrap(True)
        self.connection_uptime_label.hide()
        self.connection_status_label = BodyLabel("", card)
        self.connection_status_label.setAlignment(center)
        self.connection_status_label.setWordWrap(True)
        layout.addWidget(self.connection_state_label)
        layout.addWidget(self.connection_uptime_label)
        layout.addWidget(self.connection_status_label)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        buttons.addStretch(1)
        self.toggle_btn = PrimaryPushButton(FIF.PLAY_SOLID, "Подключить", card)
        self.toggle_btn.setMinimumWidth(220)
        self.toggle_btn.clicked.connect(self.toggle_connection_requested)
        buttons.addWidget(self.toggle_btn)
        self.logs_btn = PushButton(FIF.DOCUMENT, "Открыть логи", card)
        self.logs_btn.clicked.connect(self.logs_requested)
        self.logs_btn.hide()
        buttons.addWidget(self.logs_btn)
        buttons.addStretch(1)
        layout.addSpacing(6)
        layout.addLayout(buttons)
        self.startup_progress = IndeterminateProgressBar(card)
        self.startup_progress.hide()
        layout.addWidget(self.startup_progress)

        separator = QFrame(card)
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Plain)
        separator.setEnabled(False)
        layout.addSpacing(8)
        layout.addWidget(separator)
        layout.addSpacing(4)

        # Строка текущего сервера — «где я», как выбор локации в VPN-клиентах.
        self.server_row = QWidget(card)
        row = QHBoxLayout(self.server_row)
        row.setContentsMargins(0, 4, 0, 0)
        row.setSpacing(12)
        self.server_flag = FlagBadge(self.server_row, diameter=40)
        row.addWidget(self.server_flag)
        info = QVBoxLayout()
        info.setSpacing(0)
        self.server_name_label = StrongBodyLabel("Сервер не выбран", self.server_row)
        self.server_name_label.setWordWrap(True)
        self.connection_target_label = CaptionLabel("", self.server_row)
        self.connection_target_label.setWordWrap(True)
        info.addWidget(self.server_name_label)
        info.addWidget(self.connection_target_label)
        row.addLayout(info, 1)
        self.signal_bars = SignalBars(self.server_row)
        row.addWidget(self.signal_bars, 0, Qt.AlignmentFlag.AlignVCenter)
        self.server_ping_label = CaptionLabel("--", self.server_row)
        self.server_ping_label.setMinimumWidth(48)
        row.addWidget(self.server_ping_label, 0, Qt.AlignmentFlag.AlignVCenter)
        self.next_server_btn = PushButton(FIF.SYNC, "Следующий", self.server_row)
        self.next_server_btn.setToolTip("Переключиться на следующий сервер из списка")
        self.next_server_btn.clicked.connect(self.next_node_requested)
        row.addWidget(self.next_server_btn)
        self.servers_btn = PushButton(FIF.MENU, "Все серверы", self.server_row)
        self.servers_btn.clicked.connect(self.servers_requested)
        row.addWidget(self.servers_btn)
        # Не хватает места — подписи кнопок уходят в подсказки, остаются значки.
        self._server_buttons_fit = AdaptiveButtonRow(row, [self.servers_btn, self.next_server_btn])
        layout.addWidget(self.server_row)

    def _build_mode_card(self, container: QWidget) -> None:
        card = CardWidget(container)
        self.mode_card = card
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 14, 18, 16)
        layout.setSpacing(10)
        header, _title = _card_header(card, "Режим работы")
        self.connection_engine_label = CaptionLabel("", card)
        self.connection_engine_label.setWordWrap(True)
        header.addWidget(self.connection_engine_label)
        layout.addLayout(header)

        tiles = QHBoxLayout()
        tiles.setSpacing(10)
        self.vpn_tile = ModeTile(
            "vpn", "VPN (TUN)", "Весь трафик компьютера идёт через туннель — любые программы и игры", card
        )
        self.proxy_tile = ModeTile(
            "proxy", "Прокси", "Через туннель идут программы, которые используют прокси: браузеры и большинство приложений", card
        )
        # Слоты — bound-методы, не лямбды: замыкание на self держало бы
        # Python-обёртку страницы (см. motion.FrameGate про циклы владения).
        self.vpn_tile.clicked.connect(self._on_vpn_tile_clicked)
        self.proxy_tile.clicked.connect(self._on_proxy_tile_clicked)
        tiles.addWidget(self.vpn_tile, 1)
        tiles.addWidget(self.proxy_tile, 1)
        layout.addLayout(tiles)

        self.proxy_options = QWidget(card)
        options = QHBoxLayout(self.proxy_options)
        options.setContentsMargins(4, 2, 0, 0)
        options.setSpacing(12)
        texts = QVBoxLayout()
        texts.setSpacing(0)
        texts.addWidget(BodyLabel("Системный прокси Windows", self.proxy_options))
        self.proxy_hint_label = CaptionLabel(
            "Программы подхватят прокси сами; выключите, чтобы настраивать их вручную", self.proxy_options
        )
        self.proxy_hint_label.setWordWrap(True)
        texts.addWidget(self.proxy_hint_label)
        options.addLayout(texts, 1)
        self.proxy_switch = SwitchButton(self.proxy_options)
        self.proxy_switch.setOnText("Вкл")
        self.proxy_switch.setOffText("Выкл")
        self.proxy_switch.checkedChanged.connect(self._on_proxy_toggled)
        options.addWidget(self.proxy_switch, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.proxy_options)

        self.connection_ports_label = CaptionLabel("", card)
        self.connection_ports_label.setWordWrap(True)
        self.connection_ports_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.connection_ports_label.setVisible(False)
        layout.addWidget(self.connection_ports_label)

    def _build_traffic_card(self, container: QWidget) -> None:
        card = CardWidget(container)
        self.traffic_card = card
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 14, 18, 16)
        layout.setSpacing(10)
        header, _title = _card_header(card, "Трафик")
        details = TransparentPushButton(FIF.CHEVRON_RIGHT, "Подробнее", card)
        details.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        details.clicked.connect(self._show_traffic_page)
        header.addWidget(details)
        layout.addLayout(header)

        self.down_tile = StatTile("● Загрузка", card, value="0 B/s")
        self.up_tile = StatTile("● Отдача", card, value="0 B/s")
        self.ping_tile = StatTile("Пинг", card)
        self.session_tile = StatTile("Через VPN за сессию", card)
        self.traffic_down_label = self.down_tile.value_label
        self.traffic_up_label = self.up_tile.value_label
        self.traffic_rtt_label = self.ping_tile.value_label
        self.traffic_session_label = self.session_tile.value_label
        self.traffic_peak_label = self.session_tile.detail_label
        self._traffic_down_caption = self.down_tile.caption_label
        self._traffic_up_caption = self.up_tile.caption_label
        self.ping_quality_label = self.ping_tile.detail_label
        self.down_tile.detail_label.setText("к вам")
        self.up_tile.detail_label.setText("от вас")
        self._stat_tiles = (self.down_tile, self.up_tile, self.ping_tile, self.session_tile)
        stats = QGridLayout()
        stats.setHorizontalSpacing(16)
        stats.setVerticalSpacing(10)
        self._stats_grid = stats
        self._place_stat_tiles(narrow=False)
        layout.addLayout(stats)

        self.traffic_graph = TrafficGraphWidget(card)
        self.traffic_graph.clicked.connect(self._show_traffic_page)
        layout.addWidget(self.traffic_graph, 1)

    def _build_processes_card(self, container: QWidget) -> None:
        card = CardWidget(container)
        self.processes_card = card
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 14, 18, 16)
        layout.setSpacing(8)
        header, _title = _card_header(card, "Приложения")
        self.processes_btn = TransparentPushButton(FIF.CHEVRON_RIGHT, "Все", card)
        self.processes_btn.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        self.processes_btn.clicked.connect(self._show_proc_page)
        header.addWidget(self.processes_btn)
        layout.addLayout(header)
        self.process_summary_label = CaptionLabel("Статистика появится после подключения", card)
        self.process_summary_label.setWordWrap(True)
        layout.addWidget(self.process_summary_label)
        self.process_bars = ProcessBars(card, rows=4)
        self.process_bars.hide()
        layout.addWidget(self.process_bars)
        layout.addStretch(1)

    def _build_routing_card(self, container: QWidget) -> None:
        card = CardWidget(container)
        self.routing_card = card
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 14, 18, 16)
        layout.setSpacing(6)
        header, _title = _card_header(card, "Маршрутизация")
        self.configs_btn = TransparentPushButton(FIF.CODE, "Конфиг", card)
        self.configs_btn.setToolTip("Открыть редактор конфига — правила и DNS задаются там")
        self.configs_btn.clicked.connect(self.configs_requested)
        header.addWidget(self.configs_btn)
        layout.addLayout(header)
        self.routing_mode_label = BodyLabel("", card)
        self.routing_mode_label.setWordWrap(True)
        layout.addWidget(self.routing_mode_label)
        self.mode_combo = ComboBox(card)
        self.mode_combo.addItem("Глобальный", userData="global")
        self.mode_combo.addItem("Правила", userData="rule")
        self.mode_combo.addItem("Прямой", userData="direct")
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        layout.addWidget(self.mode_combo)
        self.routing_rules_label = CaptionLabel("", card)
        self.routing_bypass_label = CaptionLabel("", card)
        self.routing_dns_label = CaptionLabel("", card)
        for label in (self.routing_rules_label, self.routing_bypass_label, self.routing_dns_label):
            label.setWordWrap(True)
            layout.addWidget(label)
        layout.addStretch(1)

    def _build_sub_pages(self) -> None:
        # ── Sub-page: traffic detail (scrollable, AC7) ──
        self._traffic_detail_page = DetailPage(
            "Панель управления",
            "Трафик",
            root_key="dashboard",
            page_key="traffic",
        )
        self.add_sub_page(self._traffic_detail_page)

        detail_layout = self._traffic_detail_page.content_layout

        self._detail_graph = DetailTrafficGraphWidget(self._traffic_detail_page)
        detail_layout.addWidget(self._detail_graph, 1)

        detail_stats_row = QHBoxLayout()
        detail_stats_row.setSpacing(16)
        self._detail_down_label = BodyLabel("Загрузка: 0 B/s", self._traffic_detail_page)
        self._detail_up_label = BodyLabel("Выгрузка: 0 B/s", self._traffic_detail_page)
        self._detail_rtt_label = BodyLabel("RTT: --", self._traffic_detail_page)
        self._detail_peak_label = BodyLabel("Пик: 0 B/s", self._traffic_detail_page)
        detail_stats_row.addWidget(self._detail_down_label)
        detail_stats_row.addWidget(self._detail_up_label)
        detail_stats_row.addWidget(self._detail_rtt_label)
        detail_stats_row.addWidget(self._detail_peak_label)
        detail_stats_row.addStretch(1)
        detail_layout.addLayout(detail_stats_row)

        # ── Sub-page: process traffic detail (scrollable, AC7) ──
        self._proc_detail_page = DetailPage(
            "Панель управления",
            "Трафик по процессам",
            root_key="dashboard",
            page_key="processes",
        )
        self.add_sub_page(self._proc_detail_page)

        proc_detail_layout = self._proc_detail_page.content_layout

        col_tooltips = [
            "Имя исполняемого файла приложения",
            "Текущая скорость загрузки/выгрузки",
            "Объём трафика через VPN (зашифрованный, через прокси-сервер)",
            "Объём трафика напрямую (без VPN, к серверу напрямую)",
            "Активные соединения (всего за сессию)",
            "Домен или IP с наибольшим трафиком",
            "Общий объём трафика за сессию",
        ]
        self._proc_detail_table = TableWidget(self._proc_detail_page)
        self._proc_detail_table.setColumnCount(7)
        self._proc_detail_table.setHorizontalHeaderLabels(
            ["Процесс", "Скорость", "VPN", "Прямой", "Соединения", "Основной хост", "Всего"]
        )
        header = self._proc_detail_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        for col in (1, 2, 3, 4, 6):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        for col, tip in enumerate(col_tooltips):
            item = self._proc_detail_table.horizontalHeaderItem(col)
            if item:
                item.setToolTip(tip)
        self._proc_detail_table.verticalHeader().setVisible(False)
        self._proc_detail_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._proc_detail_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._proc_detail_table.setMinimumHeight(400)
        proc_detail_layout.addWidget(self._proc_detail_table, 1)

    # ── Adaptive card grid (AC10) ─────────────────────────────

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._update_adaptive_grid()

    def _place_stat_tiles(self, *, narrow: bool) -> None:
        for tile in self._stat_tiles:
            self._stats_grid.removeWidget(tile)
        columns = 2 if narrow else 4
        for index, tile in enumerate(self._stat_tiles):
            self._stats_grid.addWidget(tile, index // columns, index % columns)
        for column in range(4):
            self._stats_grid.setColumnStretch(column, 1 if column < columns else 0)

    def _apply_hero_size(self, viewport_height: int) -> None:
        """Сфера, сцена и график плавно следуют высоте окна."""
        orb, padding, graph = hero_sizes(viewport_height)
        if abs(orb - self.connection_orb.width()) >= 2:
            self.connection_scene.set_orb_diameter(orb, padding)
        if abs(graph - self.traffic_graph.maximumHeight()) >= 2:
            self.traffic_graph.setFixedHeight(graph)

    def _apply_density(self, compact: bool) -> None:
        """Размеры под экран: на маленьком всё меньше, чтобы главное влезало.

        Меняются только размеры и поля существующих виджетов.
        """
        self.connection_state_label.setFont(getFont(_TITLE_PX[compact], QFont.Weight.DemiBold))
        self._connection_layout.setContentsMargins(*((12, 4, 12, 10) if compact else (16, 8, 16, 14)))
        self.toggle_btn.setMinimumWidth(180 if compact else 220)
        self.server_flag.set_diameter(32 if compact else 40)
        for tile in (self.vpn_tile, self.proxy_tile):
            tile.set_compact(compact)
        body = self._main_page.body_layout
        body.setContentsMargins(*((16, 12, 16, 12) if compact else BODY_MARGINS))
        body.setSpacing(8 if compact else 12)

    def _update_adaptive_grid(self) -> None:
        """На узком окне (< 900 px) карточки встают в одну колонку.

        «Маршрутизация» уходит во вторую строку под «Приложения», плитки
        трафика — в сетку 2×2. Виджеты только переставляются, не пересоздаются.
        На маленьком экране (``COMPACT_*``) панель ещё и уменьшается.
        """
        if self._in_grid_relayout:
            return
        viewport = self._main_page.scroll_area.viewport()
        self._apply_hero_size(viewport.height())
        compact = viewport.height() < COMPACT_HEIGHT or viewport.width() < COMPACT_WIDTH
        if compact != self._compact:
            self._compact = compact
            self._apply_density(compact)
        narrow = viewport.width() < NARROW_WIDTH
        if narrow == self._grid_narrow:
            return
        self._in_grid_relayout = True
        try:
            self._grid_narrow = narrow
            self._cards_grid.removeWidget(self.routing_card)
            self._cards_grid.removeWidget(self.processes_card)
            if narrow:
                self._cards_grid.addWidget(self.processes_card, 0, 0, 1, 2)
                self._cards_grid.addWidget(self.routing_card, 1, 0, 1, 2)
            else:
                self._cards_grid.addWidget(self.processes_card, 0, 0)
                self._cards_grid.addWidget(self.routing_card, 0, 1)
            self._place_stat_tiles(narrow=narrow)
        finally:
            self._in_grid_relayout = False

    def eventFilter(self, obj, event):
        if obj is self._main_page.scroll_area.viewport() and event.type() == QEvent.Type.Resize:
            QTimer.singleShot(0, self._update_adaptive_grid)
        return super().eventFilter(obj, event)

    def set_initializing(self, initializing: bool):
        self._initializing = initializing
        self.startup_progress.setVisible(initializing)
        if initializing:
            self.startup_progress.start()
        else:
            self.startup_progress.stop()
        self._refresh_dashboard()

    # ── Public API ────────────────────────────────────────────

    def set_nodes(self, nodes: list[Node], selected_node_id: str | None) -> None:
        self._node_count = len(nodes)
        self._selected_node = next(
            (node for node in nodes if selected_node_id and node.id == selected_node_id),
            nodes[0] if nodes else None,
        )
        self._refresh_dashboard()

    def set_selected_node(self, node: Node | None) -> None:
        self._selected_node = node
        self._refresh_dashboard()

    def set_connection(self, connected: bool) -> None:
        if connected and not self._connected:
            self._connected_since = time.monotonic()
        elif not connected:
            self._connected_since = None
        self._connected = connected
        if not connected:
            self._last_down_bps = 0.0
            self._last_up_bps = 0.0
            self._live_rtt_ms = None
            self._peak_bps = 0.0
            self._session_proxy_bytes = None
            self._down_history.clear()
            self._up_history.clear()
            self.traffic_graph.clear_data()
            self.connection_scene.set_traffic(0.0, 0.0)
            self._clear_process_tables()
            self._last_process_stats = None
            self._show_process_summary("Статистика появится после подключения", [])
            if self._connection_phase == "running":
                self._connection_phase = "idle"
                self._connection_message = self._default_connection_message()
        elif self._connection_phase == "idle":
            self._connection_phase = "running"
            self._connection_message = self._default_connection_message()
        self._refresh_dashboard()

    def set_runtime_status(self, phase: str, message: str) -> None:
        normalized = (phase or "idle").strip().lower()
        if normalized not in {"idle", "starting", "running", "error"}:
            normalized = "idle"
        self._connection_phase = normalized
        self._connection_message = connection_message(message) or self._default_connection_message()
        self._refresh_dashboard()

    def set_mode(self, mode: str) -> None:
        self._mode = mode
        self._routing.mode = mode
        self.mode_combo.blockSignals(True)
        for index in range(self.mode_combo.count()):
            if self.mode_combo.itemData(index) == mode:
                self.mode_combo.setCurrentIndex(index)
                break
        self.mode_combo.blockSignals(False)
        self._refresh_dashboard()

    def set_proxy_ports(self, socks_port: int, http_port: int) -> None:
        self._proxy_socks_port = max(0, int(socks_port))
        self._proxy_http_port = max(0, int(http_port))
        self._refresh_dashboard()

    def set_tun_mode(self, enabled: bool) -> None:
        self._settings.tun_mode = enabled
        if self._connection_phase in {"idle", "running"}:
            self._connection_message = self._default_connection_message()
        self._sync_switches()
        self._refresh_dashboard()

    def set_settings_snapshot(self, settings: AppSettings) -> None:
        self._settings = settings
        if self._connection_phase in {"idle", "running"}:
            self._connection_message = self._default_connection_message()
        self._sync_switches()
        self._refresh_dashboard()

    def set_system_proxy_state(self, state: SystemProxyState | None) -> None:
        """Реальное состояние системного прокси Windows (снимок из реестра).

        На не-Windows (``supported=False``) переключатель по-прежнему отражает
        сохранённый флаг ``enable_system_proxy``.
        """
        self._system_proxy_state = state
        self._sync_switches()
        self._refresh_dashboard()

    def set_routing_snapshot(self, routing: RoutingSettings) -> None:
        self._routing = routing
        self.set_mode(routing.mode)

    def set_selected_latency(self, value: int | None) -> None:
        self._selected_latency_ms = value
        if self._selected_node is not None:
            self._selected_node.ping_ms = value
        self._refresh_dashboard()

    def set_live_metrics(self, down_bps: float, up_bps: float, latency_ms: int | None) -> None:
        self._last_down_bps = max(0.0, down_bps)
        self._last_up_bps = max(0.0, up_bps)
        self._live_rtt_ms = latency_ms
        self._peak_bps = max(self._peak_bps, self._last_down_bps, self._last_up_bps)
        self._down_history.append(self._last_down_bps)
        self._up_history.append(self._last_up_bps)
        self.traffic_graph.add_point(self._last_down_bps, self._last_up_bps)
        self.connection_scene.set_traffic(self._last_down_bps, self._last_up_bps)
        if self._stack.currentWidget() is self._traffic_detail_page:
            self._detail_graph.add_point(self._last_down_bps, self._last_up_bps)
        self._refresh_dashboard()

    def set_process_stats(self, stats: list | None) -> None:
        if stats is None:
            self._last_process_stats = None
            self._session_proxy_bytes = None
            self._clear_process_tables()
            self._show_process_summary("Статистика по приложениям недоступна для этого режима", [])
            self._refresh_dashboard()
            return
        self._last_process_stats = list(stats)
        # Счётчики процессов накопительные за сессию — сумма не теряет
        # выборки, пропущенные, пока панель была скрыта.
        self._session_proxy_bytes = sum(max(0, int(ps.proxy_bytes)) for ps in stats)
        ranked = sorted(stats, key=lambda ps: ps.upload + ps.download, reverse=True)
        top_total = max((ps.upload + ps.download for ps in ranked), default=0)
        items = [
            (ps.exe, self._format_bytes(ps.upload + ps.download),
             (ps.upload + ps.download) / top_total if top_total > 0 else 0.0)
            for ps in ranked[: self.process_bars.rows()]
        ]
        if stats:
            summary = f"Приложений с трафиком: {len(stats)}"
        else:
            summary = "Активных соединений пока нет"
        self._show_process_summary(summary, items)
        if self._stack.currentWidget() is self._proc_detail_page:
            self._apply_process_stats_to_table(self._proc_detail_table, stats)
        self._refresh_dashboard()

    def set_transition_busy(self, busy: bool) -> None:
        self._transition_busy = busy
        self._apply_interaction_state()
        self._refresh_dashboard()

    @staticmethod
    def _format_bytes(b: int) -> str:
        value = float(max(0, int(b)))
        units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"]
        unit_idx = 0
        while value >= 1024.0 and unit_idx < len(units) - 1:
            value /= 1024.0
            unit_idx += 1

        if unit_idx == 0:
            return f"{int(value)} {units[unit_idx]}"
        if unit_idx <= 2:
            return f"{value:.1f} {units[unit_idx]}"
        return f"{value:.2f} {units[unit_idx]}"

    # ── Refresh logic ─────────────────────────────────────────

    def _refresh_dashboard(self) -> None:
        if not self._refresh_timer.isActive():
            self._refresh_timer.start()

    def _do_refresh_dashboard(self) -> None:
        self._refresh_connection_card()
        self._refresh_mode_card()
        self._refresh_traffic_card()
        self._refresh_routing_card()
        self._apply_interaction_state()
        if self._stack.currentWidget() is self._traffic_detail_page:
            self._refresh_detail_stats()

    def _refresh_connection_card(self) -> None:
        self.connection_state_label.setText(self._headline())
        self.connection_status_label.setText(self._status_line())
        self.logs_btn.setVisible(self._connection_phase == "error")
        self.toggle_btn.setText("Подготовка…" if self._initializing else self._toggle_action_text())
        icon = FIF.PAUSE_BOLD if self._connected else FIF.PLAY_SOLID
        if icon is not getattr(self, "_toggle_icon", None):
            self._toggle_icon = icon
            self.toggle_btn.setIcon(icon)
        orb_state = self._orb_state()
        self.connection_orb.set_state(orb_state)
        self.connection_orb.setToolTip(self._toggle_action_text())
        self.connection_scene.set_state(orb_state)
        if orb_state != self._title_state:
            self._title_state = orb_state
            self._color_state_title()
        uptime = self._uptime_text()
        self.connection_uptime_label.setText(uptime)
        self.connection_uptime_label.setVisible(bool(uptime))

        node = self._selected_node
        country = (node.country_code or node.country_override) if node is not None else ""
        self.server_name_label.setText(self._server_title())
        self.connection_target_label.setText(self._selected_node_summary())
        self.server_flag.set_country(country)
        self.connection_scene.set_server(node_name_text(node) if node is not None else "Сервер", country)
        latency = self._effective_latency()
        self.signal_bars.set_latency(latency)
        self.server_ping_label.setText(_format_latency(latency))

    def _refresh_mode_card(self) -> None:
        core = self._settings.tun_engine if self._settings.tun_mode else self._settings.proxy_engine
        self.connection_engine_label.setText(f"Ядро: {core}")
        self.connection_engine_label.setToolTip(self._route_engine_label())
        self.proxy_options.setVisible(not self._settings.tun_mode)
        ports_text = self._proxy_ports_text()
        self.connection_ports_label.setText(ports_text)
        self.connection_ports_label.setVisible(bool(ports_text))

    def _color_state_title(self, *_args) -> None:
        """Заголовок состояния в цвет сферы: зелёный — есть защита, красный — ошибка."""
        state = self._title_state
        if state == CONNECTED:
            color = positive_color()
            self.connection_state_label.setTextColor(color, color)
        elif state == ERROR:
            color = error_color()
            self.connection_state_label.setTextColor(color, color)
        else:
            self.connection_state_label.setTextColor(QColor(0, 0, 0), QColor(255, 255, 255))

    def _orb_state(self) -> str:
        if self._initializing or self._transition_busy or self._connection_phase == "starting":
            return CONNECTING
        if self._connection_phase == "error":
            return ERROR
        if self._connected:
            return CONNECTED
        return IDLE

    def _uptime_text(self) -> str:
        if not self._connected or self._connected_since is None:
            return ""
        seconds = int(time.monotonic() - self._connected_since)
        hours, rest = divmod(seconds, 3600)
        return f"В сети {hours:d}:{rest // 60:02d}:{rest % 60:02d}"

    def _on_orb_clicked(self) -> None:
        if self.toggle_btn.isEnabled():
            self.toggle_connection_requested.emit()

    def _refresh_traffic_card(self) -> None:
        self.traffic_down_label.setText(_format_speed(self._last_down_bps))
        self.traffic_up_label.setText(_format_speed(self._last_up_bps))
        latency = self._effective_latency()
        self.traffic_rtt_label.setText(_format_latency(latency))
        self.ping_quality_label.setText(_latency_quality(latency))
        self._set_quality_color(latency_color(latency))
        if self._session_proxy_bytes is None:
            self.traffic_session_label.setText("--")
        else:
            self.traffic_session_label.setText(self._format_bytes(self._session_proxy_bytes))
        self.traffic_peak_label.setText(f"Пик: {_format_speed(self._peak_bps)}")
        if not self._connected:
            self.traffic_graph.set_placeholder("График появится после подключения")
        else:
            self.traffic_graph.set_placeholder("Ждём первые данные…")

    def _color_traffic_captions(self, *_args) -> None:
        for caption, color in ((self._traffic_down_caption, graph_down_color()),
                               (self._traffic_up_caption, graph_up_color())):
            caption.setTextColor(color, color)
        self._quality_color_name = None  # тема сменилась — цвет применить заново
        self._set_quality_color(latency_color(self._effective_latency()))

    def _set_quality_color(self, color: QColor) -> None:
        # setTextColor у меток qfluentwidgets переустанавливает стиль;
        # при обновлении раз в секунду зовём только при реальной смене цвета.
        name = color.name(QColor.NameFormat.HexArgb)
        if name == getattr(self, "_quality_color_name", None):
            return
        self._quality_color_name = name
        self.ping_quality_label.setTextColor(color, color)

    def _show_process_summary(self, summary: str, items: list[tuple[str, str, float]]) -> None:
        self.process_summary_label.setText(summary)
        self.process_bars.set_items(items)
        self.process_bars.setVisible(bool(items))

    def _refresh_routing_card(self) -> None:
        self.configs_btn.setVisible(not self._is_tun2socks_mode())
        if not self._settings.tun_mode:
            core = "sing-box" if self._is_singbox_proxy_mode() else "Xray"
            self.routing_mode_label.setText(f"Правила из конфига {core}")
            self.routing_rules_label.setText(
                "Правила работают для трафика, который пришёл в прокси; что не попало в прокси — идёт напрямую."
            )
            if self._settings.enable_system_proxy:
                self.routing_bypass_label.setText(
                    "Системный прокси Windows включён — браузеры и большинство программ идут через него."
                )
            else:
                self.routing_bypass_label.setText(
                    "Системный прокси выключен — программы нужно настроить на прокси вручную."
                )
            self.routing_dns_label.setText("DNS и правила меняются в редакторе конфига.")
            return
        if self._is_xray_tun_mode():
            self.routing_mode_label.setText("Правила из конфига Xray (экспериментальный TUN)")
            self.routing_rules_label.setText(
                "Весь трафик системы попадает в Xray — правила по процессам и путям работают для всех программ."
            )
            self.routing_bypass_label.setText(
                "Системный прокси Windows не используется; статистика по приложениям скромнее, чем у sing-box."
            )
            self.routing_dns_label.setText("DNS и правила меняются в редакторе конфига.")
            return
        if self._settings.tun_engine == "singbox":
            self.routing_mode_label.setText("Правила из конфига sing-box")
            self.routing_rules_label.setText(
                "Перехватывается весь трафик системы — правила по программам, доменам и IP работают полностью."
            )
            self.routing_bypass_label.setText(
                "Серверы xhttp и Hysteria 2 автоматически обслуживаются вспомогательными ядрами."
            )
            self.routing_dns_label.setText("DNS и правила меняются в редакторе конфига.")
            return
        self.routing_mode_label.setText(f"Режим: {_mode_title(self._routing.mode)}")
        self.routing_rules_label.setText(
            f"Напрямую: {len(self._routing.direct_domains)}   Через VPN: {len(self._routing.proxy_domains)}   "
            f"Блок: {len(self._routing.block_domains)}"
        )
        bypass = "включён" if self._routing.bypass_lan else "выключен"
        self.routing_bypass_label.setText(f"Обход локальной сети: {bypass}")
        self.routing_dns_label.setText(f"DNS: {self._routing.dns_mode.title()}")

    def _refresh_detail_stats(self) -> None:
        self._detail_down_label.setText(f"Загрузка: {_format_speed(self._last_down_bps)}")
        self._detail_up_label.setText(f"Выгрузка: {_format_speed(self._last_up_bps)}")
        self._detail_rtt_label.setText(f"RTT: {_format_latency(self._effective_latency())}")
        self._detail_peak_label.setText(f"Пик: {_format_speed(self._peak_bps)}")

    # ── Traffic subpage navigation ────────────────────────────

    def _show_traffic_page(self) -> None:
        """Switch to the traffic detail subpage."""
        self._detail_graph.set_data(self._down_history, self._up_history)
        self._refresh_detail_stats()
        self.show_sub_page(self._traffic_detail_page)

    def _show_main_page(self) -> None:
        """Switch back to the main dashboard."""
        self.show_root()

    # ── Process subpage navigation ──────────────────────────

    def _show_proc_page(self) -> None:
        self._update_proc_detail_table()
        self.show_sub_page(self._proc_detail_page)

    def _update_proc_detail_table(self) -> None:
        """Refresh detail table from the latest cached process stats."""
        self._apply_process_stats_to_table(self._proc_detail_table, self._last_process_stats or [])

    def _clear_process_tables(self) -> None:
        self._proc_detail_table.setRowCount(0)

    def _apply_process_stats_to_table(self, table: TableWidget, stats: list) -> None:
        table.setUpdatesEnabled(False)
        try:
            if table.rowCount() != len(stats):
                table.setRowCount(len(stats))
            for row, ps in enumerate(stats):
                speed = f"↓{_format_speed(ps.down_speed)}  ↑{_format_speed(ps.up_speed)}"
                conn_text = f"{ps.connections} ({ps.total_connections})" if ps.total_connections > ps.connections else str(ps.connections)
                host = ps.top_host
                if len(host) > 30:
                    host = host[:27] + "..."
                total = ps.upload + ps.download

                self._set_table_text(table, row, 0, ps.exe)
                self._set_table_text(table, row, 1, speed)
                vpn_item = self._set_table_text(table, row, 2, self._format_bytes(ps.proxy_bytes))
                vpn_item.setForeground(positive_color() if ps.proxy_bytes > 0 else QBrush())
                self._set_table_text(table, row, 3, self._format_bytes(ps.direct_bytes))
                self._set_table_text(table, row, 4, conn_text)
                self._set_table_text(table, row, 5, host)
                self._set_table_text(table, row, 6, self._format_bytes(total))
        finally:
            table.setUpdatesEnabled(True)

    def _set_table_text(self, table: TableWidget, row: int, column: int, text: str) -> QTableWidgetItem:
        item = table.item(row, column)
        if item is None:
            item = QTableWidgetItem(text)
            table.setItem(row, column, item)
            return item
        if item.text() != text:
            item.setText(text)
        return item

    # ── Helpers ───────────────────────────────────────────────

    def _effective_latency(self) -> int | None:
        return self._live_rtt_ms if self._live_rtt_ms is not None else self._selected_latency_ms

    def _is_xray_tun_mode(self) -> bool:
        return bool(self._settings.tun_mode and self._settings.tun_engine == "xray")

    def _is_tun2socks_mode(self) -> bool:
        return bool(self._settings.tun_mode and self._settings.tun_engine == "tun2socks")

    def _is_singbox_proxy_mode(self) -> bool:
        return bool(not self._settings.tun_mode and self._settings.proxy_engine == "singbox")

    def _route_engine_label(self) -> str:
        if self._settings.tun_mode:
            if self._settings.tun_engine == "singbox":
                return "VPN (TUN) -> sing-box (recommended, auto hybrid)"
            if self._is_xray_tun_mode():
                config_name = Path(self._settings.xray_config_file or "default.json").name
                return f"VPN (TUN) -> xray (experimental) · raw xray config: {config_name}"
            return "VPN (TUN) -> tun2socks"
        if self._is_singbox_proxy_mode():
            config_name = Path(self._settings.singbox_config_file or "default.json").name
            target = f"sing-box extended config: {config_name}"
        else:
            config_name = Path(self._settings.xray_config_file or "default.json").name
            target = f"xray config: {config_name}"
        if self._settings.enable_system_proxy:
            return f"Системный прокси Windows -> {target}"
        return f"Локальный proxy -> {target} (только вручную настроенные приложения)"

    def _default_connection_message(self) -> str:
        action = "VPN" if self._settings.tun_mode else "Прокси"
        return f"{action} {'работает' if self._connected else 'остановлен'}"

    def _proxy_ports_text(self) -> str:
        if (
            not self._connected
            or self._settings.tun_mode
            or self._proxy_socks_port <= 0
            or self._proxy_http_port <= 0
        ):
            return ""
        socks_role = "Mixed (SOCKS5 + HTTP)" if self._is_singbox_proxy_mode() else "SOCKS5"
        return (
            f"{socks_role}: 127.0.0.1:{self._proxy_socks_port}  ·  "
            f"HTTP: 127.0.0.1:{self._proxy_http_port}"
        )

    def _system_proxy_note(self) -> str:
        """Пояснение о реальном состоянии прокси Windows (чужой прокси / PAC)."""
        state = self._system_proxy_state
        if state is None or not state.supported:
            return ""
        if state.autoconfig_url:
            return "PAC-скрипт активен в Windows"
        if state.enabled and not state.is_ours:
            return "Системный прокси: включён (другое приложение)"
        return ""

    def _config_summary(self) -> str:
        if (self._settings.tun_mode and self._settings.tun_engine == "singbox") or self._is_singbox_proxy_mode():
            return f"Конфиг sing-box: {Path(self._settings.singbox_config_file or 'default.json').name}"
        if (not self._settings.tun_mode and self._settings.proxy_engine == "xray") or self._is_xray_tun_mode():
            return f"Конфиг Xray: {Path(self._settings.xray_config_file or 'default.json').name}"
        return "Выберите сервер на странице «Серверы»"

    def _connected_title(self) -> str:
        """Честный заголовок: «Защищено» — только когда туннель ловит весь трафик."""
        if self._settings.tun_mode:
            return "Защищено"
        if self._settings.enable_system_proxy:
            return "Подключено"
        return "Прокси запущен"

    def _headline(self) -> str:
        if self._initializing:
            return "Подготовка…"
        if self._connection_phase == "starting":
            return "Подключение…"
        if self._connection_phase == "error":
            return "Ошибка подключения"
        if self._connection_phase == "running" or self._connected:
            return self._connected_title()
        return "Не подключено"

    def _status_line(self) -> str:
        if self._initializing:
            return "Загрузка данных…"
        if self._connection_phase in {"starting", "error"}:
            text = self._connection_message
        elif self._connected:
            if self._settings.tun_mode:
                text = "Весь трафик компьютера идёт через VPN"
            elif self._settings.enable_system_proxy:
                text = "Браузеры и программы, использующие системный прокси, идут через туннель"
            else:
                text = "Системный прокси выключен — через туннель идут только программы с ручной настройкой прокси"
        else:
            text = "Нажмите на кнопку питания, чтобы подключиться"
        note = self._system_proxy_note()
        if note:
            text = f"{text} • {note}" if text else note
        return text

    def _toggle_action_text(self) -> str:
        if self._settings.tun_mode:
            return "Отключить VPN" if self._connected else "Подключить VPN"
        return "Остановить прокси" if self._connected else "Запустить прокси"

    def _server_title(self) -> str:
        if self._selected_node is None:
            return "Сервер не выбран"
        return node_name_text(self._selected_node) or "Безымянный сервер"

    def _selected_node_summary(self) -> str:
        """Протокол и замаскированный адрес выбранного сервера (без имени)."""
        if self._selected_node is None:
            return self._config_summary()
        scheme = self._selected_node.scheme.upper() if self._selected_node.scheme else "NODE"
        parts = [scheme, masked_endpoint()]
        group = self._selected_node.group
        if group and group not in {"Default", "По умолчанию"}:
            parts.append(group)
        return " · ".join(parts)

    # ── Signal handlers ───────────────────────────────────────

    def _on_mode_changed(self, index: int) -> None:
        value = self.mode_combo.itemData(index)
        if value:
            self.mode_changed.emit(str(value))

    def _on_vpn_tile_clicked(self) -> None:
        self._on_mode_tile_clicked(True)

    def _on_proxy_tile_clicked(self) -> None:
        self._on_mode_tile_clicked(False)

    def _on_mode_tile_clicked(self, tun: bool) -> None:
        if tun == bool(self._settings.tun_mode):
            return
        # Плитка отзывается сразу; настоящее состояние придёт снимком настроек.
        self.vpn_tile.setChecked(tun)
        self.proxy_tile.setChecked(not tun)
        self.tun_toggled.emit(tun)

    def _on_proxy_toggled(self, checked: bool) -> None:
        # Показываем выбор сразу; фактический прокси Windows догонит в фоне.
        self._proxy_intent.request(checked)
        QTimer.singleShot(int(self._proxy_intent.timeout_s * 1000) + 50, self._sync_switches)
        self.proxy_toggled.emit(checked)

    def _observed_system_proxy(self) -> bool:
        """Факт: включён ли наш системный прокси (без подключения — просто настройка)."""
        proxy_on = self._settings.enable_system_proxy
        state = self._system_proxy_state
        if self._connected and state is not None and state.supported:
            # Подключено: правда — в реестре Windows, а не во флаге настроек.
            proxy_on = bool(state.enabled and state.is_ours)
        elif state is not None and state.supported and state.enabled and state.is_ours:
            # Наш прокси реально активен в Windows — показываем «Вкл»,
            # даже если сохранённый флаг ещё не синхронизирован.
            proxy_on = True
        return proxy_on

    def _sync_switches(self) -> None:
        self.vpn_tile.setChecked(self._settings.tun_mode)
        self.proxy_tile.setChecked(not self._settings.tun_mode)

        # Намерение пользователя поверх факта: пока изменение применяется,
        # переключатель не откатывается к старому состоянию реестра.
        proxy_on = self._proxy_intent.display(self._observed_system_proxy())
        applying = self._proxy_intent.pending
        self.proxy_switch.blockSignals(True)
        self.proxy_switch.setChecked(proxy_on)
        self.proxy_switch.setText(("Вкл" if proxy_on else "Выкл") + ("…" if applying else ""))
        self.proxy_switch.setToolTip("Применяется…" if applying else "")
        self.proxy_switch.blockSignals(False)
        self._apply_interaction_state()

    def _apply_interaction_state(self) -> None:
        has_profiles = self._node_count > 0 or not self._settings.tun_mode or (
            self._settings.tun_mode and self._settings.tun_engine in {"singbox", "xray"}
        )
        busy = self._initializing or self._transition_busy or self._connection_phase == "starting"
        self.toggle_btn.setEnabled(has_profiles and not busy)
        self.connection_orb.setEnabled(has_profiles and not busy)
        self.connection_orb.set_state(self._orb_state())
        self.vpn_tile.setEnabled(not busy)
        self.proxy_tile.setEnabled(not busy)
        self.next_server_btn.setEnabled(self._node_count > 1 and not busy)
        self.mode_combo.setVisible(self._is_tun2socks_mode())
        self.mode_combo.setEnabled(not busy and self._is_tun2socks_mode())
        self.proxy_switch.setEnabled(not busy and not self._settings.tun_mode)
