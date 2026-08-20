from __future__ import annotations

from typing import cast

from PyQt6.QtCore import QEvent, Qt, QTimer, pyqtSignal, QSize
from PyQt6.QtGui import QCursor, QKeyEvent, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QAbstractItemView, QApplication, QHBoxLayout, QHeaderView,
    QVBoxLayout, QWidget,
)
from qfluentwidgets import (
    ComboBox,
    FluentIcon as FIF,
    PrimaryToolButton,
    SearchLineEdit,
    SmoothMode,
    SubtitleLabel,
    TableView,
    TransparentToolButton,
    VerticalSeparator,
)
from qfluentwidgets import RoundMenu, Action

from ..models import Node, Subscription
from .bulk_edit_page import BulkEditPage
from .detail_page import StackedSection
from .node_detail_widget import NodeDetailWidget
from .node_edit_page import NodeEditPage
from .nodes_filter_proxy import NodesFilterProxy, SORT_KEYS
from .nodes_table_delegate import NodesActivityDelegate
from .nodes_table_model import (
    COL_ADDRESS,
    COL_GROUP,
    COL_LAST_USED,
    COL_NAME,
    COL_PING,
    COL_SOURCE,
    COL_SPEED,
    COL_TAGS,
    COL_TYPE,
    COLUMN_BY_KEY,
    COLUMN_KEYS,
    COLUMN_SPECS,
    DEFAULT_VISIBLE_COLUMNS,
    NODE_ID_ROLE,
    NodesTableModel,
)
from .privacy import HoldToRevealButton

_ROW_HEIGHT = 30
_FLAG_ICON_SIZE = QSize(18, 13)

# Kept as a compatibility export; values come from the column contract above.
_COLUMN_WIDTHS = {
    col: spec.default_width
    for col, spec in enumerate(COLUMN_SPECS)
    if not spec.stretch
}

# Stable english sort keys (persisted); russian labels only in the UI.
_SORT_KEYS = list(SORT_KEYS)
_SORT_KEY_LABELS = {
    "manual": "Вручную",
    "name": "Имя",
    "group": "Группа",
    "type": "Тип",
    "ping": "Пинг",
    "speed": "Скорость",
    "last_used": "Последнее использование",
}

_COLUMN_SORT_MAP = {
    col: spec.sort_key for col, spec in enumerate(COLUMN_SPECS) if spec.sort_key
}

_ALL_GROUPS_LABEL = "Все группы"
_ALL_TAGS_LABEL = "Все теги"
_ALL_SOURCES_LABEL = "Все источники"

_PING_BATCH_INTERVAL_MS = 150


class NodesPage(StackedSection):
    import_clipboard_requested = pyqtSignal()
    delete_requested = pyqtSignal(object)          # emits set[str] of node IDs
    ping_requested = pyqtSignal(object)             # emits set[str] or empty set
    speed_test_requested = pyqtSignal(object)       # emits set[str] of node IDs (or empty set for all)
    cancel_speed_test_requested = pyqtSignal()
    export_outbound_json_requested = pyqtSignal(str)
    export_runtime_json_requested = pyqtSignal(str)
    selected_node_changed = pyqtSignal(str)
    edit_node_requested = pyqtSignal(str)           # node_id
    node_edit_saved = pyqtSignal(str, dict)         # node_id, updated fields
    bulk_edit_requested = pyqtSignal(object)        # set[str] of node_ids
    bulk_edit_applied = pyqtSignal(object, dict)    # set[str] node_ids, operations
    copy_link_requested = pyqtSignal(str)           # node_id
    reorder_requested = pyqtSignal(str, str)        # node_id, direction
    hide_subscription_nodes_requested = pyqtSignal(object)  # set[str]
    view_prefs_changed = pyqtSignal(object)         # dict of AppSettings nodes_* fields

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("nodes")

        self._nodes: list[Node] = []
        self._id_to_node: dict[str, Node] = {}
        self._sort_ascending = True
        self._cached_groups: frozenset[str] = frozenset()
        self._cached_tags: frozenset[str] = frozenset()
        self._source_names: dict[str, str] = {}
        self._cached_sources: tuple[str, ...] = ()
        self._pending_ping_ids: set[str] = set()
        self._ping_batch_ids: set[str] = set()
        self._pending_speed_progress: dict[str, int] = {}
        self._speed_test_running = False
        self._speed_test_stopping = False
        self._suppress_pref_signals = False
        self._pending_group_filter: str | None = None
        self._pending_tag_filter: str | None = None
        self._pending_source_filter: str | None = None
        self._column_widths = {
            spec.key: spec.default_width for spec in COLUMN_SPECS if not spec.stretch
        }
        self._adjusting_column_width = False
        self._column_layout_timer = QTimer(self)
        self._column_layout_timer.setSingleShot(True)
        self._column_layout_timer.setInterval(200)
        self._column_layout_timer.timeout.connect(self._emit_view_prefs)

        # Root view = server list; sub-pages = detail / edit / bulk edit.
        list_page = QWidget()
        root = QVBoxLayout(list_page)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        title = SubtitleLabel("Серверы", self)
        root.addWidget(title)

        # --- Filter row ---
        filter_row = QHBoxLayout()
        filter_row.setSpacing(8)

        self.search_edit = SearchLineEdit(self)
        self.search_edit.setPlaceholderText("Поиск серверов")
        filter_row.addWidget(self.search_edit, 1)

        self.group_filter = ComboBox(self)
        self.group_filter.setMinimumWidth(120)
        self.group_filter.addItem(_ALL_GROUPS_LABEL)
        filter_row.addWidget(self.group_filter)

        self.tag_filter = ComboBox(self)
        self.tag_filter.setMinimumWidth(120)
        self.tag_filter.addItem(_ALL_TAGS_LABEL)
        filter_row.addWidget(self.tag_filter)

        self.source_filter = ComboBox(self)
        self.source_filter.setMinimumWidth(130)
        self.source_filter.addItem(_ALL_SOURCES_LABEL)
        filter_row.addWidget(self.source_filter)

        filter_row.addWidget(VerticalSeparator(self))

        self.sort_combo = ComboBox(self)
        self.sort_combo.setMinimumWidth(110)
        for key in _SORT_KEYS:
            self.sort_combo.addItem(_SORT_KEY_LABELS[key])
        filter_row.addWidget(self.sort_combo)

        self.sort_order_btn = TransparentToolButton(FIF.UP, self)
        self.sort_order_btn.setToolTip("Порядок сортировки")
        filter_row.addWidget(self.sort_order_btn)

        root.addLayout(filter_row)

        # --- Action toolbar ---
        toolbar = QHBoxLayout()
        toolbar.setSpacing(4)

        self.import_btn = PrimaryToolButton(FIF.ADD, self)
        self.import_btn.setToolTip("Импорт из буфера (Ctrl+V)")
        toolbar.addWidget(self.import_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.edit_btn = TransparentToolButton(FIF.EDIT, self)
        self.edit_btn.setToolTip("Редактировать")
        toolbar.addWidget(self.edit_btn)

        self.bulk_edit_btn = TransparentToolButton(FIF.CHECKBOX, self)
        self.bulk_edit_btn.setToolTip("Массовое редактирование")
        self.bulk_edit_btn.setVisible(False)
        toolbar.addWidget(self.bulk_edit_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.reveal_addresses_btn = HoldToRevealButton(self, plural=True)
        toolbar.addWidget(self.reveal_addresses_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.ping_btn = TransparentToolButton(FIF.SEND, self)
        self.ping_btn.setToolTip("Пинг выбранных")
        toolbar.addWidget(self.ping_btn)

        self.ping_all_btn = TransparentToolButton(FIF.SYNC, self)
        self.ping_all_btn.setToolTip("Пинг всех")
        toolbar.addWidget(self.ping_all_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.speed_test_btn = TransparentToolButton(FIF.SPEED_HIGH, self)
        self.speed_test_btn.setToolTip("Тест скорости выбранных")
        toolbar.addWidget(self.speed_test_btn)

        self.speed_test_all_btn = TransparentToolButton(FIF.SPEED_MEDIUM, self)
        self.speed_test_all_btn.setToolTip("Тест скорости всех")
        toolbar.addWidget(self.speed_test_all_btn)

        self.stop_speed_test_btn = TransparentToolButton(FIF.PAUSE_BOLD, self)
        self.stop_speed_test_btn.setToolTip("Остановить тест скорости")
        self.stop_speed_test_btn.setVisible(False)
        toolbar.addWidget(self.stop_speed_test_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.export_outbound_btn = TransparentToolButton(FIF.SAVE_AS, self)
        self.export_outbound_btn.setToolTip("Экспорт outbound JSON")
        toolbar.addWidget(self.export_outbound_btn)

        self.export_runtime_btn = TransparentToolButton(FIF.CODE, self)
        self.export_runtime_btn.setToolTip("Экспорт runtime конфига")
        toolbar.addWidget(self.export_runtime_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.delete_btn = TransparentToolButton(FIF.DELETE, self)
        self.delete_btn.setToolTip("Удалить выбранные")
        toolbar.addWidget(self.delete_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.move_up_btn = TransparentToolButton(FIF.UP, self)
        self.move_up_btn.setToolTip("Переместить вверх")
        self.move_up_btn.setEnabled(False)
        toolbar.addWidget(self.move_up_btn)

        self.move_down_btn = TransparentToolButton(FIF.DOWN, self)
        self.move_down_btn.setToolTip("Переместить вниз")
        self.move_down_btn.setEnabled(False)
        toolbar.addWidget(self.move_down_btn)

        toolbar.addStretch()

        root.addLayout(toolbar)

        # --- Table (source model behind a filter/sort proxy) ---
        self.table = TableView(self)
        self._table_model = NodesTableModel(self)
        self._proxy = NodesFilterProxy(self)
        self._proxy.setSourceModel(self._table_model)
        self.table.setModel(self._proxy)
        self._proxy.sort(0, Qt.SortOrder.AscendingOrder)

        vertical_header = cast(QHeaderView, self.table.verticalHeader())
        vertical_header.setVisible(False)
        vertical_header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        vertical_header.setDefaultSectionSize(_ROW_HEIGHT)

        horizontal_header = cast(QHeaderView, self.table.horizontalHeader())
        horizontal_header.setMinimumSectionSize(
            min(spec.minimum_width for spec in COLUMN_SPECS)
        )
        for col, spec in enumerate(COLUMN_SPECS):
            # All columns are Interactive; the "name" flex column is sized by
            # _relayout_flex_column() to absorb the leftover viewport width.
            horizontal_header.setSectionResizeMode(
                col, QHeaderView.ResizeMode.Interactive
            )
            horizontal_header.resizeSection(col, spec.default_width)
        horizontal_header.setSectionsClickable(True)
        horizontal_header.setSectionsMovable(True)
        horizontal_header.sectionClicked.connect(self._on_header_clicked)
        horizontal_header.sectionResized.connect(self._on_column_resized)
        horizontal_header.sectionMoved.connect(self._on_column_moved)
        horizontal_header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        horizontal_header.customContextMenuRequested.connect(self._on_header_context_menu)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.setIconSize(_FLAG_ICON_SIZE)
        self.table.setWordWrap(False)
        self.table.scrollDelagate.verticalSmoothScroll.setSmoothMode(SmoothMode.NO_SMOOTH)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerItem)
        self.table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

        self._apply_column_visibility(DEFAULT_VISIBLE_COLUMNS)

        # Recompute the flex column whenever the table viewport is resized.
        viewport = self.table.viewport()
        if viewport is not None:
            viewport.installEventFilter(self)

        self._activity_delegate = NodesActivityDelegate(self.table)
        self.table.setItemDelegate(self._activity_delegate)

        # Prevent deselection on empty area click
        orig_mouse_press = self.table.mousePressEvent

        def _no_deselect_mouse_press(event):
            if event.button() == Qt.MouseButton.LeftButton:
                index = self.table.indexAt(event.pos())
                if not index.isValid():
                    return
            orig_mouse_press(event)

        self.table.mousePressEvent = _no_deselect_mouse_press

        root.addWidget(self.table, 1)

        self.set_root_page(list_page)

        # --- Sub-page: node detail ---
        self._detail_widget = NodeDetailWidget(self)
        self._detail_widget.ping_node_requested.connect(lambda nid: self.ping_requested.emit({nid}))
        self._detail_widget.speed_test_node_requested.connect(lambda nid: self.speed_test_requested.emit({nid}))
        self._detail_widget.cancel_speed_test_requested.connect(self.cancel_speed_test_requested.emit)
        self.add_sub_page(self._detail_widget)

        # --- Sub-page: single node editor (replaces the old modal dialog) ---
        self._edit_page = NodeEditPage(self)
        self._edit_page.save_requested.connect(self.node_edit_saved)
        self.add_sub_page(self._edit_page)

        # --- Sub-page: bulk editor (replaces the old modal dialog) ---
        self._bulk_edit_page = BulkEditPage(self)
        self._bulk_edit_page.apply_requested.connect(self.bulk_edit_applied)
        self.add_sub_page(self._bulk_edit_page)

        # --- Search debounce ---
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(300)
        self._search_timer.timeout.connect(self._apply_search)

        self._speed_progress_timer = QTimer(self)
        self._speed_progress_timer.setSingleShot(True)
        self._speed_progress_timer.setInterval(50)
        self._speed_progress_timer.timeout.connect(self._flush_speed_progress)

        # --- Ping results batching (single dataChanged per batch) ---
        self._ping_batch_timer = QTimer(self)
        self._ping_batch_timer.setSingleShot(True)
        self._ping_batch_timer.setInterval(_PING_BATCH_INTERVAL_MS)
        self._ping_batch_timer.timeout.connect(self._flush_ping_batch)

        # --- Connections ---
        self.search_edit.textChanged.connect(self._search_timer.start)
        self.group_filter.currentIndexChanged.connect(self._on_group_filter_changed)
        self.tag_filter.currentIndexChanged.connect(self._on_tag_filter_changed)
        self.source_filter.currentIndexChanged.connect(self._on_source_filter_changed)
        self.sort_combo.currentIndexChanged.connect(self._on_sort_combo_changed)
        self.sort_order_btn.clicked.connect(self._toggle_sort_order)
        self.import_btn.clicked.connect(self.import_clipboard_requested)
        self.edit_btn.clicked.connect(self._on_edit)
        self.bulk_edit_btn.clicked.connect(self._on_bulk_edit)
        self.reveal_addresses_btn.revealChanged.connect(
            self._table_model.set_endpoints_revealed
        )
        self.ping_btn.clicked.connect(self._on_ping_selected)
        self.ping_all_btn.clicked.connect(self._on_ping_all)
        self.export_outbound_btn.clicked.connect(self._on_export_outbound)
        self.export_runtime_btn.clicked.connect(self._on_export_runtime)
        self.speed_test_btn.clicked.connect(self._on_speed_test_selected)
        self.speed_test_all_btn.clicked.connect(self._on_speed_test_all)
        self.stop_speed_test_btn.clicked.connect(self.cancel_speed_test_requested.emit)
        self.delete_btn.clicked.connect(self._on_delete_selected)
        self.move_up_btn.clicked.connect(self._on_move_up)
        self.move_down_btn.clicked.connect(self._on_move_down)
        self.table.selectionModel().selectionChanged.connect(lambda *_: self._emit_selection())
        self.table.doubleClicked.connect(self._on_double_click)
        self.table.customContextMenuRequested.connect(self._on_context_menu)
        # Keep qfluentwidgets row highlight in sync after proxy re-sorts.
        self._proxy.layoutChanged.connect(lambda *_: self.table.updateSelectedRows())

        # --- Keyboard shortcuts ---
        paste_shortcut = QShortcut(QKeySequence.StandardKey.Paste, self)
        paste_shortcut.activated.connect(self.import_clipboard_requested)

    # ── Public API ──

    def set_nodes(self, nodes: list[Node], selected_id: str | None = None) -> None:
        self._nodes = list(nodes)
        self._id_to_node = {node.id: node for node in self._nodes}
        self._rebuild_filter_combos()
        self._proxy.invalidate_haystacks()
        self.table.setUpdatesEnabled(False)
        self._table_model.update_nodes(self._nodes)
        self.table.setUpdatesEnabled(True)
        if selected_id and selected_id not in self._selected_ids():
            self._select_node(selected_id)
        self._emit_selection()

    def set_subscriptions(self, subscriptions: list[Subscription]) -> None:
        self._source_names = {item.id: item.name or "Подписка" for item in subscriptions}
        self._table_model.set_source_names(self._source_names)
        sources = ("Локальные",) + tuple(
            name for _, name in sorted(self._source_names.items(), key=lambda pair: pair[1].casefold())
        )
        if sources != self._cached_sources:
            previous = self.source_filter.currentText()
            self.source_filter.blockSignals(True)
            self.source_filter.clear()
            self.source_filter.addItem(_ALL_SOURCES_LABEL)
            for source in sources:
                self.source_filter.addItem(source)
            index = self.source_filter.findText(previous)
            self.source_filter.setCurrentIndex(index if index >= 0 else 0)
            self.source_filter.blockSignals(False)
            self._cached_sources = sources
        self._proxy.set_source_names(self._source_names)
        self._try_apply_pending_filters()

    def apply_view_settings(self, settings) -> None:
        """Apply persisted sort/filter/column preferences.

        Must be called before the first ``set_nodes``/``update_nodes``.
        Group/tag/source filters are applied lazily once the value shows up
        in the corresponding combo box.
        """
        self._suppress_pref_signals = True
        try:
            key = getattr(settings, "nodes_sort_key", "manual")
            if key not in _SORT_KEYS:
                key = "manual"
            self._sort_ascending = not bool(getattr(settings, "nodes_sort_desc", False))
            self.sort_order_btn.setIcon(FIF.UP if self._sort_ascending else FIF.DOWN)
            self.sort_combo.blockSignals(True)
            self.sort_combo.setCurrentIndex(_SORT_KEYS.index(key))
            self.sort_combo.blockSignals(False)
            self._proxy.set_sort_key(key)
            self._apply_sort_order()

            columns = list(getattr(settings, "nodes_visible_columns", []) or [])
            if int(getattr(settings, "nodes_column_layout_version", 0) or 0) < 1:
                # The old default omitted both useful value columns.  Preserve
                # custom visibility while making the repaired Type/Address
                # contract available after an upgrade.
                legacy_visible = set(columns or DEFAULT_VISIBLE_COLUMNS)
                legacy_visible.update(("type", "address"))
                columns = [key for key in COLUMN_KEYS if key in legacy_visible]
            widths = dict(getattr(settings, "nodes_column_widths", {}) or {})
            order = list(getattr(settings, "nodes_column_order", []) or [])
            self._apply_column_widths(widths)
            self._apply_column_order(order)
            self._apply_column_visibility(columns or DEFAULT_VISIBLE_COLUMNS)
            self._relayout_flex_column()

            self._pending_group_filter = getattr(settings, "nodes_group_filter", "") or None
            self._pending_tag_filter = getattr(settings, "nodes_tag_filter", "") or None
            self._pending_source_filter = getattr(settings, "nodes_source_filter", "") or None
            self._try_apply_pending_filters()
        finally:
            self._suppress_pref_signals = False

    def set_active_node(self, node_id: str | None) -> None:
        self._table_model.set_active_node_id(node_id)

    def update_ping(self, node_id: str, _ping_ms: int | None) -> None:
        self._pending_ping_ids.discard(node_id)
        self._ping_batch_ids.add(node_id)
        if not self._ping_batch_timer.isActive():
            self._ping_batch_timer.start()

    def update_speed(self, node_id: str, _speed_mbps: float | None) -> None:
        self._pending_speed_progress.pop(node_id, None)
        self._table_model.finish_speed(node_id)

    def update_alive_status(self, node_id: str, _is_alive: bool | None) -> None:
        self._table_model.refresh_alive_status(node_id)

    def refresh_detail(self, node_id: str | None = None) -> None:
        """Refresh detail view if it is currently visible."""
        if self._stack.currentWidget() is self._detail_widget:
            self._detail_widget.refresh(node_id)

    # ── Filter combos ──

    def _rebuild_filter_combos(self) -> None:
        new_groups = frozenset(n.group for n in self._nodes if n.group)
        new_tags: set[str] = set()
        for n in self._nodes:
            new_tags.update(n.tags)
        new_tags_frozen = frozenset(new_tags)

        if new_groups == self._cached_groups and new_tags_frozen == self._cached_tags:
            self._try_apply_pending_filters()
            return
        self._cached_groups = new_groups
        self._cached_tags = new_tags_frozen

        prev_group = self.group_filter.currentText()
        prev_tag = self.tag_filter.currentText()

        self.group_filter.blockSignals(True)
        self.group_filter.clear()
        self.group_filter.addItem(_ALL_GROUPS_LABEL)
        for g in sorted(new_groups):
            self.group_filter.addItem(g)
        idx = self.group_filter.findText(prev_group)
        self.group_filter.setCurrentIndex(idx if idx >= 0 else 0)
        self.group_filter.blockSignals(False)

        self.tag_filter.blockSignals(True)
        self.tag_filter.clear()
        self.tag_filter.addItem(_ALL_TAGS_LABEL)
        for t in sorted(new_tags_frozen):
            self.tag_filter.addItem(t)
        idx = self.tag_filter.findText(prev_tag)
        self.tag_filter.setCurrentIndex(idx if idx >= 0 else 0)
        self.tag_filter.blockSignals(False)

        # Combo may have lost the previously applied value — resync the proxy.
        self._proxy.set_group(self._combo_filter_value(self.group_filter))
        self._proxy.set_tag(self._combo_filter_value(self.tag_filter))

        self._try_apply_pending_filters()

    def _try_apply_pending_filters(self) -> None:
        """Apply persisted filters once their values exist in the combos."""
        if self._pending_group_filter:
            idx = self.group_filter.findText(self._pending_group_filter)
            if idx >= 0:
                self.group_filter.blockSignals(True)
                self.group_filter.setCurrentIndex(idx)
                self.group_filter.blockSignals(False)
                self._proxy.set_group(self._pending_group_filter)
                self._pending_group_filter = None
        if self._pending_tag_filter:
            idx = self.tag_filter.findText(self._pending_tag_filter)
            if idx >= 0:
                self.tag_filter.blockSignals(True)
                self.tag_filter.setCurrentIndex(idx)
                self.tag_filter.blockSignals(False)
                self._proxy.set_tag(self._pending_tag_filter)
                self._pending_tag_filter = None
        if self._pending_source_filter:
            idx = self.source_filter.findText(self._pending_source_filter)
            if idx >= 0:
                self.source_filter.blockSignals(True)
                self.source_filter.setCurrentIndex(idx)
                self.source_filter.blockSignals(False)
                self._proxy.set_source(self._pending_source_filter)
                self._pending_source_filter = None

    @staticmethod
    def _combo_filter_value(combo: ComboBox) -> str:
        return "" if combo.currentIndex() <= 0 else combo.currentText()

    def _on_group_filter_changed(self) -> None:
        self._pending_group_filter = None
        self._proxy.set_group(self._combo_filter_value(self.group_filter))
        self._emit_view_prefs()

    def _on_tag_filter_changed(self) -> None:
        self._pending_tag_filter = None
        self._proxy.set_tag(self._combo_filter_value(self.tag_filter))
        self._emit_view_prefs()

    def _on_source_filter_changed(self) -> None:
        self._pending_source_filter = None
        self._proxy.set_source(self._combo_filter_value(self.source_filter))
        self._emit_view_prefs()

    def _apply_search(self) -> None:
        self._proxy.set_query(self.search_edit.text())

    # ── Ping / speed activity ──

    def start_ping_activity(self, node_ids: set[str] | None = None) -> None:
        targets = set(node_ids) if node_ids else {node.id for node in self._nodes}
        if not targets:
            return
        self._pending_ping_ids = targets
        self._table_model.set_ping_busy_ids(targets)

    def start_speed_activity(self) -> None:
        self._speed_progress_timer.stop()
        self._pending_speed_progress.clear()
        self._table_model.clear_speed_progress()
        self._speed_test_running = True
        self._speed_test_stopping = False
        self._sync_speed_test_controls()

    def update_speed_progress(self, node_id: str, percent: int) -> None:
        self._pending_speed_progress[node_id] = max(0, min(100, int(percent)))
        if not self._speed_progress_timer.isActive():
            self._speed_progress_timer.start()

    def _flush_speed_progress(self) -> None:
        if not self._pending_speed_progress:
            return
        progress = self._pending_speed_progress
        self._pending_speed_progress = {}
        self._table_model.set_speed_progress_batch(progress)

    def _flush_ping_batch(self) -> None:
        if not self._ping_batch_ids:
            return
        ids = self._ping_batch_ids
        self._ping_batch_ids = set()
        self._table_model.finish_ping_batch(ids)

    def finish_ping_activity(self) -> None:
        self._ping_batch_timer.stop()
        self._flush_ping_batch()
        if not self._pending_ping_ids:
            return
        self._pending_ping_ids.clear()
        self._table_model.clear_ping_busy()

    def finish_speed_activity(self) -> None:
        self._speed_progress_timer.stop()
        self._pending_speed_progress.clear()
        self._table_model.clear_speed_progress()
        self._speed_test_running = False
        self._speed_test_stopping = False
        self._sync_speed_test_controls()

    def mark_speed_test_stopping(self) -> None:
        if not self._speed_test_running:
            return
        self._speed_test_stopping = True
        self._sync_speed_test_controls()

    def _sync_speed_test_controls(self) -> None:
        running = self._speed_test_running
        stopping = self._speed_test_stopping
        self.speed_test_btn.setEnabled(not running)
        self.speed_test_all_btn.setEnabled(not running)
        self.stop_speed_test_btn.setVisible(running)
        self.stop_speed_test_btn.setEnabled(running and not stopping)
        self._detail_widget.set_speed_test_running(running, stopping=stopping)

    # ── Sorting ──

    def _current_sort_key(self) -> str:
        index = self.sort_combo.currentIndex()
        if 0 <= index < len(_SORT_KEYS):
            return _SORT_KEYS[index]
        return "manual"

    def _apply_sort_order(self) -> None:
        order = Qt.SortOrder.AscendingOrder if self._sort_ascending else Qt.SortOrder.DescendingOrder
        self._proxy.sort(0, order)

    def _on_sort_combo_changed(self) -> None:
        self._proxy.set_sort_key(self._current_sort_key())
        self._apply_sort_order()
        self._emit_selection()
        self._emit_view_prefs()

    def _toggle_sort_order(self) -> None:
        self._sort_ascending = not self._sort_ascending
        self.sort_order_btn.setIcon(FIF.UP if self._sort_ascending else FIF.DOWN)
        self._apply_sort_order()
        self._emit_view_prefs()

    def _on_header_clicked(self, logical_index: int) -> None:
        sort_key = _COLUMN_SORT_MAP.get(logical_index)
        if sort_key is None:
            return
        idx = _SORT_KEYS.index(sort_key)
        if self.sort_combo.currentIndex() == idx:
            self._toggle_sort_order()
        else:
            self._sort_ascending = True
            self.sort_order_btn.setIcon(FIF.UP)
            self.sort_combo.setCurrentIndex(idx)

    # ── Column visibility ──

    @staticmethod
    def _clamp_column_width(key: str, width: int) -> int:
        spec = COLUMN_BY_KEY[key]
        return max(spec.minimum_width, min(spec.maximum_width, int(width)))

    def _resize_section_quietly(self, col: int, width: int) -> None:
        """Programmatic resizeSection guarded against the sectionResized handler."""
        previous = self._adjusting_column_width
        self._adjusting_column_width = True
        try:
            cast(QHeaderView, self.table.horizontalHeader()).resizeSection(col, width)
        finally:
            self._adjusting_column_width = previous

    def _visible_columns_right_of(self, logical_index: int) -> list[int]:
        """Visible logical columns to the right of ``logical_index`` in VISUAL order."""
        header = cast(QHeaderView, self.table.horizontalHeader())
        columns: list[int] = []
        for visual in range(header.visualIndex(logical_index) + 1, header.count()):
            col = header.logicalIndex(visual)
            if not self.table.isColumnHidden(col):
                columns.append(col)
        return columns

    def _relayout_flex_column(self) -> None:
        """Size "name" so the visible columns fill the viewport exactly.

        width(name) = max(minimum, viewport - sum(other visible columns)).
        When the minimums overflow the viewport, "name" stays at its minimum
        and the horizontal scrollbar takes over (by design).
        """
        viewport = self.table.viewport()
        if viewport is None:
            return
        viewport_width = viewport.width()
        if viewport_width <= 0:
            return
        header = cast(QHeaderView, self.table.horizontalHeader())
        others = sum(
            header.sectionSize(col)
            for col in range(len(COLUMN_SPECS))
            if col != COL_NAME and not self.table.isColumnHidden(col)
        )
        target = max(
            COLUMN_BY_KEY["name"].minimum_width, viewport_width - others
        )
        if header.sectionSize(COL_NAME) != target:
            self._resize_section_quietly(COL_NAME, target)

    def eventFilter(self, obj, event) -> bool:
        if obj is self.table.viewport() and event.type() == QEvent.Type.Resize:
            self._relayout_flex_column()
        return super().eventFilter(obj, event)

    def _apply_column_widths(self, widths: dict[str, int]) -> None:
        for col, spec in enumerate(COLUMN_SPECS):
            if spec.stretch:
                continue
            try:
                width = self._clamp_column_width(
                    spec.key, widths.get(spec.key, spec.default_width)
                )
            except (TypeError, ValueError):
                width = spec.default_width
            self._column_widths[spec.key] = width
            self._resize_section_quietly(col, width)

    def column_widths(self) -> dict[str, int]:
        return dict(self._column_widths)

    def _apply_column_order(self, keys: list[str]) -> None:
        desired: list[str] = []
        for key in keys:
            if key in COLUMN_BY_KEY and key not in desired:
                desired.append(key)
        desired.extend(key for key in COLUMN_KEYS if key not in desired)
        header = cast(QHeaderView, self.table.horizontalHeader())
        for visual_index, key in enumerate(desired):
            logical_index = COLUMN_KEYS.index(key)
            current_visual = header.visualIndex(logical_index)
            if current_visual != visual_index:
                header.moveSection(current_visual, visual_index)

    def column_order(self) -> list[str]:
        header = cast(QHeaderView, self.table.horizontalHeader())
        return [
            COLUMN_KEYS[header.logicalIndex(visual_index)]
            for visual_index in range(header.count())
        ]

    def _on_column_resized(
        self, logical_index: int, old_size: int, new_size: int
    ) -> None:
        if self._adjusting_column_width or new_size <= 0:
            return
        if not 0 <= logical_index < len(COLUMN_SPECS):
            return
        if self.table.isColumnHidden(logical_index):
            return
        spec = COLUMN_SPECS[logical_index]
        if spec.stretch:
            self._on_flex_column_dragged(old_size, new_size)
        else:
            self._on_fixed_column_dragged(logical_index, spec, old_size, new_size)
        self._queue_column_layout_save()

    def _on_fixed_column_dragged(
        self, logical_index: int, spec, old_size: int, new_size: int
    ) -> None:
        """User drag of a non-flex column: "name" absorbs the opposite delta."""
        width = self._clamp_column_width(spec.key, new_size)
        if width != new_size:
            self._resize_section_quietly(logical_index, width)
        self._column_widths[spec.key] = width
        delta = width - old_size
        if not delta:
            return
        header = cast(QHeaderView, self.table.horizontalHeader())
        name_current = header.sectionSize(COL_NAME)
        name_target = max(COLUMN_BY_KEY["name"].minimum_width, name_current - delta)
        if name_target != name_current:
            self._resize_section_quietly(COL_NAME, name_target)
        # When "name" is already at its minimum the remaining delta stays:
        # the sections overflow the viewport and horizontal scrolling kicks
        # in — the user's drag is never rolled back.

    def _on_flex_column_dragged(self, old_size: int, new_size: int) -> None:
        """User drag of "name": push the delta to visible right neighbors.

        The first visible neighbor to the right (visual order) absorbs the
        delta, cascading further right on shortage; every neighbor is clamped
        to its min/max. Whatever nobody absorbed clamps the drag itself.
        """
        header = cast(QHeaderView, self.table.horizontalHeader())
        clamped = max(COLUMN_BY_KEY["name"].minimum_width, new_size)
        remaining = clamped - old_size
        if remaining:
            for col in self._visible_columns_right_of(COL_NAME):
                if not remaining:
                    break
                neighbor = COLUMN_SPECS[col]
                current = header.sectionSize(col)
                if remaining > 0:
                    # "name" grew: shrink the neighbor down to its minimum.
                    absorbed = min(remaining, max(0, current - neighbor.minimum_width))
                else:
                    # "name" shrank: grow the neighbor up to its maximum.
                    absorbed = max(remaining, min(0, current - neighbor.maximum_width))
                if absorbed:
                    self._resize_section_quietly(col, current - absorbed)
                    self._column_widths[neighbor.key] = current - absorbed
                    remaining -= absorbed
        target = clamped - remaining
        if target != new_size:
            self._resize_section_quietly(COL_NAME, target)

    def _on_column_moved(
        self, _logical_index: int, _old_visual_index: int, _new_visual_index: int
    ) -> None:
        self._queue_column_layout_save()

    def _queue_column_layout_save(self) -> None:
        if not self._suppress_pref_signals:
            self._column_layout_timer.start()

    def _apply_column_visibility(self, keys: list[str]) -> None:
        visible = set(keys) | {"name"}
        previous = self._adjusting_column_width
        self._adjusting_column_width = True
        try:
            # Hiding/showing sections emits sectionResized; guard it so the
            # drag-compensation handler does not treat it as a user drag.
            for col, key in enumerate(COLUMN_KEYS):
                self.table.setColumnHidden(col, key not in visible)
        finally:
            self._adjusting_column_width = previous
        self._relayout_flex_column()

    def visible_column_keys(self) -> list[str]:
        return [key for col, key in enumerate(COLUMN_KEYS) if not self.table.isColumnHidden(col)]

    def _set_column_visible(self, col: int, visible: bool) -> None:
        previous = self._adjusting_column_width
        self._adjusting_column_width = True
        try:
            self.table.setColumnHidden(col, not visible)
            if visible and 0 <= col < len(COLUMN_SPECS):
                spec = COLUMN_SPECS[col]
                if not spec.stretch:
                    self.table.horizontalHeader().resizeSection(
                        col, self._column_widths[spec.key]
                    )
        finally:
            self._adjusting_column_width = previous
        self._relayout_flex_column()
        self._emit_view_prefs()

    def _on_header_context_menu(self, pos) -> None:
        menu = RoundMenu(parent=self)
        for col, _key in enumerate(COLUMN_KEYS):
            if col == COL_NAME:
                continue
            label = self._table_model.headerData(col, Qt.Orientation.Horizontal)
            action = Action(str(label), self)
            action.setCheckable(True)
            action.setChecked(not self.table.isColumnHidden(col))
            action.triggered.connect(lambda checked, c=col: self._set_column_visible(c, checked))
            menu.addAction(action)
        header = self.table.horizontalHeader()
        anchor = header.mapToGlobal(pos) if header is not None else QCursor.pos()
        menu.exec(anchor)

    # ── View preferences persistence ──

    def _emit_view_prefs(self) -> None:
        if self._suppress_pref_signals:
            return
        self.view_prefs_changed.emit(
            {
                "nodes_sort_key": self._current_sort_key(),
                "nodes_sort_desc": not self._sort_ascending,
                "nodes_group_filter": self._combo_filter_value(self.group_filter),
                "nodes_tag_filter": self._combo_filter_value(self.tag_filter),
                "nodes_source_filter": self._combo_filter_value(self.source_filter),
                "nodes_visible_columns": self.visible_column_keys(),
                "nodes_column_widths": self.column_widths(),
                "nodes_column_order": self.column_order(),
                "nodes_column_layout_version": 1,
            }
        )

    # ── Selection helpers ──

    def _selected_ids(self) -> set[str]:
        model = self.table.selectionModel()
        if model is None:
            return set()
        ids: set[str] = set()
        for index in model.selectedRows():
            node_id = index.data(NODE_ID_ROLE)
            if node_id:
                ids.add(node_id)
        return ids

    def _select_node(self, node_id: str) -> None:
        row = self._table_model.row_for_node(node_id)
        if row is None:
            return
        proxy_index = self._proxy.mapFromSource(self._table_model.index(row, 0))
        if proxy_index.isValid():
            self.table.selectRow(proxy_index.row())

    def _emit_selection(self) -> None:
        ids = self._selected_ids()
        self.bulk_edit_btn.setVisible(len(ids) > 1)
        is_manual = self._current_sort_key() == "manual"
        self.move_up_btn.setEnabled(is_manual and len(ids) == 1)
        self.move_down_btn.setEnabled(is_manual and len(ids) == 1)
        if len(ids) == 1:
            self.selected_node_changed.emit(next(iter(ids)))

    # ── Button handlers ──

    def _on_move_up(self) -> None:
        ids = self._selected_ids()
        if len(ids) == 1:
            self.reorder_requested.emit(next(iter(ids)), "up")

    def _on_move_down(self) -> None:
        ids = self._selected_ids()
        if len(ids) == 1:
            self.reorder_requested.emit(next(iter(ids)), "down")

    def _on_edit(self) -> None:
        ids = self._selected_ids()
        if len(ids) == 1:
            self.edit_node_requested.emit(next(iter(ids)))

    def _on_bulk_edit(self) -> None:
        ids = self._selected_ids()
        if ids:
            self.bulk_edit_requested.emit(ids)

    def _on_ping_selected(self) -> None:
        ids = self._selected_ids()
        if ids:
            self.ping_requested.emit(ids)

    def _on_ping_all(self) -> None:
        self.ping_requested.emit(set())

    def _on_speed_test_selected(self) -> None:
        ids = self._selected_ids()
        if ids:
            self.speed_test_requested.emit(ids)

    def _on_speed_test_all(self) -> None:
        self.speed_test_requested.emit(set())

    def _on_delete_selected(self) -> None:
        ids = self._selected_ids()
        if not ids:
            return
        from qfluentwidgets import MessageBox
        count = len(ids)
        subscribed = {node_id for node_id in ids if self._id_to_node.get(node_id) and self._id_to_node[node_id].subscription_id}
        local = ids - subscribed
        title = "Изменение списка серверов" if subscribed else ("Удаление серверов" if count > 1 else "Удаление сервера")
        if subscribed and local:
            msg = f"Скрыть серверов подписки: {len(subscribed)}; удалить локальных: {len(local)}?"
        elif subscribed:
            msg = f"Скрыть серверов из подписки: {len(subscribed)}? Они вернутся после сброса исключений."
        else:
            msg = f"Удалить {count} серверов?" if count > 1 else "Удалить выбранный сервер?"
        box = MessageBox(title, msg, self.window())
        box.yesButton.setText("Применить" if subscribed else "Удалить")
        box.cancelButton.setText("Отмена")
        if box.exec():
            if subscribed:
                self.hide_subscription_nodes_requested.emit(subscribed)
            if local:
                self.delete_requested.emit(local)

    def _on_export_outbound(self) -> None:
        ids = self._selected_ids()
        if len(ids) != 1:
            return
        self.export_outbound_json_requested.emit(next(iter(ids)))

    def _on_export_runtime(self) -> None:
        ids = self._selected_ids()
        if len(ids) != 1:
            return
        self.export_runtime_json_requested.emit(next(iter(ids)))

    # ── Double-click / context menu ──

    def _on_double_click(self, index) -> None:
        node_id = index.data(NODE_ID_ROLE)
        node = self._id_to_node.get(node_id) if node_id else None
        if node is not None:
            self._show_detail(node)

    def _on_context_menu(self, pos) -> None:
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        clicked_id = index.data(NODE_ID_ROLE)
        if not clicked_id:
            return

        current_ids = self._selected_ids()
        if clicked_id not in current_ids:
            self.table.clearSelection()
            self.table.selectRow(index.row())
            ids = {clicked_id}
        else:
            ids = current_ids

        menu = RoundMenu(parent=self)
        count = len(ids)

        if count == 1:
            node_id = next(iter(ids))
            edit_action = Action("Редактировать", self)
            edit_action.triggered.connect(lambda: self.edit_node_requested.emit(node_id))
            menu.addAction(edit_action)

            copy_action = Action("Копировать ссылку", self)
            copy_action.triggered.connect(lambda: self._copy_node_link(node_id))
            menu.addAction(copy_action)
        else:
            copy_action = Action(f"Копировать {count} ссылок", self)
            copy_action.triggered.connect(lambda: self._copy_multiple_links(ids))
            menu.addAction(copy_action)

        bulk_action = Action("Массовое редактирование", self)
        bulk_action.triggered.connect(lambda: self.bulk_edit_requested.emit(ids))
        menu.addAction(bulk_action)

        menu.addSeparator()

        ping_action = Action(f"Пинг ({count})" if count > 1 else "Пинг", self)
        ping_action.triggered.connect(lambda: self.ping_requested.emit(ids))
        menu.addAction(ping_action)

        speed_action = Action(f"Тест скорости ({count})" if count > 1 else "Тест скорости", self)
        speed_action.triggered.connect(lambda: self.speed_test_requested.emit(ids))
        menu.addAction(speed_action)

        menu.addSeparator()

        only_subscribed = all(
            self._id_to_node.get(node_id) and self._id_to_node[node_id].subscription_id for node_id in ids
        )
        delete_label = (
            f"Скрыть {count} серверов из подписки" if count > 1 else "Скрыть из подписки"
        ) if only_subscribed else (f"Удалить {count} серверов" if count > 1 else "Удалить")
        delete_action = Action(delete_label, self)
        delete_action.triggered.connect(self._on_delete_selected)
        menu.addAction(delete_action)

        if count == 1 and self._current_sort_key() == "manual":
            node_id = next(iter(ids))
            menu.addSeparator()
            move_top = Action("В начало списка", self)
            move_top.triggered.connect(lambda: self.reorder_requested.emit(node_id, "top"))
            menu.addAction(move_top)
            move_bottom = Action("В конец списка", self)
            move_bottom.triggered.connect(lambda: self.reorder_requested.emit(node_id, "bottom"))
            menu.addAction(move_bottom)

        menu.exec(QCursor.pos())

    # ── Navigation (list / sub-pages) ──

    def open_node_editor(self, node: Node, existing_groups: list[str]) -> None:
        """Show the single-server editor as a breadcrumb sub-page."""
        self._edit_page.set_node(node, existing_groups)
        self.show_sub_page(self._edit_page)

    def open_bulk_editor(self, node_ids: set[str], existing_groups: list[str]) -> None:
        """Show the bulk editor as a breadcrumb sub-page."""
        self._bulk_edit_page.set_targets(node_ids, existing_groups)
        self.show_sub_page(self._bulk_edit_page)

    def close_editor(self) -> None:
        """Return to the list after a committed edit (no dirty prompt)."""
        self._edit_page.mark_clean()
        self.show_root()

    def _show_detail(self, node: Node) -> None:
        self._detail_widget.set_node(node)
        self.show_sub_page(self._detail_widget)

    # ── Utilities ──

    def _copy_node_link(self, node_id: str) -> None:
        node = self._id_to_node.get(node_id)
        if node and node.link:
            clipboard = QApplication.clipboard()
            if clipboard is not None:
                clipboard.setText(node.link)

    def _copy_multiple_links(self, node_ids: set[str]) -> None:
        links: list[str] = []
        for row in range(self._proxy.rowCount()):
            node_id = self._proxy.index(row, 0).data(NODE_ID_ROLE)
            node = self._id_to_node.get(node_id) if node_id else None
            if node is not None and node.id in node_ids and node.link:
                links.append(node.link)
        if links:
            clipboard = QApplication.clipboard()
            if clipboard is not None:
                clipboard.setText("\n".join(links))

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() == Qt.Key.Key_Delete:
            self._on_delete_selected()
            return
        if event.matches(QKeySequence.StandardKey.Copy):
            ids = self._selected_ids()
            if ids:
                if len(ids) == 1:
                    self._copy_node_link(next(iter(ids)))
                else:
                    self._copy_multiple_links(ids)
            return
        super().keyPressEvent(event)
