"""Модель таблицы серверов: одна плоская модель вместо цепочки прокси.

Фильтр, сортировка и группировка считаются одним проходом по списку нод в
``_relayout``; результат — плоский список строк (заголовки групп и ноды,
дети свёрнутых групп в него не попадают). Тексты ячеек строки вычисляются
лениво при первой отрисовке и кэшируются в самой строке, поэтому отрисовка
видимой области не зависит от размера каталога, а точечные изменения
(пинг, скорость, активная нода) инвалидируют только свои строки.

Делегат читает строки напрямую через ``row_at``, минуя ``data()``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QSize, Qt, QTimer
from PyQt6.QtGui import QBrush, QFont
from qfluentwidgets import qconfig

from ..profiles.country_flags import get_flag_icon
from ..profiles.models import Node
from ..profiles.node_presentation import display_name, node_country
from .privacy import endpoint_text
from .theme import error_color, success_color, text_muted_color, warning_color

NODE_ROW_HEIGHT = 28

PING_BUSY_ROLE = int(Qt.ItemDataRole.UserRole) + 1
SPEED_PROGRESS_ROLE = int(Qt.ItemDataRole.UserRole) + 2
ACTIVE_ROLE = int(Qt.ItemDataRole.UserRole) + 3
NODE_ID_ROLE = int(Qt.ItemDataRole.UserRole) + 4
GROUP_KEY_ROLE = int(Qt.ItemDataRole.UserRole) + 20

(
    COL_NAME,
    COL_TYPE,
    COL_ADDRESS,
    COL_GROUP,
    COL_TAGS,
    COL_PING,
    COL_SPEED,
    COL_LAST_USED,
    COL_SOURCE,
) = range(9)


@dataclass(frozen=True, slots=True)
class NodeColumnSpec:
    """Single source of truth for one logical server-table column."""

    key: str
    title: str
    default_visible: bool
    default_width: int
    minimum_width: int
    maximum_width: int
    sort_key: str | None = None
    centered: bool = False
    # The single flex column: it absorbs the leftover viewport width during
    # the NodesPage relayout instead of using QHeaderView.ResizeMode.Stretch.
    stretch: bool = False


# Logical order is stable for the model; visual order can be moved and saved.
# Maximums are deliberately generous sanity bounds (persisted values clamp
# against them); live layout is governed by the flex relayout in NodesPage.
COLUMN_SPECS = (
    NodeColumnSpec("name", "Имя", True, 360, 220, 640, "name"),
    NodeColumnSpec("type", "Тип", True, 110, 90, 200, "type", centered=True),
    NodeColumnSpec("address", "Адрес", False, 180, 120, 360),
    NodeColumnSpec("group", "Группа", False, 140, 80, 800, "group"),
    NodeColumnSpec("tags", "Теги", False, 160, 90, 1000),
    NodeColumnSpec("ping", "Пинг", True, 96, 80, 160, "ping", centered=True),
    NodeColumnSpec("speed", "Скорость", True, 112, 96, 200, "speed", centered=True),
    NodeColumnSpec(
        "last_used", "Последнее использование", False, 156, 120, 480, "last_used"
    ),
    NodeColumnSpec("source", "Источник", False, 150, 90, 1000),
)

# Compatibility exports used throughout the app and in persisted settings.
COLUMN_KEYS = [spec.key for spec in COLUMN_SPECS]
DEFAULT_VISIBLE_COLUMNS = [spec.key for spec in COLUMN_SPECS if spec.default_visible]
COLUMN_BY_KEY = {spec.key: spec for spec in COLUMN_SPECS}
_HEADERS = [spec.title for spec in COLUMN_SPECS]
_COLUMN_COUNT = len(COLUMN_SPECS)
CENTERED_COLUMNS = frozenset(index for index, spec in enumerate(COLUMN_SPECS) if spec.centered)

# Stable english sort keys (persisted in AppSettings.nodes_sort_key).
SORT_KEYS = ("manual", "name", "group", "type", "ping", "speed", "last_used")
DEFAULT_SORT_KEY = "manual"

GROUP_MODES = {"source": "Подписки", "group": "Группы", "country": "Страны", "type": "Протоколы", "none": "Без группировки"}

LOCAL_SOURCE_NAME = "Локальные"

# Статус строки для цвета текста (кисти берутся из темы в момент отрисовки).
STATUS_NONE, STATUS_ALIVE, STATUS_DEGRADED, STATUS_DEAD = range(4)

# Перестройка раскладки после метрик (пинг/скорость) не чаще, чем раз в N мс.
_METRIC_RELAYOUT_MS = 300


def node_type_text(node: Node) -> str:
    """Return the protocol label, including legacy nodes with no scheme field."""
    value = (node.scheme or "").strip()
    if not value and isinstance(node.outbound, dict):
        value = str(node.outbound.get("type") or "").strip()
    if not value and "://" in (node.link or ""):
        value = node.link.split("://", 1)[0].strip()
    return value.upper() or "—"


def _format_time(value: str | None) -> str:
    if not value:
        return ""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return value


def ping_status(node: Node) -> tuple[int, str | None]:
    """Статус, который рисуется на ячейке пинга (бывшая колонка «Статус»)."""
    if node.is_alive is None:
        return STATUS_NONE, None
    if node.ping_ms is not None and node.speed_mbps is None and node.is_alive:
        if node.speed_history:
            return STATUS_DEGRADED, "Пинг есть, скорость нет — вероятно заблокирован провайдером"
        return STATUS_NONE, None
    if node.is_alive:
        return STATUS_ALIVE, "Сервер работает"
    return STATUS_DEAD, "Сервер недоступен"


class NodeRow:
    """Строка-сервер. ``texts``/``ping_status`` считаются лениво."""

    __slots__ = ("key", "node", "texts", "status")
    is_group = False

    def __init__(self, node: Node) -> None:
        self.key = "node:" + node.id
        self.node = node
        self.texts: tuple[str, ...] | None = None
        self.status: int | None = None


class GroupRow:
    __slots__ = ("key", "title", "count", "collapsed", "label")
    is_group = True

    def __init__(self, key: str, title: str, count: int, collapsed: bool) -> None:
        self.key = key
        self.title = title
        self.count = count
        self.collapsed = collapsed
        self.label = f"{title} · {count}"


class NodesTableModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._nodes: list[Node] = []
        self._by_id: dict[str, Node] = {}
        self._snapshots: dict[str, tuple] = {}
        self._layout_sigs: dict[str, tuple] = {}
        # Параметры представления.
        self._query = ""
        self._group_filter = ""
        self._tag_filter = ""
        self._source_filter = ""
        self._favorites_only = False
        self._sort_key = DEFAULT_SORT_KEY
        self._descending = False
        self._group_mode = "source"
        self._collapsed: set[str] = set()
        # Оформление поверх нод.
        self._source_names: dict[str, str] = {}
        self._active_node_id: str | None = None
        self._endpoints_revealed = False
        self._busy_ping_ids: set[str] = set()
        self._speed_progress: dict[str, int] = {}
        # Результат раскладки.
        self._rows: list[NodeRow | GroupRow] = []
        self._row_by_key: dict[str, int] = {}
        self._visible_node_count = 0
        self._ordered_ids: list[str] = []
        self._group_keys: list[str] = []
        self._haystacks: dict[str, str] = {}
        self._bold_font: QFont | None = None
        self._relayout_timer = QTimer(self)
        self._relayout_timer.setSingleShot(True)
        self._relayout_timer.setInterval(_METRIC_RELAYOUT_MS)
        self._relayout_timer.timeout.connect(self._relayout)
        qconfig.themeChanged.connect(self._on_theme_changed)

    # ── Данные ─────────────────────────────────────────────

    def set_nodes(self, nodes: list[Node]) -> None:
        """Обновить каталог. Без изменения раскладки — только точечный repaint."""
        new_nodes = list(nodes)
        old_ids = [node.id for node in self._nodes]
        self._nodes = new_nodes
        self._by_id = {node.id: node for node in new_nodes}
        snapshots = {node.id: self._snapshot(node) for node in new_nodes}
        changed = {nid for nid, snap in snapshots.items() if self._snapshots.get(nid) != snap}
        self._snapshots = snapshots
        self._haystacks = {nid: text for nid, text in self._haystacks.items() if nid not in changed and nid in snapshots}
        # Объекты нод могли быть пересозданы выше по стеку — обновить ссылки,
        # а кэш текстов изменившихся строк сбросить до любой перестройки.
        for row in self._rows:
            if not row.is_group:
                node = self._by_id.get(row.node.id)
                if node is not None:
                    row.node = node
                if row.node.id in changed:
                    row.texts = row.status = None
        if [node.id for node in new_nodes] != old_ids or self._layout_changed_for(changed):
            self._relayout()
            return
        self._repaint_nodes(changed)

    def set_source_names(self, names: dict[str, str]) -> None:
        names = dict(names)
        if names == self._source_names:
            return
        self._source_names = names
        self._haystacks.clear()
        self._relayout()

    @staticmethod
    def _snapshot(node: Node) -> tuple:
        return (node.name, node_type_text(node), node.server, node.port, node.group,
                tuple(node.tags), node.ping_ms, node.speed_mbps, node.is_alive,
                bool(node.speed_history), node.country_code, node.country_override,
                node.is_favorite, node.subscription_id, node.last_used_at, node.sort_order)

    # ── Параметры представления ────────────────────────────

    def set_query(self, query: str) -> None:
        query = (query or "").strip().lower()
        if query != self._query:
            self._query = query
            self._relayout()

    def set_group_filter(self, group: str) -> None:
        if (group or "") != self._group_filter:
            self._group_filter = group or ""
            self._relayout()

    def set_tag_filter(self, tag: str) -> None:
        if (tag or "") != self._tag_filter:
            self._tag_filter = tag or ""
            self._relayout()

    def set_source_filter(self, source: str) -> None:
        if (source or "") != self._source_filter:
            self._source_filter = source or ""
            self._relayout()

    def set_favorites_only(self, enabled: bool) -> None:
        if bool(enabled) != self._favorites_only:
            self._favorites_only = bool(enabled)
            self._relayout()

    def set_sort(self, key: str, descending: bool) -> None:
        key = key if key in SORT_KEYS else DEFAULT_SORT_KEY
        if (key, bool(descending)) != (self._sort_key, self._descending):
            self._sort_key, self._descending = key, bool(descending)
            self._relayout()

    def sort_key(self) -> str:
        return self._sort_key

    def set_group_mode(self, mode: str) -> None:
        mode = mode if mode in GROUP_MODES else "source"
        if mode != self._group_mode:
            self._group_mode = mode
            self._relayout()

    def group_mode(self) -> str:
        return self._group_mode

    def set_collapsed_groups(self, keys) -> None:
        keys = set(keys)
        if keys != self._collapsed:
            self._collapsed = keys
            self._relayout()

    def collapsed_groups(self) -> set[str]:
        return set(self._collapsed)

    def group_keys(self) -> list[str]:
        return list(self._group_keys)

    # ── Оформление ─────────────────────────────────────────

    def set_active_node_id(self, node_id: str | None) -> None:
        node_id = node_id or None
        if node_id == self._active_node_id:
            return
        previous, self._active_node_id = self._active_node_id, node_id
        self._repaint_nodes({nid for nid in (previous, node_id) if nid})

    def active_node_id(self) -> str | None:
        return self._active_node_id

    def set_endpoints_revealed(self, revealed: bool) -> None:
        """Reveal address data transiently; this state is never persisted."""
        revealed = bool(revealed)
        if revealed == self._endpoints_revealed:
            return
        self._endpoints_revealed = revealed
        for row in self._rows:
            if not row.is_group:
                row.texts = None
        self._repaint_all()

    def endpoints_revealed(self) -> bool:
        return self._endpoints_revealed

    def set_ping_busy_ids(self, node_ids) -> None:
        node_ids = set(node_ids)
        if node_ids == self._busy_ping_ids:
            return
        changed = node_ids ^ self._busy_ping_ids
        self._busy_ping_ids = node_ids
        self._repaint_nodes(changed, COL_PING)

    def clear_ping_busy(self) -> None:
        self.set_ping_busy_ids(set())

    def is_ping_busy(self, node_id: str) -> bool:
        return node_id in self._busy_ping_ids

    def set_speed_progress_batch(self, progress: dict[str, int]) -> None:
        changed = set()
        for node_id, percent in progress.items():
            percent = max(0, min(100, int(percent)))
            if self._speed_progress.get(node_id) != percent:
                self._speed_progress[node_id] = percent
                changed.add(node_id)
        self._repaint_nodes(changed, COL_SPEED)

    def clear_speed_progress(self) -> None:
        if self._speed_progress:
            changed = set(self._speed_progress)
            self._speed_progress.clear()
            self._repaint_nodes(changed, COL_SPEED)

    def speed_progress(self, node_id: str) -> int | None:
        return self._speed_progress.get(node_id)

    # ── Результаты метрик (объекты нод уже изменены на месте) ──

    def finish_ping_batch(self, node_ids) -> None:
        node_ids = set(node_ids)
        self._busy_ping_ids -= node_ids
        self._metrics_changed(node_ids)

    def finish_speed(self, node_id: str) -> None:
        self._speed_progress.pop(node_id, None)
        self._metrics_changed({node_id})

    def refresh_alive_status(self, node_id: str) -> None:
        self._metrics_changed({node_id})

    def refresh_countries(self, node_ids) -> None:
        self._metrics_changed(set(node_ids))

    def _metrics_changed(self, node_ids: set[str]) -> None:
        changed = set()
        for nid in node_ids:
            node = self._by_id.get(nid)
            if node is None:
                continue
            snap = self._snapshot(node)
            if self._snapshots.get(nid) != snap:
                self._snapshots[nid] = snap
                changed.add(nid)
        if self._layout_changed_for(changed):
            # Пачки результатов пинга не должны пересортировывать таблицу на
            # каждый ответ: одна перестройка на окно.
            if not self._relayout_timer.isActive():
                self._relayout_timer.start()
        self._invalidate_nodes(node_ids)

    # ── Доступ для страницы и делегата ─────────────────────

    def row_at(self, row: int) -> NodeRow | GroupRow | None:
        return self._rows[row] if 0 <= row < len(self._rows) else None

    def row_of_node(self, node_id: str) -> int | None:
        return self._row_by_key.get("node:" + node_id)

    def row_of_key(self, key: str) -> int | None:
        return self._row_by_key.get(key)

    def node(self, node_id: str) -> Node | None:
        return self._by_id.get(node_id)

    def node_at_row(self, row: int) -> Node | None:
        item = self.row_at(row)
        return None if item is None or item.is_group else item.node

    def collapsed_group_of(self, node_id: str) -> str | None:
        """Ключ свёрнутой группы, скрывающей ноду (None — нода видна или отфильтрована)."""
        node = self._by_id.get(node_id)
        if node is None or not self._accepts(node):
            return None
        key = self._group_of(node)[0]
        return key if key and key in self._collapsed else None

    def visible_node_count(self) -> int:
        return self._visible_node_count

    def visible_node_ids(self) -> list[str]:
        """Ноды после фильтра в порядке отображения (включая свёрнутые)."""
        return list(self._ordered_ids)

    def texts(self, row: NodeRow) -> tuple[str, ...]:
        if row.texts is None:
            row.texts = self._build_texts(row.node)
        return row.texts

    def status(self, row: NodeRow) -> int:
        if row.status is None:
            row.status = ping_status(row.node)[0]
        return row.status

    def source_name(self, node: Node) -> str:
        if not node.subscription_id:
            return LOCAL_SOURCE_NAME
        return self._source_names.get(node.subscription_id, "Подписка")

    # ── QAbstractTableModel ────────────────────────────────

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else _COLUMN_COUNT

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and 0 <= section < _COLUMN_COUNT:
            if role == Qt.ItemDataRole.TextAlignmentRole:
                return int(Qt.AlignmentFlag.AlignCenter if section in CENTERED_COLUMNS
                           else Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            if role == Qt.ItemDataRole.DisplayRole:
                return _HEADERS[section]
        return super().headerData(section, orientation, role)

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        row = self.row_at(index.row()) if index.isValid() else None
        if row is None:
            return Qt.ItemFlag.NoItemFlags
        if row.is_group:
            return Qt.ItemFlag.ItemIsEnabled
        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        # Делегат сюда не ходит; это API для тестов, подсказок и доступности.
        row = self.row_at(index.row()) if index.isValid() else None
        if row is None:
            return None
        col = index.column()
        if role == Qt.ItemDataRole.SizeHintRole:
            return QSize(0, NODE_ROW_HEIGHT)
        if row.is_group:
            if role == GROUP_KEY_ROLE:
                return row.key
            if role == Qt.ItemDataRole.DisplayRole and col == COL_NAME:
                return row.label
            if role == Qt.ItemDataRole.FontRole:
                return self._bold()
            return None
        node = row.node
        if role == NODE_ID_ROLE:
            return node.id
        if role == ACTIVE_ROLE:
            return node.id == self._active_node_id
        if role == PING_BUSY_ROLE:
            return col == COL_PING and node.id in self._busy_ping_ids
        if role == SPEED_PROGRESS_ROLE:
            return self._speed_progress.get(node.id) if col == COL_SPEED else None
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.EditRole):
            return self.display_text(row, col)
        if role == Qt.ItemDataRole.DecorationRole and col == COL_NAME:
            return get_flag_icon(node_country(node))
        if role == Qt.ItemDataRole.ToolTipRole:
            return self.tooltip(node, col)
        if role == Qt.ItemDataRole.ForegroundRole:
            color = self.status_color(row, col)
            return QBrush(color) if color is not None else None
        if role == Qt.ItemDataRole.TextAlignmentRole and col in CENTERED_COLUMNS:
            return int(Qt.AlignmentFlag.AlignCenter)
        return None

    def display_text(self, row: NodeRow, col: int) -> str:
        node_id = row.node.id
        if col == COL_PING and node_id in self._busy_ping_ids:
            return ""
        if col == COL_SPEED and node_id in self._speed_progress:
            return ""
        return self.texts(row)[col]

    def status_color(self, row: NodeRow, col: int):
        """Цвет текста ячейки по статусу; None — обычный цвет темы.

        У недоступного сервера красный только пинг, остальные ячейки
        приглушены: иначе список из половины мёртвых серверов выглядит как
        сплошная авария и перебивает рабочие строки.
        """
        if col != COL_PING:
            return text_muted_color() if row.node.is_alive is False else None
        status = self.status(row)
        if status == STATUS_ALIVE:
            return success_color()
        if status == STATUS_DEGRADED:
            return warning_color()
        if status == STATUS_DEAD:
            return error_color()
        return None

    def tooltip(self, node: Node, col: int) -> str | None:
        endpoint = endpoint_text(node.server, node.port, self._endpoints_revealed)
        if col == COL_NAME:
            lines = [node.name or "Без имени", f"Тип: {node_type_text(node)}", f"Адрес: {endpoint}"]
            if node.group:
                lines.append(f"Группа: {node.group}")
            if node.tags:
                lines.append(f"Теги: {', '.join(node.tags)}")
            lines.append(f"Источник: {self.source_name(node)}")
            return "\n".join(lines)
        if col == COL_ADDRESS:
            return endpoint
        if col == COL_PING:
            if node.id in self._busy_ping_ids:
                return "Проверка пинга..."
            _, text = ping_status(node)
            if text:
                return f"Пинг: {node.ping_ms} ms\n{text}" if node.ping_ms is not None else text
            return f"Пинг: {node.ping_ms} ms" if node.ping_ms is not None else None
        if col == COL_SPEED and node.id in self._speed_progress:
            return f"Тест скорости: {self._speed_progress[node.id]}%"
        return None

    # ── Раскладка ──────────────────────────────────────────

    def _build_texts(self, node: Node) -> tuple[str, ...]:
        return (
            ("★ " if node.is_favorite else "") + display_name(node.name),
            node_type_text(node),
            endpoint_text(node.server, node.port, self._endpoints_revealed),
            node.group,
            ", ".join(node.tags),
            "--" if node.ping_ms is None else f"{node.ping_ms} ms",
            "--" if node.speed_mbps is None else f"{node.speed_mbps:.1f} MB/s",
            _format_time(node.last_used_at),
            self.source_name(node),
        )

    def _layout_sig(self, node: Node) -> tuple:
        """Значения ноды, от которых зависят фильтр, сортировка и группа."""
        return (node.is_favorite, node.group, tuple(node.tags), node.subscription_id,
                self._sort_value(node), self._group_of(node)[0],
                self._haystack_source(node) if self._query else None)

    def _layout_changed_for(self, node_ids: set[str]) -> bool:
        changed = False
        for nid in node_ids:
            node = self._by_id.get(nid)
            if node is None:
                continue
            sig = self._layout_sig(node)
            if self._layout_sigs.get(nid) != sig:
                self._layout_sigs[nid] = sig
                changed = True
        return changed

    def _accepts(self, node: Node) -> bool:
        if self._favorites_only and not node.is_favorite:
            return False
        if self._group_filter and node.group != self._group_filter:
            return False
        if self._tag_filter and self._tag_filter not in node.tags:
            return False
        if self._source_filter and self.source_name(node) != self._source_filter:
            return False
        if self._query:
            haystack = self._haystacks.get(node.id)
            if haystack is None:
                haystack = self._haystacks[node.id] = self._haystack_source(node)
            if self._query not in haystack:
                return False
        return True

    def _haystack_source(self, node: Node) -> str:
        return " ".join((node.name, node_type_text(node), node.server, node.group,
                         self.source_name(node), " ".join(node.tags))).lower()

    def _sort_value(self, node: Node):
        key = self._sort_key
        if key == "manual":
            return node.sort_order
        if key == "type":
            return node_type_text(node).casefold()
        if key == "ping":
            return node.ping_ms
        if key == "speed":
            return node.speed_mbps
        value = {"name": node.name, "group": node.group, "last_used": node.last_used_at}[key]
        return (value or "").casefold()

    def _sorted(self, nodes: list[Node]) -> list[Node]:
        if self._sort_key in ("ping", "speed"):
            # Пустые метрики всегда в конце, в обоих направлениях.
            known = [node for node in nodes if self._sort_value(node) is not None]
            unknown = [node for node in nodes if self._sort_value(node) is None]
            known.sort(key=self._sort_value, reverse=self._descending)
            return known + unknown
        return sorted(nodes, key=self._sort_value, reverse=self._descending)

    def _group_of(self, node: Node) -> tuple[str, str]:
        mode = self._group_mode
        if mode == "none":
            return "", ""
        if mode == "source":
            key = node.subscription_id or "local"
            title = self._source_names.get(key, LOCAL_SOURCE_NAME if key == "local" else "Подписка")
            return "source:" + key, title
        if mode == "group":
            return "group:" + node.group, node.group or "Без группы"
        if mode == "country":
            code = node_country(node)
            return "country:" + code, code or "Страна не определена"
        value = node_type_text(node)
        return "type:" + value, value

    def _relayout(self) -> None:
        self._relayout_timer.stop()
        visible = self._sorted([node for node in self._nodes if self._accepts(node)])
        self._ordered_ids = [node.id for node in visible]
        self._layout_sigs = {node.id: self._layout_sig(node) for node in self._nodes}
        old_rows = {row.key: row for row in self._rows}
        rows: list[NodeRow | GroupRow] = []
        group_keys: list[str] = []
        if self._group_mode == "none":
            rows = [self._reuse_row(old_rows, node) for node in visible]
        else:
            groups: dict[str, tuple[str, list[Node]]] = {}
            for node in visible:
                key, title = self._group_of(node)
                groups.setdefault(key, (title, []))[1].append(node)
            for key, (title, members) in sorted(groups.items(), key=lambda item: (item[1][0].casefold(), item[0])):
                collapsed = key in self._collapsed
                group_keys.append(key)
                rows.append(GroupRow(key, title, len(members), collapsed))
                if not collapsed:
                    rows.extend(self._reuse_row(old_rows, node) for node in members)
        self._apply_rows(rows)
        self._group_keys = group_keys
        self._visible_node_count = len(visible)

    @staticmethod
    def _reuse_row(old_rows: dict, node: Node) -> NodeRow:
        row = old_rows.get("node:" + node.id)
        if row is None or row.is_group:
            return NodeRow(node)
        row.node = node
        return row

    def _apply_rows(self, rows: list[NodeRow | GroupRow]) -> None:
        new_keys = [row.key for row in rows]
        old_keys = [row.key for row in self._rows]
        if new_keys == old_keys:
            self._rows = rows
            self._repaint_all()
            return
        if set(new_keys) != set(old_keys):
            # Состав строк изменился (фильтр, свёртка, импорт) — контракт Qt
            # требует reset; выделение восстанавливает вид по ключам строк.
            self.beginResetModel()
            self._rows = rows
            self._row_by_key = {key: index for index, key in enumerate(new_keys)}
            self.endResetModel()
            return
        # Тот же состав, другой порядок — layoutChanged с переносом индексов,
        # чтобы выделение и текущая строка поехали вместе со строками.
        self.layoutAboutToBeChanged.emit()
        persistent = self.persistentIndexList()
        identities = [(self._rows[index.row()].key, index.column()) for index in persistent]
        self._rows = rows
        self._row_by_key = {key: index for index, key in enumerate(new_keys)}
        self.changePersistentIndexList(
            persistent,
            [self.index(self._row_by_key[key], column) for key, column in identities],
        )
        self.layoutChanged.emit()

    # ── Уведомления об изменениях ──────────────────────────

    def _invalidate_nodes(self, node_ids) -> None:
        rows = []
        for nid in node_ids:
            index = self._row_by_key.get("node:" + nid)
            if index is not None:
                item = self._rows[index]
                item.texts = None
                item.status = None
                rows.append(index)
        self._emit_rows(rows)

    def _repaint_nodes(self, node_ids, column: int | None = None) -> None:
        rows = [index for index in (self._row_by_key.get("node:" + nid) for nid in node_ids) if index is not None]
        self._emit_rows(rows, column)

    def _emit_rows(self, rows: list[int], column: int | None = None) -> None:
        if not rows:
            return
        first_col, last_col = (column, column) if column is not None else (0, _COLUMN_COUNT - 1)
        rows.sort()
        start = previous = rows[0]
        for row in rows[1:] + [None]:
            if row is not None and row == previous + 1:
                previous = row
                continue
            self.dataChanged.emit(self.index(start, first_col), self.index(previous, last_col))
            if row is not None:
                start = previous = row

    def _repaint_all(self) -> None:
        if self._rows:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self._rows) - 1, _COLUMN_COUNT - 1))

    def _on_theme_changed(self, *_args) -> None:
        self._bold_font = None
        self._repaint_all()

    def _bold(self) -> QFont:
        if self._bold_font is None:
            self._bold_font = QFont()
            self._bold_font.setBold(True)
        return self._bold_font
