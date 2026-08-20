from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt6.QtGui import QBrush
from qfluentwidgets import qconfig

from ..country_flags import get_flag_icon
from ..models import Node
from .privacy import endpoint_text
from .theme import error_color, success_color, warning_color

PING_BUSY_ROLE = int(Qt.ItemDataRole.UserRole) + 1
SPEED_PROGRESS_ROLE = int(Qt.ItemDataRole.UserRole) + 2
ACTIVE_ROLE = int(Qt.ItemDataRole.UserRole) + 3
NODE_ID_ROLE = int(Qt.ItemDataRole.UserRole) + 4


def _dead_brush() -> QBrush:
    """Brush for unreachable nodes; resolved lazily from the theme tokens."""
    return QBrush(error_color())


def _alive_brush() -> QBrush:
    return QBrush(success_color())


def _degraded_brush() -> QBrush:
    return QBrush(warning_color())

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
    stretch: bool = False


# Logical order is stable for the model; visual order can be moved and saved.
# Width limits prevent compact value columns from consuming the table while
# keeping every non-name column interactively resizable.
COLUMN_SPECS = (
    NodeColumnSpec("name", "Имя", True, 420, 180, 1600, "name", stretch=True),
    NodeColumnSpec("type", "Тип", True, 58, 44, 96, "type", centered=True),
    NodeColumnSpec("address", "Адрес", True, 190, 112, 420),
    NodeColumnSpec("group", "Группа", False, 140, 80, 320, "group"),
    NodeColumnSpec("tags", "Теги", False, 160, 90, 420),
    NodeColumnSpec("ping", "Пинг", True, 82, 64, 120, "ping", centered=True),
    NodeColumnSpec("speed", "Скорость", True, 106, 82, 150, "speed", centered=True),
    NodeColumnSpec(
        "last_used", "Последнее использование", False, 156, 120, 260, "last_used"
    ),
    NodeColumnSpec("source", "Источник", False, 150, 90, 360),
)

# Compatibility exports used throughout the app and in persisted settings.
COLUMN_KEYS = [spec.key for spec in COLUMN_SPECS]
DEFAULT_VISIBLE_COLUMNS = [spec.key for spec in COLUMN_SPECS if spec.default_visible]
COLUMN_BY_KEY = {spec.key: spec for spec in COLUMN_SPECS}
_HEADERS = [spec.title for spec in COLUMN_SPECS]
_CENTERED_COLUMNS = tuple(
    index for index, spec in enumerate(COLUMN_SPECS) if spec.centered
)

_ROW_ROLES = [
    Qt.ItemDataRole.DisplayRole,
    Qt.ItemDataRole.ToolTipRole,
    Qt.ItemDataRole.ForegroundRole,
    PING_BUSY_ROLE,
    SPEED_PROGRESS_ROLE,
]


def node_type_text(node: Node) -> str:
    """Return the protocol label, including legacy nodes with no scheme field."""
    value = (node.scheme or "").strip()
    if not value and isinstance(node.outbound, dict):
        value = str(node.outbound.get("type") or "").strip()
    if not value and "://" in (node.link or ""):
        value = node.link.split("://", 1)[0].strip()
    return value.upper() or "—"


def _contiguous_ranges(rows: list[int]) -> list[tuple[int, int]]:
    """Group sorted row indexes into contiguous (first, last) ranges."""
    ranges: list[tuple[int, int]] = []
    for row in rows:
        if ranges and ranges[-1][1] == row - 1:
            ranges[-1] = (ranges[-1][0], row)
        else:
            ranges.append((row, row))
    return ranges


class NodesTableModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._nodes: list[Node] = []
        self._id_to_row: dict[str, int] = {}
        self._busy_ping_ids: set[str] = set()
        self._speed_progress: dict[str, int] = {}
        self._source_names: dict[str, str] = {}
        self._active_node_id: str | None = None
        self._endpoints_revealed = False
        # Status brushes depend on the theme: repaint foregrounds on change.
        qconfig.themeChanged.connect(self._on_theme_changed)

    def _on_theme_changed(self) -> None:
        if not self._nodes:
            return
        self.dataChanged.emit(
            self.index(0, 0),
            self.index(len(self._nodes) - 1, len(_HEADERS) - 1),
            [Qt.ItemDataRole.ForegroundRole],
        )

    def set_source_names(self, names: dict[str, str]) -> None:
        self._source_names = dict(names)

    def set_nodes(self, nodes: list[Node]) -> None:
        self.beginResetModel()
        self._nodes = list(nodes)
        self._id_to_row = {node.id: row for row, node in enumerate(self._nodes)}
        self.endResetModel()

    def update_nodes(self, nodes: list[Node]) -> None:
        """Diff-update by node id: no modelReset for point changes."""
        new_nodes = list(nodes)
        if not self._nodes or not new_nodes:
            self.set_nodes(new_nodes)
            return

        new_by_id = {node.id: node for node in new_nodes}
        old_ids = {node.id for node in self._nodes}
        removed_rows = [
            row for row, node in enumerate(self._nodes) if node.id not in new_by_id
        ]
        added = [node for node in new_nodes if node.id not in old_ids]

        # Fallback to a full reset when more than 50% of rows changed.
        if 2 * (len(removed_rows) + len(added)) > max(len(self._nodes), len(new_nodes)):
            self.set_nodes(new_nodes)
            return

        # Remove contiguous ranges in descending order.
        for first, last in reversed(_contiguous_ranges(removed_rows)):
            self.beginRemoveRows(QModelIndex(), first, last)
            del self._nodes[first : last + 1]
            self._id_to_row = {node.id: row for row, node in enumerate(self._nodes)}
            self.endRemoveRows()

        # Refresh surviving node objects (instances may be recreated upstream).
        for row, node in enumerate(self._nodes):
            self._nodes[row] = new_by_id[node.id]

        if added:
            first = len(self._nodes)
            self.beginInsertRows(QModelIndex(), first, first + len(added) - 1)
            self._nodes.extend(added)
            self._id_to_row = {node.id: row for row, node in enumerate(self._nodes)}
            self.endInsertRows()
        else:
            self._id_to_row = {node.id: row for row, node in enumerate(self._nodes)}

        if self._nodes:
            # One wide dataChanged for updated rows (all roles).
            self.dataChanged.emit(
                self.index(0, 0),
                self.index(len(self._nodes) - 1, len(_HEADERS) - 1),
            )

    def set_active_node_id(self, node_id: str | None) -> None:
        node_id = node_id or None
        if node_id == self._active_node_id:
            return
        previous = self._active_node_id
        self._active_node_id = node_id
        for nid in (previous, node_id):
            if nid is None:
                continue
            row = self._id_to_row.get(nid)
            if row is None:
                continue
            self.dataChanged.emit(
                self.index(row, 0),
                self.index(row, len(_HEADERS) - 1),
                [Qt.ItemDataRole.DisplayRole, ACTIVE_ROLE],
            )

    def active_node_id(self) -> str | None:
        return self._active_node_id

    def set_endpoints_revealed(self, revealed: bool) -> None:
        """Reveal address data transiently; this state is never persisted."""
        revealed = bool(revealed)
        if revealed == self._endpoints_revealed:
            return
        self._endpoints_revealed = revealed
        if not self._nodes:
            return
        roles = [Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole]
        self.dataChanged.emit(
            self.index(0, COL_ADDRESS),
            self.index(len(self._nodes) - 1, COL_ADDRESS),
            roles,
        )
        # The name tooltip also contains the endpoint.
        self.dataChanged.emit(
            self.index(0, COL_NAME),
            self.index(len(self._nodes) - 1, COL_NAME),
            [Qt.ItemDataRole.ToolTipRole],
        )

    def endpoints_revealed(self) -> bool:
        return self._endpoints_revealed

    def set_ping_busy(self, node_id: str, busy: bool) -> None:
        changed = False
        if busy:
            if node_id not in self._busy_ping_ids:
                self._busy_ping_ids.add(node_id)
                changed = True
        else:
            if node_id in self._busy_ping_ids:
                self._busy_ping_ids.discard(node_id)
                changed = True
        if changed:
            self._emit_cell_changed(node_id, COL_PING)

    def set_ping_busy_ids(self, node_ids: set[str]) -> None:
        node_ids = set(node_ids)
        if node_ids == self._busy_ping_ids:
            return
        self._busy_ping_ids = node_ids
        self._emit_column_changed(COL_PING)

    def clear_ping_busy(self) -> None:
        if not self._busy_ping_ids:
            return
        self._busy_ping_ids.clear()
        self._emit_column_changed(COL_PING)

    def set_speed_progress(self, node_id: str, percent: int | None) -> None:
        if percent is None:
            if node_id not in self._speed_progress:
                return
            self._speed_progress.pop(node_id, None)
        else:
            percent = max(0, min(100, int(percent)))
            if self._speed_progress.get(node_id) == percent:
                return
            self._speed_progress[node_id] = percent
        self._emit_cell_changed(node_id, COL_SPEED)

    def set_speed_progress_batch(self, progress: dict[str, int]) -> None:
        changed_rows: list[int] = []
        for node_id, percent in progress.items():
            percent = max(0, min(100, int(percent)))
            if self._speed_progress.get(node_id) == percent:
                continue
            self._speed_progress[node_id] = percent
            row = self._id_to_row.get(node_id)
            if row is not None:
                changed_rows.append(row)
        if not changed_rows:
            return
        self.dataChanged.emit(
            self.index(min(changed_rows), COL_SPEED),
            self.index(max(changed_rows), COL_SPEED),
            [Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole, SPEED_PROGRESS_ROLE],
        )

    def clear_speed_progress(self) -> None:
        if not self._speed_progress:
            return
        self._speed_progress.clear()
        self._emit_column_changed(COL_SPEED)

    def row_for_node(self, node_id: str) -> int | None:
        return self._id_to_row.get(node_id)

    def node_at_row(self, row: int) -> Node | None:
        if 0 <= row < len(self._nodes):
            return self._nodes[row]
        return None

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._nodes)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(_HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            if 0 <= section < len(_HEADERS):
                return _HEADERS[section]
        return super().headerData(section, orientation, role)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None

        row = index.row()
        col = index.column()
        if row < 0 or row >= len(self._nodes):
            return None

        node = self._nodes[row]

        if role == NODE_ID_ROLE:
            return node.id

        if role == ACTIVE_ROLE:
            return self._active_node_id is not None and node.id == self._active_node_id

        if role == PING_BUSY_ROLE:
            return col == COL_PING and node.id in self._busy_ping_ids

        if role == SPEED_PROGRESS_ROLE:
            if col == COL_SPEED:
                return self._speed_progress.get(node.id)
            return None

        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.EditRole):
            return self._display_text(node, col)

        if role == Qt.ItemDataRole.DecorationRole and col == COL_NAME:
            return get_flag_icon(node.country_code)

        if role == Qt.ItemDataRole.ToolTipRole:
            return self._tooltip_text(node, col)

        if role == Qt.ItemDataRole.ForegroundRole:
            return self._foreground_brush(node, col)

        if role == Qt.ItemDataRole.TextAlignmentRole and col in _CENTERED_COLUMNS:
            return int(Qt.AlignmentFlag.AlignCenter)

        return None

    def refresh_ping(self, node_id: str) -> None:
        self._emit_row_changed(node_id)

    def finish_ping(self, node_id: str) -> None:
        self._busy_ping_ids.discard(node_id)
        self._emit_row_changed(node_id)

    def finish_ping_batch(self, node_ids: set[str]) -> None:
        """Flush a batch of ping results with a single dataChanged emission."""
        if not node_ids:
            return
        self._busy_ping_ids -= set(node_ids)
        rows = [
            row for row in (self._id_to_row.get(nid) for nid in node_ids) if row is not None
        ]
        if not rows:
            return
        self.dataChanged.emit(
            self.index(min(rows), 0),
            self.index(max(rows), len(_HEADERS) - 1),
            _ROW_ROLES,
        )

    def refresh_speed(self, node_id: str) -> None:
        self._emit_cell_changed(node_id, COL_SPEED)

    def finish_speed(self, node_id: str) -> None:
        self._speed_progress.pop(node_id, None)
        self._emit_row_changed(node_id)

    def refresh_alive_status(self, node_id: str) -> None:
        self._emit_row_changed(node_id)

    def _emit_row_changed(self, node_id: str) -> None:
        row = self._id_to_row.get(node_id)
        if row is None:
            return
        top_left = self.index(row, 0)
        bottom_right = self.index(row, len(_HEADERS) - 1)
        self.dataChanged.emit(top_left, bottom_right, _ROW_ROLES)

    def _display_text(self, node: Node, col: int) -> str:
        if col == COL_NAME:
            return node.name or "Без имени"
        if col == COL_TYPE:
            return node_type_text(node)
        if col == COL_ADDRESS:
            return endpoint_text(node.server, node.port, self._endpoints_revealed)
        if col == COL_GROUP:
            return node.group
        if col == COL_TAGS:
            return ", ".join(node.tags)
        if col == COL_PING:
            if node.id in self._busy_ping_ids:
                return ""
            return "--" if node.ping_ms is None else f"{node.ping_ms} ms"
        if col == COL_SPEED:
            if node.id in self._speed_progress:
                return ""
            return "--" if node.speed_mbps is None else f"{node.speed_mbps:.1f} MB/s"
        if col == COL_LAST_USED:
            return NodesTableModel._format_time(node.last_used_at)
        if col == COL_SOURCE:
            return self._source_name(node)
        return ""

    def _source_name(self, node: Node) -> str:
        if not node.subscription_id:
            return "Локальные"
        return self._source_names.get(node.subscription_id, "Подписка")

    def _tooltip_text(self, node: Node, col: int) -> str | None:
        if col == COL_NAME:
            lines = [node.name or "Без имени", f"Тип: {node_type_text(node)}"]
            lines.append(
                f"Адрес: {endpoint_text(node.server, node.port, self._endpoints_revealed)}"
            )
            if node.group:
                lines.append(f"Группа: {node.group}")
            if node.tags:
                lines.append(f"Теги: {', '.join(node.tags)}")
            lines.append(f"Источник: {self._source_name(node)}")
            return "\n".join(lines)
        if col == COL_ADDRESS:
            return endpoint_text(node.server, node.port, self._endpoints_revealed)
        if col == COL_PING:
            if node.id in self._busy_ping_ids:
                return "Проверка пинга..."
            status_tooltip, _ = NodesTableModel._ping_status_meta(node)
            if status_tooltip:
                if node.ping_ms is not None:
                    return f"Пинг: {node.ping_ms} ms\n{status_tooltip}"
                return status_tooltip
            if node.ping_ms is not None:
                return f"Пинг: {node.ping_ms} ms"
            return None
        if col == COL_SPEED and node.id in self._speed_progress:
            return f"Тест скорости: {self._speed_progress[node.id]}%"
        return None

    @staticmethod
    def _foreground_brush(node: Node, col: int) -> QBrush | None:
        if node.is_alive is False:
            return _dead_brush()
        if col == COL_PING:
            _, brush = NodesTableModel._ping_status_meta(node)
            return brush
        return None

    @staticmethod
    def _ping_status_meta(node: Node) -> tuple[str | None, QBrush | None]:
        """Status semantics rendered onto the ping cell (former «Статус» column)."""
        if node.is_alive is None:
            return None, None

        if node.ping_ms is not None and node.speed_mbps is None and node.is_alive:
            if node.speed_history:
                return (
                    "Пинг есть, скорость нет — вероятно заблокирован провайдером",
                    _degraded_brush(),
                )
            return None, None

        if node.is_alive:
            return "Сервер работает", _alive_brush()

        return "Сервер недоступен", _dead_brush()

    @staticmethod
    def _format_time(value: str | None) -> str:
        if not value:
            return ""
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M")
        except ValueError:
            return value

    def _emit_cell_changed(self, node_id: str, column: int) -> None:
        row = self._id_to_row.get(node_id)
        if row is None:
            return
        index = self.index(row, column)
        self.dataChanged.emit(index, index, _ROW_ROLES)

    def _emit_column_changed(self, column: int) -> None:
        if not self._nodes:
            return
        self.dataChanged.emit(
            self.index(0, column),
            self.index(len(self._nodes) - 1, column),
            [
                Qt.ItemDataRole.DisplayRole,
                Qt.ItemDataRole.ToolTipRole,
                PING_BUSY_ROLE,
                SPEED_PROGRESS_ROLE,
            ],
        )
