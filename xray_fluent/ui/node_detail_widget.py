from __future__ import annotations

from datetime import datetime

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    CardWidget,
    FluentIcon as FIF,
    StrongBodyLabel,
    TableWidget,
    TransparentToolButton,
)

from ..models import Node
from .detail_page import DetailPage


class NodeDetailWidget(DetailPage):
    ping_node_requested = pyqtSignal(str)       # node_id
    speed_test_node_requested = pyqtSignal(str)  # node_id
    cancel_speed_test_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(
            "Серверы",
            "Детали сервера",
            parent,
            root_key="nodes",
            page_key="node-detail",
        )
        self._node: Node | None = None

        root = self.content_layout

        # Action buttons in the shared header row
        self.ping_btn = TransparentToolButton(FIF.SEND, self)
        self.ping_btn.setToolTip("Пинг")
        self.ping_btn.clicked.connect(self._ping)
        self.add_header_action(self.ping_btn)
        self.speed_btn = TransparentToolButton(FIF.SPEED_HIGH, self)
        self.speed_btn.setToolTip("Тест скорости")
        self.speed_btn.clicked.connect(self._speed_test)
        self.add_header_action(self.speed_btn)
        self.stop_speed_btn = TransparentToolButton(FIF.PAUSE_BOLD, self)
        self.stop_speed_btn.setToolTip("Остановить тест скорости")
        self.stop_speed_btn.clicked.connect(self.cancel_speed_test_requested.emit)
        self.stop_speed_btn.setVisible(False)
        self.add_header_action(self.stop_speed_btn)

        # Info card
        self.info_card = CardWidget(self)
        info_layout = QVBoxLayout(self.info_card)
        info_layout.setContentsMargins(18, 16, 18, 16)
        info_layout.setSpacing(4)
        self.name_label = StrongBodyLabel("", self.info_card)
        self.endpoint_label = BodyLabel("", self.info_card)
        self.details_label = CaptionLabel("", self.info_card)
        self.status_label = CaptionLabel("", self.info_card)
        info_layout.addWidget(self.name_label)
        info_layout.addWidget(self.endpoint_label)
        info_layout.addWidget(self.details_label)
        info_layout.addWidget(self.status_label)
        root.addWidget(self.info_card)

        # Two tables side by side: ping history + speed history
        tables_row = QHBoxLayout()
        tables_row.setSpacing(12)

        # Ping history
        ping_card = CardWidget(self)
        ping_layout = QVBoxLayout(ping_card)
        ping_layout.setContentsMargins(12, 12, 12, 12)
        ping_layout.addWidget(StrongBodyLabel("История пинга", ping_card))
        self.ping_table = TableWidget(ping_card)
        self.ping_table.setColumnCount(2)
        self.ping_table.setHorizontalHeaderLabels(["Время", "Пинг"])
        self.ping_table.verticalHeader().setVisible(False)
        h = self.ping_table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        h.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.ping_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        ping_layout.addWidget(self.ping_table, 1)
        tables_row.addWidget(ping_card)

        # Speed history
        speed_card = CardWidget(self)
        speed_layout = QVBoxLayout(speed_card)
        speed_layout.setContentsMargins(12, 12, 12, 12)
        speed_layout.addWidget(StrongBodyLabel("История скорости", speed_card))
        self.speed_table = TableWidget(speed_card)
        self.speed_table.setColumnCount(2)
        self.speed_table.setHorizontalHeaderLabels(["Время", "Скорость"])
        self.speed_table.verticalHeader().setVisible(False)
        h2 = self.speed_table.horizontalHeader()
        h2.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        h2.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.speed_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        speed_layout.addWidget(self.speed_table, 1)
        tables_row.addWidget(speed_card)

        root.addLayout(tables_row, 1)

    def set_node(self, node: Node) -> None:
        self._node = node
        self.set_page_label(node.name or "Без имени")
        self._refresh()

    def refresh(self, node_id: str | None = None) -> None:
        """Refresh display with latest data (call after ping/speed update)."""
        if self._node and (node_id is None or self._node.id == node_id):
            self._refresh()

    def set_speed_test_running(self, running: bool, *, stopping: bool = False) -> None:
        self.speed_btn.setEnabled(not running)
        self.stop_speed_btn.setVisible(running)
        self.stop_speed_btn.setEnabled(running and not stopping)

    def _refresh(self) -> None:
        node = self._node
        if not node:
            return

        # Info
        self.name_label.setText(node.name or "Без имени")

        scheme = node.scheme.upper() if node.scheme else "?"
        self.endpoint_label.setText(f"{node.server}:{node.port}  ({scheme})")
        self.details_label.setText(
            f"Группа: {node.group or 'Default'}  |  "
            f"Страна: {node.country_code.upper() or '?'}  |  "
            f"Теги: {', '.join(node.tags) or chr(8212)}"
        )

        parts: list[str] = []
        if node.ping_ms is not None:
            parts.append(f"Пинг: {node.ping_ms} ms")
        if node.speed_mbps is not None:
            parts.append(f"Скорость: {node.speed_mbps:.1f} MB/s")
        if node.is_alive is not None:
            parts.append("Статус: OK" if node.is_alive else "Статус: Недоступен")
        self.status_label.setText("  |  ".join(parts) if parts else "Не тестировался")

        # Ping history table (newest first)
        history = list(reversed(node.ping_history))
        self.ping_table.setRowCount(len(history))
        for row, (ts, ms) in enumerate(history):
            time_str = self._format_ts(ts)
            self.ping_table.setItem(row, 0, QTableWidgetItem(time_str))
            self.ping_table.setItem(row, 1, QTableWidgetItem("--" if ms is None else f"{ms} ms"))

        # Speed history table (newest first)
        history = list(reversed(node.speed_history))
        self.speed_table.setRowCount(len(history))
        for row, (ts, spd) in enumerate(history):
            time_str = self._format_ts(ts)
            self.speed_table.setItem(row, 0, QTableWidgetItem(time_str))
            self.speed_table.setItem(row, 1, QTableWidgetItem("--" if spd is None else f"{spd:.1f} MB/s"))

    def _ping(self) -> None:
        if self._node:
            self.ping_node_requested.emit(self._node.id)

    def _speed_test(self) -> None:
        if self._node:
            self.speed_test_node_requested.emit(self._node.id)

    @staticmethod
    def _format_ts(iso: str) -> str:
        try:
            dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
            return dt.strftime("%H:%M:%S")
        except (ValueError, AttributeError):
            return iso
