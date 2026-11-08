"""Вкладка «Кто подключается»: кто обращался к этому компьютеру за файлами обновления.

Показывает, работает ли раздача по локальной сети и через интернет, и журнал обращений: когда,
откуда (локальная сеть или интернет), с какого адреса, что просили, сколько байт ушло и чем кончилось.
Журнал лежит только в памяти, пока программа запущена; адреса на диск не пишутся. Слова и журнал —
из общего ядра ``zapret_update`` (те же, что у Zapret 2 GUI). Вкладка читает готовый снимок из
памяти каждые две секунды, пока она на экране.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import QAbstractItemView, QHBoxLayout, QHeaderView, QTableWidgetItem, QVBoxLayout, QWidget
from qfluentwidgets import BodyLabel, CaptionLabel, FluentIcon as FIF, PushButton, SubtitleLabel, TableWidget

from zapret_update import share_activity_view as view

REFRESH_MS = 2000
ROWS_SHOWN = 300
HEADERS = ("Время", "Кто к кому", "Откуда", "Адрес", "Что", "Размер", "Итог")
WHAT_COLUMN = 4


def _plain(_key: str, default: str) -> str:
    return default


class SharingPage(QWidget):
    def __init__(self, parent: QWidget | None = None, *, snapshot=None, clear=None):
        super().__init__(parent)
        self.setObjectName("sharing")
        if snapshot is None or clear is None:
            from ..updates import share_wiring

            snapshot, clear = snapshot or share_wiring.activity_snapshot, clear or share_wiring.clear_activity
        self._snapshot, self._clear_source = snapshot, clear
        self._last_signature: object = None
        self._timer = QTimer(self)
        self._timer.setInterval(REFRESH_MS)
        self._timer.timeout.connect(self.refresh)

        root = QVBoxLayout(self)
        root.setContentsMargins(36, 28, 36, 28)
        root.setSpacing(14)
        root.addWidget(SubtitleLabel("Кто подключается", self))

        self.status_labels = []
        for _ in range(2):
            label = BodyLabel("", self)
            label.setWordWrap(True)
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            root.addWidget(label)
            self.status_labels.append(label)
        self.notes_label = CaptionLabel("", self)
        self.notes_label.setWordWrap(True)
        self.notes_label.hide()
        root.addWidget(self.notes_label)

        bar = QHBoxLayout()
        self.summary_label = BodyLabel("", self)
        bar.addWidget(self.summary_label, 1)
        self.clear_button = PushButton(FIF.DELETE, "Очистить журнал", self)
        self.clear_button.clicked.connect(self._clear)
        bar.addWidget(self.clear_button)
        root.addLayout(bar)

        self.table = TableWidget(self)
        self.table.setColumnCount(len(HEADERS))
        self.table.setHorizontalHeaderLabels(list(HEADERS))
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().hide()
        self.table.setBorderVisible(True)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(WHAT_COLUMN, QHeaderView.ResizeMode.Stretch)
        self.table.setAccessibleName("Журнал обращений к раздаче обновлений")
        root.addWidget(self.table, 100)

        self.empty_label = CaptionLabel("", self)
        self.empty_label.setWordWrap(True)
        root.addWidget(self.empty_label)
        self.hint_label = CaptionLabel(
            "Журнал хранится, только пока программа запущена: адреса других компьютеров на диск не записываются.", self
        )
        self.hint_label.setWordWrap(True)
        root.addWidget(self.hint_label)
        # Пока таблица спрятана (журнал пуст), лишнее место уходит сюда, а не растаскивает надписи по окну.
        root.addStretch(1)
        self.refresh()

    def refresh(self) -> None:
        """Перерисовывает вкладку по снимку из памяти; не трогает диск и сеть."""
        try:
            snapshot = self._snapshot()
        except Exception:  # noqa: BLE001 — вкладка не должна падать из-за журнала
            snapshot = {"available": False}
        events = list(snapshot.get("events", ()))[:ROWS_SHOWN]
        signature = (
            tuple(snapshot.get("notes", ())), snapshot.get("lan_port"), snapshot.get("internet_running"),
            snapshot.get("internet_address"), snapshot.get("available"), len(events),
            events[0].when if events else 0,
        )
        if signature == self._last_signature:
            return  # ничего не изменилось: таблицу не перестраиваем
        self._last_signature = signature
        lines = view.status_lines(snapshot, _plain)
        for label, text in zip(self.status_labels, lines + [""] * len(self.status_labels)):
            label.setText(text)
            label.setVisible(bool(text))
        notes = list(snapshot.get("notes", ()))
        self.notes_label.setText("\n".join(notes))
        self.notes_label.setVisible(bool(notes))
        self.summary_label.setText(view.summary_text(snapshot.get("summary", {}), _plain))
        self.table.setRowCount(len(events))
        for row, event in enumerate(events):
            texts = view.row_texts(event, _plain)
            for column, text in enumerate(texts):
                item = QTableWidgetItem(text)
                item.setData(Qt.ItemDataRole.AccessibleTextRole, ", ".join(texts) if column == 0 else text)
                self.table.setItem(row, column, item)
        self.table.setVisible(bool(events))
        if events:
            self.empty_label.hide()
        else:
            self.empty_label.setText(
                "Пока никто не подключался. Когда другой компьютер возьмёт у вас файл или спросит про версию, это появится здесь."
                if snapshot.get("available")
                else "Раздача выключена или ещё не запустилась: включите её в настройках, в разделе «Обновления»."
            )
            self.empty_label.show()

    def _clear(self) -> None:
        try:
            self._clear_source()
        finally:
            self._last_signature = None
            self.refresh()

    def showEvent(self, event) -> None:  # noqa: N802 — имя задано Qt
        super().showEvent(event)
        self._timer.start()
        self.refresh()

    def hideEvent(self, event) -> None:  # noqa: N802
        self._timer.stop()
        super().hideEvent(event)


__all__ = ["SharingPage"]
