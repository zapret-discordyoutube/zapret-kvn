from __future__ import annotations

from datetime import datetime
import re

from PyQt6.QtCore import QPoint, QRect, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QImage, QKeyEvent, QMouseEvent, QPainter, QPen
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    Action,
    BodyLabel,
    CheckBox,
    FluentIcon as FIF,
    InfoBar,
    InfoBarPosition,
    LineEdit,
    PrimaryPushButton,
    PrimaryToolButton,
    PushButton,
    RoundMenu,
    SpinBox,
    SubtitleLabel,
    SwitchButton,
    TableWidget,
    TransparentToolButton,
)

from ..models import Node, Subscription
from ..qr_utils import QrDecodeError, decode_subscription_qr
from ..subscription_http import default_subscription_user_agent, mask_subscription_url, validate_subscription_url
from ..subscription_parser import validate_filter_patterns


class ScreenRegionSelector(QWidget):
    image_selected = pyqtSignal(object)

    def __init__(self, screen, parent=None):
        super().__init__(parent)
        self._screen = screen
        self._origin = QPoint()
        self._selection = QRect()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.setCursor(Qt.CursorShape.CrossCursor)
        self.setGeometry(screen.geometry())

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(0, 0, 0, 110))
        if not self._selection.isNull():
            painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Clear)
            painter.fillRect(self._selection, Qt.GlobalColor.transparent)
            painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver)
            painter.setPen(QPen(QColor("#0078D4"), 2))
            painter.drawRect(self._selection)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._origin = event.position().toPoint()
            self._selection = QRect(self._origin, self._origin)
            self.update()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if event.buttons() & Qt.MouseButton.LeftButton:
            self._selection = QRect(self._origin, event.position().toPoint()).normalized()
            self.update()

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if event.button() != Qt.MouseButton.LeftButton:
            return
        self._selection = QRect(self._origin, event.position().toPoint()).normalized()
        if self._selection.width() < 8 or self._selection.height() < 8:
            self.close()
            return
        selection = QRect(self._selection)
        self.hide()

        def capture() -> None:
            pixmap = self._screen.grabWindow(
                0,
                selection.x(),
                selection.y(),
                selection.width(),
                selection.height(),
            )
            self.image_selected.emit(pixmap.toImage())
            self.close()

        QTimer.singleShot(100, capture)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() == Qt.Key.Key_Escape:
            self.close()
            return
        super().keyPressEvent(event)


class SubscriptionDialog(QDialog):
    def __init__(
        self,
        subscription: Subscription | None = None,
        parent=None,
        *,
        provider_names: list[str] | None = None,
    ):
        super().__init__(parent)
        self._source = subscription
        self._provider_names = list(provider_names or [])
        self._screen_selector: ScreenRegionSelector | None = None
        self.setModal(True)
        self.setMinimumWidth(560)
        self.setWindowTitle("Редактирование подписки" if subscription else "Новая подписка")

        root = QVBoxLayout(self)
        root.setContentsMargins(22, 22, 22, 22)
        root.setSpacing(9)
        root.addWidget(SubtitleLabel(self.windowTitle(), self))

        root.addWidget(BodyLabel("Название (необязательно)", self))
        self.name_edit = LineEdit(self)
        self.name_edit.setPlaceholderText("Название провайдера будет определено автоматически")
        root.addWidget(self.name_edit)

        root.addWidget(BodyLabel("URL подписки", self))
        self.url_edit = LineEdit(self)
        self.url_edit.setPlaceholderText("https://example.com/sub/token")
        self.url_edit.setEchoMode(QLineEdit.EchoMode.Password)
        root.addWidget(self.url_edit)

        import_row = QHBoxLayout()
        self.paste_btn = PushButton(FIF.PASTE, "Вставить URL", self)
        self.qr_file_btn = PushButton("QR из файла", self)
        self.qr_clipboard_btn = PushButton("QR из буфера", self)
        self.qr_screen_btn = PushButton("QR с экрана", self)
        for button in (self.paste_btn, self.qr_file_btn, self.qr_clipboard_btn, self.qr_screen_btn):
            import_row.addWidget(button)
        root.addLayout(import_row)

        root.addWidget(BodyLabel("User-Agent", self))
        self.user_agent_edit = LineEdit(self)
        self.user_agent_edit.setPlaceholderText(default_subscription_user_agent())
        root.addWidget(self.user_agent_edit)
        ua_row = QHBoxLayout()
        for title, value in (
            ("ZapretKVN", ""),
            ("v2rayN", "v2rayN"),
            ("Hiddify", "HiddifyNext"),
        ):
            button = PushButton(title, self)
            button.clicked.connect(lambda _checked=False, ua=value: self.user_agent_edit.setText(ua))
            ua_row.addWidget(button)
        ua_row.addStretch(1)
        root.addLayout(ua_row)

        options_row = QHBoxLayout()
        self.auto_update_check = CheckBox("Автоматически обновлять", self)
        self.interval_spin = SpinBox(self)
        self.interval_spin.setRange(0, 8760)
        self.interval_spin.setSpecialValueText("Интервал провайдера / 24 ч")
        self.interval_spin.setSuffix(" ч")
        self.interval_spin.setMinimumWidth(190)
        options_row.addWidget(self.auto_update_check)
        options_row.addStretch(1)
        options_row.addWidget(self.interval_spin)
        root.addLayout(options_row)

        root.addWidget(BodyLabel("Include regex (необязательно)", self))
        self.include_edit = LineEdit(self)
        self.include_edit.setPlaceholderText("Например: 🇩🇪|Germany|DE")
        root.addWidget(self.include_edit)
        root.addWidget(BodyLabel("Exclude regex (необязательно)", self))
        self.exclude_edit = LineEdit(self)
        self.exclude_edit.setPlaceholderText("Например: test|expired")
        root.addWidget(self.exclude_edit)
        self.match_label = BodyLabel("", self)
        root.addWidget(self.match_label)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.cancel_btn = PushButton("Отмена", self)
        self.save_btn = PrimaryPushButton("Сохранить" if subscription else "Проверить и добавить", self)
        buttons.addWidget(self.cancel_btn)
        buttons.addWidget(self.save_btn)
        root.addLayout(buttons)

        self.cancel_btn.clicked.connect(self.reject)
        self.save_btn.clicked.connect(self._validate_and_accept)
        self.paste_btn.clicked.connect(self._paste_url)
        self.qr_file_btn.clicked.connect(self._qr_from_file)
        self.qr_clipboard_btn.clicked.connect(self._qr_from_clipboard)
        self.qr_screen_btn.clicked.connect(self._qr_from_screen)
        self.include_edit.textChanged.connect(self._update_match_count)
        self.exclude_edit.textChanged.connect(self._update_match_count)

        if subscription is not None:
            self.name_edit.setText(subscription.name)
            self.url_edit.setText(subscription.url)
            self.user_agent_edit.setText(subscription.user_agent)
            self.auto_update_check.setChecked(subscription.auto_update)
            self.interval_spin.setValue(subscription.update_interval_hours or 0)
            self.include_edit.setText(subscription.include_pattern)
            self.exclude_edit.setText(subscription.exclude_pattern)
        else:
            self.auto_update_check.setChecked(True)
        self._update_match_count()

    def subscription_value(self) -> Subscription:
        return Subscription(
            id=self._source.id if self._source else Subscription().id,
            name=self.name_edit.text().strip(),
            url=self.url_edit.text().strip(),
            user_agent=self.user_agent_edit.text().strip(),
            auto_update=self.auto_update_check.isChecked(),
            update_interval_hours=self.interval_spin.value() or None,
            include_pattern=self.include_edit.text().strip(),
            exclude_pattern=self.exclude_edit.text().strip(),
        )

    def update_values(self) -> dict:
        value = self.subscription_value()
        return {
            "name": value.name,
            "url": value.url,
            "user_agent": value.user_agent,
            "auto_update": value.auto_update,
            "update_interval_hours": value.update_interval_hours,
            "include_pattern": value.include_pattern,
            "exclude_pattern": value.exclude_pattern,
        }

    def _validate_and_accept(self) -> None:
        try:
            validate_subscription_url(self.url_edit.text())
            validate_filter_patterns(self.include_edit.text().strip(), self.exclude_edit.text().strip())
        except Exception as exc:
            self._show_error(str(exc))
            return
        self.accept()

    def _paste_url(self) -> None:
        clipboard = QApplication.clipboard()
        text = clipboard.text().strip() if clipboard is not None else ""
        if text:
            self.url_edit.setText(text)
        else:
            self._show_error("Буфер обмена не содержит текста")

    def _qr_from_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите изображение с QR-кодом",
            "",
            "Изображения (*.png *.jpg *.jpeg *.bmp *.webp)",
        )
        if path:
            self._decode_qr(QImage(path))

    def _qr_from_clipboard(self) -> None:
        clipboard = QApplication.clipboard()
        image = clipboard.image() if clipboard is not None else QImage()
        self._decode_qr(image)

    def _qr_from_screen(self) -> None:
        screen = self.screen() or QApplication.primaryScreen()
        if screen is None:
            self._show_error("Экран не найден")
            return
        self.hide()
        selector = ScreenRegionSelector(screen)
        self._screen_selector = selector
        selector.image_selected.connect(self._on_screen_image)
        selector.destroyed.connect(lambda: self.show())
        selector.show()
        selector.activateWindow()

    def _on_screen_image(self, image: QImage) -> None:
        self.show()
        self.raise_()
        self._decode_qr(image)

    def _decode_qr(self, image: QImage) -> None:
        try:
            self.url_edit.setText(decode_subscription_qr(image))
        except QrDecodeError as exc:
            self._show_error(str(exc))

    def _show_error(self, message: str) -> None:
        InfoBar.error(
            "Ошибка",
            message,
            position=InfoBarPosition.TOP_RIGHT,
            duration=5000,
            parent=self,
        )

    def _update_match_count(self) -> None:
        if not self._provider_names:
            self.match_label.setText("Совпадения будут рассчитаны при проверке подписки")
            return
        try:
            include = re.compile(self.include_edit.text(), re.IGNORECASE) if self.include_edit.text() else None
            exclude = re.compile(self.exclude_edit.text(), re.IGNORECASE) if self.exclude_edit.text() else None
        except re.error as exc:
            self.match_label.setText(f"Некорректный regex: {exc}")
            return
        count = sum(
            1
            for name in self._provider_names
            if (include is None or include.search(name)) and (exclude is None or not exclude.search(name))
        )
        self.match_label.setText(f"Совпадений: {count} из {len(self._provider_names)}")


class SubscriptionDeleteDialog(QDialog):
    def __init__(self, name: str, parent=None):
        super().__init__(parent)
        self.setModal(True)
        self.setWindowTitle("Удаление подписки")
        root = QVBoxLayout(self)
        root.setContentsMargins(22, 22, 22, 22)
        root.setSpacing(12)
        root.addWidget(SubtitleLabel("Удаление подписки", self))
        root.addWidget(BodyLabel(f"Удалить «{name}»?", self))
        self.keep_nodes_check = CheckBox("Сохранить серверы как локальные", self)
        root.addWidget(self.keep_nodes_check)
        row = QHBoxLayout()
        row.addStretch(1)
        cancel = PushButton("Отмена", self)
        delete = PrimaryPushButton("Удалить", self)
        row.addWidget(cancel)
        row.addWidget(delete)
        root.addLayout(row)
        cancel.clicked.connect(self.reject)
        delete.clicked.connect(self.accept)


class SubscriptionsPage(QWidget):
    add_requested = pyqtSignal()
    edit_requested = pyqtSignal(str)
    update_requested = pyqtSignal(str, str)
    check_requested = pyqtSignal(str, str)
    update_all_requested = pyqtSignal(str)
    delete_requested = pyqtSignal(str)
    auto_update_changed = pyqtSignal(str, bool)
    open_url_requested = pyqtSignal(str)
    show_url_requested = pyqtSignal(str)
    reset_hidden_requested = pyqtSignal(str)
    accept_pending_url_requested = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("subscriptions")
        self._subscriptions: dict[str, Subscription] = {}
        self._row_ids: list[str] = []
        self._updating: set[str] = set()
        self._nodes: list[Node] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(SubtitleLabel("Подписки", self))

        toolbar = QHBoxLayout()
        self.add_btn = PrimaryToolButton(FIF.ADD, self)
        self.add_btn.setToolTip("Добавить подписку")
        self.update_all_btn = TransparentToolButton(FIF.SYNC, self)
        self.update_all_btn.setToolTip("Обновить все")
        self.edit_btn = TransparentToolButton(FIF.EDIT, self)
        self.edit_btn.setToolTip("Редактировать")
        self.update_btn = TransparentToolButton(FIF.DOWNLOAD, self)
        self.update_btn.setToolTip("Обновить выбранную")
        self.check_btn = PushButton("Проверить", self)
        self.check_btn.setToolTip("Проверить источник без изменения серверов")
        self.delete_btn = TransparentToolButton(FIF.DELETE, self)
        self.delete_btn.setToolTip("Удалить")
        for button in (
            self.add_btn,
            self.update_all_btn,
            self.check_btn,
            self.edit_btn,
            self.update_btn,
            self.delete_btn,
        ):
            toolbar.addWidget(button)
        toolbar.addStretch(1)
        root.addLayout(toolbar)

        self.table = TableWidget(self)
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(
            ["Название", "Серверы", "Трафик", "Истекает", "Последняя проверка", "Статус", "Авто"]
        )
        self.table.setEditTriggers(TableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(TableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(TableWidget.SelectionMode.SingleSelection)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in range(1, 7):
            self.table.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        root.addWidget(self.table, 1)

        self.add_btn.clicked.connect(self.add_requested)
        self.update_all_btn.clicked.connect(lambda: self.update_all_requested.emit("auto"))
        self.check_btn.clicked.connect(self._emit_check)
        self.edit_btn.clicked.connect(self._emit_edit)
        self.update_btn.clicked.connect(self._emit_update)
        self.delete_btn.clicked.connect(self._emit_delete)
        self.table.itemSelectionChanged.connect(self._sync_controls)
        self.table.cellDoubleClicked.connect(lambda _r, _c: self._emit_edit())
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self._sync_controls()

    def set_data(self, subscriptions: list[Subscription], nodes: list[Node]) -> None:
        selected_id = self.selected_id()
        self._subscriptions = {item.id: item for item in subscriptions}
        self._nodes = list(nodes)
        ordered = sorted(subscriptions, key=lambda item: (item.sort_order, item.name.casefold()))
        self._row_ids = [item.id for item in ordered]
        counts: dict[str, int] = {}
        for node in nodes:
            if node.subscription_id:
                counts[node.subscription_id] = counts.get(node.subscription_id, 0) + 1

        self.table.setRowCount(len(ordered))
        for row, subscription in enumerate(ordered):
            name = subscription.name or "Подписка"
            if subscription.pending_url:
                name += "  ⚠"
            name_item = QTableWidgetItem(name)
            name_item.setToolTip(mask_subscription_url(subscription.url))
            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, QTableWidgetItem(str(counts.get(subscription.id, 0))))
            self.table.setItem(row, 2, QTableWidgetItem(_format_traffic(subscription)))
            self.table.setItem(row, 3, QTableWidgetItem(_format_expire(subscription.info.expire)))
            self.table.setItem(row, 4, QTableWidgetItem(_format_time(subscription.last_checked_at)))
            status = "Обновление…" if subscription.id in self._updating else subscription.last_error or "OK"
            status_item = QTableWidgetItem(status if len(status) <= 80 else f"{status[:77]}…")
            status_item.setToolTip(status)
            self.table.setItem(row, 5, status_item)
            switch = SwitchButton(self.table)
            switch.setChecked(subscription.auto_update)
            switch.checkedChanged.connect(
                lambda checked, sid=subscription.id: self.auto_update_changed.emit(sid, bool(checked))
            )
            self.table.setCellWidget(row, 6, switch)

        if selected_id in self._row_ids:
            self.table.selectRow(self._row_ids.index(selected_id))
        self._sync_controls()

    def selected_id(self) -> str | None:
        rows = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if not rows:
            return None
        row = rows[0].row()
        return self._row_ids[row] if 0 <= row < len(self._row_ids) else None

    def set_updating(self, subscription_id: str, updating: bool) -> None:
        if updating:
            self._updating.add(subscription_id)
        else:
            self._updating.discard(subscription_id)
        self.set_data(list(self._subscriptions.values()), self._nodes)

    def _sync_controls(self) -> None:
        subscription_id = self.selected_id()
        enabled = bool(subscription_id)
        busy = subscription_id in self._updating if subscription_id else False
        self.edit_btn.setEnabled(enabled and not busy)
        self.check_btn.setEnabled(enabled and not busy)
        self.update_btn.setEnabled(enabled and not busy)
        self.delete_btn.setEnabled(enabled and not busy)

    def _emit_edit(self) -> None:
        subscription_id = self.selected_id()
        if subscription_id:
            self.edit_requested.emit(subscription_id)

    def _emit_update(self) -> None:
        subscription_id = self.selected_id()
        if subscription_id:
            self.update_requested.emit(subscription_id, "auto")

    def _emit_check(self) -> None:
        subscription_id = self.selected_id()
        if subscription_id:
            self.check_requested.emit(subscription_id, "auto")

    def _emit_delete(self) -> None:
        subscription_id = self.selected_id()
        if subscription_id:
            self.delete_requested.emit(subscription_id)

    def _show_context_menu(self, pos) -> None:
        row = self.table.rowAt(pos.y())
        if row < 0 or row >= len(self._row_ids):
            return
        self.table.selectRow(row)
        subscription_id = self._row_ids[row]
        subscription = self._subscriptions[subscription_id]
        menu = RoundMenu(parent=self)
        check = Action("Проверить без обновления", self)
        check.triggered.connect(
            lambda: self.check_requested.emit(subscription_id, "auto")
        )
        menu.addAction(check)
        for title, mode in (("Обновить автоматически", "auto"), ("Обновить напрямую", "direct"), ("Обновить через прокси", "proxy")):
            action = Action(title, self)
            action.triggered.connect(
                lambda _checked=False, sid=subscription_id, fetch_mode=mode: self.update_requested.emit(sid, fetch_mode)
            )
            menu.addAction(action)
        menu.addSeparator()
        edit = Action("Редактировать", self)
        edit.triggered.connect(lambda: self.edit_requested.emit(subscription_id))
        menu.addAction(edit)
        show_url = Action("Показать маскированный URL", self)
        show_url.triggered.connect(lambda: self.show_url_requested.emit(subscription_id))
        menu.addAction(show_url)
        if subscription.info.web_page_url:
            cabinet = Action("Открыть кабинет", self)
            cabinet.triggered.connect(lambda: self.open_url_requested.emit(subscription.info.web_page_url))
            menu.addAction(cabinet)
        if subscription.info.support_url:
            support = Action("Открыть поддержку", self)
            support.triggered.connect(lambda: self.open_url_requested.emit(subscription.info.support_url))
            menu.addAction(support)
        if subscription.hidden_source_keys:
            reset_hidden = Action("Сбросить скрытые серверы", self)
            reset_hidden.triggered.connect(lambda: self.reset_hidden_requested.emit(subscription_id))
            menu.addAction(reset_hidden)
        if subscription.pending_url:
            accept_url = Action("Принять новый домен подписки", self)
            accept_url.triggered.connect(lambda: self.accept_pending_url_requested.emit(subscription_id))
            menu.addAction(accept_url)
        menu.addSeparator()
        delete = Action("Удалить", self)
        delete.triggered.connect(lambda: self.delete_requested.emit(subscription_id))
        menu.addAction(delete)
        menu.exec(self.table.viewport().mapToGlobal(pos))


def _format_bytes(value: int) -> str:
    number = float(max(0, value))
    units = ("Б", "КиБ", "МиБ", "ГиБ", "ТиБ")
    for unit in units:
        if number < 1024 or unit == units[-1]:
            return f"{number:.1f} {unit}" if unit != "Б" else f"{int(number)} {unit}"
        number /= 1024
    return "0 Б"


def _format_traffic(subscription: Subscription) -> str:
    info = subscription.info
    if info.total <= 0:
        return _format_bytes(info.used) if info.used else "—"
    return f"{_format_bytes(info.used)} / {_format_bytes(info.total)}"


def _format_expire(timestamp: int) -> str:
    if timestamp <= 0:
        return "—"
    try:
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return "—"


def _format_time(value: str | None) -> str:
    if not value:
        return "—"
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return value
