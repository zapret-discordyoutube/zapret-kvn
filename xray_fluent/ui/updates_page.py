from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    FluentIcon as FIF,
    IndeterminateProgressBar,
    PrimaryPushButton,
    ProgressBar,
    PushButton,
    SubtitleLabel,
    TitleLabel,
    setCustomStyleSheet,
)

from ..constants import APP_VERSION
from .theme import token_pair

_SECTION_TITLE_QSS = "BodyLabel { font-weight: bold; font-size: 16px; }"


def _status_qss(token: str, bold: bool) -> tuple[str, str]:
    """Build (light, dark) qss for a status CaptionLabel from a theme token."""
    light, dark = token_pair(token)
    extra = " font-weight: bold;" if bold else ""
    return (
        f"CaptionLabel {{ color: {light};{extra} }}",
        f"CaptionLabel {{ color: {dark};{extra} }}",
    )


def _set_status_style(label: CaptionLabel, kind: str) -> None:
    if kind == "success":
        light, dark = _status_qss("success", bold=True)
    elif kind == "error":
        light, dark = _status_qss("error", bold=True)
    else:
        light, dark = _status_qss("text_muted", bold=False)
    setCustomStyleSheet(label, light, dark)


class UpdatesPage(QWidget):
    check_app_requested = pyqtSignal()
    check_xray_requested = pyqtSignal()
    update_xray_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("updates")

        root = QVBoxLayout(self)
        root.setContentsMargins(36, 28, 36, 28)
        root.setSpacing(20)

        title = SubtitleLabel("Обновления", self)
        root.addWidget(title)

        # ── App version info ──
        app_box = QVBoxLayout()
        app_box.setSpacing(6)
        app_title = BodyLabel("zapret kvn", self)
        setCustomStyleSheet(app_title, _SECTION_TITLE_QSS, _SECTION_TITLE_QSS)
        app_box.addWidget(app_title)

        self._app_version_label = BodyLabel(f"Текущая версия: v{APP_VERSION}", self)
        app_box.addWidget(self._app_version_label)

        self._app_status = CaptionLabel("", self)
        _set_status_style(self._app_status, "neutral")
        app_box.addWidget(self._app_status)

        # Progress bar
        self._app_progress = ProgressBar(self)
        self._app_progress.setFixedHeight(4)
        self._app_progress.setValue(0)
        self._app_progress.hide()
        app_box.addWidget(self._app_progress)

        self._app_spinner = IndeterminateProgressBar(self)
        self._app_spinner.setFixedHeight(4)
        self._app_spinner.hide()
        app_box.addWidget(self._app_spinner)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.check_app_btn = PrimaryPushButton(FIF.SYNC, "Проверить обновления", self)
        self.download_btn = PushButton(FIF.DOWNLOAD, "Скачать и установить", self)
        self.download_btn.hide()
        btn_row.addWidget(self.check_app_btn)
        btn_row.addWidget(self.download_btn)
        btn_row.addStretch()
        app_box.addLayout(btn_row)

        root.addLayout(app_box)

        # Separator
        sep = QWidget(self)
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: rgba(128,128,128,0.3);")
        root.addWidget(sep)

        # ── Xray core info ──
        xray_box = QVBoxLayout()
        xray_box.setSpacing(6)
        xray_title = BodyLabel("Xray Core", self)
        setCustomStyleSheet(xray_title, _SECTION_TITLE_QSS, _SECTION_TITLE_QSS)
        xray_box.addWidget(xray_title)

        self._xray_version_label = BodyLabel("Версия: загрузка...", self)
        xray_box.addWidget(self._xray_version_label)

        self._xray_status = CaptionLabel("", self)
        _set_status_style(self._xray_status, "neutral")
        xray_box.addWidget(self._xray_status)

        xray_btn_row = QHBoxLayout()
        xray_btn_row.setSpacing(10)
        self.check_xray_btn = PushButton(FIF.SYNC, "Проверить обновления Xray", self)
        self.update_xray_btn = PrimaryPushButton(FIF.DOWNLOAD, "Обновить Xray core", self)
        xray_btn_row.addWidget(self.check_xray_btn)
        xray_btn_row.addWidget(self.update_xray_btn)
        xray_btn_row.addStretch()
        xray_box.addLayout(xray_btn_row)

        root.addLayout(xray_box)
        root.addStretch()

        # ── Connections ──
        self.check_app_btn.clicked.connect(self.check_app_requested)
        self.check_xray_btn.clicked.connect(self.check_xray_requested)
        self.update_xray_btn.clicked.connect(self.update_xray_requested)

    # ── Public API ──

    def set_xray_version(self, version: str) -> None:
        self._xray_version_label.setText(f"Версия: {version}" if version else "Версия: не найдена")

    def set_app_status(self, text: str) -> None:
        _set_status_style(self._app_status, "neutral")
        self._app_status.setText(text)

    def set_xray_status(self, text: str) -> None:
        _set_status_style(self._xray_status, "neutral")
        self._xray_status.setText(text)

    def set_app_error(self, text: str) -> None:
        _set_status_style(self._app_status, "error")
        self._app_status.setText(text)

    def set_xray_error(self, text: str) -> None:
        _set_status_style(self._xray_status, "error")
        self._xray_status.setText(text)

    def set_xray_success(self, text: str) -> None:
        _set_status_style(self._xray_status, "success")
        self._xray_status.setText(text)

    def show_checking(self) -> None:
        self._app_progress.hide()
        self._app_spinner.show()
        self._app_spinner.start()
        self.check_app_btn.setEnabled(False)
        _set_status_style(self._app_status, "neutral")
        self._app_status.setText("Проверка обновлений...")

    def show_download_progress(self, percent: int) -> None:
        self._app_spinner.hide()
        self._app_progress.show()
        self._app_progress.setValue(percent)
        _set_status_style(self._app_status, "neutral")
        self._app_status.setText(f"Загрузка: {percent}%")
        self.check_app_btn.setEnabled(False)
        self.download_btn.setEnabled(False)

    def show_idle(self) -> None:
        self._app_spinner.stop()
        self._app_spinner.hide()
        self._app_progress.hide()
        self._app_progress.setValue(0)
        self.check_app_btn.setEnabled(True)
        self.download_btn.hide()

    def show_update_available(self, version: str) -> None:
        self._app_spinner.stop()
        self._app_spinner.hide()
        self.check_app_btn.setEnabled(True)
        self._app_status.setText(f"Доступна новая версия: v{version}")
        _set_status_style(self._app_status, "success")
        self.download_btn.show()
        self.download_btn.setText(f"Скачать v{version} и установить")

    def show_up_to_date(self) -> None:
        self.show_idle()
        self._app_status.setText("У вас последняя версия")
        _set_status_style(self._app_status, "success")
