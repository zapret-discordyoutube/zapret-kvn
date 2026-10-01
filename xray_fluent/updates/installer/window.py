"""Окно обновления: его видно всё время, пока приложение закрыто."""

from __future__ import annotations

import time

from PyQt6.QtCore import QPropertyAnimation, QRect, Qt, QTimer
from PyQt6.QtGui import QColor, QGuiApplication, QPainter, QPen, QPixmap
from PyQt6.QtWidgets import QGraphicsOpacityEffect, QHBoxLayout, QLabel, QVBoxLayout, QWidget
from qfluentwidgets import BodyLabel, CaptionLabel, ProgressBar, SubtitleLabel, isDarkTheme

from ...constants import APP_ICON_PATH
from ...ui.theme import surface_color, token_pair
from . import phrases
from .plan import InstallPlan
from .runner import Stage

_WIDTH = 460
_MARGIN = 24
_RADIUS = 10
_PHRASE_INTERVAL_MS = 4200
_FADE_MS = 180
# Быстрая установка не должна мелькнуть: окно живёт столько, чтобы успеть
# прочитать хотя бы пару фраз. Приложение в это время уже запущено и ждёт.
_MIN_VISIBLE_MS = 7000
_FAREWELL_MS = {Stage.DONE: 1200, Stage.FAILED: 4500}
_PROGRESS_STEPS = 1000

# Доля общего индикатора, отведённая каждому шагу: (начало, конец).
_STAGE_SPAN = {
    Stage.PREPARE: (0.0, 0.55),
    Stage.WAIT_APP: (0.55, 0.62),
    Stage.SWAP: (0.62, 0.72),
    Stage.START: (0.72, 1.0),
}
_STAGE_TEXT = {
    Stage.PREPARE: "Готовим файлы новой версии",
    Stage.WAIT_APP: "Ждём, пока закроется прежняя версия",
    Stage.SWAP: "Заменяем файлы",
    Stage.START: "Запускаем новую версию",
    Stage.DONE: "Обновление установлено",
    Stage.ROLLBACK: "Не получилось — возвращаем прежнюю версию",
    Stage.FAILED: "Прежняя версия возвращена, причина — на странице «Обновления»",
}


def overall_progress(stage: Stage, fraction: float) -> float | None:
    """Положение общего индикатора; None — оставить как есть."""

    if stage in (Stage.DONE, Stage.FAILED):
        return 1.0
    span = _STAGE_SPAN.get(stage)
    if span is None:
        return None
    start, end = span
    return start + (end - start) * min(1.0, max(0.0, fraction))


class UpdateWindow(QWidget):
    def __init__(self, plan: InstallPlan):
        super().__init__()
        self._plan = plan
        self._finished = False
        self._shown_at = time.monotonic()
        self._drag_offset = None
        self._deck = phrases.PhraseDeck()

        flags = Qt.WindowType.FramelessWindowHint
        if plan.start_in_tray:
            # Приложение работало в трее: окно появляется рядом с ним и не
            # забирает фокус у программы, в которой сейчас пользователь.
            flags |= Qt.WindowType.Tool | Qt.WindowType.WindowDoesNotAcceptFocus
            self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        else:
            flags |= Qt.WindowType.Window
        self.setWindowFlags(flags)
        # Отдельное маленькое окно без рамки: прозрачность нужна только для
        # скруглённых углов, фон рисуется в paintEvent.
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setWindowTitle("Обновление Zapret KVN")
        self.setFixedWidth(_WIDTH)

        root = QVBoxLayout(self)
        root.setContentsMargins(_MARGIN, 22, _MARGIN, 22)
        root.setSpacing(0)

        header = QHBoxLayout()
        header.setSpacing(14)
        icon = QLabel(self)
        pixmap = QPixmap(str(APP_ICON_PATH))
        if not pixmap.isNull():
            ratio = self.devicePixelRatioF()
            pixmap = pixmap.scaled(
                int(40 * ratio), int(40 * ratio),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            pixmap.setDevicePixelRatio(ratio)
            icon.setPixmap(pixmap)
        icon.setFixedSize(40, 40)
        header.addWidget(icon)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        titles.addWidget(SubtitleLabel("Обновляем Zapret KVN", self))
        self._version_label = CaptionLabel(f"Ставим версию {plan.version}", self)
        self._version_label.setTextColor(*self._muted_pair())
        titles.addWidget(self._version_label)
        header.addLayout(titles, 1)
        root.addLayout(header)
        root.addSpacing(18)

        self._phrase_label = BodyLabel(self._deck.next(), self)
        self._phrase_label.setWordWrap(True)
        self._phrase_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        # Высота по самой длинной фразе: окно не прыгает при их смене.
        metrics = self._phrase_label.fontMetrics()
        text_width = _WIDTH - 2 * _MARGIN
        self._phrase_label.setFixedHeight(2 + max(
            metrics.boundingRect(
                QRect(0, 0, text_width, 1000), int(Qt.TextFlag.TextWordWrap), text
            ).height()
            for text in (*phrases.WAITING, phrases.DONE, phrases.FAILED)
        ))
        self._phrase_opacity = QGraphicsOpacityEffect(self._phrase_label)
        self._phrase_opacity.setOpacity(1.0)
        self._phrase_label.setGraphicsEffect(self._phrase_opacity)
        self._fade = QPropertyAnimation(self._phrase_opacity, b"opacity", self)
        self._fade.setDuration(_FADE_MS)
        self._fade.finished.connect(self._on_fade_finished)
        self._pending_phrase: str | None = None
        root.addWidget(self._phrase_label)
        root.addSpacing(14)

        self._progress = ProgressBar(self)
        self._progress.setRange(0, _PROGRESS_STEPS)
        self._progress.setValue(0)
        root.addWidget(self._progress)
        root.addSpacing(10)

        self._status_label = CaptionLabel(_STAGE_TEXT[Stage.PREPARE], self)
        self._status_label.setTextColor(*self._muted_pair())
        root.addWidget(self._status_label)

        self._phrase_timer = QTimer(self)
        self._phrase_timer.setInterval(_PHRASE_INTERVAL_MS)
        self._phrase_timer.timeout.connect(lambda: self._show_phrase(self._deck.next()))
        self._phrase_timer.start()

        self.adjustSize()
        self._place()

    @staticmethod
    def _muted_pair() -> tuple[QColor, QColor]:
        light, dark = token_pair("text_muted")
        return QColor(light), QColor(dark)

    # ── положение ───────────────────────────────────────────────

    def _place(self) -> None:
        screen = QGuiApplication.primaryScreen()
        area = screen.availableGeometry() if screen is not None else QRect(0, 0, 1280, 720)
        if self._plan.start_in_tray:
            self.move(area.right() - self.width() - 16, area.bottom() - self.height() - 16)
            return
        if self._plan.anchor is not None:
            anchor = QRect(*self._plan.anchor)
            anchor_screen = QGuiApplication.screenAt(anchor.center())
            if anchor_screen is not None:
                area = anchor_screen.availableGeometry().intersected(anchor)
        self.move(
            area.center().x() - self.width() // 2,
            area.center().y() - self.height() // 2,
        )

    # ── ход установки ───────────────────────────────────────────

    def on_progress(self, stage: Stage, fraction: float) -> None:
        self._status_label.setText(_STAGE_TEXT[stage])
        value = overall_progress(stage, fraction)
        if value is not None:
            self._progress.setValue(int(value * _PROGRESS_STEPS))
        if stage is Stage.ROLLBACK:
            self._progress.setError(True)
        if stage in (Stage.DONE, Stage.FAILED):
            self._finish(stage)

    def _finish(self, stage: Stage) -> None:
        self._finished = True
        farewell = _FAREWELL_MS[stage]
        shown_ms = int((time.monotonic() - self._shown_at) * 1000)
        # До прощальной фразы продолжают сменяться обычные.
        QTimer.singleShot(
            max(0, _MIN_VISIBLE_MS - farewell - shown_ms), lambda: self._say_farewell(stage)
        )

    def _say_farewell(self, stage: Stage) -> None:
        self._phrase_timer.stop()
        self._show_phrase(phrases.DONE if stage is Stage.DONE else phrases.FAILED)
        # Главное окно приложения появится, когда закроется это.
        QTimer.singleShot(_FAREWELL_MS[stage], self.close)

    def showEvent(self, event) -> None:
        self._shown_at = time.monotonic()
        super().showEvent(event)

    # ── фразы ───────────────────────────────────────────────────

    def _show_phrase(self, text: str) -> None:
        self._pending_phrase = text
        self._fade.stop()
        self._fade.setStartValue(self._phrase_opacity.opacity())
        self._fade.setEndValue(0.0)
        self._fade.start()

    def _on_fade_finished(self) -> None:
        if self._pending_phrase is None:
            return
        self._phrase_label.setText(self._pending_phrase)
        self._pending_phrase = None
        self._fade.setStartValue(0.0)
        self._fade.setEndValue(1.0)
        self._fade.start()

    # ── окно ────────────────────────────────────────────────────

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        border = QColor(255, 255, 255, 28) if isDarkTheme() else QColor(0, 0, 0, 36)
        painter.setPen(QPen(border, 1))
        painter.setBrush(surface_color())
        painter.drawRoundedRect(self.rect().adjusted(0, 0, -1, -1), _RADIUS, _RADIUS)

    def closeEvent(self, event) -> None:
        # Закрыть окно посреди замены файлов нельзя: установка всё равно
        # продолжится, а пользователь останется без объяснения.
        if self._finished:
            event.accept()
        else:
            event.ignore()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_offset = event.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, event) -> None:
        if self._drag_offset is not None and event.buttons() & Qt.MouseButton.LeftButton:
            self.move(event.globalPosition().toPoint() - self._drag_offset)

    def mouseReleaseEvent(self, event) -> None:
        self._drag_offset = None
