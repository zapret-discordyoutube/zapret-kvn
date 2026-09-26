"""«Сфера подключения» — векторная эмблема состояния с кнопкой питания.

Рисуется QPainter'ом (без SVG-файлов и растров), поэтому чёткая на любом
DPI и сразу подхватывает цвета темы/акцента.

Состояния:
* ``idle``       — спокойное приглушённое кольцо, без анимации;
* ``connecting`` — по кольцу бежит «комета» (дуга с хвостом);
* ``connected``  — кольцо цвета успеха, медленное «дыхание» свечения и три
  спутника на орбитах;
* ``error``      — кольцо цвета ошибки, без анимации.

Экономия CPU: таймер кадров работает только в анимированных состояниях и
только пока виджет виден, а окно не свёрнуто; перерисовывается лишь
собственный прямоугольник виджета. Фаза анимации считается от реального
времени, так что просадка кадров не замедляет движение.
"""

from __future__ import annotations

import math

from PyQt6.QtCore import QElapsedTimer, QEvent, QPointF, QRectF, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QPainter, QPen, QRadialGradient
from PyQt6.QtWidgets import QSizePolicy, QWidget

from .theme import accent_color, error_color, on_theme_or_accent_changed, success_color, text_color, text_muted_color

IDLE, CONNECTING, CONNECTED, ERROR = "idle", "connecting", "connected", "error"
_STATES = (IDLE, CONNECTING, CONNECTED, ERROR)

# Интервалы кадров: «комете» нужна плавность, дыханию хватает 20 fps.
_FRAME_MS = {CONNECTING: 33, CONNECTED: 50}
_BREATH_PERIOD_S = 3.2
_SPIN_PERIOD_S = 1.15
# (доля радиуса орбиты, период оборота в секундах, начальный угол, радиус точки)
_SATELLITES = ((0.92, 9.0, 0.0, 3.2), (0.92, 9.0, math.pi, 2.4), (0.64, 5.5, math.pi / 2, 2.2))


class ConnectionOrb(QWidget):
    clicked = pyqtSignal()

    def __init__(self, parent: QWidget | None = None, diameter: int = 148):
        super().__init__(parent)
        self.setFixedSize(diameter, diameter)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.setMouseTracking(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._state = IDLE
        self._hover = False
        self._pressed = False
        self._clock = QElapsedTimer()
        self._clock.start()
        self._timer = QTimer(self)
        self._timer.setTimerType(Qt.TimerType.CoarseTimer)
        self._timer.timeout.connect(self._tick)
        self._watched_window: QWidget | None = None
        on_theme_or_accent_changed(self._on_theme_changed)

    # ── Состояние ──────────────────────────────────────────

    def state(self) -> str:
        return self._state

    def set_state(self, state: str) -> None:
        state = state if state in _STATES else IDLE
        if state == self._state:
            return
        self._state = state
        self._sync_timer()
        self.update()

    def is_animating(self) -> bool:
        return self._timer.isActive()

    def _should_animate(self) -> bool:
        if self._state not in _FRAME_MS or not self.isVisible():
            return False
        window = self.window()
        return window is None or not window.isMinimized()

    def _sync_timer(self) -> None:
        if self._should_animate():
            interval = _FRAME_MS[self._state]
            if not self._timer.isActive() or self._timer.interval() != interval:
                self._timer.start(interval)
        else:
            self._timer.stop()

    def _tick(self) -> None:
        if not self._should_animate():
            self._timer.stop()
            return
        self.update()

    def _on_theme_changed(self, *_args) -> None:
        self.update()

    # ── Видимость окна ─────────────────────────────────────

    def showEvent(self, event) -> None:
        super().showEvent(event)
        window = self.window()
        if window is not self._watched_window and window is not self:
            if self._watched_window is not None:
                self._watched_window.removeEventFilter(self)
            self._watched_window = window
            window.installEventFilter(self)
        self._sync_timer()

    def hideEvent(self, event) -> None:
        super().hideEvent(event)
        self._timer.stop()

    def eventFilter(self, obj, event) -> bool:
        if obj is self._watched_window and event.type() in (
            QEvent.Type.WindowStateChange, QEvent.Type.Show, QEvent.Type.Hide
        ):
            QTimer.singleShot(0, self._sync_timer)
        return super().eventFilter(obj, event)

    # ── Мышь: кликабелен только центральный диск ───────────

    def _in_button(self, pos) -> bool:
        center = QPointF(self.width() / 2, self.height() / 2)
        radius = self._radius() * 0.5
        return (pos.x() - center.x()) ** 2 + (pos.y() - center.y()) ** 2 <= radius * radius

    def mouseMoveEvent(self, event) -> None:
        hover = self._in_button(event.position())
        if hover != self._hover:
            self._hover = hover
            self.setCursor(Qt.CursorShape.PointingHandCursor if hover else Qt.CursorShape.ArrowCursor)
            self.update()
        super().mouseMoveEvent(event)

    def leaveEvent(self, event) -> None:
        if self._hover or self._pressed:
            self._hover = self._pressed = False
            self.update()
        super().leaveEvent(event)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton and self._in_button(event.position()):
            self._pressed = True
            self.update()
            return
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        if self._pressed and event.button() == Qt.MouseButton.LeftButton:
            self._pressed = False
            self.update()
            if self._in_button(event.position()) and self.isEnabled():
                self.clicked.emit()
            return
        super().mouseReleaseEvent(event)

    def changeEvent(self, event) -> None:
        if event.type() == QEvent.Type.EnabledChange:
            self.update()
        super().changeEvent(event)

    # ── Отрисовка ──────────────────────────────────────────

    def _radius(self) -> float:
        return min(self.width(), self.height()) / 2 - 4

    def _state_color(self) -> QColor:
        if self._state == CONNECTED:
            return success_color()
        if self._state == CONNECTING:
            return accent_color()
        if self._state == ERROR:
            return error_color()
        return text_muted_color()

    def paintEvent(self, event) -> None:
        seconds = self._clock.elapsed() / 1000.0
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        center = QPointF(self.width() / 2, self.height() / 2)
        radius = self._radius()
        color = self._state_color()
        enabled = self.isEnabled()

        # Свечение: у подключённого «дышит», у остальных — ровное и слабое.
        if self._state == CONNECTED:
            breath = 0.5 + 0.5 * math.sin(2 * math.pi * seconds / _BREATH_PERIOD_S)
            glow_alpha = int(55 + 45 * breath)
        else:
            glow_alpha = 40 if self._state in (CONNECTING, ERROR) else 18
        glow = QRadialGradient(center, radius)
        inner = QColor(color)
        inner.setAlpha(glow_alpha)
        outer = QColor(color)
        outer.setAlpha(0)
        glow.setColorAt(0.45, inner)
        glow.setColorAt(1.0, outer)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(glow)
        painter.drawEllipse(center, radius, radius)

        # Кольцо-дорожка.
        ring_radius = radius * 0.78
        ring_rect = QRectF(center.x() - ring_radius, center.y() - ring_radius, ring_radius * 2, ring_radius * 2)
        track = QColor(text_muted_color())
        track.setAlpha(55)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(track, 3))
        painter.drawEllipse(ring_rect)

        if self._state == CONNECTING:
            self._paint_comet(painter, ring_rect, color, seconds)
        elif self._state in (CONNECTED, ERROR):
            ring = QPen(color, 3)
            painter.setPen(ring)
            painter.drawEllipse(ring_rect)
            if self._state == CONNECTED:
                self._paint_satellites(painter, center, radius, color, seconds)

        # Центральная кнопка.
        disc_radius = radius * (0.47 if self._pressed else 0.5)
        fill = QColor(color)
        fill.setAlpha(60 if self._hover and enabled else 34)
        border = QColor(color)
        border.setAlpha(150 if enabled else 60)
        painter.setPen(QPen(border, 1.2))
        painter.setBrush(fill)
        painter.drawEllipse(center, disc_radius, disc_radius)
        self._paint_power_icon(painter, center, disc_radius, enabled)
        painter.end()

    @staticmethod
    def _paint_comet(painter: QPainter, rect: QRectF, color: QColor, seconds: float) -> None:
        head = -360.0 * ((seconds / _SPIN_PERIOD_S) % 1.0)  # Qt: против часовой при +
        # Хвост из нескольких сегментов с убывающей прозрачностью.
        segments = 6
        span = 110.0
        for index in range(segments):
            part = QColor(color)
            part.setAlpha(int(255 * (1 - index / segments) ** 1.6))
            pen = QPen(part, 3.2)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            start = head + index * span / segments
            painter.drawArc(rect, int(start * 16), int(span / segments * 16))

    @staticmethod
    def _paint_satellites(painter: QPainter, center: QPointF, radius: float, color: QColor, seconds: float) -> None:
        painter.setPen(Qt.PenStyle.NoPen)
        for orbit, period, phase, dot in _SATELLITES:
            angle = phase + 2 * math.pi * seconds / period
            point = QPointF(center.x() + math.cos(angle) * radius * orbit,
                            center.y() + math.sin(angle) * radius * orbit)
            halo = QColor(color)
            halo.setAlpha(60)
            painter.setBrush(halo)
            painter.drawEllipse(point, dot * 2.2, dot * 2.2)
            painter.setBrush(color)
            painter.drawEllipse(point, dot, dot)

    def _paint_power_icon(self, painter: QPainter, center: QPointF, disc_radius: float, enabled: bool) -> None:
        icon_color = self._state_color() if self._state != IDLE else text_color()
        if not enabled:
            icon_color.setAlpha(110)
        pen = QPen(icon_color, max(2.0, disc_radius * 0.085))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        r = disc_radius * 0.42
        arc = QRectF(center.x() - r, center.y() - r + disc_radius * 0.04, r * 2, r * 2)
        # Дуга с разрывом сверху (60°) и вертикальная черта.
        painter.drawArc(arc, 120 * 16, 300 * 16)
        painter.drawLine(QPointF(center.x(), center.y() - r * 1.18), QPointF(center.x(), center.y() - r * 0.05))
