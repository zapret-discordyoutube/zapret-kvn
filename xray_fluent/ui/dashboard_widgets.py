"""Живая графика главной панели: сцена туннеля, плитки режима, сигнал, приложения.

Всё рисуется QPainter'ом (векторно, без файлов), цвета — только токены
``theme.py``, поэтому графика чёткая на любом DPI и сразу следует теме/акценту.

Бюджет CPU — инвариант, а не пожелание:

* таймер кадров (``motion.FrameGate``) есть только у ``ConnectionScene`` и
  только в состояниях «подключение»/«подключено», пока виджет виден, окно не
  свёрнуто и в Windows не выключена анимация;
* неподвижные слои (свечение, сетка точек, дорожка, значки концов) рисуются
  один раз в кэш-``QImage``; кадр — это копия кэша плюс десяток частиц
  (именно ``QImage``: ``QPixmap`` в атрибуте Python-обёртки может пережить
  ``QApplication`` при выходе и уронить процесс при освобождении);
* кадр перерисовывает только полосу туннеля без круга сферы: сфера — дочерний
  прозрачный виджет со своим таймером, и полная перерисовка родителя
  заставляла бы её перерисовываться на каждом кадре сцены;
* плитки режима и полосы приложений анимируются короткими твинами, которые
  останавливаются сами.
"""

from __future__ import annotations

import math

from PyQt6.QtCore import (
    QElapsedTimer,
    QEvent,
    QPointF,
    QRect,
    QRectF,
    QSize,
    Qt,
    QVariantAnimation,
    pyqtSignal,
)
from PyQt6.QtGui import (
    QColor,
    QFontMetrics,
    QImage,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QRadialGradient,
    QRegion,
)
from PyQt6.QtWidgets import QHBoxLayout, QSizePolicy, QVBoxLayout, QWidget
from qfluentwidgets import CaptionLabel, StrongBodyLabel, SubtitleLabel

from ..constants import FLAGS_DIR
from .connection_orb import CONNECTED, CONNECTING, ERROR, IDLE, ConnectionOrb
from .motion import FrameGate, reduced_motion
from .theme import (
    accent_color,
    accent_soft_bg,
    accent_soft_bg_hover,
    error_color,
    graph_down_color,
    graph_up_color,
    on_theme_or_accent_changed,
    positive_color,
    text_color,
    text_muted_color,
    warning_color,
)

# Кадры: «комете» подключения нужна плавность, течению частиц хватает 24 fps.
_SCENE_FRAME_MS = {CONNECTING: 33, CONNECTED: 42}
_BURST_S = 1.1
_PULSE_PERIOD_S = 1.5
_PATH_SAMPLES = 160
# Подключено, но трафика нет дольше этого — сцена замирает (покой = без кадров).
_QUIET_BPS = 1024.0
# Насколько видны огоньки, проходящие сквозь сферу (1 — как снаружи).
_THROUGH_ORB_FADE = 0.55
# Шкала трафика: смесь логарифма (слабый трафик тоже заметен огоньками) и
# корня (на больших скоростях видна разница); 1.0 — 1 Гбит/с.
_LEVEL_CAP_BPS = 125_000_000.0
_LEVEL_LOG_FLOOR = 2.0  # 100 Б/с
# Толщина и цвет полосы меняются только под реальной нагрузкой: фон (до
# ~1 МБ/с) полосу не трогает.
_LOAD_VISIBLE_FROM = 0.38
_QUIET_AFTER_S = 4.0
# (направление, число частиц, фазовый сдвиг): вниз — от сервера к ПК.
_LANES = (("down", 7, 0.0), ("up", 5, 0.37))


def _mix(a: QColor, b: QColor, t: float) -> QColor:
    """Линейная смесь двух цветов, ``t`` в [0, 1]."""
    t = max(0.0, min(1.0, t))
    return QColor(
        round(a.red() + (b.red() - a.red()) * t),
        round(a.green() + (b.green() - a.green()) * t),
        round(a.blue() + (b.blue() - a.blue()) * t),
    )


def _with_alpha(color: QColor, alpha: int) -> QColor:
    result = QColor(color)
    result.setAlpha(max(0, min(255, int(alpha))))
    return result


def latency_color(latency_ms: int | None) -> QColor:
    if latency_ms is None:
        return text_muted_color()
    if latency_ms < 150:
        return positive_color()
    if latency_ms < 300:
        return warning_color()
    return error_color()


def latency_bars(latency_ms: int | None) -> int:
    if latency_ms is None:
        return 0
    if latency_ms < 80:
        return 4
    if latency_ms < 150:
        return 3
    if latency_ms < 300:
        return 2
    return 1


def load_flag_pixmap(code: str, size: QSize, ratio: float) -> QPixmap | None:
    """Флаг из ``assets/flags`` в нужном размере (исходники 40×24, не иконка 18×13)."""
    code = (code or "").strip().lower()
    if len(code) != 2 or not code.isalpha():
        return None
    path = FLAGS_DIR / f"{code}.png"
    if not path.is_file():
        return None
    source = QPixmap(str(path))
    if source.isNull():
        return None
    scaled = source.scaled(
        round(size.width() * ratio),
        round(size.height() * ratio),
        Qt.AspectRatioMode.IgnoreAspectRatio,
        Qt.TransformationMode.SmoothTransformation,
    )
    scaled.setDevicePixelRatio(ratio)
    return scaled


# ── Векторные глифы ──────────────────────────────────────────────────


def paint_monitor(painter: QPainter, center: QPointF, size: float, color: QColor) -> None:
    pen = QPen(color, max(1.6, size * 0.075))
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    w, h = size, size * 0.64
    screen = QRectF(center.x() - w / 2, center.y() - h / 2 - size * 0.1, w, h)
    painter.drawRoundedRect(screen, size * 0.08, size * 0.08)
    base_y = screen.bottom() + size * 0.22
    painter.drawLine(QPointF(center.x(), screen.bottom()), QPointF(center.x(), base_y))
    painter.drawLine(QPointF(center.x() - w * 0.24, base_y), QPointF(center.x() + w * 0.24, base_y))


def paint_globe(painter: QPainter, center: QPointF, size: float, color: QColor) -> None:
    pen = QPen(color, max(1.4, size * 0.065))
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    r = size / 2
    painter.drawEllipse(center, r, r)
    painter.drawEllipse(center, r * 0.42, r)
    painter.drawLine(QPointF(center.x() - r, center.y()), QPointF(center.x() + r, center.y()))
    for dy in (-0.5, 0.5):
        half = r * math.sqrt(1 - dy * dy)
        y = center.y() + dy * r
        painter.drawLine(QPointF(center.x() - half, y), QPointF(center.x() + half, y))


def paint_shield(painter: QPainter, center: QPointF, size: float, color: QColor, *, check: bool = True) -> None:
    w, h = size * 0.82, size
    top = center.y() - h / 2
    path = QPainterPath(QPointF(center.x(), top))
    path.cubicTo(QPointF(center.x() + w * 0.28, top + h * 0.1), QPointF(center.x() + w / 2, top + h * 0.1),
                 QPointF(center.x() + w / 2, top + h * 0.14))
    path.cubicTo(QPointF(center.x() + w / 2, top + h * 0.62), QPointF(center.x() + w * 0.2, top + h * 0.86),
                 QPointF(center.x(), top + h))
    path.cubicTo(QPointF(center.x() - w * 0.2, top + h * 0.86), QPointF(center.x() - w / 2, top + h * 0.62),
                 QPointF(center.x() - w / 2, top + h * 0.14))
    path.cubicTo(QPointF(center.x() - w / 2, top + h * 0.1), QPointF(center.x() - w * 0.28, top + h * 0.1),
                 QPointF(center.x(), top))
    pen = QPen(color, max(1.6, size * 0.075))
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    painter.setPen(pen)
    painter.setBrush(_with_alpha(color, 40))
    painter.drawPath(path)
    if check:
        tick = QPainterPath(QPointF(center.x() - w * 0.2, center.y() + h * 0.02))
        tick.lineTo(QPointF(center.x() - w * 0.04, center.y() + h * 0.18))
        tick.lineTo(QPointF(center.x() + w * 0.24, center.y() - h * 0.14))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(tick)


def paint_proxy_glyph(painter: QPainter, center: QPointF, size: float, color: QColor) -> None:
    """Две встречные стрелки через шлюз — «приложения → прокси → сеть»."""
    pen = QPen(color, max(1.6, size * 0.075))
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(_with_alpha(color, 40))
    gate = QRectF(center.x() - size * 0.14, center.y() - size * 0.36, size * 0.28, size * 0.72)
    painter.drawRoundedRect(gate, size * 0.08, size * 0.08)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    for dy, direction in ((-0.18, 1), (0.18, -1)):
        y = center.y() + dy * size
        x0, x1 = center.x() - size * 0.5, center.x() + size * 0.5
        start, end = (x0, x1) if direction > 0 else (x1, x0)
        painter.drawLine(QPointF(start, y), QPointF(end, y))
        head = size * 0.12 * direction
        painter.drawLine(QPointF(end, y), QPointF(end - head, y - size * 0.1))
        painter.drawLine(QPointF(end, y), QPointF(end - head, y + size * 0.1))


def paint_server_glyph(painter: QPainter, center: QPointF, radius: float, country: str, ratio: float) -> None:
    """Флаг страны сервера в скруглённой рамке, а без страны — глобус."""
    width, height = round(radius * 1.08), round(radius * 0.72)
    flag = load_flag_pixmap(country, QSize(width, height), ratio)
    if flag is None:
        paint_globe(painter, center, radius * 0.95, text_color())
        return
    target = QRectF(center.x() - width / 2, center.y() - height / 2, width, height)
    clip = QPainterPath()
    clip.addRoundedRect(target, 3, 3)
    painter.save()
    painter.setClipPath(clip)
    painter.drawPixmap(target.toRect(), flag)
    painter.restore()
    painter.setPen(QPen(_with_alpha(text_color(), 50), 1))
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawRoundedRect(target, 3, 3)


# ── Сцена туннеля ─────────────────────────────────────────────────────


class ConnectionScene(QWidget):
    """«Этот ПК ⟷ сфера ⟷ сервер»: туннель, по которому течёт трафик.

    Частицы загрузки идут от сервера к ПК, отдачи — обратно; их скорость
    растёт с реальной скоростью трафика (логарифмически). Сфера подключения —
    дочерний виджет по центру и остаётся единственной кнопкой питания сцены.
    """

    def __init__(self, parent: QWidget | None = None, *, orb_diameter: int = 168):
        super().__init__(parent)
        self.setFixedHeight(orb_diameter + 36)
        self.setMinimumWidth(320)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.orb = ConnectionOrb(self, diameter=orb_diameter)
        self._state = IDLE
        self._server_caption = "Сервер"
        self._country = ""
        self._down_bps = 0.0
        self._up_bps = 0.0
        self._level = 0.0
        self._phase = {"down": 0.0, "up": 0.0}
        self._burst_started: float | None = None
        self._quiet_since: float | None = None
        self._cache: QImage | None = None
        self._cache_key: tuple | None = None
        self._samples: list[QPointF] = []
        self._clock = QElapsedTimer()
        self._clock.start()
        self._last_frame_s = 0.0
        self._frames = FrameGate(self)
        self._frames.frame.connect(self._tick)
        on_theme_or_accent_changed(self._invalidate)

    def sizeHint(self) -> QSize:
        return QSize(640, self.minimumHeight())

    # ── Данные ──────────────────────────────────────────

    def state(self) -> str:
        return self._state

    def set_state(self, state: str) -> None:
        if state == self._state:
            return
        if state == CONNECTED and self._state != CONNECTED and self._frames.motion_allowed():
            self._burst_started = self._now()
        elif state != CONNECTED:
            self._burst_started = None
        self._state = state
        self._last_frame_s = self._now()
        self._quiet_since = None
        self._invalidate()
        self._frames.set_interval(_SCENE_FRAME_MS.get(state))

    def set_server(self, caption: str, country_code: str) -> None:
        caption = caption or "Сервер"
        country_code = (country_code or "").strip().lower()
        if (caption, country_code) == (self._server_caption, self._country):
            return
        self._server_caption = caption
        self._country = country_code
        self._invalidate()

    def set_traffic(self, down_bps: float, up_bps: float) -> None:
        self._down_bps = max(0.0, down_bps)
        self._up_bps = max(0.0, up_bps)
        if max(self._down_bps, self._up_bps) >= _QUIET_BPS:
            self._quiet_since = None
            if self._state == CONNECTED and not self._frames.is_running():
                self._last_frame_s = self._now()
                self._frames.set_interval(_SCENE_FRAME_MS[CONNECTED])

    def is_resting(self) -> bool:
        """Подключено, но трафика нет — кадров нет, туннель нарисован статично."""
        return self._state == CONNECTED and not self._frames.is_running()

    def is_animating(self) -> bool:
        return self._frames.is_running()

    # ── Кадры ──────────────────────────────────────────

    def _now(self) -> float:
        return self._clock.elapsed() / 1000.0

    def _burst_active(self) -> bool:
        return self._burst_started is not None and self._now() - self._burst_started < _BURST_S

    def _tick(self) -> None:
        now = self._now()
        if self._state == CONNECTED and not self._burst_active():
            if max(self._down_bps, self._up_bps) < _QUIET_BPS:
                if self._quiet_since is None:
                    self._quiet_since = now
                elif now - self._quiet_since >= _QUIET_AFTER_S:
                    self._frames.set_interval(None)
                    self.update()
                    return
            else:
                self._quiet_since = None
        dt = min(0.2, max(0.0, now - self._last_frame_s))
        self._last_frame_s = now
        # Плавно подтягиваем «уровень» к трафику, чтобы скорость не дёргалась.
        target = self._traffic_level(max(self._down_bps, self._up_bps))
        self._level += (target - self._level) * min(1.0, dt * 2.5)
        for lane, bps in (("down", self._down_bps), ("up", self._up_bps)):
            speed = 0.07 + 0.55 * max(self._level * 0.35, self._traffic_level(bps))
            self._phase[lane] = (self._phase[lane] + dt * speed) % 1.0
        if self._burst_started is not None and not self._burst_active():
            self._burst_started = None
            self.update()
            return
        self.update(self._dirty_region())

    @staticmethod
    def _traffic_level(bps: float) -> float:
        """0 при простое, 1 на 1 Гбит/с (см. ``_LEVEL_CAP_BPS``)."""
        if bps <= 0:
            return 0.0
        span = math.log10(_LEVEL_CAP_BPS) - _LEVEL_LOG_FLOOR
        log_part = (math.log10(1.0 + bps) - _LEVEL_LOG_FLOOR) / span
        root_part = math.sqrt(bps / _LEVEL_CAP_BPS)
        return max(0.0, min(1.0, 0.5 * max(0.0, log_part) + 0.5 * root_part))

    def load_level(self) -> float:
        """Насколько «нагружена» полоса туннеля: 0 — фон/простой, 1 — канал под завязку."""
        return max(0.0, min(1.0, (self._level - _LOAD_VISIBLE_FROM) / (1.0 - _LOAD_VISIBLE_FROM)))

    def _dirty_region(self) -> QRegion:
        if self._burst_active() or not self._samples:
            region = QRegion(self.rect())
        else:
            left, right = self._endpoints()
            band = QRect(int(left.x() - 44), int(left.y() - 48), int(right.x() - left.x() + 88), 96)
            region = QRegion(band)
        # Сферу не вычитаем: поток проходит через её центр.
        return region

    def set_orb_diameter(self, diameter: int, padding: int = 36) -> None:
        """Высота сцены идёт за сферой: на маленьком экране сцена ниже."""
        self.orb.set_diameter(diameter)
        self.setFixedHeight(diameter + padding)
        self._center_orb()
        self._invalidate()

    def _center_orb(self) -> None:
        self.orb.move(int((self.width() - self.orb.width()) / 2), int((self.height() - self.orb.height()) / 2))

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._center_orb()
        self._invalidate()

    def changeEvent(self, event) -> None:
        if event.type() == QEvent.Type.EnabledChange:
            self._invalidate()
        super().changeEvent(event)

    def _invalidate(self, *_args) -> None:
        self._cache = None
        self._cache_key = None
        self.update()

    # ── Геометрия ───────────────────────────────────────

    def _endpoints(self) -> tuple[QPointF, QPointF]:
        margin = max(56.0, min(self.width() * 0.14, 150.0))
        y = self.height() / 2 - 6
        return QPointF(margin, y), QPointF(self.width() - margin, y)

    def _badge_radius(self) -> float:
        return 28.0

    def _tunnel_path(self) -> QPainterPath:
        left, right = self._endpoints()
        radius = self._badge_radius()
        start = QPointF(left.x() + radius + 6, left.y())
        end = QPointF(right.x() - radius - 6, right.y())
        mid = QPointF((start.x() + end.x()) / 2, left.y())
        bend = 14.0
        path = QPainterPath(start)
        path.cubicTo(QPointF(start.x() + (mid.x() - start.x()) * 0.5, start.y() - bend),
                     QPointF(mid.x() - (mid.x() - start.x()) * 0.35, mid.y() + bend * 0.6), mid)
        path.cubicTo(QPointF(mid.x() + (end.x() - mid.x()) * 0.35, mid.y() - bend * 0.6),
                     QPointF(end.x() - (end.x() - mid.x()) * 0.5, end.y() + bend), end)
        return path

    def _state_color(self) -> QColor:
        if self._state == CONNECTED:
            return positive_color()
        if self._state == CONNECTING:
            return accent_color()
        if self._state == ERROR:
            return error_color()
        return text_muted_color()

    # ── Отрисовка ───────────────────────────────────────

    def _ensure_cache(self) -> QImage:
        ratio = self.devicePixelRatioF()
        key = (self.width(), self.height(), ratio, self._state, self._server_caption, self._country, self.isEnabled())
        if self._cache is not None and self._cache_key == key:
            return self._cache
        image = QImage(
            max(1, round(self.width() * ratio)),
            max(1, round(self.height() * ratio)),
            QImage.Format.Format_ARGB32_Premultiplied,
        )
        image.setDevicePixelRatio(ratio)
        image.fill(Qt.GlobalColor.transparent)
        painter = QPainter(image)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._paint_static(painter)
        painter.end()
        path = self._tunnel_path()
        self._samples = [path.pointAtPercent(i / (_PATH_SAMPLES - 1)) for i in range(_PATH_SAMPLES)]
        self._cache = image
        self._cache_key = key
        return image

    def _paint_static(self, painter: QPainter) -> None:
        w, h = self.width(), self.height()
        color = self._state_color()
        center = QPointF(w / 2, h / 2)

        # Свечение состояния за сферой: эллипс, который гаснет раньше краёв
        # сцены, — иначе градиент обрезается и видна прямоугольная «коробка».
        painter.save()
        painter.translate(center)
        painter.scale(2.2, 1.0)
        glow_radius = h / 2
        glow = QRadialGradient(QPointF(0, 0), glow_radius)
        glow.setColorAt(0.0, _with_alpha(color, 50 if self._state != IDLE else 20))
        glow.setColorAt(0.55, _with_alpha(color, 18 if self._state != IDLE else 7))
        glow.setColorAt(1.0, _with_alpha(color, 0))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(glow)
        painter.drawEllipse(QPointF(0, 0), glow_radius, glow_radius)
        painter.restore()

        # Сетка точек с виньеткой к краям — «карта сети».
        dot = text_muted_color()
        step = 22
        half_w, half_h = w / 2, h / 2
        for x in range(step // 2, w, step):
            for y in range(step // 2, h, step):
                # Эллиптическая виньетка: к любому краю сцены точки гаснут в ноль.
                fade = 1.0 - math.hypot((x - center.x()) / half_w, (y - center.y()) / half_h)
                if fade <= 0.04:
                    continue
                painter.setBrush(_with_alpha(dot, 30 * fade ** 1.5))
                painter.drawEllipse(QPointF(x, y), 0.9, 0.9)

        # Дорожка туннеля.
        path = self._tunnel_path()
        painter.setBrush(Qt.BrushStyle.NoBrush)
        if self._state == CONNECTED:
            pass  # полоса зависит от нагрузки — рисуется в _paint_tunnel_flow каждый кадр
        elif self._state == ERROR:
            self._paint_broken_tunnel(painter, path, color)
        else:
            pen = QPen(_with_alpha(text_muted_color(), 110 if self._state == CONNECTING else 80), 2)
            pen.setStyle(Qt.PenStyle.DashLine)
            pen.setDashPattern([3, 4])
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            painter.drawPath(path)

        left, right = self._endpoints()
        self._paint_badge(painter, left, "Этот ПК", self._local_glyph)
        self._paint_badge(painter, right, self._server_caption, self._server_glyph)

    def _paint_broken_tunnel(self, painter: QPainter, path: QPainterPath, color: QColor) -> None:
        gap_from, gap_to = 0.66, 0.74
        pen = QPen(_with_alpha(color, 170), 2.4, cap=Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        for start, end in ((0.0, gap_from), (gap_to, 1.0)):
            piece = QPainterPath(path.pointAtPercent(start))
            steps = 40
            for i in range(1, steps + 1):
                piece.lineTo(path.pointAtPercent(start + (end - start) * i / steps))
            painter.drawPath(piece)
        # Искра-молния на месте разрыва.
        mid = path.pointAtPercent((gap_from + gap_to) / 2)
        bolt = QPainterPath(QPointF(mid.x() - 3, mid.y() - 11))
        bolt.lineTo(QPointF(mid.x() + 4, mid.y() - 1))
        bolt.lineTo(QPointF(mid.x() - 3, mid.y() + 1))
        bolt.lineTo(QPointF(mid.x() + 3, mid.y() + 11))
        painter.setPen(QPen(color, 2, cap=Qt.PenCapStyle.RoundCap, join=Qt.PenJoinStyle.RoundJoin))
        painter.drawPath(bolt)

    def _paint_badge(self, painter: QPainter, center: QPointF, caption: str, glyph) -> None:
        radius = self._badge_radius()
        active = self._state == CONNECTED
        ring = positive_color() if active else text_muted_color()
        painter.setPen(QPen(_with_alpha(ring, 170 if active else 90), 1.4))
        painter.setBrush(_with_alpha(text_color(), 10))
        painter.drawEllipse(center, radius, radius)
        glyph(painter, center, radius)
        font = painter.font()
        font.setPixelSize(12)
        painter.setFont(font)
        metrics = QFontMetrics(font)
        width = int(min(170.0, max(90.0, center.x() * 2 - 8, (self.width() - center.x()) * 2 - 8)))
        text = metrics.elidedText(caption, Qt.TextElideMode.ElideRight, width)
        painter.setPen(text_color() if self.isEnabled() else text_muted_color())
        painter.drawText(QRectF(center.x() - width / 2, center.y() + radius + 6, width, 18),
                         Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, text)

    def _local_glyph(self, painter: QPainter, center: QPointF, radius: float) -> None:
        paint_monitor(painter, center, radius * 0.95, text_color())

    def _server_glyph(self, painter: QPainter, center: QPointF, radius: float) -> None:
        paint_server_glyph(painter, center, radius, self._country, self.devicePixelRatioF())

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.drawImage(0, 0, self._ensure_cache())
        if self._state == CONNECTED:
            self._paint_tunnel_flow(painter)
        if self._frames.is_running() or self._burst_active():
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            if self._state == CONNECTED:
                self._paint_particles(painter)
                self._paint_server_pulse(painter)
            elif self._state == CONNECTING:
                self._paint_probe(painter)
            if self._burst_active():
                self._paint_burst(painter)
        painter.end()

    def _paint_tunnel_flow(self, painter: QPainter) -> None:
        """Полоса туннеля: толще и «горячее» только под реальной нагрузкой.

        Спокойно — акцент, как раньше; под нагрузкой полоса утолщается,
        светлеет до почти белой и получает широкий ореол.
        """
        load = self.load_level()
        base = positive_color()
        hot = QColor(base).lighter(150)
        white = QColor(255, 255, 255)
        if load < 0.6:
            core = _mix(base, hot, load / 0.6)
        else:
            core = _mix(hot, white, (load - 0.6) / 0.4 * 0.7)
        path = self._tunnel_path()
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(_with_alpha(base, 34 + 70 * load), 12 + 18 * load, cap=Qt.PenCapStyle.RoundCap))
        painter.drawPath(path)
        if load > 0.05:
            painter.setPen(QPen(_with_alpha(hot, 60 * load), 6 + 8 * load, cap=Qt.PenCapStyle.RoundCap))
            painter.drawPath(path)
        painter.setPen(QPen(_with_alpha(core, 150 + 100 * load), 2.4 + 4.6 * load, cap=Qt.PenCapStyle.RoundCap))
        painter.drawPath(path)
        painter.restore()

    def _sample(self, t: float) -> QPointF:
        index = max(0, min(len(self._samples) - 1, round(t * (len(self._samples) - 1))))
        return self._samples[index]

    def _paint_particles(self, painter: QPainter) -> None:
        if not self._samples:
            return
        orb_center = QPointF(self.width() / 2, self.height() / 2)
        hide_radius = self.orb.width() * 0.44
        painter.setPen(Qt.PenStyle.NoPen)
        for lane, count, offset in _LANES:
            color = graph_down_color() if lane == "down" else graph_up_color()
            for index in range(count):
                t = (self._phase[lane] + offset + index / count) % 1.0
                if lane == "down":
                    t = 1.0 - t
                point = self._sample(t)
                fade = min(1.0, t * 8, (1.0 - t) * 8)
                # Через сферу поток идёт насквозь, но приглушённо — значок
                # питания (дочерний виджет) остаётся поверх и читается.
                if math.hypot(point.x() - orb_center.x(), point.y() - orb_center.y()) < hide_radius:
                    fade *= _THROUGH_ORB_FADE
                dy = -3.2 if lane == "down" else 3.2
                point = QPointF(point.x(), point.y() + dy)
                grow = 1.0 + 0.6 * self.load_level()
                painter.setBrush(_with_alpha(color, 60 * fade))
                painter.drawEllipse(point, 5.5 * grow, 5.5 * grow)
                painter.setBrush(_with_alpha(color, 235 * fade))
                painter.drawEllipse(point, 2.3 * grow, 2.3 * grow)

    def _paint_server_pulse(self, painter: QPainter) -> None:
        _left, right = self._endpoints()
        phase = (self._now() / (_PULSE_PERIOD_S * 2)) % 1.0
        radius = self._badge_radius() * (1.0 + 0.45 * phase)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(_with_alpha(positive_color(), 120 * (1.0 - phase)), 1.5))
        painter.drawEllipse(right, radius, radius)

    def _paint_probe(self, painter: QPainter) -> None:
        if not self._samples:
            return
        color = accent_color()
        head = (self._now() / _PULSE_PERIOD_S) % 1.0
        painter.setPen(Qt.PenStyle.NoPen)
        for index in range(10):
            t = head - index * 0.018
            if t < 0:
                continue
            fade = (1 - index / 10) ** 1.5
            painter.setBrush(_with_alpha(color, 230 * fade))
            painter.drawEllipse(self._sample(t), 3.2 * (1 - index / 14), 3.2 * (1 - index / 14))

    def _paint_burst(self, painter: QPainter) -> None:
        progress = (self._now() - (self._burst_started or 0.0)) / _BURST_S
        ease = 1 - (1 - progress) ** 3
        center = QPointF(self.width() / 2, self.height() / 2)
        base = self.orb.width() * 0.4
        painter.setBrush(Qt.BrushStyle.NoBrush)
        for delay, width in ((0.0, 3.0), (0.18, 1.6)):
            local = max(0.0, min(1.0, (ease - delay) / (1 - delay)))
            if local <= 0:
                continue
            radius = base + local * self.width() * 0.32
            painter.setPen(QPen(_with_alpha(positive_color(), 200 * (1 - local)), width))
            # По вертикали волна не выходит за сцену — на низкой сцене её не обрезает.
            painter.drawEllipse(center, radius, min(radius * 0.62, self.height() / 2 - 2))


# ── Плитка режима ─────────────────────────────────────────────────────


class ModeTile(QWidget):
    """Выбираемая плитка режима: глиф, заголовок, пояснение. Выбор — плавная рамка."""

    clicked = pyqtSignal()

    def __init__(self, glyph: str, title: str, description: str, parent: QWidget | None = None):
        super().__init__(parent)
        self._glyph = glyph
        self._title = title
        self._applying = False
        self._checked = False
        self._hover = False
        self._selection = 0.0
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.setAccessibleName(title)
        layout = QHBoxLayout(self)
        self._layout = layout
        layout.setContentsMargins(16 + 44 + 12, 12, 14, 12)
        text = QVBoxLayout()
        text.setSpacing(2)
        self.title_label = StrongBodyLabel(title, self)
        self.description_label = CaptionLabel(description, self)
        self.description_label.setWordWrap(True)
        text.addWidget(self.title_label)
        text.addWidget(self.description_label)
        layout.addLayout(text, 1)
        self.setMinimumHeight(76)
        self._animation = QVariantAnimation(self)
        self._animation.setDuration(220)
        self._animation.valueChanged.connect(self._on_animation)
        on_theme_or_accent_changed(self._repaint)

    def _repaint(self, *_args) -> None:
        self.update()

    def set_compact(self, compact: bool) -> None:
        """Ниже плитка и поля на маленьком экране; глиф 44 px по-прежнему влезает."""
        vertical = 6 if compact else 12
        self._layout.setContentsMargins(16 + 44 + 12, vertical, 14, vertical)
        self.setMinimumHeight(58 if compact else 76)

    def isChecked(self) -> bool:
        return self._checked

    def is_applying(self) -> bool:
        return self._applying

    def set_applying(self, applying: bool) -> None:
        """Выбор принят, но ещё применяется: «…» в заголовке и подсказка."""
        applying = bool(applying)
        if applying == self._applying:
            return
        self._applying = applying
        self.title_label.setText(self._title + ("…" if applying else ""))
        self.setToolTip("Применяется…" if applying else "")

    def setChecked(self, checked: bool) -> None:
        checked = bool(checked)
        if checked == self._checked:
            return
        self._checked = checked
        target = 1.0 if checked else 0.0
        if not self.isVisible() or reduced_motion():
            self._animation.stop()
            self._selection = target
            self.update()
            return
        self._animation.stop()
        self._animation.setStartValue(self._selection)
        self._animation.setEndValue(target)
        self._animation.start()

    def is_animating(self) -> bool:
        return self._animation.state() == QVariantAnimation.State.Running

    def _on_animation(self, value) -> None:
        self._selection = float(value)
        self.update()

    def enterEvent(self, event) -> None:
        self._hover = True
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self._hover = False
        self.update()
        super().leaveEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton and self.rect().contains(event.position().toPoint()):
            if self.isEnabled():
                self.clicked.emit()
            return
        super().mouseReleaseEvent(event)

    def keyPressEvent(self, event) -> None:
        if event.key() in (Qt.Key.Key_Space, Qt.Key.Key_Return, Qt.Key.Key_Enter) and self.isEnabled():
            self.clicked.emit()
            return
        super().keyPressEvent(event)

    def changeEvent(self, event) -> None:
        if event.type() == QEvent.Type.EnabledChange:
            self.update()
        super().changeEvent(event)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        sel = self._selection
        enabled = self.isEnabled()
        accent = accent_color()

        fill = accent_soft_bg_hover() if self._hover and enabled else accent_soft_bg()
        fill.setAlpha(int(fill.alpha() * sel) + (10 if self._hover and enabled else 0))
        border = QColor(text_muted_color())
        border.setAlpha(60)
        painter.setBrush(fill)
        painter.setPen(QPen(border, 1))
        painter.drawRoundedRect(rect, 8, 8)
        if sel > 0.01:
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(_with_alpha(accent, 255 * sel if enabled else 110 * sel), 2))
            painter.drawRoundedRect(rect.adjusted(0.5, 0.5, -0.5, -0.5), 8, 8)
        if self.hasFocus():
            focus = QPen(_with_alpha(text_color(), 120), 1, Qt.PenStyle.DotLine)
            painter.setPen(focus)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(rect.adjusted(3, 3, -3, -3), 6, 6)

        # Кружок с глифом слева.
        center = QPointF(16 + 22, self.height() / 2)
        glyph_color = QColor(accent) if sel > 0.5 else text_muted_color()
        if not enabled:
            glyph_color.setAlpha(110)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(_with_alpha(glyph_color, 26 + 30 * sel))
        painter.drawEllipse(center, 22, 22)
        if self._glyph == "vpn":
            paint_shield(painter, center, 22, glyph_color, check=sel > 0.5)
        else:
            paint_proxy_glyph(painter, center, 24, glyph_color)

        # Галочка выбора в правом верхнем углу.
        if sel > 0.01:
            mark = QPointF(rect.right() - 14, rect.top() + 14)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(_with_alpha(accent, 255 * sel))
            painter.drawEllipse(mark, 7 * sel, 7 * sel)
            tick = QPainterPath(QPointF(mark.x() - 3, mark.y()))
            tick.lineTo(QPointF(mark.x() - 0.8, mark.y() + 2.3))
            tick.lineTo(QPointF(mark.x() + 3.2, mark.y() - 2.3))
            pen = QPen(_with_alpha(QColor(255, 255, 255), 255 * sel), 1.6)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(tick)
        painter.end()


class FlagBadge(QWidget):
    """Круглый значок сервера: флаг страны или глобус."""

    def __init__(self, parent: QWidget | None = None, diameter: int = 40):
        super().__init__(parent)
        self._country = ""
        self.setFixedSize(diameter, diameter)
        on_theme_or_accent_changed(self._repaint)

    def set_diameter(self, diameter: int) -> None:
        if diameter != self.width():
            self.setFixedSize(diameter, diameter)
            self.update()

    def _repaint(self, *_args) -> None:
        self.update()

    def country(self) -> str:
        return self._country

    def set_country(self, code: str) -> None:
        code = (code or "").strip().lower()
        if code != self._country:
            self._country = code
            self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        radius = self.width() / 2 - 1
        center = QPointF(self.width() / 2, self.height() / 2)
        painter.setPen(QPen(_with_alpha(text_muted_color(), 90), 1.2))
        painter.setBrush(_with_alpha(text_color(), 10))
        painter.drawEllipse(center, radius, radius)
        paint_server_glyph(painter, center, radius, self._country, self.devicePixelRatioF())
        painter.end()


# ── Индикатор качества связи ──────────────────────────────────────────


class SignalBars(QWidget):
    """Четыре столбика «сигнала» по пингу; без замера — все приглушены."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._latency: int | None = None
        self.setFixedSize(22, 18)
        on_theme_or_accent_changed(self._repaint)

    def _repaint(self, *_args) -> None:
        self.update()

    def set_latency(self, latency_ms: int | None) -> None:
        if latency_ms == self._latency:
            return
        self._latency = latency_ms
        self.setToolTip("Пинг не измерен" if latency_ms is None else f"Пинг: {latency_ms} ms")
        self.update()

    def active_bars(self) -> int:
        return latency_bars(self._latency)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        bars = self.active_bars()
        on = latency_color(self._latency)
        off = _with_alpha(text_muted_color(), 70)
        painter.setPen(Qt.PenStyle.NoPen)
        width, gap = 4.0, 2.0
        for index in range(4):
            height = 5 + index * 4.2
            x = index * (width + gap)
            painter.setBrush(on if index < bars else off)
            painter.drawRoundedRect(QRectF(x, self.height() - height, width, height), 1.5, 1.5)
        painter.end()


# ── Топ приложений ────────────────────────────────────────────────────


class ProcessBars(QWidget):
    """Несколько строк «приложение — полоса доли — объём»; полосы плавно растут."""

    ROW_HEIGHT = 30

    def __init__(self, parent: QWidget | None = None, *, rows: int = 4):
        super().__init__(parent)
        self._rows = rows
        self._items: list[tuple[str, str, float]] = []
        self._shown: list[float] = []
        self._from: list[float] = []
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setFixedHeight(self.ROW_HEIGHT * rows)
        self._animation = QVariantAnimation(self)
        self._animation.setDuration(380)
        self._animation.setStartValue(0.0)
        self._animation.setEndValue(1.0)
        self._animation.valueChanged.connect(self._on_animation)
        on_theme_or_accent_changed(self._repaint)

    def _repaint(self, *_args) -> None:
        self.update()

    def rows(self) -> int:
        return self._rows

    def items(self) -> list[tuple[str, str, float]]:
        return list(self._items)

    def set_items(self, items: list[tuple[str, str, float]]) -> None:
        """``items``: (имя, подпись справа, доля 0..1), не больше ``rows``."""
        items = [(name, value, max(0.0, min(1.0, share))) for name, value, share in items[: self._rows]]
        if items == self._items:
            return
        previous = {name: shown for (name, _v, _s), shown in zip(self._items, self._shown)}
        self._items = items
        self._from = [previous.get(name, 0.0) for name, _v, _s in items]
        self._shown = list(self._from)
        if not self.isVisible() or reduced_motion():
            self._animation.stop()
            self._shown = [share for _n, _v, share in items]
            self.update()
            return
        self._animation.stop()
        self._animation.start()

    def is_animating(self) -> bool:
        return self._animation.state() == QVariantAnimation.State.Running

    def _on_animation(self, value) -> None:
        progress = 1 - (1 - float(value)) ** 3
        self._shown = [start + (share - start) * progress
                       for start, (_n, _v, share) in zip(self._from, self._items)]
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        font = painter.font()
        font.setPixelSize(12)
        painter.setFont(font)
        metrics = QFontMetrics(font)
        name_w = min(170, max(90, int(self.width() * 0.32)))
        value_w = 78
        bar_x = name_w + 10
        bar_w = max(20, self.width() - bar_x - value_w - 10)
        accent = accent_color()
        track = _with_alpha(text_muted_color(), 38)
        for row, ((name, value, _share), shown) in enumerate(zip(self._items, self._shown)):
            top = row * self.ROW_HEIGHT
            mid = top + self.ROW_HEIGHT / 2
            painter.setPen(text_color())
            painter.drawText(QRectF(0, top, name_w, self.ROW_HEIGHT),
                             Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                             metrics.elidedText(name, Qt.TextElideMode.ElideMiddle, name_w))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(track)
            painter.drawRoundedRect(QRectF(bar_x, mid - 3, bar_w, 6), 3, 3)
            if shown > 0.001:
                painter.setBrush(_with_alpha(accent, 150 + 105 * (1 - row / max(1, self._rows))))
                painter.drawRoundedRect(QRectF(bar_x, mid - 3, max(6.0, bar_w * shown), 6), 3, 3)
            painter.setPen(text_muted_color())
            painter.drawText(QRectF(self.width() - value_w, top, value_w, self.ROW_HEIGHT),
                             Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight, value)
        painter.end()


class StatTile(QWidget):
    """Плитка метрики: подпись (+ необязательный значок справа), крупное значение, пояснение."""

    def __init__(self, caption: str, parent: QWidget | None = None, *, value: str = "--"):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        head = QHBoxLayout()
        head.setSpacing(6)
        self.caption_label = CaptionLabel(caption, self)
        head.addWidget(self.caption_label)
        head.addStretch(1)
        self.head_layout = head
        layout.addLayout(head)
        self.value_label = SubtitleLabel(value, self)
        self.detail_label = CaptionLabel("", self)
        self.detail_label.setWordWrap(True)
        layout.addWidget(self.value_label)
        layout.addWidget(self.detail_label)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)


__all__ = [
    "FlagBadge",
    "ConnectionScene",
    "ModeTile",
    "ProcessBars",
    "SignalBars",
    "StatTile",
    "latency_bars",
    "latency_color",
    "load_flag_pixmap",
    "reduced_motion",
]
