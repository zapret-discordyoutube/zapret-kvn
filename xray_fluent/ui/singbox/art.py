"""Vector art of the routing editor: badges, section illustrations, pulses.

Everything is painted with ``QPainter`` in theme/accent colours at paint time
(like ``connection_orb.ConnectionOrb``), so it is crisp on any DPI and follows
theme switches. Animated pieces run on ``motion.FrameGate``: frames tick only
while the widget is visible and Windows animations are enabled; the phase is
taken from real time, so dropped frames never slow the motion. With animations
disabled every illustration shows a still frame.

Illustrations are data-driven: they draw the user's own config (how many rules
go to proxy/direct/block, which actions the rules use, how many DNS servers and
outbounds exist).
"""

from __future__ import annotations

import math

from PyQt6.QtCore import QElapsedTimer, QPointF, QRectF, QSize, Qt
from PyQt6.QtGui import (
    QColor,
    QFont,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QRadialGradient,
)
from PyQt6.QtWidgets import QSizePolicy, QWidget
from qfluentwidgets import FluentIcon as FIF, isDarkTheme

from ..motion import FrameGate
from ..theme import accent_color, on_theme_or_accent_changed, text_color, text_muted_color
from .visuals import BLOCK, DIRECT, DNS, NEUTRAL, PROXY, Visual, tone_color

TAU = math.tau


# ── helpers ─────────────────────────────────────────────────────────────────

def with_alpha(color: QColor, alpha: int) -> QColor:
    result = QColor(color)
    result.setAlpha(max(0, min(255, int(alpha))))
    return result


def lerp(a: float, b: float, u: float) -> float:
    return a + (b - a) * u


def ease_in_out(u: float) -> float:
    return 0.5 - 0.5 * math.cos(math.pi * max(0.0, min(1.0, u)))


_ICON_CACHE: dict[tuple, QPixmap] = {}


def icon_pixmap(icon: FIF, color: QColor, size: int, dpr: float) -> QPixmap:
    """Coloured Fluent icon as a pixmap; cached (parsing SVG per frame is slow)."""

    key = (icon.value, color.rgba(), size, round(dpr, 2))
    pixmap = _ICON_CACHE.get(key)
    if pixmap is None:
        if len(_ICON_CACHE) > 512:
            _ICON_CACHE.clear()
        pixmap = icon.icon(color=color).pixmap(QSize(size, size), dpr)
        _ICON_CACHE[key] = pixmap
    return pixmap


def draw_icon(painter: QPainter, icon: FIF, center: QPointF, size: float, color: QColor) -> None:
    dpr = painter.device().devicePixelRatioF() if painter.device() is not None else 1.0
    pixmap = icon_pixmap(icon, color, max(1, round(size)), dpr)
    painter.drawPixmap(QRectF(center.x() - size / 2, center.y() - size / 2, size, size).toRect(), pixmap)


def glow_dot(painter: QPainter, center: QPointF, radius: float, color: QColor, alpha: float = 1.0) -> None:
    halo = QRadialGradient(center, radius * 2.8)
    halo.setColorAt(0.0, with_alpha(color, 110 * alpha))
    halo.setColorAt(1.0, with_alpha(color, 0))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(halo)
    painter.drawEllipse(center, radius * 2.8, radius * 2.8)
    painter.setBrush(with_alpha(color, 255 * alpha))
    painter.drawEllipse(center, radius, radius)


def node(painter: QPainter, center: QPointF, radius: float, icon: FIF, color: QColor, *, glow: float = 0.0) -> None:
    """Round node with a soft fill, ring and icon — the building block of maps."""

    if glow > 0:
        halo = QRadialGradient(center, radius * 2.0)
        halo.setColorAt(0.0, with_alpha(color, 90 * glow))
        halo.setColorAt(1.0, with_alpha(color, 0))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(halo)
        painter.drawEllipse(center, radius * 2.0, radius * 2.0)
    fill = QRadialGradient(QPointF(center.x() - radius * 0.3, center.y() - radius * 0.4), radius * 1.4)
    fill.setColorAt(0.0, with_alpha(color, 90 if isDarkTheme() else 60))
    fill.setColorAt(1.0, with_alpha(color, 36 if isDarkTheme() else 22))
    painter.setBrush(fill)
    painter.setPen(QPen(with_alpha(color, 200), 1.4))
    painter.drawEllipse(center, radius, radius)
    draw_icon(painter, icon, center, radius * 1.05, color.lighter(125) if isDarkTheme() else color)


def label(painter: QPainter, rect: QRectF, text: str, color: QColor, *, size: int = 9, bold: bool = False,
          align=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter) -> None:
    font = QFont(painter.font())
    font.setPointSizeF(size)
    font.setBold(bold)
    painter.setFont(font)
    painter.setPen(color)
    painter.drawText(rect, int(align), text)


# ── badge ───────────────────────────────────────────────────────────────────

class KindBadge(QWidget):
    """Rounded tile with a Fluent icon in the object's semantic tone."""

    def __init__(self, parent: QWidget | None = None, size: int = 34):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self._visual = Visual(FIF.FILTER, NEUTRAL)
        self._vivid = False
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    def set_visual(self, visual: Visual, *, vivid: bool = False) -> None:
        if (visual, vivid) != (self._visual, self._vivid):
            self._visual = visual
            self._vivid = vivid
            self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        color = tone_color(self._visual.tone)
        radius = rect.width() * 0.28
        if self._vivid:
            gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
            gradient.setColorAt(0.0, color.lighter(118))
            gradient.setColorAt(1.0, color.darker(112))
            painter.setBrush(gradient)
            painter.setPen(Qt.PenStyle.NoPen)
            icon_color = QColor(Qt.GlobalColor.white)
        else:
            gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
            gradient.setColorAt(0.0, with_alpha(color, 58 if isDarkTheme() else 40))
            gradient.setColorAt(1.0, with_alpha(color, 26 if isDarkTheme() else 16))
            painter.setBrush(gradient)
            painter.setPen(QPen(with_alpha(color, 80), 1.0))
            icon_color = color.lighter(130) if isDarkTheme() else color
        painter.drawRoundedRect(rect, radius, radius)
        draw_icon(painter, self._visual.icon, rect.center(), rect.width() * 0.5, icon_color)
        painter.end()


# ── animated canvas ─────────────────────────────────────────────────────────

class ArtCanvas(QWidget):
    """Base of the animated illustrations."""

    frame_ms: int | None = 40
    #: Phase shown when Windows animations are off.
    still_time = 1.3

    def __init__(self, parent: QWidget | None = None, *, height: int = 120, min_width: int = 220):
        super().__init__(parent)
        self.setFixedHeight(height)
        self.setMinimumWidth(min_width)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._clock = QElapsedTimer()
        self._clock.start()
        self._frames = FrameGate(self)
        self._frames.frame.connect(self.update)
        self._frames.set_interval(self.frame_ms)
        on_theme_or_accent_changed(self._on_theme_changed)

    def _on_theme_changed(self, *_args) -> None:
        self.update()

    def is_animating(self) -> bool:
        return self._frames.is_running()

    def phase(self) -> float:
        if not self._frames.motion_allowed():
            return self.still_time
        return self._clock.elapsed() / 1000.0

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.paint_art(painter, QRectF(self.rect()), self.phase())
        painter.end()

    def paint_art(self, painter: QPainter, rect: QRectF, t: float) -> None:
        raise NotImplementedError


# ── section illustrations ───────────────────────────────────────────────────

_LANES = ((PROXY, FIF.VPN, "Прокси"), (DIRECT, FIF.SEND, "Напрямую"), (BLOCK, FIF.CLOSE, "Блок"))


class RouteMapArt(ArtCanvas):
    """Overview: packets leave the computer, pass the rules, split by outcome."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent, height=156, min_width=320)
        self._counts = (1, 1, 1)

    def set_counts(self, proxy: int, direct: int, block: int) -> None:
        counts = (max(0, proxy), max(0, direct), max(0, block))
        if counts != self._counts:
            self._counts = counts
            self.update()

    def _lane_cycle(self) -> list[int]:
        total = sum(self._counts)
        if not total:
            return [0]
        cycle: list[int] = []
        for lane, count in enumerate(self._counts):
            if count:
                cycle += [lane] * max(1, round(12 * count / total))
        # Interleave so neighbouring packets take different lanes.
        return [cycle[(index * 5) % len(cycle)] for index in range(len(cycle))]

    def paint_art(self, painter: QPainter, rect: QRectF, t: float) -> None:
        width = rect.width()
        height = rect.height()
        muted = text_muted_color()
        src = QPointF(rect.left() + 34, rect.center().y())
        hub = QPointF(rect.left() + width * 0.44, rect.center().y())
        dest_x = rect.left() + width * 0.74
        dests = [QPointF(dest_x, rect.top() + height * frac) for frac in (0.2, 0.5, 0.8)]

        trunk = QPainterPath(src)
        trunk.cubicTo(QPointF(lerp(src.x(), hub.x(), 0.5), src.y() - 18), QPointF(lerp(src.x(), hub.x(), 0.5), hub.y() + 18), hub)
        lanes = []
        for dest in dests:
            path = QPainterPath(hub)
            mid = lerp(hub.x(), dest.x(), 0.55)
            path.cubicTo(QPointF(mid, hub.y()), QPointF(mid, dest.y()), dest)
            lanes.append(path)

        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(with_alpha(muted, 70), 2.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawPath(trunk)
        for (tone, _icon, _text), path, count in zip(_LANES, lanes, self._counts):
            color = tone_color(tone)
            painter.setPen(QPen(with_alpha(color, 26 if count else 10), 7.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            painter.drawPath(path)
            pen = QPen(with_alpha(color, 150 if count else 40), 1.6, Qt.PenStyle.DashLine if not count else Qt.PenStyle.SolidLine)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            painter.drawPath(path)

        # Packets: travel the trunk (neutral), then their lane (lane colour).
        cycle = self._lane_cycle()
        packets = 14
        arrivals = [0.0, 0.0, 0.0]
        for index in range(packets):
            u = (t * 0.32 + index / packets) % 1.0
            lane = cycle[index % len(cycle)]
            if not sum(self._counts):
                break
            color = tone_color(_LANES[lane][0])
            if u < 0.42:
                point = trunk.pointAtPercent(u / 0.42)
                glow_dot(painter, point, 2.6, accent_color(), 0.85)
                continue
            v = (u - 0.42) / 0.58
            alpha = 1.0
            if _LANES[lane][0] == BLOCK and v > 0.78:
                alpha = max(0.0, 1.0 - (v - 0.78) / 0.22)
            if v > 0.9:
                arrivals[lane] = max(arrivals[lane], (v - 0.9) / 0.1)
            glow_dot(painter, lanes[lane].pointAtPercent(min(v, 1.0)), 3.0, color, alpha)

        # Nodes.
        node(painter, src, 17, FIF.APPLICATION, accent_color())
        label(painter, QRectF(src.x() - 40, src.y() + 20, 80, 16), "Устройство", muted, size=8,
              align=Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)
        breathe = 0.5 + 0.5 * math.sin(t * TAU / 2.6)
        node(painter, hub, 20, FIF.FILTER, accent_color(), glow=0.35 + 0.35 * breathe)
        label(painter, QRectF(hub.x() - 80, hub.y() + 23, 160, 16), "правила по порядку", muted, size=8,
              align=Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)
        for (tone, icon, text), dest, count, arrival in zip(_LANES, dests, self._counts, arrivals):
            color = tone_color(tone)
            node(painter, dest, 15, icon, color, glow=arrival * 0.9 if count else 0.0)
            label(painter, QRectF(dest.x() + 22, dest.y() - 15, 150, 16), text, text_color(), size=9, bold=True)
            words = "правило" if count % 10 == 1 and count % 100 != 11 else (
                "правила" if count % 10 in (2, 3, 4) and count % 100 not in (12, 13, 14) else "правил")
            label(painter, QRectF(dest.x() + 22, dest.y() + 1, 150, 14), f"{count} {words}", muted, size=8)


class RuleScanArt(ArtCanvas):
    """Rules: a probe walks the list top-down and stops at the first match."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent, height=128, min_width=260)
        self._visuals: list[Visual] = []

    def set_rules(self, visuals: list[Visual]) -> None:
        visuals = list(visuals)[:8]
        if visuals != self._visuals:
            self._visuals = visuals
            self.update()

    def paint_art(self, painter: QPainter, rect: QRectF, t: float) -> None:
        visuals = self._visuals or [Visual(FIF.FLAG, NEUTRAL)]
        count = len(visuals)
        muted = text_muted_color()
        bar_h, gap = 9.0, 5.0
        top = rect.center().y() - (count * (bar_h + gap) - gap) / 2
        left = rect.left() + 14
        bar_w = rect.width() * 0.5
        period = 2.8
        cycle = int(t / period)
        local = (t % period) / period
        # Deterministic pseudo-random target so the probe visits every rule.
        target = (cycle * 3 + 1) % count
        descend = min(1.0, local / 0.55)
        probe_pos = ease_in_out(descend) * target
        matched = local >= 0.55
        for index, visual in enumerate(visuals):
            y = top + index * (bar_h + gap)
            color = tone_color(visual.tone)
            passed = probe_pos > index + 0.05 and not (matched and index == target)
            alpha = 40
            if index == target and matched:
                alpha = 220
            elif abs(probe_pos - index) < 0.5:
                alpha = 120
            elif passed:
                alpha = 26
            width = bar_w * (0.55 + 0.45 * ((index * 37) % 10) / 10)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(with_alpha(color, alpha))
            painter.drawRoundedRect(QRectF(left + 18, y, width, bar_h), bar_h / 2, bar_h / 2)
            label(painter, QRectF(left - 4, y - 3, 18, bar_h + 6), str(index + 1), with_alpha(muted, 200), size=7,
                  align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        probe_y = top + probe_pos * (bar_h + gap) + bar_h / 2
        glow_dot(painter, QPointF(left + 12, probe_y), 3.2, accent_color())
        visual = visuals[target]
        color = tone_color(visual.tone)
        target_rect_x = rect.left() + rect.width() * 0.8
        dest = QPointF(target_rect_x, rect.center().y())
        if matched:
            shoot = min(1.0, (local - 0.55) / 0.3)
            start = QPointF(left + 18 + bar_w, top + target * (bar_h + gap) + bar_h / 2)
            path = QPainterPath(start)
            path.cubicTo(QPointF(lerp(start.x(), dest.x(), 0.5), start.y()), QPointF(lerp(start.x(), dest.x(), 0.5), dest.y()), dest)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(with_alpha(color, 90), 1.6, Qt.PenStyle.DashLine))
            painter.drawPath(path)
            glow_dot(painter, path.pointAtPercent(ease_in_out(shoot)), 3.2, color)
        node(painter, dest, 18, visual.icon, color, glow=0.8 if matched and local > 0.8 else 0.2)
        label(painter, QRectF(dest.x() - 90, dest.y() + 22, 180, 14),
              f"сработало правило {target + 1}" if matched else "ищу совпадение…", muted, size=8,
              align=Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)


class RuleSetArt(ArtCanvas):
    """Rule-sets: stacked data disks gently floating; a download drops in."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent, height=120)
        self._counts = (0, 0, 0)  # local, remote, inline

    def set_counts(self, local: int, remote: int, inline: int) -> None:
        if (local, remote, inline) != self._counts:
            self._counts = (local, remote, inline)
            self.update()

    def paint_art(self, painter: QPainter, rect: QRectF, t: float) -> None:
        base = QPointF(rect.left() + rect.width() * 0.5, rect.center().y() + 22)
        disks = max(2, min(5, sum(self._counts) or 3))
        colors = [tone_color(PROXY), tone_color(DNS), tone_color(DIRECT), tone_color(PROXY), tone_color(DNS)]
        for index in range(disks):
            bob = math.sin(t * TAU / 3.2 + index * 0.9) * 3.0
            center = QPointF(base.x(), base.y() - index * 15 + bob)
            color = colors[index % len(colors)]
            painter.setPen(QPen(with_alpha(color, 170), 1.3))
            painter.setBrush(with_alpha(color, 40 if isDarkTheme() else 26))
            body = QRectF(center.x() - 46, center.y() - 8, 92, 16)
            painter.drawRoundedRect(body, 46, 8)
            painter.setBrush(with_alpha(color, 70 if isDarkTheme() else 48))
            painter.drawEllipse(QPointF(center.x(), center.y() - 4), 46, 6)
        if self._counts[1] or not sum(self._counts):
            drop = (t % 2.2) / 2.2
            y = lerp(rect.top() + 4, base.y() - disks * 15 - 6, ease_in_out(min(1.0, drop / 0.8)))
            alpha = 1.0 if drop < 0.8 else max(0.0, 1.0 - (drop - 0.8) / 0.2)
            painter.setOpacity(alpha)
            draw_icon(painter, FIF.CLOUD_DOWNLOAD, QPointF(base.x() + 64, y + 8), 18, tone_color(DNS))
            painter.setOpacity(1.0)
        muted = text_muted_color()
        local, remote, inline = self._counts
        label(painter, QRectF(base.x() - 150, rect.bottom() - 18, 300, 14),
              f"локальных {local} · по URL {remote} · встроенных {inline}", muted, size=8,
              align=Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter)


class DnsArt(ArtCanvas):
    """DNS: a spinning globe answers a query; servers orbit it."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent, height=128)
        self._servers = 3

    def set_servers(self, count: int) -> None:
        if count != self._servers:
            self._servers = count
            self.update()

    def paint_art(self, painter: QPainter, rect: QRectF, t: float) -> None:
        color = tone_color(DNS)
        muted = text_muted_color()
        center = QPointF(rect.left() + rect.width() * 0.66, rect.center().y())
        radius = min(38.0, rect.height() * 0.3)
        halo = QRadialGradient(center, radius * 1.7)
        halo.setColorAt(0.0, with_alpha(color, 60))
        halo.setColorAt(1.0, with_alpha(color, 0))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(halo)
        painter.drawEllipse(center, radius * 1.7, radius * 1.7)
        painter.setBrush(with_alpha(color, 34 if isDarkTheme() else 20))
        painter.setPen(QPen(with_alpha(color, 200), 1.5))
        painter.drawEllipse(center, radius, radius)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(with_alpha(color, 110), 1.0))
        spin = t * TAU / 7.0
        for index in range(4):
            angle = spin + index * math.pi / 4
            rx = abs(math.cos(angle)) * radius
            painter.drawEllipse(center, rx, radius)
        for frac in (-0.5, 0.0, 0.5):
            y = center.y() + frac * radius
            half = math.sqrt(max(0.0, radius * radius - (frac * radius) ** 2))
            painter.drawLine(QPointF(center.x() - half, y), QPointF(center.x() + half, y))
        # Orbiting servers on a tilted ellipse.
        servers = max(1, min(8, self._servers))
        for index in range(servers):
            angle = t * TAU / 9.0 + index * TAU / servers
            point = QPointF(center.x() + math.cos(angle) * radius * 1.55, center.y() + math.sin(angle) * radius * 0.55)
            front = math.sin(angle) > 0
            glow_dot(painter, point, 2.6 if front else 1.9, color, 1.0 if front else 0.45)
        # Query → answer.
        client = QPointF(rect.left() + rect.width() * 0.2, center.y())
        node(painter, client, 15, FIF.APPLICATION, accent_color())
        cycle = (t % 3.0) / 3.0
        if cycle < 0.45:
            u = ease_in_out(cycle / 0.45)
            point = QPointF(lerp(client.x() + 16, center.x() - radius, u), center.y() - 10 * math.sin(math.pi * u))
            glow_dot(painter, point, 3.0, accent_color())
            label(painter, QRectF(point.x() - 30, point.y() - 22, 60, 12), "example.org?", muted, size=7,
                  align=Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter)
        elif cycle > 0.55:
            u = ease_in_out((cycle - 0.55) / 0.45)
            point = QPointF(lerp(center.x() - radius, client.x() + 16, u), center.y() + 10 * math.sin(math.pi * u))
            answer = tone_color(DIRECT)
            glow_dot(painter, point, 3.0, answer)
            label(painter, QRectF(point.x() - 30, point.y() + 8, 60, 12), "93.184.…", muted, size=7,
                  align=Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter)
        label(painter, QRectF(center.x() - 60, center.y() + radius + 6, 120, 14), f"серверов: {self._servers}", muted,
              size=8, align=Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)


class OutboundHubArt(ArtCanvas):
    """Outbounds: pulses leave the router hub towards every outbound."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent, height=132)
        self._visuals: list[Visual] = []

    def set_outbounds(self, visuals: list[Visual]) -> None:
        visuals = list(visuals)[:7]
        if visuals != self._visuals:
            self._visuals = visuals
            self.update()

    def paint_art(self, painter: QPainter, rect: QRectF, t: float) -> None:
        visuals = self._visuals or [Visual(FIF.SEND, DIRECT)]
        hub = QPointF(rect.left() + rect.width() * 0.3, rect.center().y())
        count = len(visuals)
        spread = min(rect.height() * 0.86, 36.0 * (count - 1))
        points = []
        for index in range(count):
            frac = 0.5 if count == 1 else index / (count - 1)
            y = rect.center().y() - spread / 2 + frac * spread
            x = rect.left() + rect.width() * 0.72 + math.sin(frac * math.pi) * 18
            points.append(QPointF(x, y))
        for index, (visual, point) in enumerate(zip(visuals, points)):
            color = tone_color(visual.tone)
            path = QPainterPath(hub)
            path.quadTo(QPointF(lerp(hub.x(), point.x(), 0.5), point.y()), point)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(with_alpha(color, 70), 1.4))
            painter.drawPath(path)
            u = (t * 0.45 + index * 0.37) % 1.0
            glow_dot(painter, path.pointAtPercent(ease_in_out(u)), 2.6, color, 1.0 - max(0.0, u - 0.85) / 0.15)
        for visual, point in zip(visuals, points):
            color = tone_color(visual.tone)
            radius = 11 if count > 3 else 14
            node(painter, point, radius, visual.icon, color, glow=0.5 if visual.tone == PROXY else 0.0)
        breathe = 0.5 + 0.5 * math.sin(t * TAU / 2.4)
        node(painter, hub, 19, FIF.SHARE, accent_color(), glow=0.3 + 0.4 * breathe)


class TunnelArt(ArtCanvas):
    """System: traffic enters the TUN tunnel; rings rush towards the viewer."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent, height=120)

    def paint_art(self, painter: QPainter, rect: QRectF, t: float) -> None:
        color = accent_color()
        center = QPointF(rect.left() + rect.width() * 0.62, rect.center().y())
        rings = 7
        painter.setBrush(Qt.BrushStyle.NoBrush)
        for index in range(rings):
            s = (t * 0.28 + index / rings) % 1.0
            scale = s * s
            w = lerp(10, rect.height() * 1.5, scale)
            h = w * 0.62
            alpha = math.sin(math.pi * s) * 170
            painter.setPen(QPen(with_alpha(color, alpha), 1.2 + 1.6 * scale))
            painter.drawRoundedRect(QRectF(center.x() - w / 2, center.y() - h / 2, w, h), h * 0.3, h * 0.3)
        muted = text_muted_color()
        for index in range(6):
            u = (t * 0.5 + index / 6) % 1.0
            start = QPointF(rect.left() + 20, center.y() + (index - 2.5) * 9)
            point = QPointF(lerp(start.x(), center.x(), ease_in_out(u)), lerp(start.y(), center.y(), u * u))
            glow_dot(painter, point, 2.4 * (1.0 - 0.6 * u), color, 1.0 - u * 0.7)
        core = QRadialGradient(center, 14)
        core.setColorAt(0.0, with_alpha(color, 220))
        core.setColorAt(1.0, with_alpha(color, 0))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(core)
        painter.drawEllipse(center, 14, 14)
        label(painter, QRectF(center.x() - 40, rect.bottom() - 16, 80, 14), "TUN", muted, size=8, bold=True,
              align=Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter)


class JsonArt(ArtCanvas):
    """JSON: braces with lines being typed and a blinking caret."""

    frame_ms = 80

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent, height=96)

    def paint_art(self, painter: QPainter, rect: QRectF, t: float) -> None:
        color = accent_color()
        muted = text_muted_color()
        center = QPointF(rect.left() + rect.width() * 0.5, rect.center().y())
        font = QFont(painter.font())
        font.setPointSizeF(42)
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(with_alpha(color, 200))
        painter.drawText(QRectF(center.x() - 110, rect.top(), 40, rect.height()), int(Qt.AlignmentFlag.AlignCenter), "{")
        painter.drawText(QRectF(center.x() + 70, rect.top(), 40, rect.height()), int(Qt.AlignmentFlag.AlignCenter), "}")
        widths = (0.9, 0.6, 0.75, 0.45)
        cycle = (t % 4.0) / 4.0
        typed = cycle * (len(widths) + 1)
        painter.setPen(Qt.PenStyle.NoPen)
        for index, width in enumerate(widths):
            progress = max(0.0, min(1.0, typed - index))
            if progress <= 0:
                continue
            y = rect.center().y() - 26 + index * 14
            indent = 10 if index in (1, 2) else 0
            painter.setBrush(with_alpha(muted if index % 2 else color, 150))
            painter.drawRoundedRect(QRectF(center.x() - 60 + indent, y, 120 * width * progress, 7), 3.5, 3.5)
            if 0 < progress < 1 or (index == len(widths) - 1 and progress >= 1):
                if int(t * 2.5) % 2 == 0:
                    painter.setBrush(with_alpha(color, 230))
                    painter.drawRect(QRectF(center.x() - 58 + indent + 120 * width * progress, y - 2, 2, 11))


class PulseDot(QWidget):
    """Small breathing dot, e.g. «есть несохранённые изменения»."""

    def __init__(self, parent: QWidget | None = None, size: int = 10):
        super().__init__(parent)
        self.setFixedSize(size + 8, size + 8)
        self._radius = size / 2
        self._clock = QElapsedTimer()
        self._clock.start()
        self._frames = FrameGate(self)
        self._frames.frame.connect(self.update)
        self.setVisible(False)

    def set_active(self, active: bool) -> None:
        self.setVisible(active)
        self._frames.set_interval(50 if active else None)

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        center = QRectF(self.rect()).center()
        color = tone_color("special")
        phase = 0.5 + 0.5 * math.sin(self._clock.elapsed() / 1000.0 * TAU / 1.6) if self._frames.motion_allowed() else 0.6
        glow_dot(painter, center, self._radius * (0.75 + 0.15 * phase), color, 0.55 + 0.45 * phase)
        painter.end()
