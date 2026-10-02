"""Оверлей обучающей экскурсии: затемнение, подсветка элемента и карточка.

Обычный дочерний виджет главного окна, лежит поверх страниц ниже заголовка —
кнопки «свернуть/закрыть» остаются доступны. Стили страниц он не трогает:
затемнение рисуется самим оверлеем, поэтому Mica под страницами не ломается.

Положение подсветки не запоминается, а вычисляется заново на каждом кадре
таймера: так она сама следует за прокруткой, изменением размера окна и
страницами, которые достраиваются после показа.

Про плавность. Оверлей полупрозрачный, поэтому любая его перерисовка заново
рисует и страницу под ним. Отсюда три правила:

* перерисовывается только то, что изменилось, — старое и новое место
  подсветки и карточки, а не всё окно;
* карточка едет, но не растягивается: размер под текст шага ставится сразу,
  иначе текст на каждом кадре переносился бы по строкам заново;
* в покое таймер только сверяет цель и ничего не рисует.

Оверлей — потомок окна и не хранит на него сильных ссылок (см. ``motion.py``):
окно берётся через ``parentWidget()``, а страницу шага открывает само окно по
сигналу ``step_opening``.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Sequence

from PyQt6 import sip
from PyQt6.QtCore import (
    QElapsedTimer,
    QEvent,
    QPointF,
    QRect,
    QRectF,
    QSize,
    Qt,
    QTimer,
    pyqtSignal,
)
from PyQt6.QtGui import QColor, QPainter, QPainterPath, QPen, QRegion
from PyQt6.QtWidgets import (
    QApplication,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    PrimaryPushButton,
    PushButton,
    SubtitleLabel,
    TransparentPushButton,
)

from ..motion import reduced_motion
from ..qt_lifecycle import dispose_later
from ..theme import accent_color, surface_color, text_color
from .steps import TourStep

_log = logging.getLogger(__name__)

FRAME_MS = 16
PULSE_FRAME_MS = 33
#: Когда всё стоит на месте, цель перепроверяется реже — этого хватает, чтобы
#: заметить прокрутку или достроившуюся страницу.
SETTLED_MS = 120
MOTION_TAU_MS = 90.0
FADE_IN_MS = 200.0
FADE_OUT_MS = 150.0
CONTENT_FADE_MS = 220.0
PULSE_PERIOD_MS = 1500.0
#: Кольцо расходится от подсветки несколько раз после смены шага и замирает:
#: внимание привлечено, дальше окно под оверлеем не перерисовывается.
PULSE_CYCLES = 2
PREWARM_DELAY_MS = 350

CARD_WIDTH = 440
HERO_CARD_WIDTH = 560
CARD_MARGIN = 16
CARD_GAP = 18
CARD_RADIUS = 10
CARD_SHADOW = 14
CARD_ENTER_OFFSET = 24
HOLE_PADDING = 6
HOLE_RADIUS = 8
HOLE_ENTER_GROW = 60
RING_REACH = 22
DIM_ALPHA = 140


def place_card(bounds: QRect, hole: QRect | None, size: QSize) -> QRect:
    """Где поставить карточку: рядом с подсвеченным элементом, не закрывая его.

    Пробует справа, снизу, сверху и слева. Если элемент слишком велик и рядом
    места нет — выбирает положение, где карточка закрывает его меньше всего.
    """
    width = min(size.width(), bounds.width())
    height = min(size.height(), bounds.height())
    if hole is None:
        return QRect(
            bounds.x() + (bounds.width() - width) // 2,
            bounds.y() + (bounds.height() - height) // 2,
            width,
            height,
        )

    def clamped(x: int, y: int) -> QRect:
        x = max(bounds.left(), min(x, bounds.right() + 1 - width))
        y = max(bounds.top(), min(y, bounds.bottom() + 1 - height))
        return QRect(x, y, width, height)

    candidates = (
        QRect(hole.right() + 1 + CARD_GAP, hole.top(), width, height),
        QRect(hole.left(), hole.bottom() + 1 + CARD_GAP, width, height),
        QRect(hole.left(), hole.top() - CARD_GAP - height, width, height),
        QRect(hole.left() - CARD_GAP - width, hole.top(), width, height),
    )
    for index, rect in enumerate(candidates):
        fitted = clamped(rect.x(), rect.y())
        # Сдвиг вдоль элемента допустим, поперёк — нет: иначе карточка на него наедет.
        along_ok = fitted.x() == rect.x() if index in (0, 3) else fitted.y() == rect.y()
        if along_ok and not fitted.intersects(hole):
            return fitted

    best: QRect | None = None
    best_overlap = -1
    for rect in candidates:
        fitted = clamped(rect.x(), rect.y())
        overlap = fitted.intersected(hole)
        area = overlap.width() * overlap.height()
        if best is None or area < best_overlap:
            best, best_overlap = fitted, area
    return best


def _lerp_rect(current: QRectF, target: QRectF, k: float) -> QRectF:
    if k >= 1.0:
        return QRectF(target)
    result = QRectF(
        current.x() + (target.x() - current.x()) * k,
        current.y() + (target.y() - current.y()) * k,
        current.width() + (target.width() - current.width()) * k,
        current.height() + (target.height() - current.height()) * k,
    )
    close = max(
        abs(result.x() - target.x()),
        abs(result.y() - target.y()),
        abs(result.width() - target.width()),
        abs(result.height() - target.height()),
    )
    return QRectF(target) if close < 0.5 else result


def _lerp_point(current: QPointF, target: QPointF, k: float) -> QPointF:
    if k >= 1.0:
        return QPointF(target)
    result = current + (target - current) * k
    delta = result - target
    return QPointF(target) if max(abs(delta.x()), abs(delta.y())) < 0.5 else result


def _ring_region(hole: QRectF) -> QRegion:
    """Полоса вокруг подсветки, где рисуются рамка и расходящееся кольцо."""
    outer = hole.adjusted(-RING_REACH, -RING_REACH, RING_REACH, RING_REACH).toAlignedRect()
    inner = hole.adjusted(HOLE_RADIUS, HOLE_RADIUS, -HOLE_RADIUS, -HOLE_RADIUS).toAlignedRect()
    region = QRegion(outer)
    return region.subtracted(QRegion(inner)) if inner.isValid() else region


class _TourCard(QWidget):
    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self._progress = 0.0
        self._progress_target = 0.0

        # Заголовок и текст проявляются при смене шага; кнопки остаются на месте.
        self.content = QWidget(self)
        self.content_effect = QGraphicsOpacityEffect(self.content)
        self.content.setGraphicsEffect(self.content_effect)
        # Эффект включается только на время проявления: на Windows его кэш
        # после переезда карточки иногда рисует текст со сдвигом.
        self.content_effect.setEnabled(False)

        self.icon_label = QLabel(self.content)
        self.icon_label.setFixedSize(48, 48)
        self.icon_label.setScaledContents(True)
        self.title_label = SubtitleLabel(self.content)
        self.title_label.setWordWrap(True)
        self.body_label = BodyLabel(self.content)
        self.body_label.setWordWrap(True)
        self.body_label.setTextFormat(Qt.TextFormat.PlainText)
        content_layout = QVBoxLayout(self.content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(10)
        content_layout.addWidget(self.icon_label)
        content_layout.addWidget(self.title_label)
        content_layout.addWidget(self.body_label)

        self.counter_label = CaptionLabel(self)
        self.skip_btn = TransparentPushButton("Пропустить", self)
        self.back_btn = PushButton("Назад", self)
        self.next_btn = PrimaryPushButton("Далее", self)
        self.next_btn.setMinimumWidth(104)
        # Фокус остаётся у оверлея: стрелки и Enter листают шаги, а не
        # перескакивают между кнопками.
        for button in (self.skip_btn, self.back_btn, self.next_btn):
            button.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        buttons.addWidget(self.counter_label)
        buttons.addStretch(1)
        buttons.addWidget(self.skip_btn)
        buttons.addWidget(self.back_btn)
        buttons.addWidget(self.next_btn)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 18)
        layout.setSpacing(16)
        layout.addWidget(self.content)
        layout.addLayout(buttons)

    def set_step(self, step: TourStep, index: int, total: int) -> None:
        self.title_label.setText(step.title)
        self.body_label.setText(step.body)
        self.counter_label.setText(f"Шаг {index + 1} из {total}")
        self.back_btn.setVisible(index > 0)
        last = index == total - 1
        self.skip_btn.setVisible(not last)
        self.next_btn.setText("Готово" if last else "Начнём" if index == 0 else "Далее")
        icon = self.window().windowIcon() if step.hero else None
        self.icon_label.setVisible(icon is not None and not icon.isNull())
        if self.icon_label.isVisibleTo(self.content):
            self.icon_label.setPixmap(icon.pixmap(96, 96))
        self._progress_target = (index + 1) / total

    def height_for(self, width: int) -> int:
        self.content.layout().activate()
        self.layout().activate()
        return self.layout().totalHeightForWidth(width)

    def set_content_opacity(self, value: float) -> None:
        fading = value < 0.999
        if self.content_effect.isEnabled() != fading:
            self.content_effect.setEnabled(fading)
        if fading and abs(self.content_effect.opacity() - value) > 0.001:
            self.content_effect.setOpacity(value)

    def advance(self, k: float) -> bool:
        """Сдвинуть полоску прогресса к цели; ``True`` — ещё движется."""
        if self._progress == self._progress_target:
            return False
        gap = self._progress_target - self._progress
        self._progress = self._progress_target if abs(gap) < 0.002 or k >= 1.0 else self._progress + gap * k
        self.update(0, 0, self.width(), 4)
        return self._progress != self._progress_target

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        shape = QPainterPath()
        shape.addRoundedRect(rect, CARD_RADIUS, CARD_RADIUS)
        painter.fillPath(shape, surface_color())
        # Полоска прогресса по верхнему краю.
        painter.save()
        painter.setClipPath(shape)
        painter.fillRect(QRectF(0, 0, self.width() * self._progress, 3), accent_color())
        painter.restore()
        border = text_color()
        border.setAlpha(34)
        painter.setPen(QPen(border, 1))
        painter.drawPath(shape)


class TourOverlay(QWidget):
    #: Перед показом шага: окно открывает его страницу (соединение прямое,
    #: к возврату из ``emit`` страница уже на экране).
    step_opening = pyqtSignal(object)
    #: Пока пользователь читает шаг: окно заранее строит страницу следующего,
    #: чтобы «Далее» не подвисало на создании страницы.
    step_upcoming = pyqtSignal(object)
    #: ``done`` — пройдена до конца, ``skipped`` — закрыта пользователем,
    #: ``hidden`` — окно спрятали, ``interrupted`` — прервана приложением.
    finished = pyqtSignal(str)

    def __init__(self, window: QWidget, steps: Sequence[TourStep]):
        super().__init__(window)
        self.setObjectName("tourOverlay")
        self.setAccessibleName("Обучающая экскурсия по приложению")
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

        self._steps = tuple(steps)
        self._index = -1
        self._done = False
        self._closing = False
        self._hole: QRectF | None = None
        self._card_pos: QPointF | None = None
        self._opacity = 0.0
        self._content_opacity = 1.0
        self._pulse = 0.0
        self._pulses_left = 0
        self._resolve_failed = False
        self._card_heights: dict[tuple[int, int], int] = {}
        self._clock = QElapsedTimer()

        self.card = _TourCard(self)
        self.card.skip_btn.clicked.connect(self.skip)
        self.card.back_btn.clicked.connect(self.go_back)
        self.card.next_btn.clicked.connect(self.go_next)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        # Страница после показа ещё раскладывается — докручиваем к цели повторно.
        self._scroll_timer = QTimer(self)
        self._scroll_timer.setSingleShot(True)
        self._scroll_timer.setInterval(220)
        self._scroll_timer.timeout.connect(self._scroll_to_target)
        self._prewarm_timer = QTimer(self)
        self._prewarm_timer.setSingleShot(True)
        self._prewarm_timer.setInterval(PREWARM_DELAY_MS)
        self._prewarm_timer.timeout.connect(self._prewarm_next)

    # ── Управление ─────────────────────────────────────────────

    @property
    def index(self) -> int:
        return self._index

    @property
    def step(self) -> TourStep:
        return self._steps[self._index]

    def start(self) -> None:
        self.parentWidget().installEventFilter(self)
        self._sync_geometry()
        self.show()
        self._clock.start()
        self._enter(0)

    def go_next(self) -> None:
        if self._done:
            return
        if self._index >= len(self._steps) - 1:
            self.finish("done")
        else:
            self._enter(self._index + 1)

    def go_back(self) -> None:
        if not self._done and self._index > 0:
            self._enter(self._index - 1)

    def skip(self) -> None:
        self.finish("skipped")

    def finish(self, reason: str) -> None:
        if self._done:
            return
        self._done = True
        self._scroll_timer.stop()
        self._prewarm_timer.stop()
        self.finished.emit(reason)
        if reason in ("done", "skipped") and not reduced_motion() and self.parentWidget().isVisible():
            # Экскурсия уже закончена — затемнение просто гаснет.
            self._closing = True
            self.card.hide()
            self._timer.start(FRAME_MS)
        else:
            self._dispose()

    def _dispose(self) -> None:
        self._closing = False
        self._timer.stop()
        window = self.parentWidget()
        if window is not None:
            window.removeEventFilter(self)
        dispose_later(self)

    def _enter(self, index: int) -> None:
        self._index = index
        self._resolve_failed = False
        step = self._steps[index]
        self.step_opening.emit(step)
        self.card.set_step(step, index, len(self._steps))
        self._content_opacity = 0.0
        self._pulse = 0.0
        self._pulses_left = PULSE_CYCLES
        self.raise_()
        self._scroll_to_target()
        self._scroll_timer.start()
        self._prewarm_timer.start()
        self.setFocus()
        self._timer.start(FRAME_MS)
        self._tick()

    def _prewarm_next(self) -> None:
        if not self._done and self._index + 1 < len(self._steps):
            self.step_upcoming.emit(self._steps[self._index + 1])

    # ── Цель шага ──────────────────────────────────────────────

    def _targets(self) -> list[QWidget]:
        step = self._steps[self._index]
        if step.hero or step.target is None:
            return []
        try:
            widgets = step.target(self.parentWidget())
        except Exception:  # noqa: BLE001 - страница могла измениться; шаг покажется без подсветки
            # Вызывается каждый кадр — пишем в лог один раз на шаг.
            if not self._resolve_failed:
                self._resolve_failed = True
                _log.exception("tour step %s: target lookup failed", step.key)
            return []
        return [w for w in widgets if not sip.isdeleted(w)]

    def _target_rect(self) -> QRect | None:
        united = QRect()
        for widget in self._targets():
            if not widget.isVisible():
                continue
            # Только видимая часть: элемент может быть частично прокручен.
            visible = widget.visibleRegion().boundingRect()
            if visible.isEmpty():
                continue
            top_left = self.mapFromGlobal(widget.mapToGlobal(visible.topLeft()))
            united = united.united(QRect(top_left, visible.size()))
        if united.isEmpty():
            return None
        padded = united.adjusted(-HOLE_PADDING, -HOLE_PADDING, HOLE_PADDING, HOLE_PADDING)
        clipped = padded.intersected(self.rect().adjusted(2, 2, -2, -2))
        return None if clipped.isEmpty() else clipped

    def _scroll_to_target(self) -> None:
        if self._done:
            return
        for widget in self._targets():
            parent = widget.parentWidget()
            while parent is not None and not isinstance(parent, QScrollArea):
                parent = parent.parentWidget()
            if parent is not None:
                parent.ensureWidgetVisible(widget, 24, 72)

    def _card_size(self) -> QSize:
        step = self._steps[self._index]
        width = min(HERO_CARD_WIDTH if step.hero else CARD_WIDTH, max(200, self.width() - 2 * CARD_MARGIN))
        key = (self._index, width)
        height = self._card_heights.get(key)
        if height is None:
            height = self._card_heights[key] = self.card.height_for(width)
        return QSize(width, height)

    # ── Кадр ───────────────────────────────────────────────────

    def _sync_geometry(self) -> None:
        window = self.parentWidget()
        title_bar = getattr(window, "titleBar", None)
        top = title_bar.height() if title_bar is not None and title_bar.isVisible() else 0
        geometry = QRect(0, top, window.width(), max(0, window.height() - top))
        if geometry != self.geometry():
            self.setGeometry(geometry)

    def _tick(self) -> None:
        window = self.parentWidget()
        if self._closing:
            elapsed = max(1, self._clock.restart())
            self._opacity -= elapsed / FADE_OUT_MS
            if self._opacity <= 0.0 or not window.isVisible():
                self._dispose()
            else:
                self.update()
            return
        if self._done:
            return
        if not window.isVisible():
            self.finish("hidden")
            return
        if window.isMinimized():
            return
        self._sync_geometry()

        elapsed = max(1, min(self._clock.restart(), 100)) if self._clock.isValid() else FRAME_MS
        animated = not reduced_motion()
        k = 1.0 - math.exp(-elapsed / MOTION_TAU_MS) if animated else 1.0
        dirty = QRegion()
        repaint_all = False
        moving = False

        if self._opacity < 1.0:
            self._opacity = min(1.0, self._opacity + elapsed / FADE_IN_MS) if animated else 1.0
            repaint_all = True
            moving = self._opacity < 1.0

        # Подсветка.
        hole = self._target_rect()
        previous_hole = None if self._hole is None else QRectF(self._hole)
        if hole is None:
            self._hole = None
        elif self._hole is None:
            # Подсветка «съезжается» к элементу, а не возникает на месте.
            grow = HOLE_ENTER_GROW if animated else 0
            self._hole = QRectF(hole).adjusted(-grow, -grow, grow, grow)
        else:
            self._hole = _lerp_rect(self._hole, QRectF(hole), k)
        if self._hole != previous_hole:
            for rect in (previous_hole, self._hole):
                if rect is not None:
                    dirty += rect.adjusted(-RING_REACH, -RING_REACH, RING_REACH, RING_REACH).toAlignedRect()
        if self._hole is not None and self._hole != QRectF(hole):
            moving = True

        # Карточка: размер сразу под текст шага, плавно меняется только место.
        size = self._card_size()
        bounds = self.rect().adjusted(CARD_MARGIN, CARD_MARGIN, -CARD_MARGIN, -CARD_MARGIN)
        target = place_card(bounds, hole, size)
        target_pos = QPointF(target.topLeft())
        if self._card_pos is None:
            self._card_pos = target_pos + QPointF(0, CARD_ENTER_OFFSET if animated else 0)
        self._card_pos = _lerp_point(self._card_pos, target_pos, k)
        if self._card_pos != target_pos:
            moving = True
        geometry = QRect(self._card_pos.toPoint(), target.size())
        if geometry != self.card.geometry():
            margin = CARD_SHADOW + 2
            for rect in (self.card.geometry(), geometry):
                dirty += rect.adjusted(-margin, -margin, margin, margin)
            self.card.setGeometry(geometry)
            if self.card.content_effect.isEnabled():
                self.card.content_effect.update()

        if self._content_opacity < 1.0:
            self._content_opacity = min(1.0, self._content_opacity + elapsed / CONTENT_FADE_MS) if animated else 1.0
            moving = moving or self._content_opacity < 1.0
        self.card.set_content_opacity(self._content_opacity)
        if self.card.advance(k):
            moving = True

        pulsing = animated and self._hole is not None and self._pulses_left > 0 and not moving
        if pulsing:
            self._pulse += elapsed / PULSE_PERIOD_MS
            if self._pulse >= 1.0:
                self._pulse = 0.0
                self._pulses_left -= 1
            dirty += _ring_region(self._hole)

        if repaint_all:
            self.update()
        elif not dirty.isEmpty():
            self.update(dirty)
        interval = FRAME_MS if moving else PULSE_FRAME_MS if pulsing and self._pulses_left > 0 else SETTLED_MS
        if self._timer.interval() != interval:
            self._timer.start(interval)
        self._keep_focus()

    def _keep_focus(self) -> None:
        # Страницы при показе забирают фокус себе; без возврата клавиши
        # уходили бы в элементы под затемнением.
        app = QApplication.instance()
        if app.activeModalWidget() is not None or app.activePopupWidget() is not None:
            return
        if self.parentWidget().isActiveWindow() and not self.hasFocus():
            self.setFocus()

    # ── События ────────────────────────────────────────────────

    def eventFilter(self, obj, event) -> bool:
        if obj is self.parentWidget() and event.type() == QEvent.Type.Resize and not self._done:
            self._sync_geometry()
            self._timer.start(FRAME_MS)
        return False

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        opacity = max(0.0, min(1.0, self._opacity))

        shade = QPainterPath()
        shade.addRect(QRectF(self.rect()))
        hole_path: QPainterPath | None = None
        if self._hole is not None:
            hole_path = QPainterPath()
            hole_path.addRoundedRect(self._hole, HOLE_RADIUS, HOLE_RADIUS)
            shade = shade.subtracted(hole_path)
        painter.fillPath(shade, QColor(0, 0, 0, int(DIM_ALPHA * opacity)))

        if self.card.isVisible():
            card = QRectF(self.card.geometry())
            for spread, alpha in ((CARD_SHADOW, 8), (9, 14), (5, 20), (2, 26)):
                shadow = QPainterPath()
                shadow.addRoundedRect(
                    card.adjusted(-spread, -spread + 2, spread, spread + 2),
                    CARD_RADIUS + spread,
                    CARD_RADIUS + spread,
                )
                painter.fillPath(shadow, QColor(0, 0, 0, int(alpha * opacity)))

        if hole_path is None:
            return
        painter.setBrush(Qt.BrushStyle.NoBrush)
        if self._pulses_left > 0 and self._pulse > 0.0:
            # Кольцо расходится от подсветки и гаснет.
            grow = 3 + self._pulse * (RING_REACH - 6)
            ring = accent_color()
            ring.setAlpha(int(160 * (1.0 - self._pulse) ** 2 * opacity))
            painter.setPen(QPen(ring, 2))
            painter.drawRoundedRect(
                self._hole.adjusted(-grow, -grow, grow, grow), HOLE_RADIUS + grow, HOLE_RADIUS + grow
            )
        glow = accent_color()
        glow.setAlpha(int(70 * opacity))
        painter.setPen(QPen(glow, 6))
        painter.drawPath(hole_path)
        border = accent_color()
        border.setAlpha(int(255 * opacity))
        painter.setPen(QPen(border, 2))
        painter.drawPath(hole_path)

    def keyPressEvent(self, event) -> None:
        key = event.key()
        if key in (Qt.Key.Key_Right, Qt.Key.Key_PageDown, Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Space):
            self.go_next()
        elif key in (Qt.Key.Key_Left, Qt.Key.Key_PageUp, Qt.Key.Key_Backspace):
            self.go_back()
        elif key == Qt.Key.Key_Escape:
            self.skip()
        event.accept()

    def focusNextPrevChild(self, _next: bool) -> bool:
        return True

    # Элементы под затемнением недоступны: экскурсия только показывает.
    def mousePressEvent(self, event) -> None:
        event.accept()

    def mouseReleaseEvent(self, event) -> None:
        event.accept()

    def mouseDoubleClickEvent(self, event) -> None:
        event.accept()

    def wheelEvent(self, event) -> None:
        event.accept()
