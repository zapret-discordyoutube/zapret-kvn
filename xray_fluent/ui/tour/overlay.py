"""Оверлей обучающей экскурсии: затемнение, подсветка элемента и карточка.

Обычный дочерний виджет главного окна, лежит поверх страниц ниже заголовка —
кнопки «свернуть/закрыть» остаются доступны. Стили страниц он не трогает:
затемнение рисуется самим оверлеем, поэтому Mica под страницами не ломается.

Положение подсветки не запоминается, а вычисляется заново на каждом кадре
таймера: так она сама следует за прокруткой, изменением размера окна и
страницами, которые достраиваются после показа.

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
    QRect,
    QRectF,
    QSize,
    Qt,
    QTimer,
    pyqtSignal,
)
from PyQt6.QtGui import QColor, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import (
    QApplication,
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
#: Когда всё стоит на месте, цель перепроверяется реже — этого хватает, чтобы
#: заметить прокрутку или достроившуюся страницу.
SETTLED_MS = 120
MOTION_TAU_MS = 90.0
FADE_MS = 200.0

CARD_WIDTH = 440
HERO_CARD_WIDTH = 560
CARD_MARGIN = 16
CARD_GAP = 18
CARD_RADIUS = 10
HOLE_PADDING = 6
HOLE_RADIUS = 8
DIM_ALPHA = 130
HERO_DIM_ALPHA = 165


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


class _TourCard(QWidget):
    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self._progress = 0.0

        self.icon_label = QLabel(self)
        self.icon_label.setFixedSize(48, 48)
        self.icon_label.setScaledContents(True)
        self.title_label = SubtitleLabel(self)
        self.title_label.setWordWrap(True)
        self.body_label = BodyLabel(self)
        self.body_label.setWordWrap(True)
        self.body_label.setTextFormat(Qt.TextFormat.PlainText)
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
        layout.setSpacing(10)
        layout.addWidget(self.icon_label)
        layout.addWidget(self.title_label)
        layout.addWidget(self.body_label)
        layout.addSpacing(6)
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
        if self.icon_label.isVisibleTo(self):
            self.icon_label.setPixmap(icon.pixmap(96, 96))
        self._progress = (index + 1) / total
        self.update()

    def height_for(self, width: int) -> int:
        self.layout().activate()
        return self.layout().totalHeightForWidth(width)

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
        self._hole: QRectF | None = None
        self._card_rect: QRectF | None = None
        self._dim = 0.0
        self._opacity = 0.0
        self._resolve_failed = False
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
        self._timer.stop()
        self._scroll_timer.stop()
        window = self.parentWidget()
        if window is not None:
            window.removeEventFilter(self)
        self.finished.emit(reason)
        dispose_later(self)

    def _enter(self, index: int) -> None:
        self._index = index
        self._resolve_failed = False
        step = self._steps[index]
        self.step_opening.emit(step)
        self.card.set_step(step, index, len(self._steps))
        self.raise_()
        self._scroll_to_target()
        self._scroll_timer.start()
        self.setFocus()
        self._timer.start(FRAME_MS)
        self._tick()

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

    # ── Кадр ───────────────────────────────────────────────────

    def _sync_geometry(self) -> None:
        window = self.parentWidget()
        title_bar = getattr(window, "titleBar", None)
        top = title_bar.height() if title_bar is not None and title_bar.isVisible() else 0
        geometry = QRect(0, top, window.width(), max(0, window.height() - top))
        if geometry != self.geometry():
            self.setGeometry(geometry)

    def _tick(self) -> None:
        if self._done:
            return
        window = self.parentWidget()
        if not window.isVisible():
            self.finish("hidden")
            return
        if window.isMinimized():
            return
        self._sync_geometry()

        elapsed = max(1, self._clock.restart()) if self._clock.isValid() else FRAME_MS
        snap = reduced_motion()
        k = 1.0 if snap else 1.0 - math.exp(-min(elapsed, 100) / MOTION_TAU_MS)

        hole = self._target_rect()
        step = self._steps[self._index]
        width = min(HERO_CARD_WIDTH if step.hero else CARD_WIDTH, max(200, self.width() - 2 * CARD_MARGIN))
        size = QSize(width, self.card.height_for(width))
        bounds = self.rect().adjusted(CARD_MARGIN, CARD_MARGIN, -CARD_MARGIN, -CARD_MARGIN)
        card_target = QRectF(place_card(bounds, hole, size))

        previous = (
            None if self._hole is None else QRectF(self._hole),
            None if self._card_rect is None else QRectF(self._card_rect),
            self._dim,
            self._opacity,
        )

        if hole is None:
            self._hole = None
        elif self._hole is None:
            # Подсветка «съезжается» к элементу, а не возникает на месте.
            grow = 0 if snap else 40
            self._hole = _lerp_rect(QRectF(hole).adjusted(-grow, -grow, grow, grow), QRectF(hole), k)
        else:
            self._hole = _lerp_rect(self._hole, QRectF(hole), k)

        if self._card_rect is None:
            self._card_rect = card_target
        else:
            self._card_rect = _lerp_rect(self._card_rect, card_target, k)

        dim_target = float(DIM_ALPHA if hole is not None else HERO_DIM_ALPHA)
        self._dim = dim_target if abs(dim_target - self._dim) < 1.0 else self._dim + (dim_target - self._dim) * k
        self._opacity = 1.0 if snap else min(1.0, self._opacity + elapsed / FADE_MS)

        card_geometry = self._card_rect.toRect()
        if card_geometry != self.card.geometry():
            self.card.setGeometry(card_geometry)

        state = (self._hole, self._card_rect, self._dim, self._opacity)
        if state != previous:
            self.update()
        settled = (
            self._card_rect == card_target
            and (self._hole is None or self._hole == QRectF(hole))
            and self._dim == dim_target
            and self._opacity >= 1.0
        )
        interval = SETTLED_MS if settled else FRAME_MS
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
        opacity = self._opacity

        shade = QPainterPath()
        shade.addRect(QRectF(self.rect()))
        hole_path: QPainterPath | None = None
        if self._hole is not None:
            hole_path = QPainterPath()
            hole_path.addRoundedRect(self._hole, HOLE_RADIUS, HOLE_RADIUS)
            shade = shade.subtracted(hole_path)
        painter.fillPath(shade, QColor(0, 0, 0, int(self._dim * opacity)))

        if self._card_rect is not None:
            for spread, alpha in ((12, 10), (8, 16), (4, 22), (2, 28)):
                shadow = QPainterPath()
                shadow.addRoundedRect(
                    self._card_rect.adjusted(-spread, -spread + 2, spread, spread + 2),
                    CARD_RADIUS + spread,
                    CARD_RADIUS + spread,
                )
                painter.fillPath(shadow, QColor(0, 0, 0, int(alpha * opacity)))

        if hole_path is not None:
            painter.setBrush(Qt.BrushStyle.NoBrush)
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
