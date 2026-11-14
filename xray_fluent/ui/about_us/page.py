from __future__ import annotations

import webbrowser

from PyQt6.QtCore import QRect, QSize, Qt
from PyQt6.QtGui import QIcon, QIconEngine, QImage, QPainter, QPixmap
from PyQt6.QtWidgets import QHBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    PrimaryPushButton,
    PushButton,
    SubtitleLabel,
    TitleLabel,
    isDarkTheme,
    setCustomStyleSheet,
)
from qfluentwidgets.common.icon import drawSvgIcon

from ..base_page import ScrollablePage
from ..theme import token_pair
from . import links
from .icons import ALL as ICONS, BrandIcon
from .links import AboutUsLink

_BUTTON_WIDTH = 290
_ON_ACCENT = "#ffffff"


def _muted_caption_qss() -> tuple[str, str]:
    light, dark = token_pair("text_muted")
    return f"CaptionLabel {{ color: {light}; }}", f"CaptionLabel {{ color: {dark}; }}"


class BrandIconEngine(QIconEngine):
    """Рисует SVG-логотип сервиса в момент отрисовки.

    Фирменные значки идут своим цветом. Остальные (GitHub, книга) берут цвет текста
    темы при каждой перерисовке, поэтому смена светлой и тёмной темы их не теряет.
    ``on_accent`` красит всё белым: на цветной кнопке акцента фирменный синий пропал бы.
    """

    def __init__(self, icon: BrandIcon, on_accent: bool = False):
        super().__init__()
        self._icon = icon
        self._on_accent = on_accent

    def _fill(self) -> str:
        if self._on_accent:
            return _ON_ACCENT
        return "#ffffff" if isDarkTheme() else "#000000"

    def paint(self, painter: QPainter, rect: QRect, mode, state) -> None:
        svg = self._icon.svg(self._fill(), mono=self._on_accent)
        drawSvgIcon(svg.encode(), painter, rect)

    def clone(self) -> "BrandIconEngine":
        return BrandIconEngine(self._icon, self._on_accent)

    def pixmap(self, size: QSize, mode, state) -> QPixmap:
        image = QImage(size, QImage.Format.Format_ARGB32)
        image.fill(Qt.GlobalColor.transparent)
        pixmap = QPixmap.fromImage(image, Qt.ImageConversionFlag.NoFormatConversion)
        painter = QPainter(pixmap)
        self.paint(painter, QRect(0, 0, size.width(), size.height()), mode, state)
        painter.end()
        return pixmap


def brand_qicon(key: str, on_accent: bool = False) -> QIcon:
    return QIcon(BrandIconEngine(ICONS[key], on_accent))


class AboutUsPage(ScrollablePage):
    """Бот с покупкой подписки сверху, под ним каналы и главные ресурсы."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("about_us")

        body = self.body
        root = self.body_layout
        root.addWidget(TitleLabel("О нас", body))

        intro = BodyLabel(
            "Независимый клиент работает с любыми совместимыми профилями. "
            "Эти ссылки относятся только к проекту Zapret KVN.",
            body,
        )
        intro.setWordWrap(True)
        root.addWidget(intro)

        self._add_section("Подписка", (links.BOT,), primary=True)
        self._add_section("Каналы", links.CHANNELS)
        self._add_section("Ресурсы", links.RESOURCES)
        root.addStretch()

    def _add_section(
        self,
        title: str,
        items: tuple[AboutUsLink, ...],
        primary: bool = False,
    ) -> None:
        root = self.body_layout
        root.addSpacing(8)
        root.addWidget(SubtitleLabel(title, self.body))
        for item in items:
            row = QHBoxLayout()
            row.setSpacing(12)
            button_type = PrimaryPushButton if primary else PushButton
            button = button_type(brand_qicon(item.icon, on_accent=primary), item.title, self.body)
            button.setFixedWidth(_BUTTON_WIDTH)
            button.clicked.connect(lambda _checked=False, url=item.url: webbrowser.open(url))
            row.addWidget(button)
            caption = CaptionLabel(item.subtitle, self.body)
            setCustomStyleSheet(caption, *_muted_caption_qss())
            row.addWidget(caption)
            row.addStretch()
            root.addLayout(row)
