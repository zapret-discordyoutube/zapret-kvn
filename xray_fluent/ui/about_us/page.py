from __future__ import annotations

import webbrowser

from PyQt6.QtWidgets import QHBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    FluentIcon as FIF,
    PrimaryPushButton,
    PushButton,
    SubtitleLabel,
    TitleLabel,
    setCustomStyleSheet,
)

from ..base_page import ScrollablePage
from ..theme import token_pair
from . import links
from .links import AboutUsLink

_BUTTON_WIDTH = 290


def _muted_caption_qss() -> tuple[str, str]:
    light, dark = token_pair("text_muted")
    return f"CaptionLabel {{ color: {light}; }}", f"CaptionLabel {{ color: {dark}; }}"


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

        self._add_section("Подписка", (links.BOT,), FIF.SHOPPING_CART, primary=True)
        self._add_section("Каналы", links.CHANNELS, FIF.SEND)
        self._add_section("Ресурсы", links.RESOURCES, FIF.LINK)
        root.addStretch()

    def _add_section(
        self,
        title: str,
        items: tuple[AboutUsLink, ...],
        icon: FIF,
        primary: bool = False,
    ) -> None:
        root = self.body_layout
        root.addSpacing(8)
        root.addWidget(SubtitleLabel(title, self.body))
        for item in items:
            row = QHBoxLayout()
            row.setSpacing(12)
            button_type = PrimaryPushButton if primary else PushButton
            button = button_type(icon, item.title, self.body)
            button.setFixedWidth(_BUTTON_WIDTH)
            button.clicked.connect(lambda _checked=False, url=item.url: webbrowser.open(url))
            row.addWidget(button)
            caption = CaptionLabel(item.subtitle, self.body)
            setCustomStyleSheet(caption, *_muted_caption_qss())
            row.addWidget(caption)
            row.addStretch()
            root.addLayout(row)
