from __future__ import annotations

import webbrowser

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget
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

from ..constants import APP_VERSION
from .theme import token_pair


def _muted_caption_qss(extra: str = "") -> tuple[str, str]:
    light, dark = token_pair("text_muted")
    return (
        f"CaptionLabel {{ color: {light};{extra} }}",
        f"CaptionLabel {{ color: {dark};{extra} }}",
    )


class AboutPage(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("about")

        root = QVBoxLayout(self)
        root.setContentsMargins(36, 28, 36, 28)
        root.setSpacing(16)

        # ── Title ──
        title = TitleLabel("Zapret KVN", self)
        root.addWidget(title)

        version = CaptionLabel(f"v{APP_VERSION}", self)
        setCustomStyleSheet(version, *_muted_caption_qss(" font-size: 13px;"))
        root.addWidget(version)

        # ── Separator ──
        sep = QWidget(self)
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: rgba(128,128,128,0.3);")
        root.addWidget(sep)

        # ── Description ──
        desc1 = BodyLabel(
            "Zapret KVN — уникальный туннель до любой страны мира, "
            "созданный передовыми мировыми инженерами "
            "(не является тем чем вы думаете).",
            self,
        )
        desc1.setWordWrap(True)
        desc1_qss = "BodyLabel { font-size: 15px; }"
        setCustomStyleSheet(desc1, desc1_qss, desc1_qss)
        root.addWidget(desc1)

        desc2 = BodyLabel(
            "Позволяет ускорить замедленные сервера Ютуба и Дискорда "
            "в случае если те перестали работать и начали деградировать.",
            self,
        )
        desc2.setWordWrap(True)
        root.addWidget(desc2)

        desc3 = BodyLabel(
            "Также подходит для ускорения игровых серверов.",
            self,
        )
        desc3.setWordWrap(True)
        root.addWidget(desc3)

        # ── Separator ──
        sep2 = QWidget(self)
        sep2.setFixedHeight(1)
        sep2.setStyleSheet("background-color: rgba(128,128,128,0.3);")
        root.addWidget(sep2)

        # ── Links ──
        links_title = SubtitleLabel("Ссылки", self)
        root.addWidget(links_title)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        tg_channel_btn = PrimaryPushButton(FIF.SEND, "Telegram канал", self)
        tg_channel_btn.clicked.connect(
            lambda: webbrowser.open("https://t.me/vpndiscordyooutube")
        )
        btn_row.addWidget(tg_channel_btn)

        tg_bot_btn = PushButton(FIF.SHOPPING_CART, "Купить подписку", self)
        tg_bot_btn.clicked.connect(
            lambda: webbrowser.open("https://t.me/zapretvpns_bot")
        )
        btn_row.addWidget(tg_bot_btn)

        btn_row.addStretch()
        root.addLayout(btn_row)

        # ── Footer ──
        footer = CaptionLabel("Подробнее здесь @zapretvpns_bot", self)
        setCustomStyleSheet(footer, *_muted_caption_qss(" margin-top: 12px;"))
        root.addWidget(footer)

        root.addStretch()
