from __future__ import annotations

import webbrowser
from pathlib import Path

from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    FluentIcon as FIF,
    InfoBar,
    InfoBarPosition,
    PrimaryPushButton,
    PushButton,
    SubtitleLabel,
    TitleLabel,
    setCustomStyleSheet,
)

from ..constants import APP_VERSION, LOG_DIR
from ..support.service import SupportAction, SupportResult
from .file_manager import reveal_file
from .theme import token_pair

# Рекламная метка deep-link бота: источник kvnwin + место about.
BOT_ABOUT_URL = "https://t.me/zapretvpns_bot?start=kvnwin_about"


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
            lambda: webbrowser.open(BOT_ABOUT_URL)
        )
        btn_row.addWidget(tg_bot_btn)

        self._support_button = PushButton(FIF.HELP, "Поддержка", self)
        self._support_button.setToolTip(
            "Собрать архив журналов без ссылок и паролей и открыть страницу обращения на рабочем зеркале сайта"
        )
        self._support_button.clicked.connect(self._on_support_clicked)
        btn_row.addWidget(self._support_button)
        self._support: SupportAction | None = None

        btn_row.addStretch()
        root.addLayout(btn_row)

        # ── Footer ──
        footer = CaptionLabel("Подробнее здесь @zapretvpns_bot", self)
        setCustomStyleSheet(footer, *_muted_caption_qss(" margin-top: 12px;"))
        root.addWidget(footer)

        root.addStretch()

    # ── Поддержка ──

    def _support_action(self) -> SupportAction | None:
        if self._support is not None:
            return self._support
        # Контроллер живёт в главном окне; страница строится лениво и ссылки на него не хранит.
        controller = getattr(self.window(), "controller", None)
        if controller is None:
            return None
        action = SupportAction(
            controller.build_diagnostics,
            LOG_DIR,
            open_url=lambda url: QDesktopServices.openUrl(QUrl(url)),
            reveal_file=reveal_file,
            parent=self,
        )
        action.started.connect(lambda: self._set_support_busy(True))
        action.finished_ok.connect(self._on_support_ready)
        action.failed.connect(self._on_support_failed)
        self._support = action
        return action

    def _set_support_busy(self, busy: bool) -> None:
        self._support_button.setEnabled(not busy)
        self._support_button.setText("Собираем архив…" if busy else "Поддержка")

    def _on_support_clicked(self) -> None:
        action = self._support_action()
        if action is None:
            self._on_support_failed("главное окно приложения недоступно")
            return
        action.start()

    def _on_support_ready(self, result: SupportResult) -> None:
        self._set_support_busy(False)
        InfoBar.success(
            "Архив для поддержки готов",
            f"{Path(result.zip_path).name} — приложите его к обращению на открывшейся странице. "
            "В нём нет ссылок подписок и паролей.",
            duration=15000,
            position=InfoBarPosition.TOP,
            parent=self.window(),
        )

    def _on_support_failed(self, message: str) -> None:
        self._set_support_busy(False)
        InfoBar.error(
            "Поддержка",
            f"Не получилось подготовить обращение: {message}",
            duration=12000,
            position=InfoBarPosition.TOP,
            parent=self.window(),
        )
