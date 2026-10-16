"""Страница «Простое правило»: куда отправить и списки сайтов, IP и программ.

Документ не меняется, пока пользователь не нажмёт «Добавить»: открытие и
ввод ничего не пишут в конфиг. Правило встаёт сразу после служебных
sniff/hijack-dns — выше стоковых, иначе его перехватит набор ниже по списку.

Поэтому программа «через VPN» по умолчанию идёт «кроме российских сайтов»:
иначе правило перекрывает стоковое «РФ напрямую», и VK, Яндекс, банки этой
программы уходят в туннель, где с зарубежного адреса часто не открываются.
"""

from __future__ import annotations

from typing import Callable

from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    CheckBox,
    FluentIcon as FIF,
    PlainTextEdit,
    PrimaryPushButton,
    PushButton,
    SegmentedWidget,
    StrongBodyLabel,
)

from ...singbox_config.simple_rule import BLOCK, ParsedRule, build_rule, routes_through_tunnel
from ..detail_page import DetailPage

#: (ключ, подпись) вариантов «Куда»; ключ — тег выхода или BLOCK.
TARGETS: tuple[tuple[str, str], ...] = (("proxy", "Через VPN"), ("direct", "Напрямую"), (BLOCK, "Блокировать"))

_FIELDS = (
    ("sites", "Сайты", "2ip.ru\nyoutube.com\ngeosite:category-ru"),
    ("ips", "IP-адреса и подсети", "1.1.1.1\n10.0.0.0/8\ngeoip:ru"),
    ("programs", "Программы", "chrome.exe\nC:\\Games\\game.exe"),
)


class SimpleRulePage(DetailPage):
    """Добавление правила в духе v2rayN: по одному значению в строке."""

    def __init__(
        self,
        parent: QWidget,
        root_label: str,
        *,
        outbounds: list[str],
        rule_sets: set[str],
        on_add: Callable[[dict, bool], None],
    ):
        super().__init__(root_label, "Новое правило", parent, root_key="back", page_key="simple")
        self._rule_sets = rule_sets
        self._on_add = on_add
        self._targets = [(key, text) for key, text in TARGETS if key == BLOCK or key in outbounds]

        self.content_layout.addWidget(StrongBodyLabel("Куда отправить", self.body))
        self.target = SegmentedWidget(self.body)
        for key, text in self._targets:
            self.target.addItem(key, text, onClick=self._refresh)
        self.target.setCurrentItem(self._targets[0][0])
        self.content_layout.addWidget(self.target)

        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.editors: dict[str, PlainTextEdit] = {}
        for key, title, example in _FIELDS:
            self.content_layout.addWidget(StrongBodyLabel(title, self.body))
            editor = PlainTextEdit(self.body)
            editor.setPlaceholderText(example)
            editor.setFont(font)
            editor.setFixedHeight(96)
            editor.textChanged.connect(self._schedule_refresh)
            self.content_layout.addWidget(editor)
            self.editors[key] = editor
        self.hint = CaptionLabel(
            "По одному в строке. Правило сработает, если совпадёт что-нибудь из списков. "
            "Сайт «2ip.ru» — вместе со всеми поддоменами, программа — без учёта регистра.",
            self.body,
        )
        self.hint.setWordWrap(True)
        self.content_layout.addWidget(self.hint)
        self.except_russian = CheckBox("Кроме российских сайтов", self.body)
        self.except_russian.setChecked(True)
        self.except_russian.setToolTip(
            "Российские сайты этих программ пойдут дальше по списку правил — обычно напрямую"
        )
        self.except_russian.stateChanged.connect(lambda _state: self._refresh())
        self.content_layout.addWidget(self.except_russian)
        self.russian_note = CaptionLabel("", self.body)
        self.russian_note.setWordWrap(True)
        self.content_layout.addWidget(self.russian_note)
        self.preview = BodyLabel("", self.body)
        self.preview.setWordWrap(True)
        self.content_layout.addWidget(self.preview)
        self.content_layout.addStretch(1)

        self.add_btn = PushButton(FIF.ADD, "Добавить", self)
        self.add_btn.setToolTip("Добавить в конфиг; заработает после «Применить»")
        self.add_btn.clicked.connect(lambda: self._submit(apply=False))
        self.apply_btn = PrimaryPushButton(FIF.PLAY, "Добавить и применить", self)
        self.apply_btn.setToolTip("Добавить, сохранить и, если VPN подключён, сразу переподключиться")
        self.apply_btn.clicked.connect(lambda: self._submit(apply=True))
        self.add_header_action(self.add_btn)
        self.add_header_action(self.apply_btn)

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.setInterval(150)
        self._refresh_timer.timeout.connect(self._refresh)
        self._refresh()

    # -- state ------------------------------------------------------------------

    def target_key(self) -> str:
        return self.target.currentRouteKey() or self._targets[0][0]

    def set_target(self, key: str) -> None:
        self.target.setCurrentItem(key)
        self._refresh()

    def texts(self) -> dict[str, str]:
        return {key: editor.toPlainText() for key, editor in self.editors.items()}

    def programs_through_tunnel(self) -> bool:
        """Программы отправляются в туннель — тут и нужен выбор про российские сайты."""
        return routes_through_tunnel(self.target_key()) and bool(self.texts()["programs"].strip())

    def parsed(self) -> ParsedRule:
        texts = self.texts()
        return build_rule(
            self.target_key(),
            texts["sites"],
            texts["ips"],
            texts["programs"],
            self._rule_sets,
            except_russian=self.programs_through_tunnel() and self.except_russian.isChecked(),
        )

    def is_dirty(self) -> bool:
        return any(text.strip() for text in self.texts().values())

    def first_site(self) -> str:
        """Первый обычный сайт из списка — для проверки маршрута после добавления."""
        for line in self.texts()["sites"].replace(",", "\n").splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            if value.lower().startswith(("http://", "https://")):
                return value
            head, sep, rest = value.partition(":")
            if not sep:
                return value
            if head.strip().lower() in ("domain", "full"):
                return rest.strip()
        return ""

    # -- UI -----------------------------------------------------------------------

    def _schedule_refresh(self) -> None:
        self._refresh_timer.start()

    def _refresh_russian_choice(self) -> None:
        relevant = self.programs_through_tunnel()
        self.except_russian.setVisible(relevant)
        self.russian_note.setVisible(relevant)
        if self.except_russian.isChecked():
            self.russian_note.setText(
                "Российские сайты (.ru, .рф, .su, наборы geosite-category-ru и geoip-ru) "
                "не совпадут с правилом и пойдут дальше по списку — обычно напрямую."
            )
        else:
            self.russian_note.setText(
                "Все сайты этих программ, включая российские, пойдут через VPN. VK, Яндекс, "
                "банки и госсервисы с зарубежного адреса часто не открываются."
            )

    def _refresh(self) -> None:
        self._refresh_russian_choice()
        result = self.parsed()
        filled = self.is_dirty()
        ready = result.rule is not None
        self.add_btn.setEnabled(ready)
        self.apply_btn.setEnabled(ready)
        if ready:
            target = dict(self._targets)[self.target_key()]
            self.preview.setText(f"{result.summary} → {target}. Правило встанет наверх — после служебных и защитных.")
        elif filled:
            self.preview.setText("\n".join(error for error in result.errors if not error.startswith("Укажите")))
        else:
            self.preview.setText("")

    def _submit(self, *, apply: bool) -> None:
        self._refresh_timer.stop()
        result = self.parsed()
        if result.rule is None:
            self._refresh()
            return
        self._on_add(result.rule, apply)
