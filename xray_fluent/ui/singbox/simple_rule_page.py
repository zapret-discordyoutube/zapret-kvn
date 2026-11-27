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
from PyQt6.QtWidgets import QFileDialog, QHBoxLayout, QWidget
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

from ...singbox_config import tun_bypass
from ...singbox_config.simple_rule import BLOCK, ParsedRule, build_rule, routes_through_tunnel
from ...platform.windows.running_programs import established_connections, group_programs, running_program_paths
from ..detail_page import DetailPage
from .running_programs_dialog import RunningProgramsDialog

#: (ключ, подпись) вариантов «Куда»; ключ — тег выхода или BLOCK.
TARGETS: tuple[tuple[str, str], ...] = (("proxy", "Через VPN"), ("direct", "Напрямую"), (BLOCK, "Блокировать"))

#: «Мимо TUN»: not a route rule. The addresses go into the TUN inbound's ``route_exclude_address`` of the same JSON, and the
#: packets to them never enter the adapter (owner request 2026-11-27). Domains cannot be excluded, only IP addresses.
BYPASS = "bypass-tun"
BYPASS_TITLE = "Мимо TUN"

_FIELDS = (
    ("sites", "Сайты", "2ip.ru\nyoutube.com\ngeosite:category-ru"),
    ("ips", "IP-адреса и подсети", "1.1.1.1\n10.0.0.0/8\ngeoip:ru"),
    ("programs", "Программы и игры", "chrome.exe\nC:\\Games\\game.exe\nC:\\Program Files (x86)\\World of Warcraft\\"),
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
        bypass_available: bool = False,
        on_bypass: Callable[[list[str], bool], None] | None = None,
        on_bypass_clear: Callable[[], None] | None = None,
        bypass_current: Callable[[], list[str]] | None = None,
    ):
        super().__init__(root_label, "Новое правило", parent, root_key="back", page_key="simple")
        self._rule_sets = rule_sets
        self._on_add = on_add
        self._targets = [(key, text) for key, text in TARGETS if key == BLOCK or key in outbounds]
        self._on_bypass = on_bypass
        self._on_bypass_clear = on_bypass_clear
        self._bypass_current = bypass_current or (lambda: [])
        if bypass_available and on_bypass is not None:
            self._targets.append((BYPASS, BYPASS_TITLE))

        self.content_layout.addWidget(StrongBodyLabel("Куда отправить", self.body))
        self.target = SegmentedWidget(self.body)
        for key, text in self._targets:
            self.target.addItem(key, text, onClick=self._refresh)
        self.target.setCurrentItem(self._targets[0][0])
        self.content_layout.addWidget(self.target)

        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.editors: dict[str, PlainTextEdit] = {}
        self._field_titles: dict[str, StrongBodyLabel] = {}
        for key, title, example in _FIELDS:
            self._field_titles[key] = StrongBodyLabel(title, self.body)
            self.content_layout.addWidget(self._field_titles[key])
            editor = PlainTextEdit(self.body)
            editor.setPlaceholderText(example)
            editor.setFont(font)
            editor.setFixedHeight(96)
            editor.textChanged.connect(self._schedule_refresh)
            self.content_layout.addWidget(editor)
            self.editors[key] = editor
            if key == "programs":
                self.content_layout.addLayout(self._program_helpers())
            if key == "ips":
                self.content_layout.addLayout(self._bypass_helpers())
        self.hint = CaptionLabel(
            "По одному в строке. Правило сработает, если совпадёт что-нибудь из списков. "
            "Сайт «2ip.ru» — вместе со всеми поддоменами, программа — без учёта регистра. "
            "Строка с косой чертой на конце — папка: правило охватит всё, что запускается из неё "
            "(у игры десятки процессов — укажите её папку, а не каждый .exe).",
            self.body,
        )
        self.hint.setWordWrap(True)
        self.content_layout.addWidget(self.hint)
        self.bypass_note = CaptionLabel(
            "«Мимо TUN» работает по IP-адресам: пакеты к ним вообще не заходят в адаптер TUN и идут через обычную сетевую карту. "
            "Домены тут не подходят. Игре нужны адреса её серверов: запустите игру, дождитесь входа и нажмите "
            "«Определить адреса». Список фиксированный: если игра подключится к другому серверу, определите адреса заново. "
            "Работает в режиме «VPN (TUN)» и после «Применить».",
            self.body,
        )
        self.bypass_note.setWordWrap(True)
        self.content_layout.addWidget(self.bypass_note)
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

    # -- «Мимо TUN» ---------------------------------------------------------------------

    def _bypass_helpers(self) -> QHBoxLayout:
        row = QHBoxLayout()
        self.find_addresses_btn = PushButton(FIF.SEARCH, "Определить адреса", self.body)
        self.find_addresses_btn.setToolTip("Взять адреса, к которым сейчас подключены программы из списка выше")
        self.find_addresses_btn.clicked.connect(self._find_addresses)
        self.widen_check = CheckBox("Всю подсеть /24", self.body)
        self.widen_check.setToolTip("Соседние адреса сервера игры тоже пойдут мимо TUN: надёжнее, но захватывает больше")
        self.clear_bypass_btn = PushButton(FIF.DELETE, "Убрать все «Мимо TUN»", self.body)
        self.clear_bypass_btn.setToolTip("Очистить «Кроме этих адресов» у входа TUN")
        self.clear_bypass_btn.clicked.connect(self._clear_bypass)
        for widget in (self.find_addresses_btn, self.widen_check, self.clear_bypass_btn):
            row.addWidget(widget)
        row.addStretch(1)
        self._bypass_widgets = (self.find_addresses_btn, self.widen_check, self.clear_bypass_btn)
        return row

    def _is_bypass(self) -> bool:
        return self.target_key() == BYPASS

    def _find_addresses(self) -> None:
        entries = self.texts()["programs"].splitlines()
        found = tun_bypass.remote_addresses_of_programs(established_connections(), entries)
        if not found:
            self.preview.setText(
                "Подключений у этих программ не нашлось. Запустите игру, дождитесь входа в игру и нажмите ещё раз."
                if any(line.strip() for line in entries)
                else "Сначала укажите программы или папку игры выше."
            )
            return
        if self.widen_check.isChecked():
            found = tun_bypass.widen_to_subnet(found)
        editor = self.editors["ips"]
        have = {line.strip() for line in editor.toPlainText().splitlines()}
        fresh = [item for item in found if item not in have]
        text = editor.toPlainText().rstrip("\n")
        editor.setPlainText("\n".join(([text] if text else []) + fresh))

    def _clear_bypass(self) -> None:
        if self._on_bypass_clear is not None:
            self._on_bypass_clear()
        self._refresh()

    def parsed_bypass(self) -> tun_bypass.ParsedAddresses:
        return tun_bypass.parse_addresses(self.texts()["ips"])

    def _apply_target_layout(self) -> None:
        """«Мимо TUN» hides what it cannot use (domains) and shows its own helpers."""
        bypass = self._is_bypass()
        for key in ("sites",):
            self._field_titles[key].setVisible(not bypass)
            self.editors[key].setVisible(not bypass)
        self._field_titles["ips"].setText("IP-адреса и подсети мимо TUN" if bypass else "IP-адреса и подсети")
        self._field_titles["programs"].setText("Программы и игры (чтобы определить их адреса)" if bypass else "Программы и игры")
        for widget in self._bypass_widgets:
            widget.setVisible(bypass)
        self.bypass_note.setVisible(bypass)
        self.hint.setVisible(not bypass)
        self.clear_bypass_btn.setEnabled(bool(self._bypass_current()))

    # -- programs: whole folders ------------------------------------------------------

    def _program_helpers(self) -> QHBoxLayout:
        row = QHBoxLayout()
        pick = PushButton(FIF.FOLDER, "Папка игры…", self.body)
        pick.setToolTip("Выбрать папку установки: одно правило на все процессы игры")
        pick.clicked.connect(self._pick_folder)
        scan = PushButton(FIF.SEARCH, "Найти запущенные…", self.body)
        scan.setToolTip("Показать работающие программы, сгруппированные по папкам")
        scan.clicked.connect(self._scan_running)
        row.addWidget(pick)
        row.addWidget(scan)
        row.addStretch(1)
        return row

    def add_programs(self, entries: list[str]) -> None:
        """Append lines to the programs editor, skipping the ones already there."""
        editor = self.editors["programs"]
        have = {line.strip().lower() for line in editor.toPlainText().splitlines()}
        fresh = [entry for entry in entries if entry.strip().lower() not in have]
        if not fresh:
            return
        text = editor.toPlainText().rstrip("\n")
        editor.setPlainText("\n".join(([text] if text else []) + fresh))

    def _pick_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Папка игры или программы")
        if folder:
            self.add_programs([folder.replace("/", "\\").rstrip("\\") + "\\"])

    def _scan_running(self) -> None:
        groups = group_programs(running_program_paths())
        dialog = RunningProgramsDialog(groups, self.window())
        if groups and dialog.exec():
            self.add_programs(dialog.chosen_folders())

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

    def _refresh_bypass(self) -> None:
        result = self.parsed_bypass()
        filled = bool(self.texts()["ips"].strip())
        ready = bool(result.cidrs) and not result.errors
        self.add_btn.setEnabled(ready)
        self.apply_btn.setEnabled(ready)
        current = self._bypass_current()
        lines = []
        if ready:
            lines.append(f"{tun_bypass.summary(result.cidrs)} → мимо TUN. Заработает после «Применить» и только в режиме TUN.")
        elif filled:
            lines.extend(result.errors or ["Укажите хотя бы один IP-адрес."])
        if current:
            lines.append(f"Сейчас мимо TUN: {tun_bypass.summary(current)}.")
        self.preview.setText("\n".join(lines))

    def _refresh(self) -> None:
        self._apply_target_layout()
        if self._is_bypass():
            self.russian_note.setVisible(False)
            self.except_russian.setVisible(False)
            self._refresh_bypass()
            return
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
        if self._is_bypass():
            parsed = self.parsed_bypass()
            if parsed.cidrs and not parsed.errors and self._on_bypass is not None:
                self._on_bypass(parsed.cidrs, apply)
            else:
                self._refresh()
            return
        result = self.parsed()
        if result.rule is None:
            self._refresh()
            return
        self._on_add(result.rule, apply)
