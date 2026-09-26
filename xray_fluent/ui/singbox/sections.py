"""Routing sub-pages: rules, rule-sets, DNS, outbounds and system options.

Each section edits the session's native document in place. Containers such as
``route`` or ``dns`` are created only on the first real edit, so opening a page
never changes the user's JSON.
"""

from __future__ import annotations

import json
from typing import Callable

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget
from qfluentwidgets import (
    CaptionLabel,
    IconWidget,
    InfoBarIcon,
    PushButton,
    PrimaryPushButton,
    FluentIcon as FIF,
    SubtitleLabel,
)

from ...singbox_config import catalog
from ...singbox_config.document import (
    LAUNCH_REQUIRED_TAGS,
    app_owned_note,
    ensure_section_items,
    section_items,
    tags,
)
from ...singbox_config.schema import SingboxSchema, bundled_schema
from ..base_page import ScrollablePage
from ..detail_page import DetailPage
from ..qt_lifecycle import dispose_later
from .fields import FieldEditor, FormContext, create_editor
from .form import SchemaForm
from .lists import AddOption, NavStack, ObjectList, RowInfo, section_header, unique_tag
from .session import SingboxSession


class InlineNote(QWidget):
    """Icon plus wrapped caption; a plain layout widget (unlike ``InfoBar``)."""

    def __init__(self, text: str, parent: QWidget | None = None, *, warning: bool = False):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(8)
        icon = IconWidget(InfoBarIcon.WARNING if warning else InfoBarIcon.INFORMATION, self)
        icon.setFixedSize(16, 16)
        layout.addWidget(icon, 0, Qt.AlignmentFlag.AlignTop)
        self.label = CaptionLabel(text, self)
        self.label.setWordWrap(True)
        layout.addWidget(self.label, 1)

    def set_text(self, text: str) -> None:
        self.label.setText(text)
        self.setVisible(bool(text))


def inline_note(text: str, parent: QWidget, *, warning: bool = False) -> InlineNote:
    return InlineNote(text, parent, warning=warning)


def count_references(document: dict, tag: str, own: dict) -> int:
    """How often ``tag`` is referenced by other parts of the document."""

    total = 0

    def walk(node, key: str | None = None) -> None:
        nonlocal total
        if node is own:
            return
        if isinstance(node, dict):
            for child_key, child in node.items():
                walk(child, child_key)
        elif isinstance(node, list):
            for child in node:
                walk(child, key)
        elif isinstance(node, str) and node == tag and key != "tag":
            total += 1

    walk(document)
    return total


class _LazyObject:
    """A top-level object section that joins the document on first edit."""

    def __init__(self, document: dict, key: str):
        self.document = document
        self.key = key
        current = document.get(key)
        self.value = current if isinstance(current, dict) else {}

    def attach(self) -> None:
        if self.document.get(self.key) is not self.value:
            self.document[self.key] = self.value


class ItemPage(DetailPage):
    """Edit one object of a list; changes are live, «Отменить правки» restores."""

    def __init__(
        self,
        section: "Section",
        item: dict,
        node: dict,
        context: str,
        root_label: str,
        page_label: str,
        *,
        note: str = "",
        locked: bool = False,
        check: Callable[[dict], str] | None = None,
    ):
        super().__init__(root_label, page_label, section, root_key="back", page_key="item")
        self.section = section
        self.item = item
        self._snapshot = json.loads(json.dumps(item))
        self._check = check
        if note:
            self.content_layout.addWidget(inline_note(note, self.body))
        self.warning = inline_note("", self.body, warning=True)
        self.content_layout.addWidget(self.warning)
        self.form = SchemaForm(section.ctx(), node, item, context, self.body, locked=locked)
        self.form.changed.connect(self._on_changed)
        self.content_layout.addWidget(self.form)
        self.content_layout.addStretch(1)
        self.undo_btn = PushButton(FIF.CANCEL, "Отменить правки", self)
        self.undo_btn.clicked.connect(self._undo)
        self.undo_btn.setEnabled(False)
        done = PrimaryPushButton(FIF.ACCEPT, "Готово", self)
        done.clicked.connect(self.request_back)
        if not locked:
            self.add_header_action(self.undo_btn)
        self.add_header_action(done)
        self._refresh_warning()

    def _on_changed(self) -> None:
        self.undo_btn.setEnabled(self.item != self._snapshot)
        self._refresh_warning()
        self.section.edited()

    def _refresh_warning(self) -> None:
        problem = self._check(self.item) if self._check is not None else ""
        self.warning.set_text(problem)

    def request_back(self) -> None:
        self.form.flush()
        super().request_back()

    def _undo(self) -> None:
        self.form.flush()
        self.item.clear()
        self.item.update(json.loads(json.dumps(self._snapshot)))
        self.form.rebuild()
        self._on_changed()


class ListPage(DetailPage):
    """Nested list of rule objects (logical rule members, inline rule-set)."""

    def __init__(self, section: "Section", title: str, items: list, item_node: dict, context: str):
        super().__init__(section.title, title, section, root_key="back", page_key="list")
        self.section = section
        self.items = items
        self.item_node = item_node
        self.context = context
        self.list = ObjectList(
            lambda: self.items,
            lambda: self.items,
            lambda item, _index: RowInfo(catalog.match_summary(item)),
            [AddOption("Условие", dict)],
            self.body,
            add_text="Добавить правило",
            empty_text="Вложенных правил нет — ядро не примет пустой список.",
        )
        self.list.changed.connect(section.edited)
        self.list.open_requested.connect(self._open)
        self.content_layout.addWidget(self.list)
        self.content_layout.addStretch(1)
        done = PrimaryPushButton(FIF.ACCEPT, "Готово", self)
        done.clicked.connect(self.request_back)
        self.add_header_action(done)

    def _open(self, index: int) -> None:
        self.section.push_item(
            self.items[index],
            self.item_node,
            self.context,
            f"Правило {index + 1}",
            check=_rule_condition_check,
            on_close=self.list.refresh,
        )


def _rule_condition_check(rule: dict) -> str:
    ignored = set(catalog.ACTION_KEYS) | {"type", "invert"}
    if rule.get("type") == "logical":
        if not rule.get("rules"):
            return "Добавьте вложенные правила — пустое логическое правило ядро не примет."
        return ""
    if not any(key not in ignored for key in rule):
        return (
            "Добавьте хотя бы одно условие. Для всего остального трафика используйте "
            "«Если ничего не подошло» на странице правил."
        )
    return ""


class Section(QWidget):
    """Base for a routing sub-page: scrollable root plus nested sub-pages."""

    key = ""
    title = ""
    hint = ""

    def __init__(self, session: SingboxSession, parent: QWidget | None = None, schema: SingboxSchema | None = None):
        super().__init__(parent)
        self.session = session
        self._schema = schema
        self.root = ScrollablePage(self)
        self.nav = NavStack(self.root, self)
        self.nav.popped.connect(self._on_popped)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.nav)
        self._on_close: list[Callable[[], None] | None] = []
        self._content: QWidget | None = None
        self.body: QWidget = self.root.body
        self._active = False
        self._stale = True
        session.document_replaced.connect(self._on_document_replaced)

    @property
    def scroll_area(self):
        return self.root.scroll_area

    @property
    def schema(self) -> SingboxSchema:
        # Loaded on the first build: the parsed core schema is large and the
        # overview/JSON pages do not need it.
        if self._schema is None:
            self._schema = bundled_schema()
        return self._schema

    @property
    def document(self) -> dict:
        return self.session.document if self.session.document is not None else {}

    def ctx(self) -> FormContext:
        return FormContext(self.schema, self.document, open_list=self.open_list)

    def edited(self) -> None:
        self.session.mark_edited()

    def flush(self) -> None:
        """Commit pending input of every editor on this section's pages."""
        for editor in self.findChildren(FieldEditor):
            editor.flush()

    def set_active(self, active: bool) -> None:
        """The container shows this section; build it if the document changed."""
        self._active = active
        if active and self._stale:
            self.reload()

    def _on_document_replaced(self) -> None:
        # Only the visible section rebuilds now; the others on first show.
        self.nav.pop_all()
        if self._active:
            self.reload()
        else:
            self._stale = True

    def reload(self) -> None:
        self._stale = False
        self.nav.pop_all()
        if self._content is not None:
            self.root.body_layout.removeWidget(self._content)
            dispose_later(self._content)
        self._content = QWidget(self.root.body)
        self.root.body_layout.addWidget(self._content)
        layout = QVBoxLayout(self._content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        self.body = self._content
        layout.addWidget(SubtitleLabel(self.title, self.body))
        if self.hint:
            hint = CaptionLabel(self.hint, self.body)
            hint.setWordWrap(True)
            layout.addWidget(hint)
        if not self.session.editable:
            layout.addWidget(
                inline_note(
                    "Сейчас в конфиге ошибка JSON, поэтому разделы недоступны. "
                    f"Исправьте её на странице «JSON».\n{self.session.parse_error}",
                    self.body,
                    warning=True,
                )
            )
            layout.addStretch(1)
            return
        self.build(layout)
        layout.addStretch(1)

    def build(self, layout: QVBoxLayout) -> None:
        raise NotImplementedError

    # -- navigation -----------------------------------------------------------

    def push_item(
        self,
        item: dict,
        node: dict,
        context: str,
        label: str,
        *,
        note: str = "",
        locked: bool = False,
        check: Callable[[dict], str] | None = None,
        on_close: Callable[[], None] | None = None,
    ) -> None:
        root_label = self.title if self.nav.depth == 0 else "Назад"
        page = ItemPage(self, item, node, context, root_label, label, note=note, locked=locked, check=check)
        self._on_close.append(on_close)
        self.nav.push(page)

    def open_list(self, title: str, items: list, item_node: dict, context: str) -> None:
        self._on_close.append(None)
        self.nav.push(ListPage(self, title, items, item_node, context))

    def _on_popped(self) -> None:
        callback = self._on_close.pop() if self._on_close else None
        if callback is not None:
            callback()

    # -- helpers ----------------------------------------------------------------

    def add_list(
        self,
        layout: QVBoxLayout,
        path: tuple[str, ...],
        node: dict,
        context: str,
        describe: Callable[[dict, int], RowInfo],
        options: list[AddOption],
        *,
        add_text: str,
        empty_text: str,
        item_label: Callable[[dict, int], str],
        note: Callable[[dict], str] = lambda _item: "",
        locked: Callable[[dict], bool] = lambda _item: False,
        check: Callable[[dict], str] | None = None,
        can_remove: Callable[[dict], str] | None = None,
    ) -> ObjectList:
        view = ObjectList(
            lambda: section_items(self.document, path),
            lambda: ensure_section_items(self.document, path),
            describe,
            options,
            self.body,
            add_text=add_text,
            empty_text=empty_text,
            can_remove=can_remove,
        )
        view.changed.connect(self.edited)

        def open_item(index: int) -> None:
            items = section_items(self.document, path)
            if not 0 <= index < len(items) or not isinstance(items[index], dict):
                return
            item = items[index]
            self.push_item(
                item,
                node,
                context,
                item_label(item, index),
                note=note(item),
                locked=locked(item),
                check=check,
                on_close=view.refresh,
            )

        view.open_requested.connect(open_item)
        layout.addWidget(view)
        return view

    def add_object_form(
        self,
        layout: QVBoxLayout,
        key: str,
        context: str,
        *,
        hidden: tuple[str, ...] = (),
    ) -> SchemaForm:
        lazy = _LazyObject(self.document, key)
        form = SchemaForm(self.ctx(), self.schema.section(key), lazy.value, context, self.body, hidden=hidden)

        def changed() -> None:
            lazy.attach()
            self.edited()

        form.changed.connect(changed)
        layout.addWidget(form)
        return form

    def default_outbound(self) -> str:
        outbounds = tags(self.document, "outbound")
        for preferred in ("proxy", "direct"):
            if preferred in outbounds:
                return preferred
        return outbounds[0] if outbounds else "direct"

    def reference_warning(self, noun: str, section: str = "") -> Callable[[dict], str]:
        """Why deleting this tagged item would break the core or the launch."""

        def check(item: dict) -> str:
            tag = item.get("tag")
            if not isinstance(tag, str):
                return ""
            problems: list[str] = []
            required = LAUNCH_REQUIRED_TAGS.get(section, {}).get(tag)
            if required:
                problems.append(f"{required} Без него подключение не запустится.")
            count = count_references(self.document, tag, item)
            if count:
                problems.append(
                    f"На {noun} «{tag}» ссылаются другие места конфига ({count}). "
                    "Пока ссылки не убраны, ядро не запустит такой конфиг."
                )
            return "\n\n".join(problems)

        return check


def _type_options(schema: SingboxSchema, node: dict, common: tuple[str, ...], factory) -> list[AddOption]:
    variants = [item.value for item in schema.variants(node)]
    options = [AddOption(value, lambda v=value: factory(v)) for value in common if value in variants]
    options += [
        AddOption(value, lambda v=value: factory(v), submenu="Другие типы")
        for value in variants
        if value not in common
    ]
    return options


class RulesSection(Section):
    key = "rules"
    title = "Правила"
    hint = (
        "Правила проверяются сверху вниз, срабатывает первое подошедшее. "
        "Это native route.rules ядра sing-box: одинаково для TUN и системного прокси."
    )

    def build(self, layout: QVBoxLayout) -> None:
        node = self.schema.definition("Rule")

        def new_rule() -> dict:
            return {"action": "route", "outbound": self.default_outbound()}

        def new_logical() -> dict:
            return {"type": "logical", "mode": "or", "rules": [], "action": "route", "outbound": self.default_outbound()}

        self.rules = self.add_list(
            layout,
            ("route", "rules"),
            node,
            "rule",
            lambda rule, _index: RowInfo(catalog.match_summary(rule), catalog.action_summary(rule)),
            [AddOption("Правило", new_rule), AddOption("Логическое правило (И / ИЛИ)", new_logical)],
            add_text="Добавить правило",
            empty_text="Правил нет — весь трафик уходит по «Если ничего не подошло».",
            item_label=lambda _rule, index: f"Правило {index + 1}",
            check=_rule_condition_check,
        )
        layout.addWidget(section_header("Если ничего не подошло", "Куда отправить остальной трафик (route.final).", self.body))
        route = _LazyObject(self.document, "route")
        final_shape = self.schema.fields(self.schema.section("route"), route.value)["final"].shape
        editor = create_editor(self.ctx(), route.value, "final", final_shape, self.body)

        def final_changed() -> None:
            route.attach()
            self.edited()

        editor.changed.connect(final_changed)
        layout.addWidget(editor)


class RuleSetsSection(Section):
    key = "rule_sets"
    title = "Наборы правил"
    hint = (
        "Наборы (route.rule_set) подключают готовые списки доменов и адресов: локальные .srs/.json, "
        "загружаемые по URL или встроенные. Относительные пути считаются от папки core."
    )

    def build(self, layout: QVBoxLayout) -> None:
        node = self.schema.definition("RuleSet")

        def factory(kind: str) -> dict:
            tag = unique_tag("new-set", section_items(self.document, ("route", "rule_set")))
            if kind == "local":
                return {"type": "local", "tag": tag, "format": "binary", "path": ""}
            if kind == "remote":
                return {"type": "remote", "tag": tag, "format": "binary", "url": ""}
            return {"type": "inline", "tag": tag, "rules": []}

        def describe(item: dict, _index: int) -> RowInfo:
            kind = item.get("type") or "inline"
            detail = {
                "local": item.get("path", ""),
                "remote": item.get("url", ""),
            }.get(kind, f"встроенных правил: {len(item.get('rules') or [])}")
            tag = item.get("tag")
            uses = count_references(self.document, tag, item) if isinstance(tag, str) else 0
            used = f" · используется: {uses}" if uses else " · не используется"
            return RowInfo(str(tag or "без тега"), f"{catalog.TYPE_LABELS.get(kind, kind)} · {detail}{used}")

        self.add_list(
            layout,
            ("route", "rule_set"),
            node,
            "rule_set",
            describe,
            [
                AddOption("Локальный файл", lambda: factory("local")),
                AddOption("По URL", lambda: factory("remote")),
                AddOption("Встроенный", lambda: factory("inline")),
            ],
            add_text="Добавить набор",
            empty_text="Наборов нет.",
            item_label=lambda item, _index: str(item.get("tag") or "Набор"),
            can_remove=self.reference_warning("набор"),
        )


class DnsSection(Section):
    key = "dns"
    title = "DNS"
    hint = (
        "Native секция dns: серверы, правила выбора сервера и общие параметры. "
        "Приложение её больше не перезаписывает; вернуть стоковый вариант можно на странице «Обзор»."
    )

    def build(self, layout: QVBoxLayout) -> None:
        self.add_object_form(layout, "dns", "dns", hidden=("servers", "rules"))
        layout.addWidget(section_header("Серверы", "Порядок не важен; сервер выбирают правила и «final».", self.body))
        server_node = self.schema.definition("DNSServer")

        def new_server(kind: str) -> dict:
            tag = unique_tag(f"dns-{kind}", section_items(self.document, ("dns", "servers")))
            return {"type": kind, "tag": tag}

        def describe_server(item: dict, _index: int) -> RowInfo:
            server = item.get("server")
            detail = f" · {server}" if server else ""
            return RowInfo(
                str(item.get("tag") or "без тега"),
                f"{item.get('type', '?')}{detail}",
                note=app_owned_note("dns.servers", item),
            )

        self.add_list(
            layout,
            ("dns", "servers"),
            server_node,
            "dns_server",
            describe_server,
            _type_options(self.schema, server_node, ("udp", "tcp", "tls", "https", "quic", "h3", "local", "fallback", "hosts", "fakeip"), new_server),
            add_text="Добавить сервер",
            empty_text="Серверов нет.",
            item_label=lambda item, _index: str(item.get("tag") or "Сервер"),
            note=lambda item: app_owned_note("dns.servers", item),
            can_remove=self.reference_warning("сервер", "dns.servers"),
        )
        layout.addWidget(section_header("Правила DNS", "Проверяются сверху вниз; выбирают сервер или ответ.", self.body))
        rule_node = self.schema.definition("DNSRule")

        def new_rule() -> dict:
            servers = tags(self.document, "dns_server")
            return {"action": "route", "server": servers[0] if servers else ""}

        self.add_list(
            layout,
            ("dns", "rules"),
            rule_node,
            "dns_rule",
            lambda rule, _index: RowInfo(catalog.match_summary(rule), catalog.action_summary(rule, dns=True)),
            [
                AddOption("Правило", new_rule),
                AddOption("Логическое правило (И / ИЛИ)", lambda: {"type": "logical", "mode": "or", "rules": [], **new_rule()}),
            ],
            add_text="Добавить правило",
            empty_text="Правил DNS нет — все запросы идут на «final».",
            item_label=lambda _rule, index: f"Правило DNS {index + 1}",
            check=_rule_condition_check,
        )


class OutboundsSection(Section):
    key = "outbounds"
    title = "Исходящие"
    hint = (
        "Куда правила отправляют трафик. Outbound с тегом proxy — место, куда при запуске подставляется "
        "выбранный сервер; остальные (direct, block, selector, urltest, …) полностью ваши."
    )

    def build(self, layout: QVBoxLayout) -> None:
        node = self.schema.array_item("outbounds")

        def new_outbound(kind: str) -> dict:
            return {"type": kind, "tag": unique_tag(kind, section_items(self.document, "outbounds"))}

        def describe(item: dict, _index: int) -> RowInfo:
            server = item.get("server")
            detail = f" · {server}:{item.get('server_port', '')}" if server else ""
            tag = str(item.get("tag") or "без тега")
            return RowInfo(
                catalog.outbound_label(tag),
                f"{item.get('type', '?')}{detail}",
                note=app_owned_note("outbounds", item),
                removable=True,
            )

        self.add_list(
            layout,
            ("outbounds",),
            node,
            "outbound",
            describe,
            _type_options(self.schema, node, ("direct", "block", "selector", "urltest", "socks", "http", "shadowsocks", "vless", "vmess", "trojan", "hysteria2", "tuic"), new_outbound),
            add_text="Добавить outbound",
            empty_text="Outbound'ов нет — ядро отправит всё напрямую.",
            item_label=lambda item, _index: str(item.get("tag") or "Outbound"),
            note=lambda item: app_owned_note("outbounds", item),
            locked=lambda item: item.get("tag") == "proxy",
            can_remove=self.reference_warning("outbound", "outbounds"),
        )
        endpoint_node = self.schema.array_item("endpoints")
        layout.addWidget(
            section_header(
                "Endpoints",
                "WireGuard, WARP, Tailscale и другие endpoints. Приложение допускает один WireGuard endpoint "
                "без outbound proxy (AmneziaWG).",
                self.body,
            )
        )

        def new_endpoint(kind: str) -> dict:
            return {"type": kind, "tag": unique_tag(kind, section_items(self.document, "endpoints"))}

        self.add_list(
            layout,
            ("endpoints",),
            endpoint_node,
            "endpoint",
            lambda item, _index: RowInfo(str(item.get("tag") or "без тега"), str(item.get("type", "?"))),
            _type_options(self.schema, endpoint_node, ("wireguard", "warp"), new_endpoint),
            add_text="Добавить endpoint",
            empty_text="Endpoints нет.",
            item_label=lambda item, _index: str(item.get("tag") or "Endpoint"),
            can_remove=self.reference_warning("endpoint"),
        )


# Sections edited on dedicated pages; everything else appears under «Прочее».
_DEDICATED_ROOT_KEYS = ("log", "dns", "inbounds", "outbounds", "endpoints", "route", "experimental", "$schema")


class SystemSection(Section):
    key = "system"
    title = "Система"
    hint = "Входящие (TUN), общие параметры маршрутизации, журнал ядра и остальные секции конфига."

    def build(self, layout: QVBoxLayout) -> None:
        layout.addWidget(
            section_header(
                "Входящие",
                "Для режима TUN нужен inbound типа tun. Входящие socks/http/mixed приложение при запуске "
                "заменяет своими портами системного прокси.",
                self.body,
            )
        )
        node = self.schema.array_item("inbounds")

        def new_inbound(kind: str) -> dict:
            base = {"type": kind, "tag": unique_tag(f"{kind}-in", section_items(self.document, "inbounds"))}
            if kind == "tun":
                base.update({"address": ["172.19.0.1/30"], "auto_route": True, "stack": "mixed"})
            return base

        self.add_list(
            layout,
            ("inbounds",),
            node,
            "inbound",
            lambda item, _index: RowInfo(
                str(item.get("tag") or item.get("type") or "без тега"),
                str(item.get("type", "?")),
                note=app_owned_note("inbounds", item),
            ),
            _type_options(self.schema, node, ("tun", "mixed", "socks", "http", "direct"), new_inbound),
            add_text="Добавить inbound",
            empty_text="Входящих нет — режим TUN не запустится.",
            item_label=lambda item, _index: str(item.get("tag") or "Inbound"),
            note=lambda item: app_owned_note("inbounds", item),
            can_remove=self.reference_warning("inbound"),
        )
        layout.addWidget(section_header("Маршрутизация: общие параметры", "route.* кроме правил и наборов.", self.body))
        self.add_object_form(layout, "route", "route", hidden=("rules", "rule_set", "final"))
        layout.addWidget(section_header("Журнал ядра", "Приложение читает журнал из вывода ядра: файл и отключение скроют ошибки.", self.body))
        self.add_object_form(layout, "log", "log")
        layout.addWidget(
            section_header(
                "Experimental",
                "cache_file хранит кэш наборов и DNS. Адрес Clash API приложение назначает само при запуске; "
                "секрет Clash API не поддерживается (перестанут работать метрики и переключение).",
                self.body,
            )
        )
        self.add_object_form(layout, "experimental", "experimental")
        layout.addWidget(section_header("Прочие секции", "Остальные секции верхнего уровня, которые знает ядро.", self.body))
        rest = SchemaForm(
            self.ctx(),
            self.schema.document,
            self.document,
            "root",
            self.body,
            hidden=_DEDICATED_ROOT_KEYS,
        )
        rest.changed.connect(self.edited)
        layout.addWidget(rest)
