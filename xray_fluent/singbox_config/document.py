"""Native sing-box JSON document edited by the structured GUI.

The document is the parsed active config itself — a plain ``dict`` in file
order. Editors change it in place, so keys the GUI does not know about stay
untouched, and serialisation writes the same native JSON back. There is no
intermediate model and no routing policy of the application's own.
"""

from __future__ import annotations

import json
from typing import Any

from .schema import Shape


# Top-level array sections whose items carry a ``tag``.
TAGGED_SECTIONS = {
    "outbound": ("outbounds", "endpoints"),
    "inbound": ("inbounds",),
    "dns_server": (("dns", "servers"),),
    "rule_set": (("route", "rule_set"),),
    "http_client": ("http_clients",),
    "network_namespace": ("network_namespaces",),
    "certificate_provider": ("certificate_providers",),
}

PROXY_TAG = "proxy"
DIRECT_TAG = "direct"
BOOTSTRAP_DNS_TAG = "bootstrap-dns"

#: Tags the launch planner references although the source JSON may not:
#: ``sing-box check`` of the edited document cannot notice their absence.
LAUNCH_REQUIRED_TAGS = {
    "outbounds": {
        DIRECT_TAG: (
            "Нужен приложению: при запуске сюда направляются служебные маршруты "
            "(адрес выбранного сервера, Hysteria, тест скорости, пул серверов)."
        ),
    },
    "dns.servers": {
        BOOTSTRAP_DNS_TAG: (
            "Нужен приложению: этим DNS при запуске разрешается доменное имя "
            "выбранного сервера."
        ),
    },
}
APP_PROXY_INBOUND_TYPES = frozenset({"socks", "http", "mixed"})
RESERVED_TAG_PREFIXES = ("__app_", "node_")


def parse_document(text: str) -> tuple[dict | None, str]:
    """Return ``(document, "")`` or ``(None, error)`` for editor text."""

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, f"Строка {exc.lineno}, столбец {exc.colno}: {exc.msg}"
    if not isinstance(payload, dict):
        return None, "Корень конфига sing-box должен быть JSON-объектом."
    return payload, ""


def dump_document(document: dict) -> str:
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def section_items(document: dict, section: str | tuple[str, ...]) -> list:
    """Return the live list for ``outbounds`` or ``("dns", "servers")``."""

    path = (section,) if isinstance(section, str) else section
    node: Any = document
    for key in path:
        if not isinstance(node, dict):
            return []
        node = node.get(key)
    return node if isinstance(node, list) else []


def ensure_section_items(document: dict, section: str | tuple[str, ...]) -> list:
    """Like :func:`section_items`, creating missing containers on the way."""

    path = (section,) if isinstance(section, str) else section
    node = document
    for key in path[:-1]:
        child = node.get(key)
        if not isinstance(child, dict):
            child = {}
            node[key] = child
        node = child
    items = node.get(path[-1])
    if not isinstance(items, list):
        items = []
        node[path[-1]] = items
    return items


def ensure_object(document: dict, key: str) -> dict:
    value = document.get(key)
    if not isinstance(value, dict):
        value = {}
        document[key] = value
    return value


def tags(document: dict, kind: str) -> list[str]:
    """Tags declared in the document for an ``x-tag-reference`` kind."""

    result: list[str] = []
    for section in TAGGED_SECTIONS.get(kind, ()):
        for item in section_items(document, section):
            if not isinstance(item, dict):
                continue
            raw = item.get("tag")
            for tag in raw if isinstance(raw, list) else [raw]:
                if isinstance(tag, str) and tag and tag not in result:
                    result.append(tag)
    return result


def as_list(value: Any) -> list:
    """Normalise a native ``Listable`` value to a list."""

    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def store_list(target: dict, key: str, items: list, shape: Shape) -> None:
    """Write list ``items`` back, keeping the form the file already used.

    A listable field that held one bare value keeps being a bare value while it
    has one item, so an untouched ``"network": "tcp"`` is not rewritten to
    ``["tcp"]``. Empty lists remove the key.
    """

    if not items:
        target.pop(key, None)
        return
    previous = target.get(key)
    if shape.listable and len(items) == 1 and previous is not None and not isinstance(previous, list):
        target[key] = items[0]
        return
    target[key] = list(items)


def app_owned_note(section: str, item: dict) -> str:
    """Explain what the application does with an item at launch, if anything."""

    if not isinstance(item, dict):
        return ""
    kind = item.get("type")
    if section == "outbounds" and item.get("tag") == PROXY_TAG:
        return "Сюда при запуске подставляется выбранный сервер. Тип и параметры этого outbound задаёт приложение."
    if section == "inbounds" and kind in APP_PROXY_INBOUND_TYPES:
        return (
            "Входящие socks/http/mixed приложение удаляет при запуске и само открывает "
            "порты системного прокси."
        )
    if section == "inbounds" and kind == "tun":
        return (
            "Используется в режиме TUN. Имя интерфейса при запуске заменяется уникальным; "
            "в режиме системного прокси TUN отключается."
        )
    tag = item.get("tag")
    required = LAUNCH_REQUIRED_TAGS.get(section, {}).get(tag) if isinstance(tag, str) else None
    if required:
        return f"{required} Не удаляйте и не переименовывайте его."
    if isinstance(tag, str) and tag.startswith(RESERVED_TAG_PREFIXES):
        return "Тег зарезервирован приложением и может быть перезаписан при запуске."
    return ""


def section_differs(document: dict, stock: dict | None, key: str) -> bool:
    if stock is None:
        return False
    return document.get(key) != stock.get(key)


def differing_sections(document: dict, stock: dict | None) -> list[str]:
    if stock is None:
        return []
    keys = list(document) + [key for key in stock if key not in document]
    return [key for key in keys if document.get(key) != stock.get(key)]
