"""Страница поддержки на открытом имени сайта проекта."""

from __future__ import annotations

import logging
from urllib.parse import quote, urlsplit

from zapret_update import mirrors as git_mirrors

from ..updates import site_names

_log = logging.getLogger(__name__)

SUPPORT_PATH = "/zapretkvn/zapret-kvn/issues/new"
# Основное имя: ядро само подставляет вместо него то, которое сейчас открывается.
CANONICAL_SUPPORT_URL = f"https://{git_mirrors.CANONICAL_HOST}{SUPPORT_PATH}"
_ENTRY_HOST = "script.google.com"


def entry_page_url(path: str = SUPPORT_PATH) -> str:
    """Входная страница Zapret Links на script.google.com с путём нашего сайта.

    Страница работает в браузере человека: она проверяет зеркала там, где их будет открывать
    он, и предлагает то, что действительно грузится (фильтр провайдера видит только
    script.google.com). Это запас, когда приложение само не нашло открывающееся зеркало:
    его сеть и сеть браузера доходят до сайта по-разному. Адрес берётся из общего ядра
    (``ENTRY_LISTS``): та же страница без ``?format=json``, семейство ``git``.
    """

    for listed in git_mirrors.ENTRY_LISTS:
        parsed = urlsplit(listed)
        if parsed.hostname == _ENTRY_HOST:
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            return f"{base}?s=git&p={quote(path.strip('/'), safe='/')}"
    return CANONICAL_SUPPORT_URL


def support_url() -> str:
    """Страница нового обращения. Ждёт сеть: только из фонового потока.

    Порядок: имя нашего сайта, которое открылось с этого компьютера (общее ядро
    ``zapret_update.mirrors``: список имён, входные страницы Zapret Links), иначе входная
    страница Zapret Links, которая сама подберёт в браузере рабочее зеркало. На GitHub
    обращений нет (там только копии выпусков), поэтому он не запасной путь.
    """

    try:
        url = site_names.resolve(CANONICAL_SUPPORT_URL)
        proven = site_names.proven()
    except Exception as error:  # noqa: BLE001 — сеть не должна ронять кнопку
        _log.warning("support: открытое имя сайта не найдено (%s), страница откроется через входную", type(error).__name__)
        return entry_page_url()
    if proven:
        return url
    _log.warning("support: ни одно зеркало не ответило приложению, страница откроется через входную страницу Zapret Links")
    return entry_page_url()
