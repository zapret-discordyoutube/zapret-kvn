"""Страница поддержки на открытом имени сайта проекта."""

from __future__ import annotations

import logging

from zapret_update import mirrors as git_mirrors

from ..updates import site_names

_log = logging.getLogger(__name__)

SUPPORT_PATH = "/zapretkvn/zapret-kvn/issues/new"
# Основное имя: ядро само подставляет вместо него то, которое сейчас открывается.
CANONICAL_SUPPORT_URL = f"https://{git_mirrors.CANONICAL_HOST}{SUPPORT_PATH}"


def entry_page_url(path: str = SUPPORT_PATH, family: str = "git") -> str:
    """Входная страница Zapret Links с путём нашего сайта: запас, когда приложение само не нашло открывающееся зеркало.

    Адрес и сборка ссылки — в общем ядре (``zapret_update.mirrors.entry_page_url``), одни и те же у Zapret 2 GUI
    и здесь. Семейство ``git`` — сервер Forgejo (по умолчанию), ``wiki`` — вики проекта.
    """

    return git_mirrors.entry_page_url(path, family)


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
