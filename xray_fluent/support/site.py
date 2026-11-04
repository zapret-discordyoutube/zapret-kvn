"""Страница поддержки на открытом имени сайта проекта."""

from __future__ import annotations

import logging

from zapret_update import mirrors as git_mirrors

from ..updates import site_names
from ..updates.app_updater import GITHUB_REPO_URL

_log = logging.getLogger(__name__)

SUPPORT_PATH = "/zapretkvn/zapret-kvn/issues/new"
# Основное имя: ядро само подставляет вместо него то, которое сейчас открывается.
CANONICAL_SUPPORT_URL = f"https://{git_mirrors.CANONICAL_HOST}{SUPPORT_PATH}"
# Запасной сайт, когда не открывается ни одно зеркало (решение владельца 2026-11-04).
GITHUB_SUPPORT_URL = f"{GITHUB_REPO_URL}/issues/new"


def support_url() -> str:
    """Страница нового обращения. Ждёт сеть: только из фонового потока.

    Порядок: открытое имя нашего сайта (общее ядро ``zapret_update.mirrors``: список
    имён, входные страницы Zapret Links) → страница обращений в репозитории на GitHub,
    если не ответило ни одно имя. Лучше работающая страница, чем зеркало, которое не
    откроется; если поиск имени сам упал, берётся основное имя.
    """

    try:
        url = site_names.resolve(CANONICAL_SUPPORT_URL)
    except Exception as error:  # noqa: BLE001 — сеть не должна ронять кнопку
        _log.warning("support: открытое имя сайта не найдено (%s), берётся основное", type(error).__name__)
        return CANONICAL_SUPPORT_URL
    if site_names.proven():
        return url
    _log.warning("support: ни одно зеркало не ответило, страница обращений — на GitHub")
    return GITHUB_SUPPORT_URL
