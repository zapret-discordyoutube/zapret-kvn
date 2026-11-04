"""Страница поддержки на открытом имени сайта проекта."""

from __future__ import annotations

import logging

from zapret_update import mirrors as git_mirrors

from ..updates import site_names

_log = logging.getLogger(__name__)

SUPPORT_PATH = "/zapretkvn/zapret-kvn/issues/new"
# Основное имя: ядро само подставляет вместо него то, которое сейчас открывается.
CANONICAL_SUPPORT_URL = f"https://{git_mirrors.CANONICAL_HOST}{SUPPORT_PATH}"


def support_url() -> str:
    """Страница нового обращения под открытым именем. Ждёт сеть: только из фонового потока.

    Если открытое имя найти не вышло, возвращается основное: лучше страница,
    которая может не открыться, чем кнопка, которая ничего не делает.
    """

    try:
        return site_names.resolve(CANONICAL_SUPPORT_URL)
    except Exception as error:  # noqa: BLE001 — сеть не должна ронять кнопку
        _log.warning("support: открытое имя сайта не найдено (%s), берётся основное", type(error).__name__)
        return CANONICAL_SUPPORT_URL
