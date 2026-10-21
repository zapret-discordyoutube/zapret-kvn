"""Открытое имя сервера обновлений: выбирается один раз для проверки выпуска и очереди.

Основное имя ``git.zapret.moe`` режут по TLS, а тот же Forgejo под ``git2…``/
``git3…`` открывается. Список имён и выбор — в общем ядре
(``zapret_update.mirrors``); здесь один общий список на программу. Проверка
выпуска (``app_updater``) сообщает сюда имя, под которым ей ответили, а очередь
обновлений (``release_watch``) спрашивает сервер под этим же именем.
"""

from __future__ import annotations

import logging
from urllib.request import Request

from zapret_update import mirrors as git_mirrors

from ..network.http_utils import fetch_bytes

_log = logging.getLogger(__name__)

_MIRROR_LIST_TIMEOUT = 3
_MAX_MIRROR_LIST_BYTES = 64 * 1024


def _fetch_names(url: str) -> bytes | None:
    """Список имён сервера: одна короткая попытка на каждом маршруте."""
    from .app_updater import USER_AGENT

    response = fetch_bytes(
        Request(url, headers={"Accept": "application/json", "User-Agent": USER_AGENT}),
        timeout=_MIRROR_LIST_TIMEOUT,
        max_bytes=_MAX_MIRROR_LIST_BYTES,
        attempts_per_route=1,
    )
    return response.data


_NAMES = git_mirrors.MirrorList(
    _fetch_names,
    report=lambda message: _log.info("[update] Имена сервера: %s", message),
)


def remember(host: str) -> None:
    """Под этим именем сервер только что ответил: дальше выбор начинается с него."""
    _NAMES.remember(host)


def resolve(url: str) -> str:
    """Тот же адрес под открытым именем сервера; чужой адрес возвращается как есть.

    Может ждать сеть (первый раз): только из фонового потока.
    """
    if not git_mirrors.is_rewritable(url):
        return str(url)
    return git_mirrors.with_host(url, _NAMES.choose())


__all__ = ["remember", "resolve"]
