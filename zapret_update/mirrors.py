"""Имена git-сервера проекта и выбор открытого из них (общее ядро обновления).

Один и тот же Forgejo открывается под несколькими именами: основное
``git.zapret.moe`` и зеркала ``git2.zapret.moe``, ``git3.zapret.moe`` и так
далее. С 2026-10-19 российские провайдеры режут TLS по основному имени, а
зеркала открываются, поэтому программа, которой нужен Forgejo (проверка
обновления, загрузка), сама находит открытое имя.

Список имён отдаёт сам сервер: ``https://<любое имя>/_sites/mirrors.json``
(схема 1: ``families.git.preferred`` и ``families.git.names[]`` с признаками
``blocked``/``open``). Он пополняется новыми зеркалами сам, поэтому свой длинный
список держать не нужно: запасной список ``BOOTSTRAP_HOSTS`` нужен только чтобы
скачать этот файл (и как запас, когда скачать его не вышло).

Адрес ссылок и проверки доверия остаются на основном имени: любое имя вида
``git*.zapret.moe`` приводится к нему функцией ``canonical_url``, а для обмена
подставляется открытое — ``with_host``. Модуль без Qt и сторонних библиотек.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

CANONICAL_HOST = "git.zapret.moe"
MIRRORS_PATH = "/_sites/mirrors.json"
# Запасной список: сначала зеркала, основное имя в конце (пометка «заблокировано»
# в списке сервера измерена из российских сетей, а не с этой машины, но на
# практике основное имя закрывают первым).
BOOTSTRAP_HOSTS = (*(f"git{number}.zapret.moe" for number in range(2, 9)), CANONICAL_HOST)
MAX_PUBLISHED_HOSTS = 16
LIST_TTL_S = 600.0
# Не удалось ни скачать список, ни разобрать: запасной список держится недолго.
FALLBACK_TTL_S = 60.0

_HOST_RE = re.compile(r"^git\d*\.zapret\.moe$", re.IGNORECASE)


def is_git_host(host: str | None) -> bool:
    """Имя git-сервера проекта: основное или зеркало (git, git2, git3, … .zapret.moe)."""
    return bool(host) and bool(_HOST_RE.fullmatch(str(host)))


def _plain_https(parsed) -> bool:
    try:
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme.lower() == "https"
        and port in (None, 443)
        and parsed.username is None
        and parsed.password is None
    )


def host_of(url: str) -> str:
    """Имя хоста из адреса в нижнем регистре; пусто, если адрес не разобрать."""
    try:
        return (urlsplit(str(url or "")).hostname or "").lower()
    except ValueError:
        return ""


def with_host(url: str, host: str) -> str:
    """Тот же адрес под другим именем git-сервера.

    Меняется только имя хоста, и только у https-адреса git-сервера без порта и
    учётных данных, на имя git-сервера. Иначе адрес возвращается как есть:
    подменить хост чужого адреса через этот модуль нельзя.
    """
    if not is_git_host(host):
        return str(url)
    try:
        parsed = urlsplit(str(url))
    except ValueError:
        return str(url)
    if not _plain_https(parsed) or not is_git_host(parsed.hostname):
        return str(url)
    return parsed._replace(netloc=host.lower()).geturl()


def canonical_url(url: str) -> str:
    """Адрес на любом имени git-сервера приводится к основному (для проверок доверия)."""
    return with_host(url, CANONICAL_HOST)


def ordered_hosts(document: Any) -> list[str]:
    """Имена из списка сервера в порядке предпочтения; пусто, если список не разобрать.

    Сначала ``preferred`` (если он не помечен заблокированным), затем остальные,
    не помеченные заблокированными, в конце заблокированные: помечены они из
    российских домашних сетей, а с этой машины всё равно могут открываться.
    """
    try:
        family = document["families"]["git"]
        items = [item for item in family["names"] if isinstance(item, dict)]
        preferred = str(family.get("preferred") or "").strip().lower()
    except (KeyError, TypeError, AttributeError):
        return []
    open_names: list[str] = []
    blocked_names: list[str] = []
    for item in items:
        name = str(item.get("name") or "").strip().lower()
        if not is_git_host(name) or name in open_names or name in blocked_names:
            continue
        (blocked_names if item.get("blocked") is True else open_names).append(name)
    if preferred in open_names:
        open_names.remove(preferred)
        open_names.insert(0, preferred)
    return (open_names + blocked_names)[:MAX_PUBLISHED_HOSTS]


class MirrorList:
    """Открытые имена git-сервера: из списка сервера, запомненное удачное — первым.

    ``fetch(url)`` — короткий (одна попытка, несколько секунд) запрос без
    повторов, возвращает тело ответа или ``None``/бросает ошибку. Работает на
    маршруте вызывающего: прямом или через прокси.
    """

    def __init__(
        self,
        fetch: Callable[[str], bytes | None],
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._fetch = fetch
        self._clock = clock
        self._hosts: list[str] | None = None
        self._expires_at = 0.0
        self._good: str | None = None

    def remember(self, host: str) -> None:
        """Под этим именем только что получили ответ: пробовать его первым."""
        if is_git_host(host):
            self._good = host.lower()

    def forget(self) -> None:
        self._hosts = None
        self._good = None

    def hosts(self) -> list[str]:
        """Имена в порядке, в котором их пробовать."""
        now = self._clock()
        if self._hosts is None or now >= self._expires_at:
            published = self._download_list()
            if published:
                self._hosts, self._expires_at = published, now + LIST_TTL_S
            else:
                self._hosts, self._expires_at = list(BOOTSTRAP_HOSTS), now + FALLBACK_TTL_S
        hosts = list(self._hosts)
        if self._good in hosts:
            hosts.remove(self._good)
            hosts.insert(0, self._good)
        return hosts

    def _download_list(self) -> list[str]:
        for host in BOOTSTRAP_HOSTS:
            try:
                body = self._fetch(f"https://{host}{MIRRORS_PATH}")
                if not body:
                    continue
                ordered = ordered_hosts(json.loads(body))
            except Exception:
                continue
            if ordered:
                return ordered
        return []


__all__ = [
    "BOOTSTRAP_HOSTS",
    "CANONICAL_HOST",
    "MIRRORS_PATH",
    "MirrorList",
    "canonical_url",
    "host_of",
    "is_git_host",
    "ordered_hosts",
    "with_host",
]
