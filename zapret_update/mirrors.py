"""Имена сайтов проекта и выбор открытого из них (общее ядро обновления).

Один и тот же сайт открывается под несколькими именами: основное
``git.zapret.moe`` и зеркала ``git2.zapret.moe``, ``git3.zapret.moe`` и так
далее; так же устроена вики (``wiki.zapret.moe``, ``wiki2…``). С 2026-10-19
российские провайдеры режут TLS по основному имени, а зеркала открываются,
поэтому программа, которой нужен сайт (проверка обновления, загрузка, кнопки со
ссылками), сама находит открытое имя.

Список имён отдаёт сам сервер: ``https://<любое имя>/_sites/mirrors.json``
(схема 1: ``families.<семейство>.preferred`` и ``families.<семейство>.names[]``
с признаками ``blocked``/``open``; семейства ``git`` и ``wiki``). Он пополняется
новыми зеркалами сам, поэтому свой длинный список держать не нужно: запасной
список ``BOOTSTRAP_HOSTS`` нужен только чтобы скачать этот файл (и как запас,
когда скачать его не вышло).

Адрес ссылок и проверки доверия остаются на основном имени: любое имя вида
``git*.zapret.moe`` приводится к нему функцией ``canonical_url``, а для обмена
подставляется открытое — ``with_host``. Подставить можно только имя того же
семейства: адрес вики под именем git не превращается. Модуль без Qt и сторонних
библиотек.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

CANONICAL_HOST = "git.zapret.moe"
FAMILIES = ("git", "wiki")
MIRRORS_PATH = "/_sites/mirrors.json"
# Запасной список: сначала зеркала, основное имя в конце (пометка «заблокировано»
# в списке сервера измерена из российских сетей, а не с этой машины, но на
# практике основное имя закрывают первым).
BOOTSTRAP_HOSTS = (*(f"git{number}.zapret.moe" for number in range(2, 9)), CANONICAL_HOST)
WIKI_BOOTSTRAP_HOSTS = (*(f"wiki{number}.zapret.moe" for number in range(2, 9)), "wiki.zapret.moe")
MAX_PUBLISHED_HOSTS = 16
LIST_TTL_S = 600.0
# Не удалось ни скачать список, ни разобрать: запасной список держится недолго.
FALLBACK_TTL_S = 60.0

_HOST_RE = re.compile(r"^(git|wiki)\d*\.zapret\.moe$", re.IGNORECASE)


def family_of(host: str | None) -> str:
    """Семейство имени (``git`` или ``wiki``); пусто, если это не имя сайта проекта."""
    match = _HOST_RE.fullmatch(str(host or ""))
    return match.group(1).lower() if match else ""


def canonical_host(family: str) -> str:
    """Основное имя семейства: ``git.zapret.moe`` или ``wiki.zapret.moe``."""
    return f"{family}.zapret.moe" if family in FAMILIES else ""


def is_git_host(host: str | None) -> bool:
    """Имя git-сервера проекта: основное или зеркало (git, git2, git3, … .zapret.moe)."""
    return family_of(host) == "git"


def is_site_host(host: str | None) -> bool:
    """Имя любого сайта проекта: git или вики, основное или зеркало."""
    return bool(family_of(host))


def bootstrap_hosts(family: str) -> tuple[str, ...]:
    """Запасной список имён семейства: сначала зеркала, основное имя последним."""
    return WIKI_BOOTSTRAP_HOSTS if family == "wiki" else BOOTSTRAP_HOSTS


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


def is_rewritable(url: str) -> bool:
    """Обычный https-адрес сайта проекта (без порта и учётных данных): имя в нём можно заменить."""
    try:
        parsed = urlsplit(str(url))
    except ValueError:
        return False
    return _plain_https(parsed) and bool(family_of(parsed.hostname))


def with_host(url: str, host: str) -> str:
    """Тот же адрес под другим именем того же сайта проекта.

    Меняется только имя хоста, и только у https-адреса сайта проекта без порта и
    учётных данных, на имя того же семейства (git на git, вики на вики). Иначе
    адрес возвращается как есть: подменить хост чужого адреса через этот модуль
    нельзя.
    """
    family = family_of(host)
    if not family:
        return str(url)
    try:
        parsed = urlsplit(str(url))
    except ValueError:
        return str(url)
    if not _plain_https(parsed) or family_of(parsed.hostname) != family:
        return str(url)
    return parsed._replace(netloc=host.lower()).geturl()


def canonical_url(url: str) -> str:
    """Адрес на любом имени сайта проекта приводится к основному (для проверок доверия)."""
    return with_host(url, canonical_host(family_of(host_of(url))))


def ordered_hosts(document: Any, family: str = "git") -> list[str]:
    """Имена семейства из списка сервера в порядке предпочтения; пусто, если список не разобрать.

    Сначала ``preferred`` (если он не помечен заблокированным), затем остальные,
    не помеченные заблокированными, в конце заблокированные: помечены они из
    российских домашних сетей, а с этой машины всё равно могут открываться.
    """
    try:
        entry = document["families"][family]
        items = [item for item in entry["names"] if isinstance(item, dict)]
        preferred = str(entry.get("preferred") or "").strip().lower()
    except (KeyError, TypeError, AttributeError):
        return []
    open_names: list[str] = []
    blocked_names: list[str] = []
    for item in items:
        name = str(item.get("name") or "").strip().lower()
        if family_of(name) != family or name in open_names or name in blocked_names:
            continue
        (blocked_names if item.get("blocked") is True else open_names).append(name)
    if preferred in open_names:
        open_names.remove(preferred)
        open_names.insert(0, preferred)
    return (open_names + blocked_names)[:MAX_PUBLISHED_HOSTS]


class MirrorList:
    """Открытые имена сайта (семейство ``git`` или ``wiki``): из списка сервера, запомненное удачное — первым.

    ``fetch(url)`` — короткий (одна попытка, несколько секунд) запрос без
    повторов, возвращает тело ответа или ``None``/бросает ошибку. Работает на
    маршруте вызывающего: прямом или через прокси.

    ``report(строка)`` — необязательный журнал: откуда получен список имён и по
    какой причине не вышло с каждым именем (без него по записи «Forgejo
    недоступен» не понять, чем именно закрыты зеркала на этом компьютере).
    """

    def __init__(
        self,
        fetch: Callable[[str], bytes | None],
        *,
        family: str = "git",
        clock: Callable[[], float] = time.monotonic,
        report: Callable[[str], None] | None = None,
    ) -> None:
        self._fetch = fetch
        self._family = family
        self._clock = clock
        self._report = report
        self._hosts: list[str] | None = None
        self._expires_at = 0.0
        self._good: str | None = None

    def remember(self, host: str) -> None:
        """Под этим именем только что получили ответ: пробовать его первым."""
        if family_of(host) == self._family:
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
                self._hosts, self._expires_at = list(bootstrap_hosts(self._family)), now + FALLBACK_TTL_S
        hosts = list(self._hosts)
        if self._good in hosts:
            hosts.remove(self._good)
            hosts.insert(0, self._good)
        return hosts

    def _say(self, message: str) -> None:
        if self._report is None:
            return
        try:
            self._report(message)
        except Exception:
            pass

    def _download_list(self) -> list[str]:
        failures: list[str] = []
        # Список один на все семейства, поэтому если свои имена закрыты, он
        # скачивается и с имён соседнего семейства.
        others = [name for name in FAMILIES if name != self._family]
        sources = [*bootstrap_hosts(self._family), *(host for name in others for host in bootstrap_hosts(name))]
        for host in sources:
            try:
                body = self._fetch(f"https://{host}{MIRRORS_PATH}")
                if not body:
                    failures.append(f"{host}: пустой ответ")
                    continue
                ordered = ordered_hosts(json.loads(body), self._family)
            except Exception as exc:
                failures.append(f"{host}: {type(exc).__name__}: {str(exc)[:120]}")
                continue
            if ordered:
                self._say(f"список имён сервера получен с {host}: {', '.join(ordered)}")
                return ordered
            failures.append(f"{host}: список без имён")
        self._say("список имён сервера не получен, берётся запасной; " + "; ".join(failures))
        return []

    def choose(self) -> str:
        """Имя, под которым сайт открывается сейчас, и оно же запоминается.

        Запомненное имя отдаётся сразу (выбор делается один раз). Иначе имена
        из списка пробуются по порядку коротким запросом, первое ответившее
        запоминается. Не ответило ни одно — первое по порядку (пометка
        «заблокировано» в списке измерена из российских сетей, поэтому лучшая
        догадка), без запоминания: в следующий раз выбор повторится.
        """
        if self._good is not None:
            return self._good
        hosts = self.hosts()
        for host in hosts:
            try:
                if self._fetch(f"https://{host}{MIRRORS_PATH}"):
                    self.remember(host)
                    return host
            except Exception as exc:
                self.note_failure(host, exc)
        return hosts[0] if hosts else canonical_host(self._family)

    def note_failure(self, host: str, exc: BaseException) -> None:
        """Журнал: под этим именем сервер не ответил (причина — для разбора на компьютере пользователя)."""
        self._say(f"{host}: {type(exc).__name__}: {str(exc)[:160]}")


__all__ = [
    "BOOTSTRAP_HOSTS",
    "CANONICAL_HOST",
    "FAMILIES",
    "MIRRORS_PATH",
    "MirrorList",
    "WIKI_BOOTSTRAP_HOSTS",
    "bootstrap_hosts",
    "canonical_host",
    "canonical_url",
    "family_of",
    "host_of",
    "is_git_host",
    "is_rewritable",
    "is_site_host",
    "ordered_hosts",
    "with_host",
]
