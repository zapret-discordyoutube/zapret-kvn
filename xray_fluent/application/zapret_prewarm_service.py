"""П5: фоновый прогрев DNS-кэша zapret для нод текущего пула (AC13/AC14).

После успешного подключения промах кэша ``_proxy_resolution_cache`` уводит
горячий свитч UDP-прокси ноды в асинхронный резолв (и, возможно, рестарт
winws2). Прогрев заранее резолвит ``proxy_protection_server`` всех нод пула
батчем в существующем воркер-пуле, чтобы промахи стали редкими.

Гарантии (A7):
- наполняется ТОЛЬКО ``_proxy_resolution_cache`` через ``cache_proxy_resolution``;
- ``_set_protected_proxy_ips`` не вызывается, winws2 не перезапускается;
- GUI-поток не блокируется (батч уходит одним заданием в воркер-пул);
- ошибки резолва глотаются молча (максимум — итоговая строка в логе).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Callable, Iterable

from ..platform.windows.subprocess_utils import _SUBPROCESS_EXECUTOR

if TYPE_CHECKING:
    from .controller import AppController


#: Троттлинг батча: пауза между резолвами, чтобы не монополизировать воркер и DNS.
PREWARM_THROTTLE_SEC = 0.05


def collect_prewarm_servers(controller: AppController) -> list[str]:
    """Сервера UDP-прокси нод текущего пула, ещё не попавшие в кэш (A7).

    «Текущий пул» — ноды ``controller.xray_outbound_pool()``; если пул пуст,
    фолбэк на ``state.nodes``. Ноды без ``proxy_protection_server`` (не
    UDP-прокси) пропускаются (AC14).
    """

    try:
        pool_nodes = list(controller.xray_outbound_pool().nodes)
    except Exception:
        pool_nodes = []
    nodes = pool_nodes or list(controller.state.nodes)
    zapret = controller.zapret
    servers: list[str] = []
    seen: set[str] = set()
    for node in nodes:
        server = zapret.proxy_protection_server(node)
        if not server or server in seen:
            continue
        seen.add(server)
        if server in zapret._proxy_resolution_cache:
            continue
        servers.append(server)
    return servers


def prewarm_proxy_resolutions(
    servers: Iterable[str],
    resolve: Callable[[str], set[str]],
    cache: Callable[[str, set[str]], None],
    *,
    throttle_sec: float = PREWARM_THROTTLE_SEC,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Резолв батча (в воркере): только кэш, ошибки — молча (AC14)."""

    warmed = 0
    for server in servers:
        try:
            cache(server, resolve(server))
            warmed += 1
        except Exception:
            # AC14: ошибка резолва не всплывает ни статусом, ни исключением.
            pass
        if throttle_sec > 0:
            sleep(throttle_sec)
    return warmed


def start_proxy_dns_prewarm(
    controller: AppController,
    *,
    submit: Callable[[Callable[[], None]], object] | None = None,
) -> bool:
    """Поставить батч-прогрев в существующий воркер-пул (AC13); не блокирует.

    Возвращает ``True``, если задание поставлено (были непрогретые сервера).
    Все обращения к состоянию контроллера выполняются здесь (в GUI-потоке);
    воркеру уходит чистое замыкание над снятым списком серверов.
    """

    servers = collect_prewarm_servers(controller)
    if not servers:
        return False
    resolve = controller.zapret._resolve_server_ips
    cache = controller.zapret.cache_proxy_resolution
    log = controller._log
    total = len(servers)

    def _job() -> None:
        warmed = prewarm_proxy_resolutions(servers, resolve, cache)
        try:
            log(f"[zapret] DNS prewarm: {warmed}/{total} UDP proxy endpoints cached")
        except Exception:
            pass

    (submit or _SUBPROCESS_EXECUTOR.submit)(_job)
    return True
