"""Публикация хранилища выпуска в реестр пакетов Forgejo (машина сборки).

Одна и та же заливка у сборок Zapret 2 GUI и Zapret KVN. Файлы хранилища
лежат пакетом ``<владелец>/generic/<продукт>-store/1/<имя>``.

HEAD у реестра пакетов размера не сообщает, поэтому что уже лежит в реестре
(и целы ли эти файлы) узнаётся одним запросом списка файлов пакета: у
каждого — размер и SHA-256. Не тот файл перезаливается, после заливки весь
набор сверяется.

Уборка (``prune``): файлы, на которые не ссылается ни один из переданных
подписанных списков выпусков, удаляются — так же, как на зеркалах. Списки
передаёт сценарий выпуска своей программы: текущий и несколько прежних
каждого канала, хранилище которого общее.

Ключ доступа — отдельный, только на запись пакетов.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from pathlib import Path

from . import store
from .manifest import file_sha256

ORIGIN = "https://git.zapret.moe"
TIMEOUT = 120
UPLOAD_TIMEOUT = 900


def files_api(owner: str, product: str, origin: str = ORIGIN) -> str:
    return f"{origin}/api/v1/packages/{owner}/generic/{product}-store/1/files"


def remote_files(owner: str, product: str, origin: str = ORIGIN) -> dict[str, tuple[int, str]]:
    """Что уже лежит в реестре: ``{имя: (размер, sha256 сжатого файла)}``."""
    request = urllib.request.Request(files_api(owner, product, origin), headers={"User-Agent": "ZapretRelease"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            listed = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:  # пакета ещё нет: первый выпуск с хранилищем
            return {}
        raise
    return {
        str(item.get("name")): (int(item.get("Size") or item.get("size") or 0), str(item.get("sha256") or ""))
        for item in listed
        if isinstance(item, dict)
    }


def upload(
    names: Iterable[str],
    *,
    cache_dir: Path,
    owner: str,
    product: str,
    token: str,
    origin: str = ORIGIN,
    log: Callable[[str], None] = lambda _message: None,
    listing: Callable[[], dict[str, tuple[int, str]]] | None = None,
) -> int:
    """Заливает в реестр недостающие файлы хранилища; возвращает, сколько залито."""
    if not token:
        raise RuntimeError("нет ключа доступа к хранилищу выпуска")
    list_remote = listing or (lambda: remote_files(owner, product, origin))
    wanted = {name: Path(cache_dir) / name for name in sorted(set(names))}
    expected = {name: (path.stat().st_size, file_sha256(path)) for name, path in wanted.items()}
    present = list_remote()
    headers = {"Authorization": f"token {token}", "User-Agent": "ZapretRelease"}
    uploaded = 0
    for name, local in wanted.items():
        if present.get(name) == expected[name]:
            continue
        url = store.forgejo_url(origin, owner, product, name)
        if name in present:
            # Лежит не тот файл: убрать и залить заново.
            with urllib.request.urlopen(urllib.request.Request(url, method="DELETE", headers=headers), timeout=TIMEOUT):
                pass
        with local.open("rb") as source:
            request = urllib.request.Request(
                url,
                data=source,
                method="PUT",
                headers={**headers, "Content-Type": "application/octet-stream", "Content-Length": str(expected[name][0])},
            )
            try:
                with urllib.request.urlopen(request, timeout=UPLOAD_TIMEOUT):
                    pass
            except urllib.error.HTTPError as exc:
                if exc.code != 409:  # уже лежит — залил параллельный выпуск
                    raise RuntimeError(f"хранилище не приняло {name}: HTTP {exc.code}") from None
        uploaded += 1
    if uploaded:
        present = list_remote()
    broken = [name for name in wanted if present.get(name) != expected[name]]
    if broken:
        raise RuntimeError(f"в хранилище не тот или нет файл: {broken[0]} (и ещё {len(broken) - 1})")
    log(f"в хранилище залито файлов: {uploaded} из {len(wanted)}, все сверены")
    return uploaded


def prune(
    keep_manifests: Iterable,
    *,
    owner: str,
    product: str,
    token: str,
    origin: str = ORIGIN,
    log: Callable[[str], None] = lambda _message: None,
    listing: Callable[[], dict[str, tuple[int, str]]] | None = None,
) -> int:
    """Убирает из реестра файлы хранилища, не нужные ни одному из ``keep_manifests``.

    Без списков ничего не удаляется: пустой набор «что оставить» значил бы
    «удалить всё», а это скорее сбой получения выпусков, чем намерение.
    """
    if not token:
        raise RuntimeError("нет ключа доступа к хранилищу выпуска")
    manifests = list(keep_manifests)
    if not manifests:
        raise ValueError("уборка хранилища без списков выпусков удалила бы всё")
    keep: set[str] = set()
    for listed in manifests:
        keep |= manifest_names(listed)
    present = (listing or (lambda: remote_files(owner, product, origin)))()
    missing = sorted(keep - set(present))
    if any(name in missing for name in manifest_names(manifests[0])):
        raise RuntimeError("текущий выпуск ещё не весь в хранилище — уборка отложена")
    headers = {"Authorization": f"token {token}", "User-Agent": "ZapretRelease"}
    removed = 0
    for name in sorted(present):
        if name in keep or not store.is_store_name(name):
            continue
        request = urllib.request.Request(store.forgejo_url(origin, owner, product, name), method="DELETE", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT):
                pass
        except urllib.error.HTTPError as exc:
            if exc.code != 404:  # уже убрал параллельный выпуск
                raise RuntimeError(f"хранилище не отдало на удаление {name}: HTTP {exc.code}") from None
        removed += 1
    log(f"из хранилища убрано ненужных файлов: {removed}, осталось {len(present) - removed}")
    return removed


def manifest_names(manifest) -> set[str]:
    """Имена файлов хранилища, на которые ссылается список выпуска."""
    names = {store.blob_name(entry.sha256) for entry in manifest.files}
    names.update(store.patch_file_name(item) for item in manifest.patches)
    return names


__all__ = ["files_api", "manifest_names", "prune", "remote_files", "upload"]
