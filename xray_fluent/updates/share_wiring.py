"""Раздача обновлений в Zapret KVN: что подставить в общий ``SharingService``.

Сама раздача (сервер файлов, поиск соседей, правило брандмауэра) лежит в общем
ядре ``zapret_update`` (``share_*``) и одинакова с Zapret 2 GUI. Здесь только
то, что знает одна эта программа: где она стоит, как называется продукт, откуда
взять включённость, подписанный список версии и куда писать журнал.

Подписанный список установленной версии лежит в ``data/runtime``: папка
``data`` обновление не трогает. Списка нет или он от другой версии — программа
берёт его сама, как только последний выпуск совпал с запущенной версией.
"""

from __future__ import annotations

import logging
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

from zapret_update import share_adopt, share_discover, share_internet, share_peers, share_service
from zapret_update.manifest import MAX_MANIFEST_BYTES, ManifestError, load_signed

from ..constants import APP_VERSION, BASE_DIR
from .installer.plan import APP_EXE_NAME
from .signed_release import CHANNEL, MAX_SIGNATURE_BYTES, PRODUCT, TRUSTED_KEYS, signed_asset_urls

_log = logging.getLogger(__name__)

INSTALLED_LIST = ("data", "runtime", "installed-manifest.json")
PEER_BOOK = ("data", "runtime", "update-peers.json")

_lock = threading.Lock()
_service: share_service.SharingService | None = None
_enabled = True
_internet = False
_book: share_peers.PeerBook | None = None
_book_lock = threading.Lock()


def is_enabled() -> bool:
    return _enabled


def is_internet_enabled() -> bool:
    return _internet


def peer_book() -> share_peers.PeerBook:
    """Книга соседей по интернету: в ``data/runtime``, которую обновление не трогает."""
    global _book
    with _book_lock:
        if _book is None:
            usable = sys.platform == "win32" and (BASE_DIR / APP_EXE_NAME).is_file()
            _book = share_peers.PeerBook(Path(BASE_DIR).joinpath(*PEER_BOOK) if usable else None)
        return _book


def registry_bases() -> list[str]:
    """Где сервер очереди ведёт книгу раздающих: тот же адрес, что и у вопроса об обновлениях."""
    from . import release_watch, site_names

    url = site_names.resolve(release_watch.WAIT_URL)
    return [url[: -len("/wait")]] if url.endswith("/wait") else []


def internet_finder(version: str):
    """Поиск соседей по интернету для запасного пути или ``None``, если человек не включил раздачу."""
    if not _internet:
        return None
    return lambda: share_internet.find_internet_neighbours(peer_book(), PRODUCT, version, bases=registry_bases())


def installed_manifest(root: Path):
    """Подписанный список установленной версии или ``None``."""
    path = Path(root).joinpath(*INSTALLED_LIST)
    try:
        return load_signed(
            path.read_bytes(),
            path.with_name(path.name + ".sig").read_bytes(),
            trusted=TRUSTED_KEYS,
            product=PRODUCT,
            channel=CHANNEL,
            allow_same=True,
        )
    except (OSError, ValueError):
        return None


def _lookup(_channel: str):
    """Новейший выпуск, как его видит проверка обновления (Forgejo и зеркала)."""
    from .app_updater import _ReleaseClient

    client = _ReleaseClient(None)
    try:
        data = client.fetch_release()
    except Exception as exc:  # noqa: BLE001
        return SimpleNamespace(release=None, error=str(exc))
    release = {
        "version": str(data.get("tag_name") or "").lstrip("v"),
        "assets": list(data.get("assets") or []),
        "client": client,
    }
    return SimpleNamespace(release=release, error="")


def _fetch(release, *, channel: str, current_version: str, allow_same: bool):
    """Подписанный список этого выпуска: с байтами и подписью, чтобы сохранить."""
    from .app_updater import _is_trusted_release_url

    manifest_url, signature_url = signed_asset_urls(release["assets"], _is_trusted_release_url)
    if not manifest_url or not signature_url:
        raise ManifestError("в выпуске нет подписанного списка", "nosig")
    client = release["client"]
    raw = client.fetch_signed(manifest_url, MAX_MANIFEST_BYTES)
    signature = client.fetch_signed(signature_url, MAX_SIGNATURE_BYTES)
    manifest = load_signed(
        raw, signature, trusted=TRUSTED_KEYS, product=PRODUCT, channel=CHANNEL,
        newer_than=current_version, allow_same=allow_same,
    )
    return SimpleNamespace(manifest=manifest, raw=bytes(raw), signature=bytes(signature))


def default_service() -> share_service.SharingService:
    global _service
    with _lock:
        if _service is None:
            root = BASE_DIR if sys.platform == "win32" and (BASE_DIR / APP_EXE_NAME).is_file() else None
            report = _log.info
            exe = (root / APP_EXE_NAME) if root else None
            side = share_internet.InternetSide(
                product=PRODUCT,
                book=peer_book(),
                bases=registry_bases,
                open_firewall=(
                    lambda port: share_service.windows_open_firewall(
                        exe, name=share_service.FIREWALL_RULE_NAME_INTERNET, remote="any", port=port
                    )
                )
                if exe
                else None,
                report=report,
            )
            _service = share_service.SharingService(
                root=root,
                enabled=is_enabled,
                load_installed=lambda: installed_manifest(root) if root else None,
                product=PRODUCT,
                current_version=APP_VERSION,
                adopt=lambda: share_adopt.adopt_installed_list(
                    root,
                    channel=CHANNEL,
                    version=APP_VERSION,
                    list_path=INSTALLED_LIST,
                    lookup=_lookup,
                    fetch=_fetch,
                    report=report,
                )
                if root
                else None,
                exe_path=exe,
                private_network=share_service.windows_private_network,
                open_firewall=share_service.windows_open_firewall,
                discovery_port=share_discover.DISCOVERY_PORT_KVN,
                report=report,
                internet_enabled=is_internet_enabled,
                internet=side,
            )
        return _service


def apply_setting(enabled: bool, internet: bool = False, *, wait: bool = False) -> None:
    """Выключатели изменились (или программа запустилась): включить или закрыть обе раздачи.

    Поход в сеть и Windows-команды идут в фоновом потоке, чтобы окно не ждало.
    """
    global _enabled, _internet
    _enabled, _internet = bool(enabled), bool(internet)

    def run() -> None:
        try:
            default_service().refresh()
        except Exception as exc:  # noqa: BLE001 — раздача не должна ронять программу
            _log.warning("[share] раздача обновлений не переключилась: %s", exc)

    thread = threading.Thread(target=run, name="update-share", daemon=True)
    thread.start()
    if wait:
        thread.join()


__all__ = [
    "INSTALLED_LIST", "apply_setting", "default_service", "installed_manifest", "internet_finder", "is_enabled",
    "is_internet_enabled", "peer_book", "registry_bases",
]
