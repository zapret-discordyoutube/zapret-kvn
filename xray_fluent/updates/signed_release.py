"""Подписанный список выпуска Zapret KVN: чем проверить архив обновления.

Сценарий выпуска кладёт в выпуск Forgejo ``update-manifest.json`` и подпись.
Программа скачивает их вместе с данными выпуска и проверяет подпись
открытыми ключами ниже (общее ядро ``zapret_update``, то же, что в Zapret 2
GUI). Контрольная сумма и размер архива берутся только из проверенного
списка: подменённый архив с подставленной суммой не пройдёт.

Ключи — рабочий и запасной; закрытые части у владельца, в git их нет.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping

from zapret_update.manifest import MANIFEST_NAME, MAX_MANIFEST_BYTES, SIGNATURE_NAME, Manifest, ManifestError, load_signed

PRODUCT = "zapret-kvn"
CHANNEL = "stable"
TRUSTED_KEYS: dict[str, bytes] = {
    "kvn-2026a": base64.b64decode("StnbabfKxv5ppg6qVBBMfJKY2j0LqG+IMtjRq3uYihE="),
    "kvn-reserve-1": base64.b64decode("m+YPRcb0w92jeopD6BjPj6TvsAh97GdAwBytFcZOrIM="),
}
MAX_SIGNATURE_BYTES = 1024


def signed_asset_urls(assets: list[Mapping], is_trusted: Callable[[str], bool]) -> tuple[str, str]:
    """Ссылки на список и подпись среди файлов выпуска; пустые, если их нет."""
    found = {}
    for asset in assets:
        name = str(asset.get("name") or "")
        url = str(asset.get("browser_download_url") or "")
        if name in (MANIFEST_NAME, SIGNATURE_NAME) and is_trusted(url):
            found[name] = url
    return found.get(MANIFEST_NAME, ""), found.get(SIGNATURE_NAME, "")


def verified_manifest(
    *,
    version: str,
    current_version: str,
    manifest_url: str,
    signature_url: str,
    fetch: Callable[[str, int], bytes],
) -> Manifest:
    """Проверенный список выпуска ``version``; иначе ``ManifestError``.

    ``fetch(url, предел_байт)`` — скачивание тем же путём, что данные выпуска.
    """
    if not manifest_url or not signature_url:
        raise ManifestError("в выпуске нет подписанного списка", "nosig")
    raw = fetch(manifest_url, MAX_MANIFEST_BYTES)
    signature = fetch(signature_url, MAX_SIGNATURE_BYTES)
    manifest = load_signed(
        raw, signature, trusted=TRUSTED_KEYS, product=PRODUCT, channel=CHANNEL, newer_than=current_version
    )
    if manifest.version != version:
        raise ManifestError(f"выпуск {version}, а подписанный список — {manifest.version}", "sign")
    if manifest.installer is None:
        raise ManifestError("в подписанном списке выпуска нет архива", "format")
    return manifest


__all__ = ["CHANNEL", "PRODUCT", "TRUSTED_KEYS", "signed_asset_urls", "verified_manifest"]
