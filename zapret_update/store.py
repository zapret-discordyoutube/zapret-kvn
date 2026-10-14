"""Хранилище файлов выпуска: файл по контрольной сумме и заплатки zstd.

Каждый файл программы лежит в хранилище один раз, под SHA-256 несжатого
содержимого, сжатый zstd: ``<sha256>.zst``. Не изменившийся между версиями
файл не хранится и не качается второй раз.

Для больших изменившихся файлов сборка кладёт заплатку от прежних версий:
``<sha256 прежнего>-<sha256 нового>.zst`` — новый файл, сжатый zstd с прежним
файлом в роли словаря (как ``zstd --patch-from``). Программа, у которой на
диске лежит прежний файл, качает заплатку: замер на Zapret KVN 0.8.21 → 0.8.22
— ``ZapretKVN.exe`` 0,09 МБ вместо 5,8 МБ. Где zstd помогает плохо (у
``Zapret.exe`` сдвигаются адреса по всему файлу), рядом лежит заплатка bsdiff
``<прежний>-<новый>.bsdiff`` (``zapret_update.bsdiff``).

Где лежит хранилище (одинаково для всех источников, имя файла — то же):

- Forgejo: ``https://git.zapret.moe/api/packages/<владелец>/generic/<продукт>-store/1/<имя>``
- зеркало: ``https://<зеркало>/store/<продукт>/<имя>``

Сжатие — ``compression.zstd`` из стандартной библиотеки Python 3.14; модуль
импортируется только при работе с содержимым, поэтому список выпуска и подпись
работают и на более старом Python.
"""

from __future__ import annotations

import hashlib
import math
import re

# Заплатки делаются только для файлов не меньше этого: маленький файл целиком
# весит столько же, сколько заплатка.
PATCH_MIN_SIZE = 256 * 1024
# Заплатка от скольких прежних версий канала хранится.
PATCH_FROM_VERSIONS = 3
# Окно zstd: прежний файл в роли словаря плюс новый должны в него помещаться.
MAX_WINDOW_LOG = 30
COMPRESSION_LEVEL = 19

_NAME_RE = re.compile(r"\A(?:[0-9a-f]{64}(?:-[0-9a-f]{64})?\.zst|[0-9a-f]{64}-[0-9a-f]{64}\.bsdiff)\Z")
_PATCH_SUFFIX = {"zstd": ".zst", "bsdiff": ".bsdiff"}


class StoreError(ValueError):
    """Файл хранилища не тот: не распаковался или не совпала контрольная сумма."""

    code = "hash"


def blob_name(sha256: str) -> str:
    return f"{sha256}.zst"


def patch_name(from_sha256: str, to_sha256: str, kind: str = "zstd") -> str:
    return f"{from_sha256}-{to_sha256}{_PATCH_SUFFIX[kind]}"


def patch_file_name(patch) -> str:
    """Имя заплатки из записи списка выпуска (``manifest.PatchEntry``)."""
    return patch_name(patch.from_sha256, patch.to_sha256, getattr(patch, "kind", "zstd"))


def is_store_name(name: str) -> bool:
    return bool(_NAME_RE.fullmatch(str(name or "")))


def forgejo_url(origin: str, owner: str, product: str, name: str) -> str:
    return f"{origin.rstrip('/')}/api/packages/{owner}/generic/{product}-store/1/{name}"


def mirror_url(base: str, product: str, name: str) -> str:
    return f"{base.rstrip('/')}/store/{product}/{name}"


def _window_log(*sizes: int) -> int:
    total = max(sum(sizes), 1)
    return min(max(int(math.ceil(math.log2(total))) + 1, 20), MAX_WINDOW_LOG)


def _zstd():
    from compression import zstd

    return zstd


def compress(data: bytes) -> bytes:
    zstd = _zstd()
    options = {
        zstd.CompressionParameter.compression_level: COMPRESSION_LEVEL,
        zstd.CompressionParameter.window_log: _window_log(len(data)),
        zstd.CompressionParameter.enable_long_distance_matching: 1,
    }
    return zstd.compress(bytes(data), options=options)


def make_patch(old: bytes, new: bytes) -> bytes:
    """Новый файл, сжатый с прежним в роли словаря."""
    zstd = _zstd()
    options = {
        zstd.CompressionParameter.compression_level: COMPRESSION_LEVEL,
        zstd.CompressionParameter.window_log: _window_log(len(old), len(new)),
        zstd.CompressionParameter.enable_long_distance_matching: 1,
    }
    return zstd.compress(bytes(new), options=options, zstd_dict=zstd.ZstdDict(bytes(old), is_raw=True))


def _decompress(data: bytes, dictionary: bytes | None = None) -> bytes:
    zstd = _zstd()
    options = {zstd.DecompressionParameter.window_log_max: MAX_WINDOW_LOG + 1}
    zstd_dict = zstd.ZstdDict(bytes(dictionary), is_raw=True) if dictionary is not None else None
    try:
        return zstd.decompress(bytes(data), zstd_dict=zstd_dict, options=options)
    except zstd.ZstdError as exc:
        raise StoreError(f"файл хранилища не распаковался: {exc}") from None


def _checked(data: bytes, sha256: str, size: int) -> bytes:
    if len(data) != size or hashlib.sha256(data).hexdigest() != sha256:
        raise StoreError("файл из хранилища не совпал с контрольной суммой списка выпуска")
    return data


def unpack_blob(data: bytes, *, sha256: str, size: int) -> bytes:
    """Файл из ``<sha256>.zst``, проверенный по списку выпуска."""
    return _checked(_decompress(data), sha256, size)


def apply_patch(old: bytes, data: bytes, *, sha256: str, size: int, kind: str = "zstd") -> bytes:
    """Новый файл из заплатки и прежнего файла, проверенный по списку выпуска."""
    if kind == "bsdiff":
        from . import bsdiff

        try:
            return _checked(bsdiff.apply(old, data, expected_size=size), sha256, size)
        except bsdiff.BsdiffError as exc:
            raise StoreError(f"заплатка bsdiff не наложилась: {exc}") from None
    return _checked(_decompress(data, old), sha256, size)


__all__ = [
    "PATCH_FROM_VERSIONS",
    "PATCH_MIN_SIZE",
    "StoreError",
    "apply_patch",
    "blob_name",
    "compress",
    "forgejo_url",
    "is_store_name",
    "make_patch",
    "mirror_url",
    "patch_file_name",
    "patch_name",
    "unpack_blob",
]
