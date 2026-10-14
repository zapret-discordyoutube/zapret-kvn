"""Подписанный список выпуска.

Список называет всё, из чего состоит версия: файлы программы с размером и
SHA-256 и установщик. Рядом лежит подпись Ed25519 над точными байтами списка.
Программа верит скачанному файлу, только если он есть в списке с верной
подписью, — тогда подменённый файл не пройдёт, даже если его отдаёт
взломанное зеркало вместе с подходящей контрольной суммой.

Порядок проверки (``load_signed``): сначала подпись над байтами — до разбора
JSON, — потом продукт, канал и версия. Версия должна быть новее
установленной: старый подписанный выпуск нельзя выдать за обновление.

Ключей у программы два: рабочий и запасной. Запасной нужен, если рабочий
потерян или утёк: выпуск с новым рабочим ключом подписывается запасным.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .ed25519 import verify_ed25519_signature

SCHEMA = 1
MANIFEST_NAME = "update-manifest.json"
SIGNATURE_NAME = MANIFEST_NAME + ".sig"
# Список выпуска больше этого — не наш список.
MAX_MANIFEST_BYTES = 4 * 1024 * 1024

_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_VERSION_RE = re.compile(r"\A\d{1,6}(?:\.\d{1,6}){1,3}\Z")
_NAME_RE = re.compile(r"\A[a-z][a-z0-9-]{0,31}\Z")


class ManifestError(ValueError):
    """Список выпуска не годится. ``code`` — короткая причина для сервера очереди."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class FileEntry:
    path: str
    size: int
    sha256: str
    # Размер ``<sha256>.zst`` в хранилище; 0 — файла в хранилище нет
    # (выпуски до хранилища), его можно взять только из установщика.
    zsize: int = 0


# Виды заплаток. ``zstd`` лежат в поле ``patches`` (его знают все версии),
# ``bsdiff`` — в своём поле ``bsdiff``: версии, которые bsdiff не умеют,
# это поле не читают и качают заплатку zstd или файл целиком.
PATCH_KINDS = ("zstd", "bsdiff")
_PATCH_FIELDS = {"zstd": "patches", "bsdiff": "bsdiff"}


@dataclass(frozen=True, slots=True)
class PatchEntry:
    """Заплатка: новый файл из прежнего (``store.patch_file_name``)."""

    from_sha256: str
    to_sha256: str
    size: int
    kind: str = "zstd"


@dataclass(frozen=True, slots=True)
class InstallerEntry:
    name: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class Manifest:
    product: str
    channel: str
    version: str
    created: int
    key: str
    files: tuple[FileEntry, ...]
    installer: InstallerEntry | None
    patches: tuple[PatchEntry, ...] = ()

    def patch_for(self, from_sha256: str, to_sha256: str, kinds=PATCH_KINDS) -> PatchEntry | None:
        """Самая маленькая заплатка от ``from`` к ``to`` из видов ``kinds``."""
        found = [
            item
            for item in self.patches
            if item.from_sha256 == from_sha256 and item.to_sha256 == to_sha256 and item.kind in kinds
        ]
        return min(found, key=lambda item: item.size) if found else None


# ── версии ──────────────────────────────────────────────────────────────────


def version_key(version: str) -> tuple[int, ...]:
    text = str(version or "").strip()
    if not _VERSION_RE.fullmatch(text):
        raise ManifestError(f"неверный номер версии: {version!r}", "format")
    parts = [int(part) for part in text.split(".")]
    return tuple(parts + [0] * (4 - len(parts)))


def compare_versions(left: str, right: str) -> int:
    a, b = version_key(left), version_key(right)
    return (a > b) - (a < b)


# ── подпись и разбор ────────────────────────────────────────────────────────


def decode_signature(signature: bytes | str) -> bytes:
    """Подпись лежит в файле base64-текстом; 64 байта."""
    text = signature.decode("ascii", "replace") if isinstance(signature, bytes) else str(signature)
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raw = b""
    if len(raw) != 64:
        raise ManifestError("подпись списка выпуска повреждена", "sign")
    return raw


def signing_key_id(raw: bytes, signature: bytes | str, trusted: Mapping[str, bytes]) -> str:
    """Каким из доверенных ключей подписан список; ошибка, если ни одним."""
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ManifestError("список выпуска слишком велик", "format")
    signed = decode_signature(signature)
    for key_id, public_key in trusted.items():
        if verify_ed25519_signature(bytes(public_key), signed, bytes(raw)):
            return str(key_id)
    raise ManifestError("подпись списка выпуска не сошлась", "sign")


def load_signed(
    raw: bytes,
    signature: bytes | str,
    *,
    trusted: Mapping[str, bytes],
    product: str,
    channel: str,
    newer_than: str = "",
    allow_same: bool = False,
) -> Manifest:
    """Проверенный список выпуска.

    ``newer_than`` — установленная версия: список должен быть новее
    (``allow_same`` — ровно та же версия, для починки установки).
    """
    key_id = signing_key_id(raw, signature, trusted)
    try:
        payload = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ManifestError(f"список выпуска не читается: {exc}", "format") from None
    manifest = parse(payload)
    if manifest.key != key_id:
        # Подпись верна, но список называет другой ключ: так не бывает у
        # честной сборки — значит, список собран не нашим инструментом.
        raise ManifestError("список выпуска подписан не тем ключом, что в нём назван", "key")
    if manifest.product != product or manifest.channel != channel:
        raise ManifestError(
            f"список выпуска для {manifest.product}/{manifest.channel}, а нужен {product}/{channel}", "product"
        )
    if newer_than:
        gap = compare_versions(manifest.version, newer_than)
        if gap < 0 or (gap == 0 and not allow_same):
            raise ManifestError(f"версия {manifest.version} не новее установленной {newer_than}", "stale")
    return manifest


def parse(payload: object) -> Manifest:
    """Разбор уже проверенного списка: только поля ожидаемого вида."""
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        raise ManifestError("список выпуска неизвестного вида", "format")
    product = str(payload.get("product") or "")
    channel = str(payload.get("channel") or "")
    key = str(payload.get("key") or "")
    if not (_NAME_RE.fullmatch(product) and _NAME_RE.fullmatch(channel) and _NAME_RE.fullmatch(key)):
        raise ManifestError("в списке выпуска неверный продукт, канал или ключ", "format")
    version = str(payload.get("version") or "")
    version_key(version)
    created = payload.get("created")
    if not isinstance(created, int) or created < 0:
        raise ManifestError("в списке выпуска нет времени сборки", "format")

    files = []
    seen: set[str] = set()
    for item in payload.get("files") or ():
        entry = _file_entry(item)
        folded = entry.path.casefold()
        if folded in seen:
            raise ManifestError(f"файл назван в списке дважды: {entry.path}", "format")
        seen.add(folded)
        files.append(entry)

    installer = None
    raw_installer = payload.get("installer")
    if raw_installer is not None:
        if not isinstance(raw_installer, dict):
            raise ManifestError("в списке выпуска неверная запись установщика", "format")
        name = str(raw_installer.get("name") or "")
        if not name or "/" in name or "\\" in name or name in (".", ".."):
            raise ManifestError("в списке выпуска неверное имя установщика", "format")
        installer = InstallerEntry(name, _size(raw_installer.get("size")), _sha(raw_installer.get("sha256")))

    targets = {entry.sha256 for entry in files}
    patches = []
    for kind in PATCH_KINDS:
        for item in payload.get(_PATCH_FIELDS[kind]) or ():
            if not isinstance(item, dict) or item.get("kind", kind) != kind:
                raise ManifestError("в списке выпуска неверная запись заплатки", "format")
            patch = PatchEntry(_sha(item.get("from")), _sha(item.get("to")), _size(item.get("size")), kind)
            if patch.to_sha256 not in targets:
                raise ManifestError("заплатка ведёт к файлу, которого нет в выпуске", "format")
            patches.append(patch)
    return Manifest(product, channel, version, created, key, tuple(files), installer, tuple(patches))


def safe_relative_path(text: str) -> str:
    """Путь файла внутри папки программы: без выхода наружу и без дисков."""
    value = str(text or "")
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or ":" in value
        or path.is_absolute()
        or any(part in ("", ".", "..") for part in value.split("/"))
    ):
        raise ManifestError(f"в списке выпуска неверный путь файла: {value!r}", "format")
    return value


def _file_entry(item: object) -> FileEntry:
    if not isinstance(item, dict):
        raise ManifestError("в списке выпуска неверная запись файла", "format")
    zsize = item.get("zsize", 0)
    return FileEntry(
        safe_relative_path(item.get("path")), _size(item.get("size")), _sha(item.get("sha256")), _size(zsize)
    )


def _size(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ManifestError("в списке выпуска неверный размер файла", "format")
    return value


def _sha(value: object) -> str:
    text = str(value or "")
    if not _SHA256_RE.fullmatch(text):
        raise ManifestError("в списке выпуска неверная контрольная сумма", "format")
    return text


# ── сборка списка (машина сборки) ───────────────────────────────────────────


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(
    *,
    product: str,
    channel: str,
    version: str,
    key: str,
    tree: Path | None = None,
    installer: Path | None = None,
    exclude: Iterable[str] = (),
    created: int | None = None,
    files: Iterable[dict] | None = None,
    patches: Iterable[dict] = (),
) -> dict:
    """Список выпуска для папки сборки и установщика.

    ``exclude`` — пути внутри папки (с ``/``), которые в выпуск не входят:
    файл или папка целиком. ``files`` — готовый список файлов (уже с
    ``zsize`` из хранилища) вместо обхода ``tree``; ``patches`` — заплатки
    (``{"from", "to", "size"}``, у bsdiff ещё ``"kind": "bsdiff"``).
    """
    skipped = tuple(str(item).strip("/") for item in exclude if str(item).strip("/"))
    listed = [dict(item) for item in files] if files is not None else None
    files = []
    if listed is not None:
        files = sorted(listed, key=lambda item: item["path"])
    elif tree is not None:
        root = Path(tree)
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            if any(relative == item or relative.startswith(item + "/") for item in skipped):
                continue
            files.append({"path": safe_relative_path(relative), "size": path.stat().st_size, "sha256": file_sha256(path)})
    payload: dict = {
        "schema": SCHEMA,
        "product": product,
        "channel": channel,
        "version": version,
        "created": int(created if created is not None else time.time()),
        "key": key,
        "files": files,
    }
    if installer is not None:
        target = Path(installer)
        payload["installer"] = {"name": target.name, "size": target.stat().st_size, "sha256": file_sha256(target)}
    grouped: dict[str, list[dict]] = {}
    for item in patches:
        record = dict(item)
        kind = str(record.pop("kind", "zstd"))
        if kind not in PATCH_KINDS:
            raise ManifestError(f"неизвестный вид заплатки: {kind}", "format")
        grouped.setdefault(_PATCH_FIELDS[kind], []).append(record)
    for name, records in grouped.items():
        payload[name] = sorted(records, key=lambda item: (item["to"], item["from"]))
    parse(payload)  # собранный список обязан проходить свой же разбор
    return payload


def dumps(payload: dict) -> bytes:
    """Байты списка: одинаковые при одинаковом содержании."""
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=1) + "\n").encode("utf-8")


__all__ = [
    "MANIFEST_NAME",
    "PATCH_KINDS",
    "SIGNATURE_NAME",
    "FileEntry",
    "InstallerEntry",
    "PatchEntry",
    "Manifest",
    "ManifestError",
    "build",
    "compare_versions",
    "dumps",
    "file_sha256",
    "load_signed",
    "parse",
    "safe_relative_path",
    "signing_key_id",
]
