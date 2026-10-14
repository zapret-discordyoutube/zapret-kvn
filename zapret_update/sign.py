"""Подпись списка выпуска на машине сборки.

Команды::

    python -m zapret_update.sign keygen --key-id gui-2026a --out ключ.key
    python -m zapret_update.sign make --key ключ.key --product zapret-gui \\
        --channel dev --version 21.1.7.153 --tree dist/app \\
        --installer Zapret2Setup.exe --exclude user --out папка_выпуска

``make`` пишет ``update-manifest.json`` и ``update-manifest.json.sig``.

Файл ключа — одна строка ``ed25519 <имя ключа> <32 байта в base64>``; его не
кладут в git и не показывают в журналах. ``keygen`` печатает открытую часть,
её вшивают в программу.

Подпись делает своя реализация Ed25519 (``ed25519``), сторонних библиотек
сборке не нужно.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

from . import manifest as manifest_module
from .ed25519 import public_key_from_seed, sign_ed25519


def read_key(path: Path) -> tuple[str, bytes]:
    """``(имя ключа, 32 байта)`` из файла ключа."""
    parts = Path(path).read_text(encoding="ascii").split()
    if len(parts) != 3 or parts[0] != "ed25519":
        raise ValueError(f"{path}: не файл ключа подписи")
    seed = base64.b64decode(parts[2], validate=True)
    if len(seed) != 32:
        raise ValueError(f"{path}: ключ подписи повреждён")
    return parts[1], seed


def generate_key(key_id: str, path: Path) -> str:
    """Создаёт ключ и возвращает открытую часть в base64. Существующий файл не перезаписывается."""
    target = Path(path)
    seed = os.urandom(32)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(f"ed25519 {key_id} {base64.b64encode(seed).decode('ascii')}\n")
    return base64.b64encode(public_key_from_seed(seed)).decode("ascii")


def public_key_of(path: Path) -> str:
    _key_id, seed = read_key(path)
    return base64.b64encode(public_key_from_seed(seed)).decode("ascii")


def sign_bytes(raw: bytes, key_path: Path) -> tuple[str, str]:
    """``(имя ключа, подпись base64)`` над точными байтами."""
    key_id, seed = read_key(key_path)
    return key_id, base64.b64encode(sign_ed25519(seed, bytes(raw))).decode("ascii")


def make(
    *,
    key_path: Path,
    product: str,
    channel: str,
    version: str,
    out_dir: Path,
    tree: Path | None = None,
    installer: Path | None = None,
    exclude: tuple[str, ...] = (),
    files: list[dict] | None = None,
    patches: list[dict] = (),
) -> tuple[Path, Path]:
    """Собирает, подписывает и сверяет список выпуска; возвращает пути двух файлов.

    ``files`` и ``patches`` — готовые записи из сборщика хранилища
    (``builder.build_store``) вместо обхода ``tree``.
    """
    key_id, seed = read_key(key_path)
    payload = manifest_module.build(
        product=product,
        channel=channel,
        version=version,
        key=key_id,
        tree=tree,
        installer=installer,
        exclude=exclude,
        files=files,
        patches=patches,
    )
    raw = manifest_module.dumps(payload)
    _same_key_id, signature = sign_bytes(raw, key_path)
    # Подпись сверяется той же проверкой, что стоит в программах.
    public = public_key_from_seed(seed)
    manifest_module.load_signed(raw, signature, trusted={key_id: public}, product=product, channel=channel)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    manifest_path = out / manifest_module.MANIFEST_NAME
    signature_path = out / manifest_module.SIGNATURE_NAME
    manifest_path.write_bytes(raw)
    signature_path.write_text(signature + "\n", encoding="ascii")
    return manifest_path, signature_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Подпись списка выпуска Zapret.")
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen", help="создать ключ подписи")
    keygen.add_argument("--key-id", required=True)
    keygen.add_argument("--out", type=Path, required=True)
    public = commands.add_parser("public", help="открытая часть ключа")
    public.add_argument("--key", type=Path, required=True)
    build = commands.add_parser("make", help="собрать и подписать список выпуска")
    build.add_argument("--key", type=Path, required=True)
    build.add_argument("--product", required=True)
    build.add_argument("--channel", required=True)
    build.add_argument("--version", required=True)
    build.add_argument("--tree", type=Path)
    build.add_argument("--installer", type=Path)
    build.add_argument("--exclude", action="append", default=[])
    build.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    if args.command == "keygen":
        print(generate_key(args.key_id, args.out))
    elif args.command == "public":
        print(public_key_of(args.key))
    else:
        paths = make(
            key_path=args.key,
            product=args.product,
            channel=args.channel,
            version=args.version,
            tree=args.tree,
            installer=args.installer,
            exclude=tuple(args.exclude),
            out_dir=args.out,
        )
        print("\n".join(str(path) for path in paths))
    return 0


if __name__ == "__main__":
    sys.exit(main())
