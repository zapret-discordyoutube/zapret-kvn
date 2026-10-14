"""Положить в Zapret KVN байт-в-байт копию общего ядра обновления.

Ядро ``zapret_update`` одно на Zapret 2 GUI и Zapret KVN; исходник — в
репозитории Zapret 2 GUI (``public_zapretgui/src/zapret_update``). Править
копию здесь нельзя: ``tests/test_update_core_identity.py`` сверяет её с
суммой ``CORE_SHA256``, которую пересчитывает только исходный репозиторий.

    python3 scripts/sync_update_core.py [--source путь/к/zapret_update]
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "zapret_update"
DEFAULT_SOURCE = Path("/home/codex-pve/zapretgui/public_zapretgui/src/zapret_update")
HASH_FILE = "CORE_SHA256"


def core_hash(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(directory.glob("*.py")):
        digest.update(path.name.encode("utf-8") + b"\0")
        digest.update(path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    args = parser.parse_args(argv)
    source = args.source.resolve()
    recorded = (source / HASH_FILE).read_text(encoding="ascii").strip()
    if core_hash(source) != recorded:
        print("В исходном ядре сумма не пересчитана: сначала scripts/update_core_hash.py там", file=sys.stderr)
        return 1
    if TARGET.exists():
        shutil.rmtree(TARGET)
    TARGET.mkdir()
    for path in sorted(source.glob("*.py")) + [source / HASH_FILE]:
        shutil.copyfile(path, TARGET / path.name)
    print(f"zapret_update {recorded[:12]} → {TARGET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
