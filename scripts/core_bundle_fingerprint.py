#!/usr/bin/env python3
"""Content key for source-built cores, including adapters, patches and build tools."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def fingerprint(root: Path, lock: Path | None = None) -> str:
    root = root.resolve()
    paths = [root / name for name in (
        "scripts/build_core_bundle.ps1", "scripts/build_singbox_front.py",
        "scripts/prepare_sing_udp_patch.py", "scripts/core_bundle_fingerprint.py",
    )]
    for directory in (root / "runtime/amnezia", root / "core-patches"):
        paths.extend(p for p in directory.rglob("*") if p.is_file() and
                     (p.suffix in {".go", ".json", ".patch"} or p.name in {"go.mod", "go.sum"}))
    digest = hashlib.sha256()
    digest.update((lock or root / "scripts/core-lock.windows-x64.json").read_bytes())
    for path in sorted(paths):
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--lock", type=Path)
    args = parser.parse_args()
    print(fingerprint(args.root, args.lock))
