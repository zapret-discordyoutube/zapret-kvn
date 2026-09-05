#!/usr/bin/env python3
"""Offline validation of one coordinated Windows/Android core version freeze."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(root: Path, platform: str, version: str) -> dict:
    freeze = json.loads((root / "core-release-freeze.json").read_text(encoding="utf-8"))
    if freeze["schema"] != 1 or freeze["releases"][platform] != version:
        raise ValueError("Core freeze belongs to a different release; prepare this release first")
    for name, expected in freeze["inputs"][platform].items():
        path = root / name
        if path.resolve().is_relative_to(root.resolve()) is False or digest(path) != expected:
            raise ValueError(f"Frozen core input changed: {name}")
    pin = freeze["amnezia"]
    if platform == "windows":
        lock = json.loads((root / "scripts/core-lock.windows-x64.json").read_text(encoding="utf-8"))
        if lock["amnezia"] != pin:
            raise ValueError("Windows Amnezia differs from coordinated freeze")
    else:
        properties = dict(line.split("=", 1) for line in (root / "core.properties").read_text().splitlines() if "=" in line)
        expected = f'{pin["module"]}@{pin["version"]}'
        if any(properties.get(key) != expected for key in ("ANDROID_WIREGUARD_GO", "ANDROID_AMNEZIAWG_GO")):
            raise ValueError("Android Amnezia differs from coordinated freeze")
        if properties["GO_VERSION"] != pin["toolchain"]["version"].removeprefix("go"):
            raise ValueError("Android and Windows Go toolchains differ")
    return freeze


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", choices=("windows", "android"))
    parser.add_argument("version")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    pin = verify(args.root, args.platform, args.version)["amnezia"]
    print(f'Frozen official Amnezia: {pin["version"]} @ {pin["commit"]}')
