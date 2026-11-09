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
    # Both platforms ship the one sing-box-extended release selected at freeze time.
    core = freeze["singbox"]
    # ...and the one official Hysteria release (older receipts predate this pin).
    hysteria = freeze.get("hysteria")
    if platform == "windows":
        lock = json.loads((root / "scripts/core-lock.windows-x64.json").read_text(encoding="utf-8"))
        if lock["amnezia"] != pin:
            raise ValueError("Windows Amnezia differs from coordinated freeze")
        if {key: lock["singbox_build"][key] for key in ("version", "commit")} != core:
            raise ValueError("Windows sing-box differs from coordinated freeze")
        if hysteria is not None:
            source = next((item for item in lock["sources"] if item.get("id") == "hysteria"), {})
            if source.get("version") != hysteria["version"]:
                raise ValueError("Windows Hysteria differs from coordinated freeze")
    else:
        properties = dict(line.split("=", 1) for line in (root / "core.properties").read_text().splitlines() if "=" in line)
        if (properties["CORE_TAG"], properties["CORE_COMMIT"]) != (core["version"], core["commit"]):
            raise ValueError("Android sing-box differs from coordinated freeze")
        expected = f'{pin["module"]}@{pin["version"]}'
        if any(properties.get(key) != expected for key in ("ANDROID_WIREGUARD_GO", "ANDROID_AMNEZIAWG_GO")):
            raise ValueError("Android Amnezia differs from coordinated freeze")
        if properties["GO_VERSION"] != pin["toolchain"]["version"].removeprefix("go"):
            raise ValueError("Android and Windows Go toolchains differ")
        check_xray(freeze, properties)
        if hysteria is not None and properties.get("HYSTERIA_CORE_TAG") != hysteria["version"]:
            raise ValueError(
                "Android Hysteria differs from coordinated freeze: regenerate core-patches/0003 "
                "for the Windows-selected release (docs/CORE_UPDATE.md)"
            )
    return freeze


def check_xray(freeze: dict, android_properties: dict) -> None:
    """Android embeds Xray from source: its pinned commit must be the one Windows ships (receipts before 2026-11-09 lack it)."""

    xray = freeze.get("xray")
    if xray is not None and android_properties.get("XRAY_CORE_COMMIT") != xray["commit"]:
        raise ValueError(
            f"Android Xray {android_properties.get('XRAY_CORE_COMMIT')} differs from the Windows-selected {xray['version']} "
            f"({xray['commit']}): update XRAY_CORE_MODULE/XRAY_CORE_COMMIT and add a core patch (docs/CORE_UPDATE.md)"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", choices=("windows", "android"))
    parser.add_argument("version")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    pin = verify(args.root, args.platform, args.version)["amnezia"]
    print(f'Frozen official Amnezia: {pin["version"]} @ {pin["commit"]}')
