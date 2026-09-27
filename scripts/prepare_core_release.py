#!/usr/bin/env python3
"""Resolve upstream once, update both platform pins, then freeze a release pair.

Run before source verification/commit. Repeating the same pair only validates
the freeze offline; a different pair always checks official GitHub upstream.
Android follows the sing-box-extended release selected for Windows: it is
pinned only when the Android core patchset still applies to it, otherwise the
whole preparation fails and both platforms keep their previous pins.
No commits, pushes, tags, publication or credentials are handled here.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.check_core_release_freeze import digest, verify
from scripts.resolve_core_versions import atomic_write_lock, resolve_lock, update_amnezia_runtime


def android_pin_changes(android: Path, pin: dict) -> dict[Path, str]:
    properties_path = android / "core.properties"
    properties_text = properties_path.read_text(encoding="utf-8")
    properties = dict(line.split("=", 1) for line in properties_text.splitlines() if "=" in line)
    if properties["GO_VERSION"] != pin["toolchain"]["version"].removeprefix("go"):
        raise ValueError("Update and validate both toolchains before release")
    module, version = pin["module"], pin["version"]
    previous = properties["ANDROID_AMNEZIAWG_GO"].split("@", 1)[1]
    patch_path = android / "core-patches/0005-official-amnezia-wg-unified.patch"
    patch = patch_path.read_text(encoding="utf-8")
    if previous != version:
        # Only retarget existing added module lines. An upstream transitive/API
        # change that needs further edits will fail the normal readonly builds.
        # Keep hunk lengths valid: substitute checksums in place, not remove rows.
        patch = re.sub(rf'(?m)^(\+\s*{re.escape(module)} ){re.escape(previous)}(?=[ /\n])', rf'\g<1>{version}', patch)
        for suffix, checksum in (("", pin["module_sum"]), ("/go.mod", pin["module_go_mod_sum"])):
            pattern = rf'(?m)^(\+{re.escape(module)} {re.escape(version + suffix)} )h1:[^\n]+$'
            patch, count = re.subn(pattern, lambda m: m.group(1) + checksum, patch)
            if count != 1:
                raise ValueError("Amnezia patch format changed; review module pin update")
    manifest_path = android / "core-patches/series.sha256"
    manifest = manifest_path.read_text(encoding="utf-8")
    patch_hash = hashlib.sha256(patch.encode()).hexdigest()
    manifest, count = re.subn(r'(?m)^[0-9a-f]{64}(\s+core-patches/0005-official-amnezia-wg-unified.patch)$', patch_hash + r'\1', manifest)
    if count != 1:
        raise ValueError("Missing official Amnezia patch in Android manifest")
    updates = {
        "ANDROID_WIREGUARD_GO": f"{module}@{version}",
        "ANDROID_AMNEZIAWG_GO": f"{module}@{version}",
        "CORE_PATCH_SHA256": hashlib.sha256(manifest.encode()).hexdigest(),
    }
    for key, value in updates.items():
        properties_text, count = re.subn(rf'(?m)^{key}=.*$', f"{key}={value}", properties_text)
        if count != 1:
            raise ValueError(f"Missing or repeated Android pin {key}")
    return {properties_path: properties_text, patch_path: patch, manifest_path: manifest}


def android_resolver(android: Path):
    """Load the Android repository's own core resolver (single source of rules)."""

    path = android / "scripts/resolve_core_version.py"
    spec = importlib.util.spec_from_file_location("android_resolve_core_version", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Android core resolver is missing: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def android_core_changes(android: Path, singbox: dict, changes: dict[Path, str]) -> None:
    """Retarget Android to the Windows-selected core after validating the patchset."""

    resolver = android_resolver(android)
    properties_path = android / "core.properties"
    properties = dict(line.split("=", 1) for line in changes[properties_path].splitlines() if "=" in line)
    if properties["CORE_UDP_PATCH_SHA256"] != singbox["udp_manifest_sha256"]:
        raise ValueError("Android and Windows sing UDP patch manifests differ")
    # Validate exactly the patch text that is about to be written (the Amnezia
    # retarget above may have rewritten 0005 in memory).
    patches = [
        (relative, changes[android / relative].encode() if android / relative in changes else (android / relative).read_bytes())
        for _, relative in (line.split() for line in changes[android / properties["CORE_PATCH_FILE"]].splitlines())
    ]
    try:
        resolver.validate_candidate(singbox["version"], singbox["commit"], root=android, patches=patches)
        changes[properties_path] = resolver.pin_changes(changes[properties_path], singbox["version"], singbox["commit"])
    except resolver.ResolverError as error:
        raise ValueError(str(error)) from error


def android_hysteria_parity(android: Path, lock: dict) -> str:
    """Both platforms ship the Windows-selected official Hysteria.

    Android embeds it through core-patches/0003, so a new release cannot be
    retargeted by rewriting a pin: fail before any write and point at the
    regeneration procedure instead of freezing a stale Android core.
    """
    version = next(item["version"] for item in lock["sources"] if item.get("id") == "hysteria")
    properties = dict(
        line.split("=", 1) for line in (android / "core.properties").read_text(encoding="utf-8").splitlines() if "=" in line
    )
    if properties.get("HYSTERIA_CORE_TAG") != version:
        raise ValueError(
            f"Android Hysteria {properties.get('HYSTERIA_CORE_TAG')} lags Windows {version}: "
            "regenerate android core-patches (docs/CORE_UPDATE.md) before freezing"
        )
    return version


def prepare(windows: Path, android: Path, windows_version: str, android_tag: str) -> dict:
    if not re.fullmatch(r"\d+\.\d+\.\d+", windows_version) or not re.fullmatch(r"v\d+\.\d+\.\d+", android_tag):
        raise ValueError("Only exact stable versions can be frozen")
    releases = {"windows": windows_version, "android": android_tag}
    receipt = windows / "core-release-freeze.json"
    if receipt.exists() and json.loads(receipt.read_text())["releases"] == releases:
        freeze = verify(windows, "windows", windows_version)
        if verify(android, "android", android_tag) != freeze:
            raise ValueError("Platform freezes differ")
        return freeze
    # Golden vectors and the dependency fix must remain identical across repos.
    for left, right in (
        ("runtime/amnezia/testdata/wg_awg_golden.json", "wireguard-import/src/test/resources/wg_awg_golden.json"),
        ("core-patches/sing-udp.json", "core-patches/sing-udp.json"),
        ("scripts/prepare_sing_udp_patch.py", "scripts/prepare_sing_udp_patch.py"),
        ("scripts/check_core_release_freeze.py", "scripts/check_core_release_freeze.py"),
    ):
        if (windows / left).read_bytes() != (android / right).read_bytes():
            raise ValueError(f"Shared platform contract differs: {left}")
    lock_path = windows / "scripts/core-lock.windows-x64.json"
    lock = resolve_lock(json.loads(lock_path.read_text(encoding="utf-8")))
    hysteria = {"version": android_hysteria_parity(android, lock)}
    changes = android_pin_changes(android, lock["amnezia"])
    singbox = {key: lock["singbox_build"][key] for key in ("version", "commit")}
    android_core_changes(android, lock["singbox_build"], changes)
    # Restore this script's own pin edits if compatibility validation fails.
    paths = [lock_path, windows / "runtime/amnezia/go.mod", windows / "runtime/amnezia/go.sum", *changes]
    original = {path: path.read_bytes() for path in paths}
    try:
        update_amnezia_runtime(lock["amnezia"], windows)
        for path, text in changes.items():
            path.write_text(text, encoding="utf-8", newline="\n")
        atomic_write_lock(lock_path, lock)
    except Exception:
        for path, data in original.items():
            path.write_bytes(data)
        raise
    inputs = {
        "windows": {name: digest(windows / name) for name in (
            "scripts/core-lock.windows-x64.json", "runtime/amnezia/go.mod", "runtime/amnezia/go.sum")},
        "android": {name: digest(android / name) for name in (
            "core.properties", "core-patches/series.sha256", "core-patches/0005-official-amnezia-wg-unified.patch")},
    }
    freeze = {"schema": 1, "releases": releases, "checked_at_utc": datetime.now(timezone.utc).isoformat(),
              "amnezia": lock["amnezia"], "singbox": singbox, "hysteria": hysteria, "inputs": inputs}
    for root in (windows, android):
        atomic_write_lock(root / "core-release-freeze.json", freeze)
    verify(windows, "windows", windows_version)
    verify(android, "android", android_tag)
    return freeze


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--windows-version", required=True)
    parser.add_argument("--android-tag", required=True)
    parser.add_argument("--android-root", type=Path, default=ROOT.parent / "android")
    args = parser.parse_args()
    freeze = prepare(ROOT, args.android_root.resolve(), args.windows_version, args.android_tag)
    print(json.dumps({"releases": freeze["releases"], "amnezia": freeze["amnezia"]["version"],
                      "singbox": freeze["singbox"]["version"], "hysteria": freeze["hysteria"]["version"]}))
