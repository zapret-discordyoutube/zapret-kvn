#!/usr/bin/env python3
"""Prepare a verified private patched dependency, without editing Go's cache.

Identical script/patch manifest in both platform repos. Unknown upstream versions
stop the build until the patch and transport gate have been checked against them.
The caller uses go mod edit -replace in its disposable core source checkout.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import shutil
import tempfile
import zipfile


FILES = (
    "common/buf/buffer_standard.go",
    "common/buf/buffer_low_memory.go",
    "common/network/direct.go",
    "common/bufio/bind_wait.go",
    "protocol/socks/packet_wait.go",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract_module(module: dict, destination: Path) -> None:
    """Extract only the already hash-verified module zip, not mutable cache files."""
    prefix = f'{module["Path"]}@{module["Version"]}/'
    with zipfile.ZipFile(module["Zip"]) as archive:
        for entry in archive.infolist():
            if not entry.filename.startswith(prefix):
                raise ValueError("Unexpected path in Go module archive")
            name = entry.filename.removeprefix(prefix)
            parts = PurePosixPath(name).parts
            if not parts or ".." in parts or "\\" in name or ":" in name or name.startswith("/"):
                raise ValueError("Unsafe path in Go module archive")
            target = destination.joinpath(*parts)
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(entry))


def prepare(source: Path, output: Path, manifest_path: Path, go: str = "go") -> Path:
    source, output, manifest_path = source.resolve(), output.resolve(), manifest_path.resolve()
    if os.environ.get("GOFLAGS", "").strip():
        raise ValueError("Prepare UDP patch with empty GOFLAGS")

    def run(*args: str) -> dict:
        return json.loads(subprocess.check_output([go, *args], cwd=source, text=True))

    selected = run("list", "-m", "-json", "github.com/sagernet/sing")
    selected = selected.get("Replace", selected)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["schema"] != 1 or selected["Path"] != manifest["module"]:
        raise ValueError("Unexpected sing dependency; UDP patch needs review")
    version = selected.get("Version", "")
    pin = manifest["versions"].get(version)
    if pin is None:
        raise ValueError(f"No verified UDP patch for sing {version}; update and test before release")
    module = run("mod", "download", "-json", f'{selected["Path"]}@{version}')
    if (module["Sum"] != pin["module_sum"] or module["Origin"]["Hash"] != pin["commit"]
            or sha256(Path(module["Zip"])) != pin["zip_sha256"]):
        raise ValueError("sing module provenance mismatch")
    patch = manifest_path.parent / pin["patch"]
    if patch.parent != manifest_path.parent or sha256(patch) != pin["patch_sha256"]:
        raise ValueError("UDP patch SHA-256 mismatch")
    # Verify unmodified cached sources as well, not merely their zip archive.
    subprocess.run([go, "mod", "verify"], cwd=source, check=True)
    output.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="sing-udp-", dir=output))
    dependency = stage / "module"
    extract_module(module, dependency)
    subprocess.run(["git", "apply", "--check", str(patch)], cwd=dependency, check=True)
    subprocess.run(["git", "apply", str(patch)], cwd=dependency, check=True)
    test_source = manifest_path.parent / "sing_udp_buffer_test.go"
    if sha256(test_source) != manifest["test_sha256"]:
        raise ValueError("UDP regression test SHA-256 mismatch")
    shutil.copyfile(test_source, dependency / "common/network/zapret_packet_test.go")
    metadata = {"module": selected["Path"], "version": version, **pin,
                "manifest_sha256": sha256(manifest_path),
                "files": {name: sha256(dependency / name) for name in FILES}}
    (stage / "provenance.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    # Stable private path also keeps production and native-symbol Go build info
    # identical. Verify the entire cached tree against newly reconstructed bytes.
    cache = output / f'{version}-{sha256(manifest_path)}'
    if cache.exists():
        def tree(root: Path) -> dict[str, str]:
            result = {}
            for path in root.rglob("*"):
                if path.is_symlink():
                    raise ValueError("Symlink in patched dependency cache")
                if path.is_file():
                    result[path.relative_to(root).as_posix()] = sha256(path)
            return result
        if tree(stage) != tree(cache):
            raise ValueError("Patched dependency cache changed; refusing to use it")
        shutil.rmtree(stage)
    else:
        stage.rename(cache)
    dependency = cache / "module"
    (output / "module-path.txt").write_text(str(dependency) + "\n", encoding="utf-8")
    return dependency


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).resolve().parents[1] / "core-patches/sing-udp.json")
    parser.add_argument("--go", default="go")
    args = parser.parse_args()
    print(prepare(args.source, args.output, args.manifest, args.go))


if __name__ == "__main__":
    main()
