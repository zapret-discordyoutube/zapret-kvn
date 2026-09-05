#!/usr/bin/env python3
"""Build the pinned sing-box source with the verified full-datagram patch."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from prepare_sing_udp_patch import extract_module, prepare, sha256


def build(lock_path: Path, output: Path, work: Path, go: str) -> dict:
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    pin = lock["singbox_build"]
    upstream = next(s for s in lock["sources"] if s["id"] == "sing-box-extended")
    if upstream["version"] != pin["version"]:
        raise ValueError("sing-box archive and source revision differ")
    manifest = Path(__file__).resolve().parents[1] / "core-patches/sing-udp.json"
    if sha256(manifest) != pin["udp_manifest_sha256"]:
        raise ValueError("sing-box UDP manifest differs from release lock")
    module = json.loads(subprocess.check_output(
        [go, "mod", "download", "-json", f'{pin["module"]}@{pin["version"]}'], text=True))
    if (module["Sum"] != pin["module_sum"] or module["GoModSum"] != pin["module_go_mod_sum"]
            or module["Origin"]["Hash"] != pin["commit"]
            or sha256(Path(module["Zip"])) != pin["zip_sha256"]):
        raise ValueError("sing-box source provenance mismatch")
    work.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="singbox-build-", dir=work))
    source = stage / "source"
    extract_module(module, source)
    dependency = prepare(source, stage / "dependency", manifest, go)
    subprocess.run([go, "mod", "edit", f"-replace=github.com/sagernet/sing={dependency}"], cwd=source, check=True)
    for tags in ("", "with_low_memory"):
        subprocess.run([go, "test", "-mod=readonly", "-tags", tags,
                        "github.com/sagernet/sing/common/network", "-run", "^TestZapret", "-count=1"],
                       cwd=source, check=True)
    tags = (source / "release/DEFAULT_BUILD_TAGS").read_text().strip() + ",with_purego"
    flags = (source / "release/LDFLAGS").read_text().strip()
    flags += f' -X github.com/sagernet/sing-box/constant.Version={pin["version"].removeprefix("v")} -s -w -buildid='
    subprocess.run([go, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-tags", tags,
                    "-ldflags", flags, "-o", str(output.resolve()), "./cmd/sing-box"], cwd=source, check=True)
    provenance = {**pin, "go": subprocess.check_output([go, "env", "GOVERSION"], text=True).strip(),
                  "goos": os.environ.get("GOOS", ""), "goarch": os.environ.get("GOARCH", ""),
                  "build_tags": tags, "binary_sha256": sha256(output),
                  "udp_patch": json.loads((dependency.parent / "provenance.json").read_text())}
    output.with_suffix(".build.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    return provenance


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--go", default="go")
    args = parser.parse_args()
    build(args.lock.resolve(), args.output.resolve(), args.work.resolve(), args.go)
