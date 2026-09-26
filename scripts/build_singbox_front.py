#!/usr/bin/env python3
"""Build the pinned sing-box source with the verified full-datagram patch."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import shutil

from prepare_sing_udp_patch import extract_module, prepare, sha256


PROCESS_LOOKUP_PATCH = "singbox-process-lookup-cache.patch"
# Signs that upstream already stopped scanning the whole connection table per
# lookup (sing dev 4ca3bebe: keyed TCP owner lookup; any table cache/single-flight).
UPSTREAM_OWNER_LOOKUP_MARKERS = ("FindSocketOwner", "nsiGetTCPConnection", "singleflight")
_OWN_FILE_PREFIX = "zapret_"


class StaleProcessLookupPatch(RuntimeError):
    """The Windows process-lookup patch no longer matches the pinned upstream."""


def _git_blob_id(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def apply_process_lookup_patch(source: Path, patch: Path) -> None:
    """Apply the patch only to the exact upstream files it was written for."""
    port_hint = (f"перенесите патч {patch.name} на новую версию или удалите его, "
                 "если upstream исправил поиск сам")
    text = patch.read_text(encoding="utf-8")
    bases = re.findall(r"^diff --git a/(\S+) b/\S+\n(?:(?:new|deleted) file mode \d+\n)?index ([0-9a-f]{40})\.\.",
                       text, re.MULTILINE)
    if not bases:
        raise StaleProcessLookupPatch(f"{patch.name}: нет полных index-строк (git diff --full-index)")
    for name, blob in bases:
        target = source / name
        if blob == "0" * 40:
            if target.exists():
                raise StaleProcessLookupPatch(f"upstream изменил поиск процесса: {name} уже существует — {port_hint}")
            continue
        actual = _git_blob_id(target) if target.is_file() else "нет файла"
        if actual != blob:
            raise StaleProcessLookupPatch(
                f"upstream изменил поиск процесса: {name} (blob {actual}, патч написан для {blob}) — {port_hint}")
    check = subprocess.run(["git", "apply", "--check", str(patch)], cwd=source, capture_output=True, text=True)
    if check.returncode != 0:
        raise StaleProcessLookupPatch(
            f"upstream изменил поиск процесса: git apply --check не прошёл ({check.stderr.strip()}) — {port_hint}")
    subprocess.run(["git", "apply", str(patch)], cwd=source, check=True)


def assert_process_lookup_patch_needed(*roots: Path) -> None:
    """Stop when the sources already carry an upstream owner-lookup fix."""
    for root in roots:
        for directory in (root / "common/process", root / "common/winiphlpapi"):
            if not directory.is_dir():
                continue
            for path in sorted(directory.glob("*.go")):
                if path.name.startswith(_OWN_FILE_PREFIX):
                    continue
                content = path.read_text(encoding="utf-8", errors="replace")
                for marker in UPSTREAM_OWNER_LOOKUP_MARKERS:
                    if marker in content:
                        raise StaleProcessLookupPatch(
                            f"патч {PROCESS_LOOKUP_PATCH}, вероятно, устарел: в {path.relative_to(root).as_posix()} "
                            f"есть upstream-признак «{marker}» — проверьте upstream-исправление и удалите или перенесите патч")


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
    dns_patch = manifest.parent / 'singbox-dns-fallback-warning.patch'
    subprocess.run(['git', 'apply', '--check', str(dns_patch)], cwd=source, check=True)
    subprocess.run(['git', 'apply', str(dns_patch)], cwd=source, check=True)
    shutil.copyfile(manifest.parent / 'singbox_dns_fallback_test.go', source / 'dns/transport/fallback/zapret_fallback_test.go')
    # Windows connection-owner lookup: cached raw table + shared refresh.
    process_patch = manifest.parent / PROCESS_LOOKUP_PATCH
    apply_process_lookup_patch(source, process_patch)
    shutil.copyfile(manifest.parent / 'singbox_process_lookup_test.go', source / 'common/process/zapret_pid_table_cache_test.go')
    dependency = prepare(source, stage / "dependency", manifest, go)
    assert_process_lookup_patch_needed(source, dependency)
    subprocess.run([go, "mod", "edit", f"-replace=github.com/sagernet/sing={dependency}"], cwd=source, check=True)
    subprocess.run([go, 'test', '-mod=readonly', './dns/transport/fallback', '-run', '^TestZapret', '-count=1'], cwd=source, check=True)
    subprocess.run([go, 'test', '-mod=readonly', './common/process', '-run', '^TestZapret', '-count=1'], cwd=source, check=True)
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
                  "udp_patch": json.loads((dependency.parent / "provenance.json").read_text()),
                  "dns_warning_patch_sha256": sha256(dns_patch),
                  "process_lookup_patch_sha256": sha256(process_patch)}
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
