"""Патч kvn-desync (пакеты-обманки «Маскировки») доходит до релизного sing-box.exe.

Патч добавляет движок common/kvndesync (тот же, что Android 0017) и опцию маршрута
`kvn_desync` в пяти файлах upstream; сборщик накладывает его только на точные blob'ы
закреплённой версии и гоняет Go-тесты; провенанс хранит sha256.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
PATCH = ROOT / "core-patches/kvn-desync.patch"
BUILDER = ROOT / "scripts/build_singbox_front.py"
LOCK = ROOT / "scripts/core-lock.windows-x64.json"

EDITED = ["adapter/inbound.go", "option/rule_action.go", "route/conn.go", "route/route.go", "route/rule/rule_action.go"]


def _pinned_source() -> Path | None:
    pin = json.loads(LOCK.read_text(encoding="utf-8"))["singbox_build"]
    cache = os.environ.get("GOMODCACHE") or str(Path.home() / "go/pkg/mod")
    source = Path(cache) / f'{pin["module"]}@{pin["version"]}'
    return source if source.is_dir() else None


class KvnDesyncPatchTests(unittest.TestCase):
    def test_patch_adds_the_engine_and_edits_only_the_route_option_path(self) -> None:
        text = PATCH.read_text(encoding="utf-8")
        touched = re.findall(r"^diff --git a/(\S+) b/", text, re.MULTILINE)
        added = sorted(name for name in touched if name.startswith("common/kvndesync/"))
        self.assertEqual(sorted(set(touched) - set(added)), EDITED)
        self.assertIn("common/kvndesync/socket_windows.go", added)
        self.assertIn("common/kvndesync/spec.go", added)
        self.assertEqual(len(re.findall(r"^new file mode", text, re.MULTILINE)), len(added))
        # The upstream files only gain lines: nothing of sing-box is removed or rewritten.
        self.assertNotRegex(text, r"(?m)^-(?!--)")
        # Full index lines: the builder checks the exact upstream blobs.
        self.assertEqual(len(re.findall(r"^index [0-9a-f]{40}\.\.[0-9a-f]{40}", text, re.MULTILINE)), len(touched))

    def test_windows_runs_only_socket_methods(self) -> None:
        text = PATCH.read_text(encoding="utf-8")
        self.assertIn('KVNDesync string `json:"kvn_desync,omitempty"`', text)
        self.assertIn("the decoy is tls_spoof", text)
        self.assertIn("sioTCPInfo = 0xD8000027", text)
        self.assertIn("kvndesync.Client(remoteConn, plan", text)

    def test_builder_applies_tests_and_records_the_patch(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        self.assertIn('KVN_DESYNC_PATCH = "kvn-desync.patch"', text)
        self.assertIn("apply_exact_patch(source, desync_patch", text)
        self.assertIn("'./common/kvndesync'", text)
        self.assertIn('"kvn_desync_patch_sha256"', text)

    def test_patch_applies_to_the_pinned_source_after_the_other_patches(self) -> None:
        source = _pinned_source()
        if source is None or shutil.which("git") is None:
            self.skipTest("pinned sing-box module is not in the Go module cache")
        from build_singbox_front import apply_exact_patch, apply_process_lookup_patch

        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory) / "source"
            shutil.copytree(source, tree)
            for path in tree.rglob("*"):
                path.chmod(0o755 if path.is_dir() else 0o644)
            patches = ROOT / "core-patches"
            for name in ("singbox-dns-fallback-warning.patch", "browser-fetch.patch"):
                subprocess.run(["git", "apply", str(patches / name)], cwd=tree, check=True)
            apply_process_lookup_patch(tree, patches / "singbox-process-lookup-cache.patch")
            apply_exact_patch(tree, PATCH, what="маршрутные опции", port_hint="тест")
            self.assertTrue((tree / "common/kvndesync/spec.go").is_file())
            self.assertIn("KVNDesync", (tree / "route/conn.go").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
