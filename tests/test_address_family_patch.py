"""Патч address-family-memory (IPv6 к серверу первым) доходит до релизного sing-box.exe.

Патч добавляет пакет common/familymemory (тот же, что Android 0020) и три точки в
upstream: гонку resolve-дайлера, гонку прямого outbound и сброс при смене сети.
Сборщик накладывает его на точные blob'ы после остальных патчей и гоняет Go-тесты.
"""
from __future__ import annotations

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
sys.path.insert(0, str(ROOT / "tests"))
PATCH = ROOT / "core-patches/address-family-memory.patch"
BUILDER = ROOT / "scripts/build_singbox_front.py"
ANDROID_PATCH = ROOT.parent / "android/core-patches/0020-ipv6-first-family-memory.patch"

EDITED = ["common/dialer/resolve.go", "protocol/direct/outbound.go", "route/network.go"]


def _new_file(text: str, name: str) -> str:
    match = re.search(rf"^diff --git a/{re.escape(name)} b/.*?(?=^diff --git |\Z)", text, re.MULTILINE | re.DOTALL)
    assert match, name
    return "\n".join(line[1:] for line in match.group(0).splitlines() if line.startswith("+") and not line.startswith("+++"))


class AddressFamilyPatchTests(unittest.TestCase):
    def test_patch_adds_the_memory_and_edits_only_the_dial_points(self) -> None:
        text = PATCH.read_text(encoding="utf-8")
        touched = re.findall(r"^diff --git a/(\S+) b/", text, re.MULTILINE)
        added = sorted(name for name in touched if name.startswith("common/familymemory/") or name.endswith("zapret_family_test.go"))
        self.assertEqual(sorted(set(touched) - set(added)), EDITED)
        self.assertEqual(len(re.findall(r"^new file mode", text, re.MULTILINE)), len(added))
        self.assertEqual(len(re.findall(r"^index [0-9a-f]{40}\.\.[0-9a-f]{40}", text, re.MULTILINE)), len(touched))

    def test_udp_keeps_ipv4_first_until_ipv6_worked(self) -> None:
        text = PATCH.read_text(encoding="utf-8")
        self.assertIn("familymemory.Default.OrderPacket(ctx, destination.Fqdn, addresses, true)", text)
        self.assertIn("familymemory.Default.Reset()", text)

    def test_memory_package_is_the_same_as_android(self) -> None:
        if not ANDROID_PATCH.is_file():
            self.skipTest("android repository is not next to windows")
        android = ANDROID_PATCH.read_text(encoding="utf-8")
        windows = PATCH.read_text(encoding="utf-8")
        for name in ("common/familymemory/memory.go", "common/familymemory/memory_test.go"):
            self.assertEqual(_new_file(windows, name), _new_file(android, name), name)

    def test_builder_applies_tests_and_records_the_patch(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        self.assertIn('ADDRESS_FAMILY_PATCH = "address-family-memory.patch"', text)
        self.assertIn("apply_exact_patch(source, family_patch", text)
        self.assertIn("'./common/familymemory', './common/dialer'", text)
        self.assertIn('"address_family_patch_sha256"', text)
        # After kvn-desync: its index lines are the blobs left by the earlier patches.
        self.assertLess(text.index("apply_exact_patch(source, desync_patch"), text.index("apply_exact_patch(source, family_patch"))

    def test_patch_applies_to_the_pinned_source_after_the_other_patches(self) -> None:
        from test_kvn_desync_patch import _pinned_source

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
            apply_exact_patch(tree, patches / "kvn-desync.patch", what="маршрутные опции", port_hint="тест")
            apply_exact_patch(tree, PATCH, what="набор адресов сервера", port_hint="тест")
            self.assertTrue((tree / "common/familymemory/memory.go").is_file())
            self.assertIn("dialRemembered", (tree / "common/dialer/resolve.go").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
