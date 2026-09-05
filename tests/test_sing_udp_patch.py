from __future__ import annotations

import json
from pathlib import Path
import tempfile
import shutil
import unittest
from unittest.mock import patch
import zipfile

from scripts import prepare_sing_udp_patch as preparation
from scripts import resolve_core_versions as resolver
from scripts.core_bundle_fingerprint import fingerprint


ROOT = Path(__file__).resolve().parents[1]


class SingPacketPatchTests(unittest.TestCase):
    def test_bundle_cache_key_tracks_adapter_patch_and_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            for name in ("build_core_bundle.ps1", "build_singbox_front.py", "prepare_sing_udp_patch.py", "core_bundle_fingerprint.py", "core-lock.windows-x64.json"):
                shutil.copyfile(ROOT / "scripts" / name, root / "scripts" / name)
            shutil.copytree(ROOT / "core-patches", root / "core-patches")
            shutil.copytree(ROOT / "runtime/amnezia", root / "runtime/amnezia")
            previous = fingerprint(root)
            for name in ("runtime/amnezia/relay.go", "core-patches/sing-udp-v8.patch", "scripts/core-lock.windows-x64.json"):
                path = root / name
                path.write_bytes(path.read_bytes() + b"\n")
                current = fingerprint(root)
                self.assertNotEqual(previous, current, name)
                previous = current

    def test_manifest_pins_every_patch_and_regression_source(self):
        root = ROOT / "core-patches"
        manifest = json.loads((root / "sing-udp.json").read_text())
        for pin in manifest["versions"].values():
            self.assertEqual(preparation.sha256(root / pin["patch"]), pin["patch_sha256"])
        self.assertEqual(preparation.sha256(root / "sing_udp_buffer_test.go"), manifest["test_sha256"])
        lock = json.loads((ROOT / "scripts/core-lock.windows-x64.json").read_text())
        self.assertEqual(lock["singbox_build"]["udp_manifest_sha256"], preparation.sha256(root / "sing-udp.json"))

    def test_unknown_dependency_stops_before_patching(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {"GOFLAGS": ""}):
            selected = {"Path": "github.com/shtorm-7/sing", "Version": "v99.0.0"}
            with patch.object(preparation.subprocess, "check_output", return_value=json.dumps(selected)):
                with self.assertRaisesRegex(ValueError, "No verified UDP patch"):
                    preparation.prepare(Path(directory), Path(directory) / "out", ROOT / "core-patches/sing-udp.json")

    def test_module_extraction_rejects_escaping_paths(self):
        # ZipInfo normalizes Windows separators on Windows itself. Include a
        # traversal component so this remains unsafe after that normalization,
        # rather than accidentally testing an ordinary nested file there.
        for name in ("../escape", "/absolute", "bad\\..\\escape", "C:drive"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = root / "module.zip"
                with zipfile.ZipFile(archive, "w") as zipped:
                    zipped.writestr("example.test/mod@v1/" + name, "data")
                with self.assertRaisesRegex(ValueError, "Unsafe path"):
                    preparation.extract_module({"Path": "example.test/mod", "Version": "v1", "Zip": str(archive)}, root / "out")

    def test_module_extraction_uses_archive_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "module.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                zipped.writestr("example.test/mod@v1/common/a.go", "verified source")
            preparation.extract_module({"Path": "example.test/mod", "Version": "v1", "Zip": str(archive)}, root / "out")
            self.assertEqual((root / "out/common/a.go").read_text(), "verified source")

    def test_next_singbox_dependency_requires_review(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "go.mod"
            path.write_text("replace github.com/sagernet/sing => github.com/shtorm-7/sing v99.0.0\n")
            result = type("Result", (), {"returncode": 0, "stdout": json.dumps({
                "Version": "v99.0.0", "Origin": {"Hash": "a" * 40}, "GoMod": str(path)})})()
            with patch.object(resolver.subprocess, "run", return_value=result):
                with self.assertRaisesRegex(resolver.ResolverError, "needs a verified UDP patch"):
                    resolver.resolve_singbox_build("v99.0.0")
