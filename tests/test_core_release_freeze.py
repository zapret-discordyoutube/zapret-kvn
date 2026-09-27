import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from scripts.check_core_release_freeze import digest, verify
from scripts.prepare_core_release import android_pin_changes

ROOT = Path(__file__).resolve().parents[1]
ANDROID = ROOT.parent / "android"


class CoreReleaseFreezeTests(unittest.TestCase):
    def test_receipt_rejects_other_release_and_changed_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            path = root / "scripts/core-lock.windows-x64.json"
            core = {"version": "v1.14.1-extended-2.7.2", "commit": "5" * 40}
            path.write_text(json.dumps({"amnezia": {"version": "v3.1.1"}, "singbox_build": {**core, "zip_sha256": "0" * 64}}))
            freeze = {"schema": 1, "releases": {"windows": "0.5.8"},
                      "amnezia": {"version": "v3.1.1"}, "singbox": core,
                      "inputs": {"windows": {"scripts/core-lock.windows-x64.json": digest(path)}}}
            (root / "core-release-freeze.json").write_text(json.dumps(freeze))
            self.assertEqual(verify(root, "windows", "0.5.8"), freeze)
            with self.assertRaisesRegex(ValueError, "different release"):
                verify(root, "windows", "0.5.9")
            path.write_text(path.read_text() + "\n")
            with self.assertRaisesRegex(ValueError, "input changed"):
                verify(root, "windows", "0.5.8")

    def test_receipt_rejects_android_core_other_than_frozen(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            properties = root / "core.properties"
            properties.write_text(
                "CORE_TAG=v1.14.0-extended-2.7.1\nCORE_COMMIT=" + "4" * 40 + "\n"
                "ANDROID_WIREGUARD_GO=m@v3.1.1\nANDROID_AMNEZIAWG_GO=m@v3.1.1\nGO_VERSION=1.26.4\n"
            )
            freeze = {"schema": 1, "releases": {"android": "v0.5.0"},
                      "amnezia": {"module": "m", "version": "v3.1.1", "toolchain": {"version": "go1.26.4"}},
                      "singbox": {"version": "v1.14.1-extended-2.7.2", "commit": "5" * 40},
                      "inputs": {"android": {"core.properties": digest(properties)}}}
            (root / "core-release-freeze.json").write_text(json.dumps(freeze))
            with self.assertRaisesRegex(ValueError, "Android sing-box differs"):
                verify(root, "android", "v0.5.0")

    @unittest.skipUnless(ANDROID.is_dir(), "paired Android checkout not available")
    def test_android_retarget_preserves_upstream_patch_context(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copyfile(ANDROID / "core.properties", root / "core.properties")
            shutil.copytree(ANDROID / "core-patches", root / "core-patches")
            pin = json.loads((ROOT / "scripts/core-lock.windows-x64.json").read_text())["amnezia"]
            unchanged = android_pin_changes(root, pin)
            for path, text in unchanged.items():
                self.assertEqual(path.read_text(), text)
            pin = copy.deepcopy(pin)
            pin.update(version="v3.1.20990101", module_sum="h1:futurezip", module_go_mod_sum="h1:futuremod")
            changes = android_pin_changes(root, pin)
            patch_path = root / "core-patches/0005-official-amnezia-wg-unified.patch"
            before, after = patch_path.read_text().splitlines(), changes[patch_path].splitlines()
            self.assertEqual(len(before), len(after))
            for old, new in zip(before, after):
                if not old.startswith("+"):
                    self.assertEqual(old, new)
            self.assertIn("v3.1.20990101 h1:futurezip", changes[patch_path])
            self.assertIn("v3.1.20990101/go.mod h1:futuremod", changes[patch_path])
