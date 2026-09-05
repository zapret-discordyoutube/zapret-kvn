import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from scripts.check_core_release_freeze import digest, verify
from scripts.prepare_core_release import android_pin_changes

ROOT = Path(__file__).resolve().parents[1]
ANDROID = ROOT.parent / "ZapretKVN"


class CoreReleaseFreezeTests(unittest.TestCase):
    def test_receipt_rejects_other_release_and_changed_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            path = root / "scripts/core-lock.windows-x64.json"
            path.write_text(json.dumps({"amnezia": {"version": "v3.1.1"}}))
            freeze = {"schema": 1, "releases": {"windows": "0.5.8"},
                      "amnezia": {"version": "v3.1.1"},
                      "inputs": {"windows": {"scripts/core-lock.windows-x64.json": digest(path)}}}
            (root / "core-release-freeze.json").write_text(json.dumps(freeze))
            self.assertEqual(verify(root, "windows", "0.5.8"), freeze)
            with self.assertRaisesRegex(ValueError, "different release"):
                verify(root, "windows", "0.5.9")
            path.write_text(path.read_text() + "\n")
            with self.assertRaisesRegex(ValueError, "input changed"):
                verify(root, "windows", "0.5.8")

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
