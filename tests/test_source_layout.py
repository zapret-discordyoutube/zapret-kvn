"""Package moves must preserve startup paths and bundled error resources."""

import importlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import build
from xray_fluent.constants import BASE_DIR
from xray_fluent.diagnostics import runtime_errors
from xray_fluent.platform.windows import startup


ROOT = Path(__file__).resolve().parents[1]


class SourceLayoutTests(unittest.TestCase):
    def test_root_contains_only_package_identity_and_constants(self):
        self.assertEqual(
            {path.name for path in (ROOT / "xray_fluent").glob("*.py")},
            {"__init__.py", "constants.py"},
        )

    def test_responsibility_packages_are_importable(self):
        for name in (
            "application.controller", "profiles.models", "profiles.storage",
            "importer.link_parser", "diagnostics.export", "network.http_utils",
            "platform.windows.proxy_manager", "updates.app_updater",
            "engines.singbox", "engines.xray", "engines.hysteria",
            "engines.amnezia.manager", "engines.zapret.manager",
        ):
            with self.subTest(module=name):
                importlib.import_module("xray_fluent." + name)

    def test_development_startup_still_targets_repository_entry_point(self):
        with patch.object(startup.sys, "frozen", False, create=True):
            command = startup.build_startup_command()
        self.assertIn(f'"{ROOT / "main.py"}"', command)
        self.assertEqual(BASE_DIR, ROOT)

    def test_builder_bundles_catalog_beside_its_consumer(self):
        class CommandCaptured(Exception):
            pass

        with patch.object(build, "ensure_venv"), patch.object(build, "_remove_path_strict"), patch.object(build, "_windows_path", side_effect=str), patch.object(
            build, "_run", side_effect=CommandCaptured,
        ) as run:
            with self.assertRaises(CommandCaptured):
                build.build_exe()
        command = run.call_args.args[0]
        resource = command[command.index("--add-data") + 1]
        catalog = Path(runtime_errors.__file__).with_name("runtime-errors.json")
        self.assertEqual(resource, str(catalog) + ";xray_fluent/diagnostics")
        self.assertIsInstance(json.loads(catalog.read_text(encoding="utf-8"))["rules"], list)
