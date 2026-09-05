from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import zipfile

import build
from scripts import release_windows


class ReleaseVersionTests(unittest.TestCase):
    def test_next_patch_comes_from_stable_tag(self) -> None:
        self.assertEqual(release_windows.next_patch("v0.4.83"), "0.4.84")
        self.assertEqual(release_windows.next_patch("v1.9.99"), "1.9.100")

    def test_explicit_immediate_minor_zero_is_allowed(self) -> None:
        self.assertEqual(
            release_windows.validate_next_stable_version("v0.4.101", "0.5.0"),
            "0.5.0",
        )
        self.assertEqual(
            release_windows.validate_next_stable_version("v0.4.101", None),
            "0.4.102",
        )

    def test_skipped_or_major_versions_are_rejected(self) -> None:
        for value in ("0.4.103", "0.5.1", "0.6.0", "1.0.0"):
            with self.subTest(value=value), self.assertRaises(release_windows.ReleaseError):
                release_windows.validate_next_stable_version("v0.4.101", value)

    def test_prerelease_or_malformed_version_is_rejected(self) -> None:
        for value in ("0.4", "0.4.84-rc1", "latest", ""):
            with self.subTest(value=value), self.assertRaises(release_windows.ReleaseError):
                release_windows.parse_version(value)

    def test_latest_stable_tag_ignores_prerelease_suffixes(self) -> None:
        with patch.object(
            release_windows,
            "output",
            return_value="v0.4.83\nv0.4.84-rc1\nv0.4.82\n",
        ):
            self.assertEqual(release_windows.latest_stable_tag(), "v0.4.83")


class ReleaseChangelogTests(unittest.TestCase):
    def test_repeated_and_semicolon_changes_are_normalized(self) -> None:
        self.assertEqual(
            release_windows.normalize_changes(
                [" First change ; Second change ", "• Third   change"]
            ),
            ["First change", "Second change", "Third change"],
        )

    def test_empty_resume_changes_are_allowed_only_explicitly(self) -> None:
        self.assertEqual(release_windows.normalize_changes([], allow_empty=True), [])
        with self.assertRaises(release_windows.ReleaseError):
            release_windows.normalize_changes([])

    def test_publisher_limits_are_enforced_before_external_writes(self) -> None:
        with self.assertRaises(release_windows.ReleaseError):
            release_windows.normalize_changes(["x"] * 7)
        with self.assertRaises(release_windows.ReleaseError):
            release_windows.normalize_changes(["x" * 181])


class ReleaseStateTests(unittest.TestCase):
    def test_phase_order_supports_resume_without_repeating_completed_work(self) -> None:
        state = {"phase": "stable_verified"}
        self.assertTrue(release_windows.phase_done(state, "dev_verified"))
        self.assertTrue(release_windows.phase_done(state, "stable_verified"))
        self.assertFalse(release_windows.phase_done(state, "assets_verified"))

    def test_atomic_json_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            release_windows.atomic_json(path, {"phase": "dev_verified", "version": "0.4.84"})
            self.assertEqual(
                release_windows.read_json(path),
                {"phase": "dev_verified", "version": "0.4.84"},
            )

    def test_execute_checks_clean_tree_before_creating_resume_state(self) -> None:
        args = release_windows.build_parser().parse_args(["--change", "Ready"])
        with (
            patch.object(release_windows, "require_clean_main", side_effect=release_windows.ReleaseError("dirty")),
            patch.object(release_windows, "load_or_create_state") as create_state,
        ):
            with self.assertRaisesRegex(release_windows.ReleaseError, "dirty"):
                release_windows.execute(args)
        create_state.assert_not_called()

    def test_core_refresh_uses_verified_write_or_nonmutating_current_check(self) -> None:
        with patch.object(release_windows, "run") as run:
            release_windows.refresh_stable_core_lock(write=True)
            release_windows.refresh_stable_core_lock(write=False)

        resolver = str(release_windows.CORE_RESOLVER_PATH.relative_to(release_windows.ROOT))
        self.assertEqual(
            run.call_args_list[0].args[0],
            [release_windows.sys.executable, resolver, "--write"],
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            [release_windows.sys.executable, resolver, "--check", "--require-current"],
        )

    @staticmethod
    def _gate_manifest(*, prerelease: bool = False) -> dict:
        return {
            "schema": 1,
            "mode": "stable",
            "version": "0.4.95",
            "commit": "a" * 40,
            "templates_verified": 4,
            "executable": {"size": 1, "sha256": "b" * 64},
            "core": {
                "lock_sha256": "c" * 64,
                "manifest_sha256": "d" * 64,
                "sources": [
                    {
                        "id": "xray-core",
                        "channel": "stable",
                        "release_prerelease": prerelease,
                        "archive_sha256": "e" * 64,
                        "asset_size": 1,
                    },
                    {
                        "id": "sing-box-extended",
                        "channel": "stable",
                        "release_prerelease": False,
                        "archive_sha256": "f" * 64,
                        "asset_size": 1,
                    },
                    {
                        "id": "hysteria",
                        "channel": "stable",
                        "release_prerelease": False,
                        "archive_sha256": "1" * 64,
                        "asset_size": 1,
                    },
                ],
            },
        }

    def test_gate_manifest_requires_exact_stable_core_proof(self) -> None:
        release_windows.verify_gate_manifest(
            self._gate_manifest(),
            "stable",
            "0.4.95",
            "a" * 40,
        )
        with self.assertRaisesRegex(release_windows.ReleaseError, "non-stable core"):
            release_windows.verify_gate_manifest(
                self._gate_manifest(prerelease=True),
                "stable",
                "0.4.95",
                "a" * 40,
            )


class AppVersionTests(unittest.TestCase):
    def test_version_update_changes_exactly_one_assignment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            constants = Path(directory) / "constants.py"
            constants.write_text('APP_NAME = "x"\nAPP_VERSION = "0.4.83"\n', encoding="utf-8")
            with patch.object(release_windows, "CONSTANTS_PATH", constants):
                self.assertEqual(release_windows.current_app_version(), "0.4.83")
                release_windows.set_app_version("0.4.84")
                self.assertEqual(release_windows.current_app_version(), "0.4.84")


class BuildPayloadTests(unittest.TestCase):
    def _make_clean_payload(self, root: Path) -> Path:
        app_dir = root / "dist" / "ZapretKVN"
        (app_dir / "data" / "templates" / "xray").mkdir(parents=True)
        (app_dir / "data" / "templates" / "xray" / "default.json").write_text(
            "{}\n", encoding="utf-8"
        )
        for relative in build.SINGBOX_RULE_SET_RELATIVE_PATHS:
            path = app_dir / "core" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"srs")
        return app_dir

    def test_clean_payload_allows_only_source_owned_templates_under_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app_dir = self._make_clean_payload(Path(directory))
            build.assert_clean_payload(app_dir)

    def test_clean_payload_rejects_runtime_data_and_orphan_files(self) -> None:
        forbidden = ("state.enc", "configs", "runtime", "logs")
        for name in forbidden:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                app_dir = self._make_clean_payload(Path(directory))
                path = app_dir / "data" / name
                if "." in name:
                    path.write_bytes(b"runtime")
                else:
                    path.mkdir()
                with self.assertRaisesRegex(RuntimeError, "runtime data"):
                    build.assert_clean_payload(app_dir)

        with tempfile.TemporaryDirectory() as directory:
            app_dir = self._make_clean_payload(Path(directory))
            (app_dir / "old-orphan.bin").write_bytes(b"stale")
            with self.assertRaisesRegex(RuntimeError, "unexpected top-level"):
                build.assert_clean_payload(app_dir)

    def test_clean_payload_requires_all_local_singbox_rule_sets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app_dir = self._make_clean_payload(Path(directory))
            (app_dir / "core" / build.SINGBOX_RULE_SET_RELATIVE_PATHS[0]).unlink()
            with self.assertRaisesRegex(RuntimeError, "missing bundled sing-box rule-set"):
                build.assert_clean_payload(app_dir)

    @staticmethod
    def _routing_archive() -> bytes:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr(
                "snapshot/sing-box/rule-set-geosite/geosite-ru-blocked.srs",
                b"blocked-domain",
            )
            archive.writestr(
                "snapshot/sing-box/rule-set-geoip/geoip-ru-blocked.srs",
                b"blocked-ip",
            )
            archive.writestr(
                "snapshot/sing-box/rule-set-geosite/geosite-category-ru.srs",
                b"direct-domain",
            )
            archive.writestr(
                "snapshot/sing-box/rule-set-geoip/geoip-ru.srs",
                b"direct-ip",
            )
        return output.getvalue()

    def test_build_downloads_locked_rule_sets_into_core_and_replaces_stale_data(self) -> None:
        archive_bytes = self._routing_archive()
        archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self, size=-1):
                nonlocal archive_bytes
                if not archive_bytes:
                    return b""
                chunk, archive_bytes = archive_bytes[:size], archive_bytes[size:]
                return chunk

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = json.loads(build.CORE_LOCK_PATH.read_text(encoding="utf-8"))
            source = next(item for item in lock["sources"] if item["id"] == build.ROUTING_SOURCE_ID)
            source["sha256"] = archive_sha256
            lock_path = root / "core-lock.json"
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            core_dir = root / "core"
            stale = core_dir / "rule-set" / "stale.srs"
            stale.parent.mkdir(parents=True)
            stale.write_bytes(b"stale")

            with (
                patch.object(build, "urlopen", return_value=Response()) as request,
                patch.object(build, "DOWNLOAD_CACHE", root / "cache"),
            ):
                destination = build.stage_singbox_rule_sets(lock_path, core_dir)
                build.stage_singbox_rule_sets(lock_path, core_dir)
                request.assert_called_once()
                self.assertTrue((root / "cache" / source["archive"]).is_file())

            self.assertEqual(destination, core_dir / "rule-set")
            self.assertFalse(stale.exists())
            self.assertEqual(
                {path.name for path in destination.iterdir()},
                {relative.name for relative in build.SINGBOX_RULE_SET_RELATIVE_PATHS},
            )
            self.assertTrue(all(path.stat().st_size > 0 for path in destination.iterdir()))

    def test_clean_removes_the_entire_previous_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist_dir = root / "dist"
            app_dir = dist_dir / "ZapretKVN"
            (app_dir / "data" / "runtime").mkdir(parents=True)
            (app_dir / "data" / "runtime" / "old.json").write_text("{}")
            (app_dir / "legacy-orphan.bin").write_bytes(b"stale")
            (root / "build" / "old").mkdir(parents=True)
            (dist_dir / "_build_tmp" / "old").mkdir(parents=True)

            with (
                patch.object(build, "DIST_DIR", dist_dir),
                patch.object(build, "APP_DIR", app_dir),
                patch.object(build, "BUILD_DIR", root / "build"),
            ):
                build.clean()

            self.assertFalse(app_dir.exists())
            self.assertFalse((root / "build").exists())
            self.assertFalse((dist_dir / "_build_tmp").exists())

    def test_copy_tree_does_not_suppress_permission_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            destination = root / "destination"
            with patch.object(build.shutil, "copytree", side_effect=PermissionError("locked")):
                with self.assertRaisesRegex(RuntimeError, "Cannot stage build files"):
                    build._copy_tree_strict(source, destination)

    def test_remove_path_does_not_suppress_permission_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "locked"
            path.mkdir()
            with patch.object(build.shutil, "rmtree", side_effect=PermissionError("locked")):
                with self.assertRaisesRegex(RuntimeError, "Cannot remove build path"):
                    build._remove_path_strict(path)

    def test_release_gate_asserts_clean_payload(self) -> None:
        source = (Path(__file__).parents[1] / "scripts" / "release_windows_gate.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("function Assert-CleanPayload", source)
        self.assertIn("only data/templates is allowed", source)
        self.assertIn("Release payload is missing bundled sing-box rule-set", source)
        self.assertIn('Invoke-Native $singbox @(\"check\", \"-D\"', source)
        self.assertIn("Assert-CleanPayload $RepoRoot", source)
        self.assertIn("function Assert-StableCoreLock", source)
        self.assertIn("release_prerelease", source)


if __name__ == "__main__":
    unittest.main()
