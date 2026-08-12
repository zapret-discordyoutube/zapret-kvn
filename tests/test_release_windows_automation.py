from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import release_windows


class ReleaseVersionTests(unittest.TestCase):
    def test_next_patch_comes_from_stable_tag(self) -> None:
        self.assertEqual(release_windows.next_patch("v0.4.83"), "0.4.84")
        self.assertEqual(release_windows.next_patch("v1.9.99"), "1.9.100")

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


class AppVersionTests(unittest.TestCase):
    def test_version_update_changes_exactly_one_assignment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            constants = Path(directory) / "constants.py"
            constants.write_text('APP_NAME = "x"\nAPP_VERSION = "0.4.83"\n', encoding="utf-8")
            with patch.object(release_windows, "CONSTANTS_PATH", constants):
                self.assertEqual(release_windows.current_app_version(), "0.4.83")
                release_windows.set_app_version("0.4.84")
                self.assertEqual(release_windows.current_app_version(), "0.4.84")


if __name__ == "__main__":
    unittest.main()
