from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import resolve_core_versions as resolver


ROOT = Path(__file__).resolve().parents[1]


def _asset(
    repository: str,
    tag: str,
    name: str,
    payload: bytes,
    *,
    digest: str | None = None,
) -> dict:
    return {
        "name": name,
        "state": "uploaded",
        "size": len(payload),
        "digest": digest or f"sha256:{hashlib.sha256(payload).hexdigest()}",
        "browser_download_url": resolver._expected_asset_url(repository, tag, name),
    }


def _release(repository: str, tag: str, assets: list[dict], *, prerelease: bool = False) -> dict:
    return {
        "tag_name": tag,
        "draft": False,
        "prerelease": prerelease,
        "assets": assets,
    }


class StableSelectionTests(unittest.TestCase):
    def test_xray_uses_github_prerelease_flag_not_tag_shape(self) -> None:
        releases = [
            _release("XTLS/Xray-core", "v26.7.28", [], prerelease=True),
            _release("XTLS/Xray-core", "v26.3.27", [], prerelease=False),
            _release("XTLS/Xray-core", "v26.2.6", [], prerelease=False),
            _release("XTLS/Xray-core", "v27.0.0-rc.1", [], prerelease=False),
        ]

        selected = resolver.select_stable_xray(releases)

        self.assertEqual(selected["tag_name"], "v26.3.27")

    def test_xray_draft_and_prerelease_releases_are_not_candidates(self) -> None:
        releases = [
            _release("XTLS/Xray-core", "v99.0.0", [], prerelease=True),
            {
                "tag_name": "v98.0.0",
                "draft": True,
                "prerelease": False,
                "assets": [],
            },
        ]

        with self.assertRaisesRegex(resolver.ResolverError, "no stable Xray"):
            resolver.select_stable_xray(releases)

    def test_singbox_selects_highest_extended_stable_pair(self) -> None:
        releases = [
            _release(
                "shtorm-7/sing-box-extended",
                "v1.13.18-extended-2.6.5",
                [],
            ),
            _release(
                "shtorm-7/sing-box-extended",
                "v1.13.18-extended-2.6.4",
                [],
            ),
            _release(
                "shtorm-7/sing-box-extended",
                "v1.14.0-extended-1.0.0",
                [],
                prerelease=True,
            ),
            _release(
                "shtorm-7/sing-box-extended",
                "v1.13.18-extended-2.5.9-rc.1",
                [],
            ),
        ]

        selected = resolver.select_stable_singbox(releases)

        self.assertEqual(selected["tag_name"], "v1.13.18-extended-2.6.5")


class AssetVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        no_curl = patch.object(resolver.shutil, "which", return_value=None)
        no_curl.start()
        self.addCleanup(no_curl.stop)

    def test_exact_asset_rejects_other_windows_variants(self) -> None:
        payload = b"xray archive"
        release = _release(
            "XTLS/Xray-core",
            "v26.3.27",
            [_asset("XTLS/Xray-core", "v26.3.27", "Xray-win7-64.zip", payload)],
        )

        with self.assertRaisesRegex(resolver.ResolverError, "Xray-windows-64.zip"):
            resolver.select_exact_asset(
                release,
                repository="XTLS/Xray-core",
                asset_name="Xray-windows-64.zip",
            )

    def test_exact_asset_rejects_unexpected_download_url(self) -> None:
        release = _release(
            "XTLS/Xray-core",
            "v26.3.27",
            [
                {
                    **_asset(
                        "XTLS/Xray-core",
                        "v26.3.27",
                        "Xray-windows-64.zip",
                        b"archive",
                    ),
                    "browser_download_url": "https://example.invalid/xray.zip",
                }
            ],
        )

        with self.assertRaisesRegex(resolver.ResolverError, "unexpected download URL"):
            resolver.select_exact_asset(
                release,
                repository="XTLS/Xray-core",
                asset_name="Xray-windows-64.zip",
            )

    def test_asset_digest_is_lowercase_and_exactly_sha256(self) -> None:
        release = _release(
            "XTLS/Xray-core",
            "v26.3.27",
            [],
        )
        asset = {
            "name": "Xray-windows-64.zip",
            "digest": "sha256:" + "AB" * 32,
        }

        self.assertEqual(
            resolver.asset_digest(
                release,
                asset,
                repository="XTLS/Xray-core",
            ),
            "ab" * 32,
        )

    def test_missing_api_digest_uses_only_exact_dgst_sidecar(self) -> None:
        archive = "Xray-windows-64.zip"
        digest = "12" * 32
        release = _release(
            "XTLS/Xray-core",
            "v26.3.27",
            [
                {
                    **_asset("XTLS/Xray-core", "v26.3.27", archive, b"archive"),
                    "digest": None,
                },
                _asset(
                    "XTLS/Xray-core",
                    "v26.3.27",
                    archive + ".dgst",
                    f"sha256:{digest}  {archive}\n".encode(),
                ),
            ],
        )

        with patch.object(
            resolver,
            "fetch_bytes",
            return_value=f"sha256:{digest}  {archive}\n".encode(),
        ):
            self.assertEqual(
                resolver.asset_digest(
                    release,
                    release["assets"][0],
                    repository="XTLS/Xray-core",
                ),
                digest,
            )

    def test_download_and_verify_checks_actual_bytes(self) -> None:
        payload = b"verified archive bytes"
        digest = hashlib.sha256(payload).hexdigest()

        class Response:
            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self, size: int = -1) -> bytes:
                nonlocal payload
                if not payload:
                    return b""
                if size < 0:
                    chunk, payload = payload, b""
                else:
                    chunk, payload = payload[:size], payload[size:]
                return chunk

        with patch.object(resolver, "urlopen", return_value=Response()):
            self.assertEqual(
                resolver.download_and_verify(
                    "https://github.com/example/archive.zip",
                    digest,
                ),
                len(b"verified archive bytes"),
            )

    def test_download_and_verify_rejects_digest_mismatch(self) -> None:
        payload = b"wrong archive bytes"
        expected = "00" * 32

        class Response:
            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self, _size: int = -1) -> bytes:
                nonlocal payload
                chunk, payload = payload, b""
                return chunk

        with patch.object(resolver, "urlopen", return_value=Response()):
            with self.assertRaisesRegex(resolver.ResolverError, "SHA-256 mismatch"):
                resolver.download_and_verify(
                    "https://github.com/example/archive.zip",
                    expected,
                )

    def test_branch_commit_must_be_an_immutable_sha(self) -> None:
        with patch.object(resolver, "fetch_json", return_value={"sha": "AB" * 20}):
            self.assertEqual(
                resolver.github_branch_commit("owner/repo", "release"),
                "ab" * 20,
            )
        with patch.object(resolver, "fetch_json", return_value={"sha": "release"}):
            with self.assertRaisesRegex(resolver.ResolverError, "invalid commit"):
                resolver.github_branch_commit("owner/repo", "release")


class CurlArchiveTests(unittest.TestCase):
    def test_curl_bytes_are_hashed_and_https_is_required(self) -> None:
        payload = b"HTTP/2 archive bytes"

        def download(command, *, stdout, **kwargs):
            self.assertEqual(command[1], "--disable")
            self.assertIn("=https", command)
            self.assertIn("--max-filesize", command)
            self.assertNotIn("--insecure", command)
            self.assertNotIn("--user-agent", command)
            self.assertTrue(kwargs["check"])
            stdout.write(payload)

        with patch.object(resolver.shutil, "which", return_value="curl"), patch.object(resolver.subprocess, "run", side_effect=download):
            self.assertEqual(resolver.download_and_verify("https://github.com/example/archive.zip", hashlib.sha256(payload).hexdigest()), len(payload))
            with self.assertRaisesRegex(resolver.ResolverError, "SHA-256 mismatch"):
                resolver.download_and_verify("https://github.com/example/archive.zip", "00" * 32)

    def test_partial_curl_download_is_rejected_and_removed(self) -> None:
        paths = []

        def interrupted(command, *, stdout, **kwargs):
            stdout.write(b"partial archive")
            raise resolver.subprocess.CalledProcessError(18, command, stderr=b"curl: transfer closed with bytes remaining")

        original_mkstemp = resolver.tempfile.mkstemp
        with tempfile.TemporaryDirectory() as directory:
            def temporary(**kwargs):
                fd, name = original_mkstemp(dir=directory, **kwargs)
                paths.append(Path(name))
                return fd, name

            with patch.object(resolver.shutil, "which", return_value="curl"), patch.object(resolver.subprocess, "run", side_effect=interrupted), patch.object(resolver.tempfile, "mkstemp", side_effect=temporary):
                with self.assertRaisesRegex(resolver.ResolverError, "curl: transfer closed with bytes remaining"):
                    resolver.download_and_hash("https://github.com/example/archive.zip")
            self.assertTrue(paths)
            self.assertTrue(all(not path.exists() for path in paths))


class LockUpdateTests(unittest.TestCase):
    def test_resolve_lock_updates_cores_and_one_routing_snapshot(self) -> None:
        current = resolver.read_lock(ROOT / "scripts" / "core-lock.windows-x64.json")
        xray_payload = b"xray"
        singbox_payload = b"singbox"
        routing_payload = b"routing"
        routing_commit = "b" * 40
        xray_release = _release(
            "XTLS/Xray-core",
            "v26.3.27",
            [_asset("XTLS/Xray-core", "v26.3.27", "Xray-windows-64.zip", xray_payload)],
        )
        singbox_release = _release(
            "shtorm-7/sing-box-extended",
            "v1.13.18-extended-2.6.5",
            [
                _asset(
                    "shtorm-7/sing-box-extended",
                    "v1.13.18-extended-2.6.5",
                    "sing-box-1.13.18-extended-2.6.5-windows-amd64-purego.zip",
                    singbox_payload,
                )
            ],
        )

        with (
            patch.object(resolver, "github_latest_release", side_effect=[
                xray_release,
                singbox_release,
            ]),
            patch.object(resolver, "github_branch_commit", return_value=routing_commit),
            patch.object(
                resolver,
                "download_and_verify",
                side_effect=[len(xray_payload), len(singbox_payload)],
            ),
            patch.object(
                resolver,
                "download_and_hash",
                return_value=(len(routing_payload), hashlib.sha256(routing_payload).hexdigest()),
            ),
        ):
            candidate = resolver.resolve_lock(current)

        current_by_id = {source["id"]: source for source in current["sources"]}
        candidate_by_id = {source["id"]: source for source in candidate["sources"]}
        self.assertEqual(candidate_by_id["xray-core"]["version"], "v26.3.27")
        self.assertEqual(
            candidate_by_id["sing-box-extended"]["version"],
            "v1.13.18-extended-2.6.5",
        )
        self.assertEqual(candidate_by_id["runetfreedom-routing-data"]["version"], routing_commit)
        self.assertEqual(
            candidate_by_id["runetfreedom-routing-data"]["sha256"],
            hashlib.sha256(routing_payload).hexdigest(),
        )
        self.assertEqual(candidate_by_id["runetfreedom-routing-data"]["asset_size"], len(routing_payload))
        self.assertEqual(candidate_by_id["xray-core"]["files"], current_by_id["xray-core"]["files"])
        self.assertEqual(
            candidate_by_id["sing-box-extended"]["files"],
            current_by_id["sing-box-extended"]["files"],
        )
        self.assertEqual(
            candidate_by_id["runetfreedom-routing-data"]["files"],
            current_by_id["runetfreedom-routing-data"]["files"],
        )
        for source_id in ("tun2socks", "wintun"):
            self.assertEqual(candidate_by_id[source_id], current_by_id[source_id])

    def test_atomic_write_preserves_original_on_replace_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "core-lock.json"
            original = {"schema": 1, "platform": "windows-x64", "sources": []}
            replacement = {"schema": 1, "platform": "windows-x64", "sources": [{"id": "xray-core"}]}
            path.write_text(resolver.lock_text(original), encoding="utf-8")

            with patch.object(resolver.os, "replace", side_effect=OSError("locked")):
                with self.assertRaisesRegex(OSError, "locked"):
                    resolver.atomic_write_lock(path, replacement)

            self.assertEqual(path.read_text(encoding="utf-8"), resolver.lock_text(original))
            self.assertEqual(list(path.parent.glob(".core-lock.json.*.tmp")), [])

    def test_atomic_write_success_replaces_lock_and_leaves_no_temp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "core-lock.json"
            replacement = {
                "schema": 1,
                "platform": "windows-x64",
                "sources": [{"id": "xray-core"}],
            }

            resolver.atomic_write_lock(path, replacement)

            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), replacement)
            self.assertEqual(list(path.parent.glob(".core-lock.json.*.tmp")), [])

    def test_check_mode_does_not_write_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "core-lock.json"
            current = resolver.read_lock(ROOT / "scripts" / "core-lock.windows-x64.json")
            path.write_text(resolver.lock_text(current), encoding="utf-8")
            before = path.read_bytes()
            candidate = json.loads(json.dumps(current))
            candidate["sources"][0]["version"] = "v1.13.18-extended-2.6.5"

            with patch.object(resolver, "read_lock", return_value=current), patch.object(
                resolver, "resolve_lock", return_value=candidate
            ):
                self.assertEqual(
                    resolver.main(["--check", "--lock-file", str(path)]),
                    0,
                )
            self.assertEqual(path.read_bytes(), before)

    def test_require_current_fails_without_writing_when_update_exists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "core-lock.json"
            current = resolver.read_lock(ROOT / "scripts" / "core-lock.windows-x64.json")
            path.write_text(resolver.lock_text(current), encoding="utf-8")
            before = path.read_bytes()
            candidate = json.loads(json.dumps(current))
            candidate["sources"][0]["version"] = "v99.0.0-extended-99.0.0"

            with patch.object(resolver, "read_lock", return_value=current), patch.object(
                resolver, "resolve_lock", return_value=candidate
            ):
                self.assertEqual(
                    resolver.main(
                        ["--check", "--require-current", "--lock-file", str(path)]
                    ),
                    2,
                )
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
