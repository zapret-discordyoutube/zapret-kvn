import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError

import build


class BuildDownloadCacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.payload = b"locked archive bytes"
        self.source = {
            "archive": "routing-commit.zip",
            "url": "https://github.com/runetfreedom/russia-v2ray-rules-dat/archive/commit.zip",
            "sha256": hashlib.sha256(self.payload).hexdigest(),
        }
        self.cached = self.cache / self.source["archive"]
        self.destination = self.root / "snapshot.zip"
        patcher = patch.object(build, "DOWNLOAD_CACHE", self.cache)
        patcher.start()
        self.addCleanup(patcher.stop)

    def download(self):
        build._download_locked_archive(self.source, self.destination)

    def test_verified_core_bundle_cache_never_opens_network(self):
        self.cached.write_bytes(self.payload)
        with patch.object(build, "urlopen") as request:
            self.download()
        request.assert_not_called()
        self.assertEqual(self.destination.read_bytes(), self.payload)

    def test_miss_downloads_once_for_repeated_builds(self):
        with patch.object(build, "urlopen", return_value=io.BytesIO(self.payload)) as request:
            self.download()
            self.download()
        request.assert_called_once()
        self.assertEqual(self.cached.read_bytes(), self.payload)
        self.assertEqual(list(self.cache.iterdir()), [self.cached])

    def test_corrupt_or_empty_cache_is_replaced(self):
        for corrupt in (b"corrupt", b""):
            with self.subTest(corrupt=corrupt):
                self.cached.write_bytes(corrupt)
                with patch.object(build, "urlopen", return_value=io.BytesIO(self.payload)) as request:
                    self.download()
                request.assert_called_once()
                self.assertEqual(self.cached.read_bytes(), self.payload)

    def test_changed_lock_hash_does_not_reuse_old_archive_name(self):
        self.cached.write_bytes(self.payload)
        updated = b"updated archive"
        self.source["sha256"] = hashlib.sha256(updated).hexdigest()
        with patch.object(build, "urlopen", return_value=io.BytesIO(updated)) as request:
            self.download()
        request.assert_called_once()
        self.assertEqual(self.destination.read_bytes(), updated)

    def test_bad_download_does_not_publish_cache_or_destination(self):
        for payload in (b"wrong hash", b""):
            with self.subTest(payload=payload):
                with patch.object(build, "urlopen", return_value=io.BytesIO(payload)):
                    with self.assertRaises(RuntimeError):
                        self.download()
                self.assertEqual(list(self.cache.iterdir()), [])
                self.assertFalse(self.destination.exists())

    def test_network_failure_keeps_old_cache_and_cleans_partial(self):
        self.cached.write_bytes(b"old snapshot")
        with patch.object(build, "urlopen", side_effect=URLError("connection interrupted")):
            with self.assertRaisesRegex(RuntimeError, "connection interrupted"):
                self.download()
        self.assertEqual(self.cached.read_bytes(), b"old snapshot")
        self.assertEqual(list(self.cache.iterdir()), [self.cached])
        self.assertFalse(self.destination.exists())

    def test_interrupted_stream_cleans_partially_written_download(self):
        class InterruptedResponse(io.BytesIO):
            def read(self, size=-1):
                if self.tell():
                    raise TimeoutError("stream interrupted")
                return super().read(3)

        with patch.object(build, "urlopen", return_value=InterruptedResponse(self.payload)):
            with self.assertRaisesRegex(RuntimeError, "stream interrupted"):
                self.download()
        self.assertEqual(list(self.cache.iterdir()), [])
        self.assertFalse(self.destination.exists())

    def test_cached_file_does_not_bypass_source_validation(self):
        self.cached.write_bytes(self.payload)
        for key, value in (("url", "https://untrusted.invalid/archive.zip"), ("sha256", "bad")):
            with self.subTest(key=key), patch.dict(self.source, {key: value}):
                with patch.object(build, "urlopen") as request:
                    with self.assertRaises(RuntimeError):
                        self.download()
                request.assert_not_called()

    def test_size_limit_applies_to_cache_and_download(self):
        self.cached.write_bytes(self.payload)
        with (
            patch.object(build, "ROUTING_ARCHIVE_LIMIT_BYTES", 4),
            patch.object(build, "urlopen", return_value=io.BytesIO(self.payload)) as request,
        ):
            with self.assertRaisesRegex(RuntimeError, "safety limit"):
                self.download()
        request.assert_called_once()
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.cache.iterdir()), [self.cached])

    def test_unsafe_cache_name_is_rejected_before_network(self):
        for name in ("../escape.zip", "C:\\escape.zip", "/escape.zip", "", "x.zip:stream"):
            with self.subTest(name=name):
                self.source["archive"] = name
                with patch.object(build, "urlopen") as request:
                    with self.assertRaisesRegex(RuntimeError, "plain ZIP filename"):
                        self.download()
                request.assert_not_called()

    def test_cache_replaced_during_copy_is_not_consumed(self):
        self.cached.write_bytes(self.payload)

        def changed_copy(_source, destination):
            destination.write_bytes(b"another concurrent snapshot")

        with patch.object(build.shutil, "copyfile", side_effect=changed_copy):
            with self.assertRaisesRegex(RuntimeError, "changed while copying"):
                self.download()
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
