from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from xray_fluent.application.config_documents import RawConfigTextCache


@contextmanager
def _count_disk_reads():
    original = Path.read_text
    counts: list[Path] = []

    def counting_read_text(self, *args, **kwargs):
        counts.append(self)
        return original(self, *args, **kwargs)

    with patch.object(Path, "read_text", counting_read_text):
        yield counts


class RawConfigTextCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "config.json"
        self.cache = RawConfigTextCache()

    def test_unchanged_file_is_read_from_disk_only_once(self) -> None:
        self.path.write_text('{"a": 1}', encoding="utf-8")
        with _count_disk_reads() as reads:
            first = self.cache.read_text(self.path)
            second = self.cache.read_text(self.path)
            third = self.cache.read_text(self.path)

        self.assertEqual(first, '{"a": 1}')
        self.assertEqual(second, '{"a": 1}')
        self.assertEqual(third, '{"a": 1}')
        self.assertEqual(len(reads), 1)

    def test_mtime_change_invalidates_cache(self) -> None:
        self.path.write_text('{"a": 1}', encoding="utf-8")
        self.assertEqual(self.cache.read_text(self.path), '{"a": 1}')

        self.path.write_text('{"a": 2}', encoding="utf-8")
        stat = self.path.stat()
        # Force a visibly different mtime even on coarse-grained filesystems.
        os.utime(self.path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 5_000_000))

        self.assertEqual(self.cache.read_text(self.path), '{"a": 2}')

    def test_size_change_invalidates_cache_even_with_same_mtime(self) -> None:
        self.path.write_text('{"a": 1}', encoding="utf-8")
        stat = self.path.stat()
        frozen = (stat.st_atime_ns, stat.st_mtime_ns)
        os.utime(self.path, ns=frozen)
        self.assertEqual(self.cache.read_text(self.path), '{"a": 1}')

        self.path.write_text('{"a": 1, "b": 2}', encoding="utf-8")
        os.utime(self.path, ns=frozen)

        self.assertEqual(self.cache.read_text(self.path), '{"a": 1, "b": 2}')

    def test_store_seeds_cache_without_extra_disk_read(self) -> None:
        self.path.write_text('{"seeded": true}', encoding="utf-8")
        self.cache.store(self.path, '{"seeded": true}')
        with _count_disk_reads() as reads:
            text = self.cache.read_text(self.path)

        self.assertEqual(text, '{"seeded": true}')
        self.assertEqual(len(reads), 0)

    def test_missing_file_raises(self) -> None:
        self.path.write_text('{"a": 1}', encoding="utf-8")
        self.assertEqual(self.cache.read_text(self.path), '{"a": 1}')
        self.path.unlink()

        with self.assertRaises(FileNotFoundError):
            self.cache.read_text(self.path)

    def test_clear_forces_reread(self) -> None:
        self.path.write_text('{"a": 1}', encoding="utf-8")
        self.cache.read_text(self.path)
        self.cache.clear()
        with _count_disk_reads() as reads:
            self.cache.read_text(self.path)

        self.assertEqual(len(reads), 1)


if __name__ == "__main__":
    unittest.main()
