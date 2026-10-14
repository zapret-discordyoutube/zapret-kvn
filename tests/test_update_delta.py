"""Частичная загрузка обновления: докачка только изменившихся файлов архива."""

from __future__ import annotations

import hashlib
import os
import random
import re
import struct
import tempfile
import threading
import unittest
import zipfile
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from xray_fluent.updates import app_updater, delta_zip
from xray_fluent.updates.delta_zip import DeltaUnavailable, HttpRangeSource, SignedFile


# ── сборка zip вручную: обычный и ZIP64 ─────────────────────────────────────


def make_zip(
    files: dict[str, bytes],
    *,
    zip64: bool = False,
    method: int = 8,
    comment: bytes = b"",
    directories: tuple[str, ...] = (),
    oem_names: bool = False,
) -> bytes:
    out = bytearray()
    directory = bytearray()
    items = [(name, b"", True) for name in directories] + [(name, data, False) for name, data in files.items()]
    for name, data, is_dir in items:
        raw = name.encode("cp866" if oem_names else "utf-8")
        flags = 0 if oem_names else 0x800
        entry_method = 0 if is_dir else method
        if entry_method == 8:
            packer = zlib.compressobj(6, zlib.DEFLATED, -15)
            packed = packer.compress(data) + packer.flush()
        else:
            packed = data
        crc = zlib.crc32(data)
        offset = len(out)
        local_extra = struct.pack("<HHQQ", 1, 16, len(data), len(packed)) if zip64 else b""
        sizes = (0xFFFFFFFF, 0xFFFFFFFF) if zip64 else (len(packed), len(data))
        out += struct.pack(
            "<4s5H3L2H", b"PK\x03\x04", 45 if zip64 else 20, flags, entry_method, 0, 0x21,
            crc, sizes[0], sizes[1], len(raw), len(local_extra),
        )
        out += raw + local_extra + packed
        central_extra = struct.pack("<HHQQQ", 1, 24, len(data), len(packed), offset) if zip64 else b""
        if oem_names:
            unicode_name = name.encode("utf-8")
            central_extra += struct.pack("<HHBL", 0x7075, 5 + len(unicode_name), 1, zlib.crc32(raw)) + unicode_name
        offset32 = 0xFFFFFFFF if zip64 else offset
        directory += struct.pack(
            "<4s6H3L5H2L", b"PK\x01\x02", 45, 45 if zip64 else 20, flags, entry_method, 0, 0x21,
            crc, sizes[0], sizes[1], len(raw), len(central_extra), 0, 0, 0, 0, offset32,
        )
        directory += raw + central_extra
    directory_offset = len(out)
    out += directory
    count = len(items)
    if zip64:
        record_offset = len(out)
        out += struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, count, count, len(directory), directory_offset)
        out += struct.pack("<4sLQL", b"PK\x06\x07", 0, record_offset, 1)
        out += struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, len(comment))
    else:
        out += struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, count, count, len(directory), directory_offset, len(comment))
    return bytes(out) + comment


def signed_for(files: dict[str, bytes]) -> list[SignedFile]:
    return [SignedFile(name, len(data), hashlib.sha256(data).hexdigest()) for name, data in files.items()]


def random_bytes(seed: int, size: int) -> bytes:
    return random.Random(seed).randbytes(size)


def release_files(changed: tuple[str, ...] = ()) -> dict[str, bytes]:
    files = {"ZapretKVN.exe": random_bytes(1, 90_000)}
    for index in range(40):
        files[f"_internal/lib{index}.dll"] = random_bytes(100 + index, 100_000)
    files["core/config.json"] = b'{"a": 1}\n' * 500
    files["empty.txt"] = b""
    for name in changed:
        files[name] = random_bytes(hash(name) & 0xFFFF, 100_000)
    return files


# ── сервер с Range ──────────────────────────────────────────────────────────


class RangeServer:
    def __init__(self, payload: bytes, *, ranges: bool = True) -> None:
        self.payload = payload
        self.ranges = ranges
        self.served = 0
        self.requests: list[str] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args) -> None:
                pass

            def _send(self, head_only: bool) -> None:
                header = self.headers.get("Range", "")
                outer.requests.append(header or "(full)")
                data = outer.payload
                match = re.fullmatch(r"bytes=(\d+)-(\d+)", header)
                if outer.ranges and match:
                    start, end = int(match[1]), min(int(match[2]), len(data) - 1)
                    self.send_response(206)
                    self.send_header("Content-Range", f"bytes {start}-{end}/{len(data)}")
                    body = data[start : end + 1]
                else:
                    self.send_response(200)
                    body = data
                if outer.ranges:
                    self.send_header("Accept-Ranges", "bytes")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if not head_only:
                    outer.served += len(body)
                    try:
                        self.wfile.write(body)
                    except OSError:
                        pass

            def do_GET(self) -> None:
                self._send(False)

            def do_HEAD(self) -> None:
                self._send(True)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/a.zip"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


class _TempCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def server(self, payload: bytes, **kwargs) -> RangeServer:
        server = RangeServer(payload, **kwargs)
        self.addCleanup(server.close)
        return server

    def install(self, files: dict[str, bytes]) -> Path:
        root = self.tmp / "installed"
        for name, data in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return root

    def source(self, server: RangeServer) -> HttpRangeSource:
        opener = app_updater.urllib.request.build_opener(app_updater.urllib.request.ProxyHandler({}))
        return HttpRangeSource(server.url, opener, total=len(server.payload), user_agent="test")

    def run_delta(self, server: RangeServer, new: dict[str, bytes], installed: Path | None, **kwargs):
        destination = self.tmp / "out"
        stats = delta_zip.prepare_delta(
            source=self.source(server),
            total_size=len(server.payload),
            signed=signed_for(new),
            local_root=installed,
            destination=destination,
            work_dir=self.tmp / "work",
            **kwargs,
        )
        return destination, stats

    def assert_tree(self, destination: Path, files: dict[str, bytes]) -> None:
        found = {
            path.relative_to(destination).as_posix(): path.read_bytes()
            for path in destination.rglob("*")
            if path.is_file()
        }
        self.assertEqual(found, files)


class DirectoryParsingTests(unittest.TestCase):
    def read(self, payload: bytes):
        class Memory:
            def read_range(self, start, end):
                return payload[start : end + 1]

            def stream_range(self, start, end, sink):
                sink(payload[start : end + 1])

        return delta_zip.read_directory(Memory(), len(payload))

    def test_matches_zipfile_on_a_regular_archive(self) -> None:
        files = release_files()
        payload = make_zip(files, comment=b"hello", directories=("core/",))
        directory = self.read(payload)
        self.assertEqual(
            sorted((e.name, e.size, e.crc32) for e in directory.entries if not e.is_dir),
            sorted((n, len(d), zlib.crc32(d)) for n, d in files.items()),
        )
        self.assertEqual([e.name for e in directory.entries if e.is_dir], ["core/"])

    def test_reads_zip64_directory_and_extra_fields(self) -> None:
        files = release_files()
        directory = self.read(make_zip(files, zip64=True))
        by_name = {e.name: e for e in directory.entries}
        self.assertEqual(by_name["ZapretKVN.exe"].size, 90_000)
        self.assertEqual(by_name["empty.txt"].size, 0)
        self.assertGreater(by_name["_internal/lib39.dll"].offset, by_name["_internal/lib1.dll"].offset)

    def test_reads_archives_made_by_python_zipfile(self) -> None:
        import io

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
            for name, data in release_files().items():
                bundle.writestr(name, data)
        payload = buffer.getvalue()
        reference = zipfile.ZipFile(io.BytesIO(payload)).infolist()
        directory = self.read(payload)
        self.assertEqual(
            [(e.name, e.offset, e.compressed_size, e.size, e.crc32) for e in directory.entries],
            [(i.filename, i.header_offset, i.compress_size, i.file_size, i.CRC) for i in reference],
        )

    def test_names_written_by_7zip_use_the_unicode_path_extra(self) -> None:
        import io

        files = {"zapret/presets/Ростелеком.txt": b"x" * 10, "ZapretKVN.exe": b"y" * 5}
        payload = make_zip(files, oem_names=True)
        names = sorted(e.name for e in self.read(payload).entries)
        self.assertEqual(names, sorted(files))
        # Так же имена читает zipfile, по которому подписан список выпуска.
        self.assertEqual(sorted(zipfile.ZipFile(io.BytesIO(payload)).namelist()), names)

    def test_garbage_is_rejected(self) -> None:
        with self.assertRaises(DeltaUnavailable):
            self.read(b"not a zip" * 100)


class PrepareDeltaTests(_TempCase):
    def _scenario(self, *, zip64: bool, method: int = 8):
        old = release_files()
        new = release_files(changed=("ZapretKVN.exe", "_internal/lib7.dll", "added.bin"))
        new["_internal/lib8.dll"] = old["_internal/lib8.dll"]
        payload = make_zip(new, zip64=zip64, method=method, directories=("core/",))
        return old, new, payload

    def test_downloads_only_changed_files(self) -> None:
        base = self.tmp
        for zip64 in (False, True):
            with self.subTest(zip64=zip64):
                self.tmp = base / f"zip64_{zip64}"
                self.tmp.mkdir()
                old, new, payload = self._scenario(zip64=zip64)
                server = self.server(payload)
                installed = self.install(old)
                seen: list[tuple[int, int]] = []
                announced: list[tuple[int, int]] = []
                destination, stats = self.run_delta(
                    server, new, installed,
                    progress=lambda done, wanted: seen.append((done, wanted)),
                    announce=lambda wanted, full: announced.append((wanted, full)),
                )
                self.assert_tree(destination, new)
                self.assertTrue((destination / "core").is_dir())
                self.assertEqual(stats.fetched_files, 3)
                self.assertEqual(stats.reused_files, len(new) - 3)
                self.assertLess(server.served, len(payload) * 0.4)
                self.assertEqual(stats.downloaded, server.served)
                self.assertLessEqual(len(server.requests), 16)
                self.assertEqual(announced, [(server.served, len(payload))])
                self.assertEqual(seen[-1][0], seen[-1][1])
                self.assertFalse((self.tmp / "work").exists())

    def test_stored_entries_work_too(self) -> None:
        old, new, payload = self._scenario(zip64=False, method=0)
        server = self.server(payload)
        destination, _ = self.run_delta(server, new, self.install(old))
        self.assert_tree(destination, new)

    def test_locally_modified_file_is_downloaded_not_trusted(self) -> None:
        old, new, payload = self._scenario(zip64=False)
        old["_internal/lib20.dll"] = b"tampered locally" + old["_internal/lib20.dll"][16:]
        new["_internal/lib20.dll"] = random_bytes(20 + 100, 100_000)
        server = self.server(make_zip(new))
        destination, stats = self.run_delta(server, new, self.install(old))
        self.assert_tree(destination, new)
        self.assertGreaterEqual(stats.fetched_files, 4)

    def test_without_installed_copy_everything_comes_from_the_archive(self) -> None:
        new = release_files()
        server = self.server(make_zip(new))
        with self.assertRaises(DeltaUnavailable):
            self.run_delta(server, new, None)

    def test_server_without_range_falls_back(self) -> None:
        old, new, payload = self._scenario(zip64=False)
        server = self.server(payload, ranges=False)
        with self.assertRaises(DeltaUnavailable):
            self.run_delta(server, new, self.install(old))
        # Весь файл сервер не успел отдать: тело 200-ответа не читается.
        self.assertLess(server.served, len(payload) * 2)

    def test_corrupted_entry_is_rejected(self) -> None:
        old, new, payload = self._scenario(zip64=False, method=0)
        marker = new["_internal/lib7.dll"][1000:1032]
        blob = bytearray(payload)
        position = blob.index(marker)
        blob[position] ^= 0xFF
        server = self.server(bytes(blob))
        with self.assertRaises(DeltaUnavailable):
            self.run_delta(server, new, self.install(old))

    def test_corrupted_deflate_stream_is_rejected(self) -> None:
        old, new, payload = self._scenario(zip64=False)
        entry = next(e for e in self._entries(payload) if e.name == "_internal/lib7.dll")
        blob = bytearray(payload)
        start = entry.offset + 30 + len(entry.raw_name) + 500
        blob[start : start + 8] = b"\xff" * 8
        server = self.server(bytes(blob))
        with self.assertRaises(DeltaUnavailable):
            self.run_delta(server, new, self.install(old))

    def test_entry_matching_crc_but_not_signed_hash_is_rejected(self) -> None:
        old, new, payload = self._scenario(zip64=False, method=0)
        forged = dict(new)
        forged["ZapretKVN.exe"] = random_bytes(999, len(new["ZapretKVN.exe"]))
        server = self.server(make_zip(forged, method=0))
        with self.assertRaises(DeltaUnavailable):
            self.run_delta(server, new, self.install(old))

    def test_archive_with_unsigned_extra_file_is_rejected(self) -> None:
        old, new, payload = self._scenario(zip64=False)
        extra = dict(new)
        extra["evil.dll"] = b"payload"
        server = self.server(make_zip(extra))
        with self.assertRaises(DeltaUnavailable):
            self.run_delta(server, new, self.install(old))

    def test_archive_missing_a_signed_file_is_rejected(self) -> None:
        old, new, payload = self._scenario(zip64=False)
        short = dict(new)
        del short["core/config.json"]
        server = self.server(make_zip(short))
        with self.assertRaises(DeltaUnavailable):
            self.run_delta(server, new, self.install(old))

    def test_not_worth_it_when_most_of_the_archive_changed(self) -> None:
        old = release_files()
        new = {name: random_bytes(7000 + i, len(data) or 1) for i, (name, data) in enumerate(old.items())}
        server = self.server(make_zip(new))
        with self.assertRaises(DeltaUnavailable):
            self.run_delta(server, new, self.install(old))
        self.assertLess(server.served, len(server.payload) * 0.7)

    def test_path_traversal_name_is_rejected(self) -> None:
        old = release_files()
        evil = dict(old)
        evil["../outside.dll"] = b"x"
        server = self.server(make_zip(evil))
        with self.assertRaises(DeltaUnavailable):
            self.run_delta(server, old, self.install(old))

    def test_ranges_are_merged_and_bounded(self) -> None:
        new = release_files()
        entries = delta_zip.read_directory(self.source(self.server(make_zip(new))), len(make_zip(new))).entries
        spans = [(e.offset, e.offset + 10) for e in entries[::2]]
        merged = delta_zip._merge_ranges(spans, gap_limit=0, max_ranges=5)
        self.assertLessEqual(len(merged), 5)
        adjacent = delta_zip._merge_ranges([(0, 10), (10, 20), (25, 30)], gap_limit=0, max_ranges=8)
        self.assertEqual(adjacent, [(0, 20), (25, 30)])

    @staticmethod
    def _entries(payload: bytes):
        class Memory:
            def read_range(self, start, end):
                return payload[start : end + 1]

            stream_range = None

        return delta_zip.read_directory(Memory(), len(payload)).entries


# ── через UpdateDownloader ──────────────────────────────────────────────────


class DownloaderDeltaTests(_TempCase):
    def setUp(self) -> None:
        super().setUp()
        for target, value in (
            (app_updater.tempfile, "gettempdir"),
        ):
            patcher = patch.object(target, value, return_value=str(self.tmp))
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(
            app_updater.tempfile, "mkdtemp", side_effect=lambda prefix: self._work_dir(prefix)
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _work_dir(self, prefix: str) -> str:
        path = self.tmp / f"{prefix}test"
        path.mkdir()
        return str(path)

    def _downloader(self, new, payload, server, installed, *, digest=None, with_files=True):
        update = app_updater.AppUpdate(
            version="9.9.9",
            tag="v9.9.9",
            download_url=server.url,
            size=len(payload),
            notes="",
            digest_sha256=digest or hashlib.sha256(payload).hexdigest(),
            files=tuple(signed_for(new)) if with_files else (),
        )
        downloader = app_updater.UpdateDownloader(update, app_dir=installed)
        self.errors: list[str] = []
        self.statuses: list[str] = []
        self.percent: list[int] = []
        downloader.error.connect(self.errors.append)
        downloader.status.connect(self.statuses.append)
        downloader.progress.connect(self.percent.append)
        return downloader

    def _scenario(self):
        old = release_files()
        new = release_files(changed=("ZapretKVN.exe", "_internal/lib3.dll"))
        return old, new, make_zip(new)

    def test_delta_download_builds_the_prepared_update_without_the_full_archive(self) -> None:
        old, new, payload = self._scenario()
        server = self.server(payload)
        downloader = self._downloader(new, payload, server, self.install(old))
        downloader.run()
        self.assertEqual(self.errors, [])
        prepared = downloader.prepared
        self.assertIsNotNone(prepared)
        self.assert_tree(prepared.source_dir, new)
        self.assertLess(server.served, len(payload) * 0.5)
        self.assertNotIn("(full)", server.requests)
        self.assertTrue(any(text.startswith("Загрузка изменений:") and "МБ из" in text for text in self.statuses))
        self.assertEqual(self.percent[-1], 100)

    def test_range_unsupported_server_gets_the_full_verified_download(self) -> None:
        old, new, payload = self._scenario()
        server = self.server(payload, ranges=False)
        downloader = self._downloader(new, payload, server, self.install(old))
        downloader.run()
        self.assertEqual(self.errors, [])
        self.assert_tree(downloader.prepared.source_dir, new)
        self.assertGreaterEqual(server.served, len(payload))

    def test_corrupted_entry_falls_back_to_full_download_and_full_checksum(self) -> None:
        old, new, payload = self._scenario()
        good = make_zip(new, method=0)
        blob = bytearray(good)
        blob[blob.index(new["ZapretKVN.exe"][2000:2032])] ^= 0xFF
        server = self.server(bytes(blob))
        # Подписанный хеш всего архива — у исправного; испорченный отдаётся сервером.
        downloader = self._downloader(new, good, server, self.install(old))
        downloader.run()
        self.assertIsNone(downloader.prepared)
        self.assertTrue(downloader.failure_permanent)
        self.assertEqual(self.errors, ["Контрольная сумма архива не совпадает"])
        # Полная загрузка была: её сумма проверена, испорченный архив не принят.
        self.assertTrue(any(r == "(full)" or r.startswith("bytes=0-") for r in server.requests))

    def test_without_signed_file_list_the_archive_is_downloaded_whole(self) -> None:
        old, new, payload = self._scenario()
        server = self.server(payload)
        downloader = self._downloader(new, payload, server, self.install(old), with_files=False)
        downloader.run()
        self.assertEqual(self.errors, [])
        self.assert_tree(downloader.prepared.source_dir, new)
        self.assertGreaterEqual(server.served, len(payload))

    def test_network_failure_of_delta_is_followed_by_the_normal_path(self) -> None:
        old, new, payload = self._scenario()
        server = self.server(payload)
        downloader = self._downloader(new, payload, server, self.install(old))
        with patch.object(app_updater, "prepare_delta", side_effect=OSError("no route")):
            downloader.run()
        self.assertEqual(self.errors, [])
        self.assert_tree(downloader.prepared.source_dir, new)


if __name__ == "__main__":
    unittest.main()
