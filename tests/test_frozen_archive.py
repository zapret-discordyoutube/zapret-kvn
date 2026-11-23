"""The module archive keeps reading this build's exe after the file is replaced (xray_fluent/platform/frozen_archive.py)."""

from __future__ import annotations

import importlib.util
import marshal
import os
import struct
import tempfile
import unittest
import zlib
from importlib.util import MAGIC_NUMBER
from pathlib import Path

from xray_fluent.platform import frozen_archive

MODULE, PACKAGE, NAMESPACE = 0, 1, 3


def _write_exe(path: Path, modules: dict[str, str], prefix: bytes) -> int:
    """A stub "exe": ``prefix`` then a PYZ in PyInstaller's format (header, zlib(marshal(code)) blobs, marshal(toc))."""
    body = bytearray(b"\0" * 17)
    toc = []
    for name, source in modules.items():
        blob = zlib.compress(marshal.dumps(compile(source, f"{name}.py", "exec")), 6)
        toc.append((name, (MODULE, len(body), len(blob))))
        body += blob
    toc.append(("spacepkg", (NAMESPACE, len(body), 0)))
    toc_offset = len(body)
    body += marshal.dumps(toc)
    body[0:12] = b"PYZ\0" + MAGIC_NUMBER + struct.pack("!i", toc_offset)
    path.write_bytes(prefix + bytes(body))
    return len(prefix)


def _real_reader_class():
    """PyInstaller's own ``ZlibArchiveReader``, loaded from its file (the package itself needs build-time tools)."""
    spec = importlib.util.find_spec("PyInstaller")
    if spec is None or not spec.submodule_search_locations:
        return None
    source = Path(next(iter(spec.submodule_search_locations))) / "loader" / "pyimod01_archive.py"
    if not source.is_file():
        return None
    module_spec = importlib.util.spec_from_file_location("_pyi_archive_for_tests", source)
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module.ZlibArchiveReader


class _Reader:
    """The three attributes PinnedExtract relies on, as PyInstaller's reader has them."""

    def __init__(self, filename: str, start_offset: int) -> None:
        self._filename = filename
        self._start_offset = start_offset
        with open(filename, "rb") as handle:
            handle.seek(start_offset + 8)
            (toc_offset,) = struct.unpack("!i", handle.read(4))
            handle.seek(start_offset + toc_offset)
            self.toc = dict(marshal.load(handle))


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _value(code) -> object:
    scope: dict[str, object] = {}
    exec(code, scope)
    return scope["VALUE"]


class PinnedExtractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp())
        self.exe = self.directory / "ZapretKVN.exe"
        self.offset = _write_exe(self.exe, {"alpha": "VALUE = 'old alpha'", "beta": "VALUE = 'old beta'"}, b"MZ" * 300)
        self.calls: list[str] = []
        self.clock = _Clock()
        self.reader = _Reader(str(self.exe), self.offset)
        descriptor = frozen_archive.open_shared(str(self.exe))
        self.extract = frozen_archive.PinnedExtract(
            self.reader, descriptor, (MODULE, PACKAGE, NAMESPACE), lambda: self.calls.append("replaced"), clock=self.clock
        )
        self.addCleanup(os.close, descriptor)

    def _replace_exe(self) -> None:
        # The updater's swap: the running exe is renamed away, a new build takes its name.
        os.replace(self.exe, self.directory / "ZapretKVN.old.exe")
        _write_exe(self.exe, {"alpha": "VALUE = 'NEW alpha'", "beta": "VALUE = 'NEW beta'"}, b"MZ" * 999)

    def test_answers_like_pyinstaller(self) -> None:
        self.assertEqual(_value(self.extract("alpha")), "old alpha")
        self.assertIsInstance(self.extract("alpha", raw=True), bytes)
        self.assertIsNone(self.extract("spacepkg"))
        with self.assertRaises(KeyError):
            self.extract("missing")
        self.assertEqual(self.calls, [])

    def test_reads_the_original_after_the_exe_is_replaced_and_says_so_once(self) -> None:
        self.assertEqual(_value(self.extract("alpha")), "old alpha")
        self._replace_exe()
        self.clock.now += frozen_archive.CHECK_EVERY_S
        self.assertEqual(_value(self.extract("beta")), "old beta")
        self.assertEqual(self.calls, ["replaced"])
        self.clock.now += frozen_archive.CHECK_EVERY_S
        self.assertEqual(_value(self.extract("alpha")), "old alpha")
        self.assertEqual(self.calls, ["replaced"])
        self.assertTrue(self.extract.replaced)

    def test_reads_the_original_after_the_exe_is_deleted(self) -> None:
        if os.name == "nt":
            self.skipTest("a deleted file stays readable through the handle; Windows keeps the name until it closes")
        os.unlink(self.exe)
        self.clock.now += frozen_archive.CHECK_EVERY_S
        self.assertEqual(_value(self.extract("beta")), "old beta")
        self.assertEqual(self.calls, ["replaced"])

    def test_the_name_is_looked_at_at_most_every_few_seconds(self) -> None:
        self.extract("alpha")  # the first read looks at the name
        self._replace_exe()
        self.extract("beta")
        self.assertEqual(self.calls, [])
        self.clock.now += frozen_archive.CHECK_EVERY_S
        self.extract("beta")
        self.assertEqual(self.calls, ["replaced"])

    def test_a_failing_callback_does_not_break_imports(self) -> None:
        def explode() -> None:
            raise RuntimeError("boom")

        descriptor = frozen_archive.open_shared(str(self.exe))
        self.addCleanup(os.close, descriptor)
        extract = frozen_archive.PinnedExtract(self.reader, descriptor, (MODULE, PACKAGE, NAMESPACE), explode, clock=self.clock)
        self._replace_exe()
        with self.assertLogs(frozen_archive.__name__, "ERROR"):
            self.assertEqual(_value(extract("alpha")), "old alpha")

    def test_install_does_nothing_outside_a_frozen_app(self) -> None:
        self.assertFalse(frozen_archive.install(lambda: None))


@unittest.skipIf(_real_reader_class() is None, "PyInstaller is not installed (the Windows build venv has it)")
class RealPyInstallerReaderTest(unittest.TestCase):
    """PyInstaller's own reader: the field crash, then the same reader pinned."""

    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp())
        self.exe = self.directory / "ZapretKVN.exe"
        offset = _write_exe(self.exe, {"alpha": "VALUE = 'old alpha'"}, b"MZ" * 300)
        self.reader = _real_reader_class()(f"{self.exe}?{offset}", check_pymagic=True)

    def _replace_exe(self) -> None:
        os.replace(self.exe, self.directory / "ZapretKVN.old.exe")
        _write_exe(self.exe, {"alpha": "VALUE = 'NEW alpha'"}, b"MZ" * 999)

    def test_unpinned_reader_crashes_after_the_exe_is_replaced(self) -> None:
        self.assertEqual(_value(self.reader.extract("alpha")), "old alpha")
        self._replace_exe()
        with self.assertRaises(zlib.error):  # crash:error at pyimod01_archive.extract:134 in the field
            self.reader.extract("alpha")

    def test_pinned_reader_keeps_reading_this_build(self) -> None:
        calls: list[str] = []
        extract = frozen_archive.pin(self.reader, (MODULE, PACKAGE, NAMESPACE), lambda: calls.append("replaced"))
        self.addCleanup(os.close, extract._descriptor)
        self.assertIs(self.reader.extract, extract)
        self.assertEqual(_value(self.reader.extract("alpha")), "old alpha")
        self._replace_exe()
        extract._checked_at = None
        self.assertEqual(_value(self.reader.extract("alpha")), "old alpha")
        self.assertEqual(calls, ["replaced"])


if __name__ == "__main__":
    unittest.main()
