"""Python modules keep loading from the exe this process started from, even after the file is replaced.

PyInstaller 6 (``pyimod01_archive.ZlibArchiveReader.extract``) reopens the exe BY NAME for every lazy import, on
purpose, so that the exe can be renamed while it runs. Once another file takes that name, the next lazy import reads
the new file at the old offsets: ``zlib.error`` (bytes of another build) or ``OSError`` (the name is mid-rename). Field
check #3 (2026-11-23): 15 such crashes on 0.8.102-0.8.107, in ``start_metrics_worker`` and in the disconnect cleanup,
often seconds from a failed update on the same install; the app errors carry no message, so which program swapped the
files is not known.

``install`` gives the reader one descriptor to the original file, opened so that renaming and deleting the exe keep
working exactly as before (``FILE_SHARE_DELETE`` on Windows: the updater's swap, an unpacked zip). A descriptor follows
the file, not the name, so every later import still reads this build's bytes. The first time the name is seen pointing
at another file, ``on_replaced`` runs once (main.py logs it and notes the app error ``update:exe_replaced``), so the
cause stays visible in the field while the app no longer crashes from it. The name is looked at no more than every
``CHECK_EVERY_S``: hundreds of imports at start cost one ``stat`` each otherwise.
"""

from __future__ import annotations

import logging
import marshal
import os
import sys
import threading
import time
import zlib
from collections.abc import Callable

_log = logging.getLogger(__name__)

APP_ERROR = "update:exe_replaced"
CHECK_EVERY_S = 5.0

_GENERIC_READ = 0x80000000
_SHARE_ALL = 0x1 | 0x2 | 0x4  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x80


def open_shared(path: str) -> int:
    """A read-only descriptor that never stops anyone renaming, replacing or deleting the file."""
    if os.name != "nt":
        return os.open(path, os.O_RDONLY)
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel32.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    handle = create(path, _GENERIC_READ, _SHARE_ALL, None, _OPEN_EXISTING, _FILE_ATTRIBUTE_NORMAL, None)
    if handle is None or handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except Exception:
        kernel32.CloseHandle(handle)
        raise


def _identity(result: os.stat_result) -> tuple[int, int]:
    return result.st_dev, result.st_ino


class PinnedExtract:
    """``ZlibArchiveReader.extract`` over a held descriptor; the same answers and errors as PyInstaller's own."""

    def __init__(
        self,
        reader,
        descriptor: int,
        kinds: tuple[int, int, int],
        on_replaced: Callable[[], None],
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._reader = reader
        self._descriptor = descriptor
        self._module, self._package, self._namespace = kinds
        self._on_replaced = on_replaced
        self._clock = clock
        self._lock = threading.Lock()
        self._identity = _identity(os.fstat(descriptor))
        self._checked_at: float | None = None
        self._replaced = False

    def __call__(self, name: str, raw: bool = False):
        entry = self._reader.toc.get(name)
        if entry is None:
            raise KeyError(f"No entry named {name!r} found in the archive!")
        typecode, offset, length = entry
        if typecode == self._namespace:
            return None
        with self._lock:  # imports of different modules may run in parallel threads
            os.lseek(self._descriptor, self._reader._start_offset + offset, os.SEEK_SET)
            blob = _read_exactly(self._descriptor, length)
        self._look_at_name()
        try:
            data = zlib.decompress(blob)
            if typecode in (self._module, self._package) and not raw:
                data = marshal.loads(data)
        except EOFError as error:
            raise ImportError(f"Failed to unmarshal PYZ entry {name!r}!") from error
        return data

    @property
    def replaced(self) -> bool:
        return self._replaced

    def _look_at_name(self) -> None:
        if self._replaced:
            return
        now = self._clock()
        if self._checked_at is not None and now - self._checked_at < CHECK_EVERY_S:
            return
        self._checked_at = now
        try:
            same = _identity(os.stat(self._reader._filename)) == self._identity
        except OSError:
            same = False
        if same:
            return
        self._replaced = True
        try:
            self._on_replaced()
        except Exception:
            _log.exception("on_replaced failed")


def _read_exactly(descriptor: int, length: int) -> bytes:
    parts: list[bytes] = []
    left = length
    while left > 0:
        chunk = os.read(descriptor, left)
        if not chunk:
            break
        parts.append(chunk)
        left -= len(chunk)
    return b"".join(parts)


def pin(reader, kinds: tuple[int, int, int], on_replaced: Callable[[], None]) -> PinnedExtract:
    """Make ``reader.extract`` read through one held descriptor to its file (the reader's own instance attribute)."""
    descriptor = open_shared(reader._filename)
    try:
        extract = PinnedExtract(reader, descriptor, kinds, on_replaced)
    except Exception:
        os.close(descriptor)
        raise
    reader.extract = extract
    return extract


def install(on_replaced: Callable[[], None]) -> bool:
    """Pin the frozen app's module archive; False when not frozen or PyInstaller's reader has another shape."""
    if not getattr(sys, "frozen", False):
        return False
    try:
        import pyimod01_archive as archive
        import pyimod02_importers as importers
    except ImportError:
        return False
    reader = getattr(importers, "pyz_archive", None)
    if (
        reader is None
        or not isinstance(getattr(reader, "_filename", None), str)
        or not isinstance(getattr(reader, "_start_offset", None), int)
        or not isinstance(getattr(reader, "toc", None), dict)
    ):
        return False
    try:
        pin(reader, (archive.PYZ_ITEM_MODULE, archive.PYZ_ITEM_PKG, archive.PYZ_ITEM_NSPKG), on_replaced)
    except Exception:
        _log.exception("Could not pin the module archive")
        return False
    return True
