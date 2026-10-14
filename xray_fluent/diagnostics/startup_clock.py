"""Время от создания процесса — для отметок запуска в startup.log.

Отметки от конструктора окна не видят импорт модулей и загрузчик
PyInstaller, а именно там уходит большая часть холодного старта.
"""

from __future__ import annotations

import sys
import time

_FALLBACK_ORIGIN = time.time()


def _process_creation_time() -> float | None:
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        kernel32.GetProcessTimes.restype = wintypes.BOOL
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel_time = wintypes.FILETIME()
        user_time = wintypes.FILETIME()
        if not kernel32.GetProcessTimes(
            kernel32.GetCurrentProcess(),
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            return None
        ticks = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
        # FILETIME: сотни наносекунд с 1601-01-01; до эпохи Unix 11644473600 с.
        return ticks / 10_000_000 - 11_644_473_600
    except Exception:
        return None


_ORIGIN = _process_creation_time() or _FALLBACK_ORIGIN


def since_process_start_ms() -> float:
    return max(0.0, (time.time() - _ORIGIN) * 1000.0)
