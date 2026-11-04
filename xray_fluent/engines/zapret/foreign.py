"""Чужой Zapret рядом с приложением: winws из других папок (чаще всего Zapret 2 GUI).

Два Zapret работают через один драйвер WinDivert и по-разному меняют одни и те же
пакеты; в режиме VPN (TUN) это может остановить трафик через туннель. Приложение не
управляет чужими процессами (решение проекта: каждая программа убирает только свои),
поэтому здесь только поиск, чтобы предупредить человека.
"""

from __future__ import annotations

import ctypes
import os
from collections.abc import Callable, Iterable
from ctypes import wintypes
from pathlib import Path

ZAPRET_EXE_NAMES = ("winws.exe", "winws2.exe")

_TH32CS_SNAPPROCESS = 0x00000002
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_INVALID_HANDLE = ctypes.c_void_p(-1).value


class _ProcessEntry(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def running_zapret_processes() -> list[tuple[int, str]]:
    """Все запущенные winws.exe / winws2.exe: ``(pid, полный путь)``. Только Windows."""

    if os.name != "nt":
        return []
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    snapshot = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == _INVALID_HANDLE:
        return []
    found: list[tuple[int, str]] = []
    try:
        entry = _ProcessEntry()
        entry.dwSize = ctypes.sizeof(_ProcessEntry)
        more = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            # Имя из снимка дешёвое: путь спрашиваем только у тёзок.
            if entry.szExeFile.lower() in ZAPRET_EXE_NAMES:
                handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, entry.th32ProcessID)
                path = ""
                if handle:
                    try:
                        size = wintypes.DWORD(32768)
                        buffer = ctypes.create_unicode_buffer(size.value)
                        if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                            path = buffer.value
                    finally:
                        kernel32.CloseHandle(handle)
                found.append((int(entry.th32ProcessID), path))
            more = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return found


def foreign_zapret_processes(
    own_paths: Iterable[Path | str],
    *,
    enumerate_processes: Callable[[], list[tuple[int, str]]] = running_zapret_processes,
) -> list[tuple[int, str]]:
    """winws из других папок, чем свои. Процесс с неизвестным путём считается чужим."""

    own = {os.path.normcase(os.path.abspath(str(path))) for path in own_paths}
    foreign: list[tuple[int, str]] = []
    for pid, path in enumerate_processes():
        if pid == os.getpid():
            continue
        if path and os.path.normcase(os.path.abspath(path)) in own:
            continue
        foreign.append((pid, path))
    return foreign


__all__ = ["ZAPRET_EXE_NAMES", "foreign_zapret_processes", "running_zapret_processes"]
