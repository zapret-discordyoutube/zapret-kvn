"""Процессы Windows, от которых зависит замена файлов (из Zapret KVN).

Модуль импортируется и вне Windows (тесты ядра идут на любой ОС), но сами
вызовы WinAPI там недоступны: функции возвращают «пусто».
"""

from __future__ import annotations

import ntpath
import os
import re
import subprocess
import sys
import time
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"

CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _SYNCHRONIZE = 0x00100000
    _PROCESS_TERMINATE = 0x0001
    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    _TH32CS_SNAPPROCESS = 0x00000002
    _WAIT_TIMEOUT = 0x00000102
    _INVALID_HANDLE = wintypes.HANDLE(-1).value

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

    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _kernel32.WaitForSingleObject.restype = wintypes.DWORD
    _kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateProcess.restype = wintypes.BOOL
    _kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry)]
    _kernel32.Process32FirstW.restype = wintypes.BOOL
    _kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry)]
    _kernel32.Process32NextW.restype = wintypes.BOOL
    _kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
    ]
    _kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL


def wait_for_exit(pid: int, timeout_s: float) -> bool:
    """Дождаться завершения процесса; True — его больше нет."""

    if not IS_WINDOWS:
        return True
    handle = _kernel32.OpenProcess(_SYNCHRONIZE, False, pid)
    if not handle:
        return True
    try:
        return _kernel32.WaitForSingleObject(handle, int(timeout_s * 1000)) != _WAIT_TIMEOUT
    finally:
        _kernel32.CloseHandle(handle)


def terminate(pid: int) -> None:
    if not IS_WINDOWS:
        return
    handle = _kernel32.OpenProcess(_PROCESS_TERMINATE, False, pid)
    if not handle:
        return
    try:
        _kernel32.TerminateProcess(handle, 1)
    finally:
        _kernel32.CloseHandle(handle)


def _image_path(pid: int) -> str:
    handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ""
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not _kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return ""
        return buffer.value
    finally:
        _kernel32.CloseHandle(handle)


def processes_under(root: Path) -> list[tuple[int, str]]:
    """Чужие процессы, чей исполняемый файл лежит внутри ``root``."""

    if not IS_WINDOWS:
        return []
    prefix = os.path.normcase(str(root)).rstrip("\\") + "\\"
    snapshot = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == _INVALID_HANDLE:
        return []
    found: list[tuple[int, str]] = []
    try:
        entry = _ProcessEntry()
        entry.dwSize = ctypes.sizeof(_ProcessEntry)
        more = _kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            pid = int(entry.th32ProcessID)
            if pid and pid != os.getpid():
                path = _image_path(pid)
                if path and os.path.normcase(path).startswith(prefix):
                    found.append((pid, path))
            more = _kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        _kernel32.CloseHandle(snapshot)
    return found


def processes_at(executable: Path) -> list[int]:
    """Процессы (кроме своего), запущенные именно из этого исполняемого файла."""

    if not IS_WINDOWS:
        return []
    target = os.path.normcase(os.path.abspath(str(executable)))
    name = os.path.basename(target)
    snapshot = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == _INVALID_HANDLE:
        raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
    found: list[int] = []
    try:
        entry = _ProcessEntry()
        entry.dwSize = ctypes.sizeof(_ProcessEntry)
        more = _kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            pid = int(entry.th32ProcessID)
            # Имя из снимка дешёвое: путь спрашиваем только у тёзок.
            if pid and pid != os.getpid() and os.path.normcase(entry.szExeFile) == name:
                path = _image_path(pid)
                if path and os.path.normcase(path) == target:
                    found.append(pid)
            more = _kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        _kernel32.CloseHandle(snapshot)
    return found


def stop_processes_under(root: Path, timeout_s: float = 20.0) -> list[str]:
    """Завершить ядра и прочие процессы приложения; вернуть тех, кто выжил.

    Ядра живут отдельными процессами внутри каталога приложения и держат
    свои файлы открытыми и после выхода главного окна.
    """

    deadline = time.monotonic() + timeout_s
    while True:
        running = processes_under(root)
        if not running:
            return []
        for pid, _ in running:
            terminate(pid)
        if time.monotonic() >= deadline:
            return [path for _, path in running]
        time.sleep(0.3)


def lock_holders(path: Path) -> list[str]:
    """Названия программ, которые держат файл открытым (Restart Manager)."""
    return [f"{name} ({image})" if image else name for name, _service, image in _holder_records(path)]


def lock_holder_codes(path: Path) -> list[str]:
    """Короткие коды держателей файла для сервера: ``msmpeng``, ``explorer``, ``wsearch``…"""
    codes = []
    for name, service, image in _holder_records(path):
        code = holder_code(image, name, service)
        if code and code not in codes:
            codes.append(code)
    return codes


def holder_code(image: str = "", name: str = "", service: str = "") -> str:
    """Код держателя в виде кода причины (``[a-z][a-z0-9]{0,15}``).

    У службы — её короткое имя (под одной svchost.exe их много), у программы —
    имя exe без «.exe»: путь и имя пользователя на сервер не уходят.
    """
    base = service or ntpath.basename(str(image or "")) or str(name or "")
    if base.lower().endswith(".exe"):
        base = base[:-4]
    text = re.sub(r"[^a-z0-9]", "", base.lower())
    if text and not text[0].isalpha():
        text = "p" + text
    return text[:16]


def _holder_records(path: Path) -> list[tuple[str, str, str]]:
    """``(название, короткое имя службы, путь к exe)`` каждого держателя файла."""
    if not IS_WINDOWS:
        return []
    try:
        return _lock_holders(path)
    except Exception:
        # Диагностика не должна мешать откату.
        return []


def _lock_holders(path: Path) -> list[tuple[str, str, str]]:
    class _UniqueProcess(ctypes.Structure):
        _fields_ = [("dwProcessId", wintypes.DWORD), ("ProcessStartTime", wintypes.FILETIME)]

    class _ProcessInfo(ctypes.Structure):
        _fields_ = [
            ("Process", _UniqueProcess),
            ("strAppName", wintypes.WCHAR * 256),
            ("strServiceShortName", wintypes.WCHAR * 64),
            ("ApplicationType", ctypes.c_int),
            ("AppStatus", wintypes.ULONG),
            ("TSSessionId", wintypes.DWORD),
            ("bRestartable", wintypes.BOOL),
        ]

    manager = ctypes.WinDLL("rstrtmgr")
    session = wintypes.DWORD(0)
    session_key = ctypes.create_unicode_buffer(33)
    if manager.RmStartSession(ctypes.byref(session), 0, session_key) != 0:
        return []
    try:
        files = (wintypes.LPCWSTR * 1)(str(path))
        if manager.RmRegisterResources(session, 1, files, 0, None, 0, None) != 0:
            return []
        needed = wintypes.UINT(0)
        count = wintypes.UINT(16)
        info = (_ProcessInfo * 16)()
        reasons = wintypes.DWORD(0)
        result = manager.RmGetList(
            session, ctypes.byref(needed), ctypes.byref(count), info, ctypes.byref(reasons)
        )
        # 234 (ERROR_MORE_DATA): держателей больше 16 — первых достаточно.
        if result not in (0, 234):
            return []
        holders = []
        for item in info[: min(count.value, 16)]:
            name = str(item.strAppName or item.strServiceShortName or "")
            holders.append((name, str(item.strServiceShortName or ""), _image_path(int(item.Process.dwProcessId))))
        return holders
    finally:
        manager.RmEndSession(session)


def clean_environment() -> dict[str, str]:
    """Окружение без служебных переменных сборщиков (PyInstaller, Nuitka).

    Установщик и приложение — разные сборки одного exe; унаследованные
    ``_PYI_*`` заставили бы дочерний процесс считать себя частью чужой.
    """

    return {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith(("_PYI_", "_MEIPASS", "NUITKA_"))
    }


def start_detached(
    command: list[str], *, cwd: Path, env: dict[str, str] | None = None
) -> subprocess.Popen:
    """Запустить процесс, не привязанный к текущему: без окна и без Ctrl+C.

    Приложение собрано консольным. Со своим окном консоли
    (``CREATE_NEW_CONSOLE``) оно на старте забирало фокус, и Ctrl+C — с
    клавиатуры или от чужой программы — обрывал запуск раньше, чем
    приложение успевало защититься само. Так 09.10.2026 сорвалось обновление
    до v0.8.18, а затем и запуск прежней версии после отката.
    ``CREATE_NEW_PROCESS_GROUP`` отключает Ctrl+C с первой инструкции
    процесса, но вместе с ``CREATE_NEW_CONSOLE`` Windows его не учитывает:
    поэтому окна консоли нет вовсе.
    """

    return subprocess.Popen(
        command,
        cwd=str(cwd),
        env={**clean_environment(), **(env or {})},
        close_fds=True,
        creationflags=(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP) if IS_WINDOWS else 0,
    )
