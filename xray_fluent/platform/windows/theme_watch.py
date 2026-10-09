"""Останавливаемое ожидание смены системной темы Windows.

``darkdetect.listener`` ждёт изменения реестра синхронным
``RegNotifyChangeKeyValue`` и не возвращается никогда. Поток с таким вызовом
нельзя завершить по просьбе, а разрушение работающего ``QThread`` — ``qFatal``:
так приложение падало при выходе (0xc0000409 в Qt6Core.dll).

Здесь уведомление реестра асинхронное: поток ждёт сразу два события — «ключ
изменился» и «пора остановиться» — и по второму выходит сам.
"""

from __future__ import annotations

import sys
from typing import Callable

IS_WINDOWS = sys.platform == "win32"

_KEY_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
_VALUE_NAME = "AppsUseLightTheme"

if IS_WINDOWS:
    import ctypes
    import winreg
    from ctypes import wintypes

    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _REG_NOTIFY_CHANGE_LAST_SET = 0x00000004
    _INFINITE = 0xFFFFFFFF
    _WAIT_OBJECT_0 = 0

    _advapi32.RegNotifyChangeKeyValue.argtypes = [
        wintypes.HANDLE, wintypes.BOOL, wintypes.DWORD, wintypes.HANDLE, wintypes.BOOL,
    ]
    _advapi32.RegNotifyChangeKeyValue.restype = wintypes.LONG
    _kernel32.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    _kernel32.CreateEventW.restype = wintypes.HANDLE
    _kernel32.SetEvent.argtypes = [wintypes.HANDLE]
    _kernel32.SetEvent.restype = wintypes.BOOL
    _kernel32.ResetEvent.argtypes = [wintypes.HANDLE]
    _kernel32.ResetEvent.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.WaitForMultipleObjects.argtypes = [
        wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE), wintypes.BOOL, wintypes.DWORD,
    ]
    _kernel32.WaitForMultipleObjects.restype = wintypes.DWORD


class ThemeRegistryWatch:
    """Ждёт смену темы приложений Windows, пока не вызван :meth:`stop`.

    Вне Windows объект пуст: :meth:`run` сразу возвращается.
    """

    def __init__(self) -> None:
        # Событие остановки создаётся сразу: stop() может прийти раньше run().
        self._stop_event = _kernel32.CreateEventW(None, True, False, None) if IS_WINDOWS else None

    def stop(self) -> None:
        if self._stop_event:
            _kernel32.SetEvent(self._stop_event)

    def close(self) -> None:
        """Освободить событие; вызывать только после завершения :meth:`run`."""
        if self._stop_event:
            _kernel32.CloseHandle(self._stop_event)
            self._stop_event = None

    def run(self, callback: Callable[[str], None]) -> None:
        """Вызывать ``callback("Light" | "Dark")`` при каждой смене темы."""
        if not self._stop_event:
            return
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY_PATH, 0, winreg.KEY_READ)
        except OSError:
            return
        changed = _kernel32.CreateEventW(None, True, False, None)
        try:
            if not changed:
                return
            last = self._read(key)
            handles = (wintypes.HANDLE * 2)(changed, self._stop_event)
            while True:
                # Асинхронная подписка одноразовая: её ставят заново на каждом круге.
                if _advapi32.RegNotifyChangeKeyValue(
                    int(key), True, _REG_NOTIFY_CHANGE_LAST_SET, changed, True
                ) != 0:
                    return
                if _kernel32.WaitForMultipleObjects(2, handles, False, _INFINITE) != _WAIT_OBJECT_0:
                    # Остановка или сбой ожидания: в обоих случаях выходим.
                    return
                _kernel32.ResetEvent(changed)
                value = self._read(key)
                if value is not None and value != last:
                    last = value
                    callback("Light" if value else "Dark")
        finally:
            if changed:
                _kernel32.CloseHandle(changed)
            winreg.CloseKey(key)

    @staticmethod
    def _read(key) -> int | None:
        try:
            return int(winreg.QueryValueEx(key, _VALUE_NAME)[0])
        except (OSError, ValueError, TypeError):
            return None
