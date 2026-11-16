"""WinDivert after «Пакеты-обманки»: unload the driver sing-box loaded, so it is free again.

sing-box `tls_spoof` (common/windivert/driver_windows.go) installs the driver as the kernel
service ``WinDivert`` from its own copy (``%LOCALAPPDATA%\\sing-box\\windivert\\v2.2.2``) and
marks the service for deletion, like WinDivert.dll does. The driver itself stays loaded after
the last handle closes, until reboot or ``sc stop`` (WinDivert 2.2 manual). Owner 2026-11-16:
when spoofing is turned off, the session stops or the app exits, WinDivert must be unloaded
and available — so after a sing-box process whose config opened WinDivert has exited, the
app stops that service.

The bundled Zapret uses the same driver binary (``Monkey64.sys`` is byte-identical to
sing-box's ``WinDivert64.sys`` 2.2.2) under another service name, ``Monkey``, and shares the
device. Stopping a driver while a process still holds a handle would leave it half-unloaded,
so nothing is stopped while any known WinDivert user runs (winws/winws2 of any folder,
GoodbyeDPI): they keep the driver, and it stays available to them.
"""

from __future__ import annotations

import ctypes
import logging
import os
import time
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass

_LOG = logging.getLogger(__name__)

#: The service sing-box creates (driverServiceName in common/windivert/driver_windows.go).
SERVICE_NAME = "WinDivert"

#: Processes known to hold WinDivert handles.
WINDIVERT_USERS = ("winws.exe", "winws2.exe", "goodbyedpi.exe")

_STOP_WAIT_S = 3.0


@dataclass(frozen=True, slots=True)
class Decision:
    release: bool
    message: str


def decide(*, state: str | None, users: list[str]) -> Decision:
    """What to do after a sing-box process that opened WinDivert has exited.

    ``state``: the ``WinDivert`` service state (``running``, ``stopped``, …) or None when
    the service does not exist; ``users``: names of running WinDivert users.
    """
    if state is None or state == "stopped":
        return Decision(False, "WinDivert не загружен")
    if users:
        return Decision(False, f"WinDivert оставлен загруженным: им пользуется {', '.join(sorted(set(users)))}")
    if state != "running":
        return Decision(False, f"WinDivert в состоянии {state}: не трогаю")
    return Decision(True, "WinDivert выгружается")


def release_if_unused(
    *,
    query: Callable[[], str | None] | None = None,
    stop: Callable[[], bool] | None = None,
    users: Callable[[], list[str]] | None = None,
) -> str:
    """Worker-only: stop the ``WinDivert`` service when nobody else uses it; the log line."""
    query = query or service_state
    stop = stop or stop_service
    users = users or running_users
    try:
        decision = decide(state=query(), users=users())
        if not decision.release:
            return decision.message
        if not stop():
            return "WinDivert не выгружен: служба не остановилась"
        deadline = time.monotonic() + _STOP_WAIT_S
        while time.monotonic() < deadline:
            if query() in (None, "stopped"):
                return "WinDivert выгружен, драйвер свободен"
            time.sleep(0.05)
        return "WinDivert не выгружен вовремя: служба ещё останавливается"
    except OSError as exc:
        _LOG.warning("WinDivert release failed: %s", exc)
        return f"WinDivert не выгружен: {exc}"


# ── Windows adapter ───────────────────────────────────────────────────────

_SC_MANAGER_CONNECT = 0x0001
_SERVICE_QUERY_STATUS = 0x0004
_SERVICE_STOP = 0x0020
_SERVICE_CONTROL_STOP = 0x00000001
_ERROR_SERVICE_DOES_NOT_EXIST = 1060
_ERROR_SERVICE_NOT_ACTIVE = 1062
_STATES = {1: "stopped", 2: "start_pending", 3: "stop_pending", 4: "running",
           5: "continue_pending", 6: "pause_pending", 7: "paused"}


class _ServiceStatus(ctypes.Structure):
    _fields_ = [(name, wintypes.DWORD) for name in (
        "dwServiceType", "dwCurrentState", "dwControlsAccepted", "dwWin32ExitCode",
        "dwServiceSpecificExitCode", "dwCheckPoint", "dwWaitHint")]


def _advapi():
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    advapi.OpenSCManagerW.restype = wintypes.HANDLE
    advapi.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    advapi.OpenServiceW.restype = wintypes.HANDLE
    advapi.QueryServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ServiceStatus)]
    advapi.QueryServiceStatus.restype = wintypes.BOOL
    advapi.ControlService.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(_ServiceStatus)]
    advapi.ControlService.restype = wintypes.BOOL
    advapi.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    advapi.CloseServiceHandle.restype = wintypes.BOOL
    return advapi


def _with_service(access: int, action: Callable[[object, int], object], missing: object) -> object:
    advapi = _advapi()
    manager = advapi.OpenSCManagerW(None, None, _SC_MANAGER_CONNECT)
    if not manager:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        service = advapi.OpenServiceW(manager, SERVICE_NAME, access)
        if not service:
            error = ctypes.get_last_error()
            if error == _ERROR_SERVICE_DOES_NOT_EXIST:
                return missing
            raise ctypes.WinError(error)
        try:
            return action(advapi, service)
        finally:
            advapi.CloseServiceHandle(service)
    finally:
        advapi.CloseServiceHandle(manager)


def service_state() -> str | None:
    """State of the ``WinDivert`` service, None when it does not exist (or not Windows)."""
    if os.name != "nt":
        return None

    def query(advapi, service) -> str:
        status = _ServiceStatus()
        if not advapi.QueryServiceStatus(service, ctypes.byref(status)):
            raise ctypes.WinError(ctypes.get_last_error())
        return _STATES.get(int(status.dwCurrentState), f"state {int(status.dwCurrentState)}")

    return _with_service(_SERVICE_QUERY_STATUS, query, None)  # type: ignore[return-value]


def stop_service() -> bool:
    """``sc stop WinDivert``; True when the stop was accepted or it is already stopped."""
    if os.name != "nt":
        return True

    def control(advapi, service) -> bool:
        status = _ServiceStatus()
        if advapi.ControlService(service, _SERVICE_CONTROL_STOP, ctypes.byref(status)):
            return True
        return ctypes.get_last_error() == _ERROR_SERVICE_NOT_ACTIVE

    return bool(_with_service(_SERVICE_STOP | _SERVICE_QUERY_STATUS, control, True))


def running_users() -> list[str]:
    """Names of running processes that are known WinDivert users."""
    from .zapret.foreign import running_processes

    return [name for _pid, name, _path in running_processes(WINDIVERT_USERS)]
