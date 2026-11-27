"""Is the person at the computer right now? (owner investigation 2026-11-27: "disconnected in WoW every hour").

The background update installs itself and restarts the program, which cuts the connection for several seconds. The busy
check of the update core sees a game only when Windows reports full screen or the window is a borderless full-screen one;
a game in a normal window, or maximized with a title bar, is invisible to it (``zapret_update.screen.is_fullscreen``).
Releases came out every one to two hours on 2026-11-26/27, so with the default «Устанавливать автоматически» a windowed
player was cut off about that often. Recent keyboard or mouse input is the signal every game gives, windowed or not.

Only the standard library (ctypes), no Qt: called from the update logic on the interface thread.
"""

from __future__ import annotations

import sys

#: No input for this long means the person is away and a restart is harmless (a game session has input every few seconds).
ACTIVE_USER_SECONDS = 5 * 60


def idle_seconds() -> float | None:
    """Seconds since the last keyboard or mouse input of this session; None when Windows cannot say."""
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class _LastInput(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]

        info = _LastInput()
        info.cbSize = ctypes.sizeof(_LastInput)
        if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info)):
            return None
        ticks = ctypes.windll.kernel32.GetTickCount() & 0xFFFFFFFF
        return ((ticks - info.dwTime) & 0xFFFFFFFF) / 1000.0  # unsigned wrap-around: the tick counter wraps every 49 days
    except Exception:
        return None


def user_is_active(idle: float | None, *, threshold: float = ACTIVE_USER_SECONDS) -> bool:
    """Whether recent input says somebody is using the computer. Unknown idle time counts as 'not active' (never blocks forever)."""
    return idle is not None and idle < threshold
