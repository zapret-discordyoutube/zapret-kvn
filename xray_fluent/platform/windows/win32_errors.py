"""Errors raised by pywin32 calls (``pywintypes.error``), recognised without importing pywin32."""
from __future__ import annotations


def is_win32_error(exc: BaseException) -> bool:
    """True for ``pywintypes.error``: a Win32 API call refused by Windows (its own class, not an OSError)."""
    kind = type(exc)
    return kind.__name__ == "error" and kind.__module__ == "pywintypes"
