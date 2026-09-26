from __future__ import annotations

from typing import TYPE_CHECKING, Any

from . import fluent_fixes as _fluent_fixes

_fluent_fixes.install()

if TYPE_CHECKING:
    from .main_window import MainWindow

__all__ = ["MainWindow"]


def __getattr__(name: str) -> Any:
    if name == "MainWindow":
        from .main_window import MainWindow

        return MainWindow
    raise AttributeError(name)
