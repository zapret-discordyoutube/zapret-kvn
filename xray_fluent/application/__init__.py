"""Application-layer orchestration helpers."""

from __future__ import annotations

from importlib import import_module
from types import ModuleType

__all__ = ["config", "nodes", "runtime"]


def __getattr__(name: str) -> ModuleType:
    if name in __all__:
        module = import_module(f"{__name__}.{name}")
        globals()[name] = module
        return module
    raise AttributeError(name)
