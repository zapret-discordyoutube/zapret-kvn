"""Single source of truth for the application theme.

Responsibilities:

* Semantic color tokens (``success_color()``, ``surface_color()``, ...) that
  branch on :func:`qfluentwidgets.isDarkTheme` **lazily at call time** — the
  module keeps no theme-dependent module-level values (C7).
* ``DEFAULT_ACCENT`` — the single copy of the default accent color.
* ``on_theme_changed(callback)`` — subscription helper over
  ``qconfig.themeChanged``.
* ``apply_theme(...)`` — deduplicated ``setTheme``/``setThemeColor`` wrapper.
* ``apply_initial_theme(...)`` — applies the persisted theme *before* the
  main window (and any dialogs) are constructed.
* ``sync_system_theme_listener(...)`` — starts/stops the qfluentwidgets
  ``SystemThemeListener`` when the theme mode is ``"system"``.
"""

from __future__ import annotations

from typing import Callable

from PyQt6.QtGui import QColor
from qfluentwidgets import (
    SystemThemeListener,
    Theme,
    isDarkTheme,
    qconfig,
    setTheme,
    setThemeColor,
    themeColor,
)

from ..constants import DEFAULT_ACCENT_COLOR

# Re-export: the single default accent value lives in constants.py (D1).
DEFAULT_ACCENT = DEFAULT_ACCENT_COLOR

# Accent presets for the settings page (ordered, exactly 8; D6).  Hex
# literals of the accent palette are allowed only here inside ui/ (C3).
ACCENT_PRESETS: list[tuple[str, str]] = [
    (DEFAULT_ACCENT, "Windows-синий"),
    ("#00B7C3", "Бирюза"),
    ("#107C10", "Зелёный"),
    ("#744DA9", "Фиолетовый"),
    ("#E3008C", "Розовый"),
    ("#E81123", "Красный"),
    ("#F76B0C", "Оранжевый"),
    ("#5D5A58", "Графит"),
]

# Semantic tokens as (light, dark) hex pairs.  Values are plain strings — the
# QColor objects are built lazily inside the token functions (C7).
_PALETTE: dict[str, tuple[str, str]] = {
    "success": ("#0F7B0F", "#4CAF50"),
    "warning": ("#9D5D00", "#FFB900"),
    "error": ("#C42B1C", "#FF6B6B"),
    "info": ("#005FB8", "#3498DB"),
    "surface": ("#f3f3f3", "#2b2b2b"),
    "text": ("#1b1b1b", "#ffffff"),
    "text_muted": ("#757575", "#9E9E9E"),
}

# Graph colors as (light, dark) RGBA tuples (alpha channels matter here).
_GRAPH: dict[str, tuple[tuple[int, int, int, int], tuple[int, int, int, int]]] = {
    "graph_up": ((15, 123, 15, 255), (0, 220, 120, 255)),
    "graph_grid": ((0, 0, 0, 40), (255, 255, 255, 20)),
    "graph_bg": ((0, 0, 0, 12), (0, 0, 0, 30)),
    "graph_text": ((90, 90, 90, 255), (190, 190, 190, 255)),
}


def token_pair(name: str) -> tuple[str, str]:
    """Return the ``(light_hex, dark_hex)`` pair for a semantic token.

    Intended for ``setCustomStyleSheet(widget, light_qss, dark_qss)`` callers
    that need both variants regardless of the current theme.
    """
    return _PALETTE[name]


def _palette_color(name: str) -> QColor:
    light, dark = _PALETTE[name]
    return QColor(dark if isDarkTheme() else light)


def _graph_color(name: str) -> QColor:
    light, dark = _GRAPH[name]
    return QColor(*(dark if isDarkTheme() else light))


def accent_color() -> QColor:
    """Current accent color (falls back to qfluentwidgets themeColor).

    Returns a copy — callers may mutate it (alpha, lighter, ...) without
    corrupting the color stored inside qconfig.
    """
    try:
        return QColor(themeColor())
    except Exception:
        return QColor(DEFAULT_ACCENT)


def accent_soft_bg() -> QColor:
    """Soft accent fill for "active" rows/cells (accent at alpha 38 ≈ 0.15)."""
    color = accent_color()
    color.setAlpha(38)
    return color


def accent_soft_bg_hover() -> QColor:
    """Hover variant of :func:`accent_soft_bg` (accent at alpha 51 = 0.20)."""
    color = accent_color()
    color.setAlpha(51)
    return color


def normalize_accent(value) -> str:
    """Normalize any accent input to "#RRGGBB" (upper case).

    Invalid input (empty, None, garbage, short hex) → ``DEFAULT_ACCENT``.
    """
    if not value:
        return DEFAULT_ACCENT
    try:
        color = QColor(str(value))
    except Exception:
        return DEFAULT_ACCENT
    if not color.isValid():
        return DEFAULT_ACCENT
    return color.name().upper()


def success_color() -> QColor:
    return _palette_color("success")


def warning_color() -> QColor:
    return _palette_color("warning")


def error_color() -> QColor:
    return _palette_color("error")


def info_color() -> QColor:
    return _palette_color("info")


def surface_color() -> QColor:
    """Dialog/backdrop surface color for the current theme."""
    return _palette_color("surface")


def text_color() -> QColor:
    return _palette_color("text")


def text_muted_color() -> QColor:
    return _palette_color("text_muted")


def placeholder_text_color() -> QColor:
    color = text_color()
    color.setAlpha(128)
    return color


def graph_down_color() -> QColor:
    """Download line color: follows the accent (D3, AC7).

    Light theme — the accent as is; dark theme — a lightened accent, so the
    token stays theme-dependent (dark != light for any accent).
    """
    accent = accent_color()
    return accent.lighter(130) if isDarkTheme() else accent


def graph_up_color() -> QColor:
    return _graph_color("graph_up")


def graph_grid_color() -> QColor:
    return _graph_color("graph_grid")


def graph_bg_color() -> QColor:
    return _graph_color("graph_bg")


def graph_text_color() -> QColor:
    return _graph_color("graph_text")


def on_theme_changed(callback: Callable) -> Callable:
    """Invoke *callback* whenever the qfluentwidgets theme changes.

    A thin wrapper over ``qconfig.themeChanged.connect`` — bound methods of
    QObjects keep Qt's automatic disconnect-on-destroy semantics.  Returns the
    callback so callers can later ``qconfig.themeChanged.disconnect(cb)``.
    """
    qconfig.themeChanged.connect(callback)
    return callback


def on_accent_changed(callback: Callable) -> Callable:
    """Invoke *callback* whenever the accent (theme color) changes (AC1).

    A thin wrapper over ``qconfig.themeColorChanged.connect``; the callback
    must accept one positional argument (a ``QColor``).  Returns the callback
    so callers can later ``qconfig.themeColorChanged.disconnect(cb)``.
    """
    qconfig.themeColorChanged.connect(callback)
    return callback


def on_theme_or_accent_changed(callback: Callable) -> Callable:
    """Invoke *callback* on any theme mode or accent change (AC1).

    The callback must accept one positional argument (``Theme`` or
    ``QColor`` depending on the signal).
    """
    qconfig.themeChanged.connect(callback)
    qconfig.themeColorChanged.connect(callback)
    return callback


# ── Theme application (deduplicated) ─────────────────────────────────────

_THEME_MAP = {"dark": Theme.DARK, "light": Theme.LIGHT}

# Last applied (mode, accent) pair; None until the first apply_theme call.
_applied: tuple[str, str] | None = None


def reset_applied_theme() -> None:
    """Forget the deduplication state (used by tests)."""
    global _applied
    _applied = None


def apply_theme(theme_name: str, accent_color: str, *, force: bool = False) -> bool:
    """Apply theme mode + accent, skipping no-op ``setTheme``/``setThemeColor``.

    Returns ``True`` when anything was actually (re)applied.
    """
    global _applied
    normalized = (theme_name or "system").lower().strip() or "system"
    # Normalization makes deduplication case-insensitive (AC4): "#0078d4"
    # and "#0078D4" are the same accent.
    accent = normalize_accent(accent_color)

    previous = _applied
    if not force and previous == (normalized, accent):
        return False

    changed = False
    if force or previous is None or previous[0] != normalized:
        setTheme(_THEME_MAP.get(normalized, Theme.AUTO))
        changed = True
    if force or previous is None or previous[1] != accent:
        try:
            setThemeColor(accent)
            changed = True
        except Exception:
            pass
    _applied = (normalized, accent)
    return changed


def apply_initial_theme(storage=None) -> tuple[str, str]:
    """Apply the persisted theme before any window/dialog is constructed.

    Reads ``AppSettings.theme``/``accent_color`` straight from storage.  When
    the state file is passphrase-encrypted the settings are unreadable before
    the unlock prompt, so defaults are applied now and the real values are
    re-applied later by the settings_changed flow (deduplicated).
    """
    theme_name, accent = "system", DEFAULT_ACCENT
    try:
        if storage is None:
            from ..profiles.storage import StateStorage

            storage = StateStorage()
        if not storage.is_encrypted():
            state = storage.load()
            settings = getattr(state, "settings", None)
            if settings is not None:
                theme_name = str(getattr(settings, "theme", "") or "system")
                accent = str(getattr(settings, "accent_color", "") or DEFAULT_ACCENT)
    except Exception:
        theme_name, accent = "system", DEFAULT_ACCENT
    apply_theme(theme_name, accent, force=True)
    return theme_name, accent


# ── System theme listener ("system" mode) ────────────────────────────────

_system_listener = None


def system_theme_listener():
    """Currently running SystemThemeListener (or None)."""
    return _system_listener


def sync_system_theme_listener(theme_name: str, parent=None, listener_factory=None):
    """Start the OS theme listener in "system" mode, stop it otherwise.

    ``listener_factory`` is injectable for tests (A6/C5); by default the
    qfluentwidgets ``SystemThemeListener`` is used.
    """
    global _system_listener
    normalized = (theme_name or "system").lower().strip() or "system"

    if normalized == "system":
        if _system_listener is None:
            factory = listener_factory or SystemThemeListener
            try:
                listener = factory(parent)
                listener.start()
            except Exception:
                listener = None
            _system_listener = listener
    elif _system_listener is not None:
        listener, _system_listener = _system_listener, None
        _stop_listener(listener)
    return _system_listener


def _stop_listener(listener) -> None:
    try:
        listener.requestInterruption()
    except Exception:
        pass
    try:
        listener.terminate()
    except Exception:
        pass
    try:
        listener.deleteLater()
    except Exception:
        pass
