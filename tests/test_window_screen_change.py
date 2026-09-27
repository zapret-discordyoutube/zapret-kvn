"""Перенос окна на другой монитор не должен двигать окно из кода."""

from __future__ import annotations

import ctypes
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from PyQt6.QtCore import QRect, QSize


class _FakeWindll:
    def __getattr__(self, name: str):
        library = SimpleNamespace()
        setattr(self, name, library)
        return library


if sys.platform == "win32":
    from xray_fluent.ui.main_window import MainWindow
else:
    _original_windll = getattr(ctypes, "windll", None)
    ctypes.windll = _FakeWindll()  # type: ignore[attr-defined]
    try:
        from xray_fluent.ui.main_window import MainWindow
    finally:
        if _original_windll is None:
            del ctypes.windll
        else:
            ctypes.windll = _original_windll  # type: ignore[attr-defined]


def _screen(width: int, height: int):
    return SimpleNamespace(availableGeometry=lambda: QRect(0, 0, width, height))


class WindowScreenChangeTest(unittest.TestCase):
    def _window(self, screen):
        return SimpleNamespace(
            minimumSize=lambda: QSize(860, 560),
            setMinimumSize=Mock(),
            setGeometry=Mock(),
            _apply_window_geometry=Mock(),
            _fit_current_screen=Mock(),
            screen=lambda: screen,
        )

    def test_screen_change_during_drag_does_not_move_window(self) -> None:
        window = self._window(_screen(1920, 1080))

        MainWindow._on_window_screen_changed(window, _screen(1920, 1080))

        window.setGeometry.assert_not_called()
        window._apply_window_geometry.assert_not_called()
        window._fit_current_screen.assert_not_called()
        window.setMinimumSize.assert_called_once_with(860, 560)

    def test_small_screen_only_lowers_minimum_size(self) -> None:
        window = self._window(_screen(1920, 1080))

        MainWindow._on_window_screen_changed(window, _screen(800, 500))

        window.setMinimumSize.assert_called_once_with(800, 500)
        window.setGeometry.assert_not_called()

    def test_other_screen_geometry_change_is_ignored(self) -> None:
        current, other = _screen(1920, 1080), _screen(1280, 720)
        window = self._window(current)

        with patch("xray_fluent.ui.main_window.QTimer") as timer:
            MainWindow._on_screen_geometry_changed(window, other)
            timer.singleShot.assert_not_called()
            MainWindow._on_screen_geometry_changed(window, current)
            timer.singleShot.assert_called_once_with(0, window._fit_current_screen)


if __name__ == "__main__":
    unittest.main()
