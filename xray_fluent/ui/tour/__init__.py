"""Обучающая экскурсия по приложению."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QWidget

from .overlay import TourOverlay
from .steps import TOUR_STEPS, WARP_HINT_STEP, TourStep

__all__ = ["TOUR_STEPS", "WARP_HINT_STEP", "TourOverlay", "TourStep", "active_tour"]


def active_tour(window: QWidget) -> TourOverlay | None:
    """Идущая в окне экскурсия, если она есть."""
    for overlay in window.findChildren(TourOverlay, options=Qt.FindChildOption.FindDirectChildrenOnly):
        if not overlay._done:
            return overlay
    return None
