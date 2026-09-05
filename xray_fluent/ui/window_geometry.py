"""Screen-aware geometry in Qt logical pixels; independent of MainWindow."""
from PyQt6.QtCore import QRect, QSize

DEFAULT_SIZE = QSize(1000, 720)
MINIMUM_SIZE = QSize(860, 560)


def fitted_geometry(settings, screens: list[QRect], primary: int = 0) -> tuple[QRect, QSize]:
    if not screens:
        screens = [QRect(0, 0, 1920, 1080)]
    width = max(1, min(100000, int(settings.window_width or DEFAULT_SIZE.width())))
    height = max(1, min(100000, int(settings.window_height or DEFAULT_SIZE.height())))
    saved = QRect(int(settings.window_x), int(settings.window_y), width, height)
    # (-1, -1) is the legacy "not saved" sentinel, other negative positions are valid.
    has_position = (settings.window_x, settings.window_y) != (-1, -1)
    screen = screens[min(primary, len(screens) - 1)]
    overlaps = [(saved.intersected(area).width() * saved.intersected(area).height(), area) for area in screens]
    visible = max(overlaps, key=lambda entry: entry[0])
    if has_position and visible[0] > 0:
        screen = visible[1]
    minimum = QSize(min(MINIMUM_SIZE.width(), screen.width()), min(MINIMUM_SIZE.height(), screen.height()))
    rect = QRect(0, 0, min(max(width, minimum.width()), screen.width()), min(max(height, minimum.height()), screen.height()))
    if has_position and visible[0] > 0:
        rect.moveTopLeft(saved.topLeft())
        rect.moveLeft(max(screen.left(), min(rect.left(), screen.right() - rect.width() + 1)))
        rect.moveTop(max(screen.top(), min(rect.top(), screen.bottom() - rect.height() + 1)))
    else:
        rect.moveCenter(screen.center())
    return rect, minimum
