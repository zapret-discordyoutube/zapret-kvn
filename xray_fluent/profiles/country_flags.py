"""Real bundled flag images only. Unknown or missing assets have no icon."""
from __future__ import annotations

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPixmap
from PyQt6.QtWidgets import QApplication
from qfluentwidgets import isDarkTheme, qconfig

from ..constants import FLAGS_DIR
from ..network.country_resolver import CountryResolver
from .geoip import normalize_country

_W, _H = 18, 13
_VALID_CODES = frozenset(p.stem.upper() for p in FLAGS_DIR.glob("*.png"))
_icon_cache: dict[tuple[str, float], QIcon] = {}


def clear_flag_icon_cache() -> None:
    _icon_cache.clear()


qconfig.themeChanged.connect(lambda *_: clear_flag_icon_cache())


def get_flag_icon(code: str) -> QIcon | None:
    code = normalize_country(code)
    if not code:
        return None
    app = QApplication.instance()
    ratio = app.devicePixelRatio() if app else 1.0
    key = (code, ratio)
    if key not in _icon_cache:
        pm = _load_flag_pixmap(code, ratio)
        if pm is None:
            return None
        _icon_cache[key] = QIcon(pm)
    return _icon_cache[key]


def _border_color() -> QColor:
    """Thin flag outline: light translucent in dark theme, dark in light theme."""
    if isDarkTheme():
        return QColor(255, 255, 255, 60)
    return QColor(0, 0, 0, 30)


def _draw_flag_frame(p: QPainter) -> None:
    """Rounded-corner thin border shared by asset-based and fallback flags."""
    p.setClipping(False)
    p.setPen(_border_color())
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawRoundedRect(QRectF(0.5, 0.5, _W - 1, _H - 1), 2, 2)


def _load_flag_pixmap(code: str, ratio: float = 1.0) -> QPixmap | None:
    """Render a flag from ``assets/flags/{code}.png``; None if unavailable."""
    path = FLAGS_DIR / f"{code.lower()}.png"
    try:
        if not path.is_file():
            return None
        source = QPixmap(str(path))
    except OSError:
        return None
    if source.isNull():
        return None

    scaled = source.scaled(
        round(_W * ratio),
        round(_H * ratio),
        Qt.AspectRatioMode.IgnoreAspectRatio,
        Qt.TransformationMode.SmoothTransformation,
    )

    pm = QPixmap(round(_W * ratio), round(_H * ratio))
    pm.setDevicePixelRatio(ratio)
    pm.fill(QColor(0, 0, 0, 0))

    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    clip = QPainterPath()
    clip.addRoundedRect(QRectF(0, 0, _W, _H), 2, 2)
    p.setClipPath(clip)
    scaled.setDevicePixelRatio(ratio)
    p.drawPixmap(0, 0, scaled)

    _draw_flag_frame(p)
    p.end()
    return pm
