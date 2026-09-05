"""Reveal generated files in the desktop file manager."""
import subprocess
import sys
from pathlib import Path

from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QDesktopServices


def reveal_file(path: Path) -> bool:
    path = Path(path).resolve(strict=True)
    if sys.platform == "win32":
        subprocess.Popen(["explorer.exe", "/select,", str(path)])
        return True
    if sys.platform == "darwin":
        subprocess.Popen(["open", "-R", str(path)])
        return True
    return QDesktopServices.openUrl(QUrl.fromLocalFile(str(path.parent)))
