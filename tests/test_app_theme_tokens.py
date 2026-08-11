"""Theme token / apply_theme tests (AC1, AC2, AC5, AC6a).

Keep the ``test_app_*`` prefix: widget/theme test modules must sort before
``tests/test_engine_process_stop.py`` which creates a bare QCoreApplication
at import time (see tests/test_app_nodes_page_view.py).
"""

from __future__ import annotations

import os
import re
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
if _existing is not None and not isinstance(_existing, QApplication):
    raise RuntimeError(
        "A bare QCoreApplication was created before test_app_theme_tokens "
        "was imported; widget tests need a QApplication."
    )
app = _existing or QApplication([])

from qfluentwidgets import Theme, qconfig, setTheme

from xray_fluent.ui import theme

REPO_ROOT = Path(__file__).resolve().parent.parent


class _ThemeRestoreMixin(unittest.TestCase):
    def setUp(self) -> None:
        self._saved_theme = qconfig.themeMode.value

    def tearDown(self) -> None:
        setTheme(self._saved_theme)
        QApplication.processEvents()


class ThemeTokensTest(_ThemeRestoreMixin):
    def test_tokens_are_lazy_and_theme_dependent(self) -> None:
        setTheme(Theme.DARK)
        dark = {
            "surface": theme.surface_color().getRgb(),
            "grid": theme.graph_grid_color().getRgb(),
            "success": theme.success_color().getRgb(),
            "warning": theme.warning_color().getRgb(),
            "error": theme.error_color().getRgb(),
            "down": theme.graph_down_color().getRgb(),
            "up": theme.graph_up_color().getRgb(),
            "bg": theme.graph_bg_color().getRgb(),
        }
        setTheme(Theme.LIGHT)
        light = {
            "surface": theme.surface_color().getRgb(),
            "grid": theme.graph_grid_color().getRgb(),
            "success": theme.success_color().getRgb(),
            "warning": theme.warning_color().getRgb(),
            "error": theme.error_color().getRgb(),
            "down": theme.graph_down_color().getRgb(),
            "up": theme.graph_up_color().getRgb(),
            "bg": theme.graph_bg_color().getRgb(),
        }
        for key in dark:
            with self.subTest(token=key):
                self.assertNotEqual(dark[key], light[key])

    def test_default_accent_constant(self) -> None:
        self.assertEqual(theme.DEFAULT_ACCENT, "#0078D4")

    def test_light_grid_is_visibly_dark(self) -> None:
        # AC6a: in the light theme the grid must not be the old
        # white-with-alpha-20 color (invisible on light backgrounds).
        setTheme(Theme.LIGHT)
        r, g, b, _a = theme.graph_grid_color().getRgb()
        self.assertLess(max(r, g, b), 128)

    def test_on_theme_changed_invokes_callback(self) -> None:
        calls: list[object] = []

        def callback(*args) -> None:
            calls.append(args)

        setTheme(Theme.DARK)
        theme.on_theme_changed(callback)
        try:
            setTheme(Theme.LIGHT)
            QApplication.processEvents()
            self.assertTrue(calls)
        finally:
            qconfig.themeChanged.disconnect(callback)

    def test_no_module_level_theme_colors(self) -> None:
        # C7: no module-level QColor/QBrush snapshots in manual-paint modules.
        for name in ("theme.py", "traffic_graph.py", "nodes_table_model.py"):
            source = (REPO_ROOT / "xray_fluent" / "ui" / name).read_text(encoding="utf-8")
            with self.subTest(module=name):
                self.assertIsNone(
                    re.search(r"^_?\w+\s*=\s*Q(Color|Brush|Font)\(", source, re.M),
                    f"module-level Qt color/brush/font snapshot in {name}",
                )
                self.assertIsNone(re.search(r"^_COLOR_\w+\s*=", source, re.M))


class ApplyThemeDedupTest(unittest.TestCase):
    def setUp(self) -> None:
        theme.reset_applied_theme()

    def tearDown(self) -> None:
        theme.reset_applied_theme()

    def test_repeated_apply_calls_set_theme_once(self) -> None:
        with mock.patch.object(theme, "setTheme") as set_theme, \
                mock.patch.object(theme, "setThemeColor") as set_color:
            self.assertTrue(theme.apply_theme("dark", "#112233"))
            self.assertFalse(theme.apply_theme("dark", "#112233"))
            self.assertFalse(theme.apply_theme("dark", "#112233"))
            self.assertEqual(set_theme.call_count, 1)
            self.assertEqual(set_color.call_count, 1)

            # Changing the mode triggers exactly one more setTheme call.
            self.assertTrue(theme.apply_theme("light", "#112233"))
            self.assertEqual(set_theme.call_count, 2)
            self.assertEqual(set_color.call_count, 1)

            # Changing the accent triggers exactly one more setThemeColor call.
            self.assertTrue(theme.apply_theme("light", "#445566"))
            self.assertEqual(set_theme.call_count, 2)
            self.assertEqual(set_color.call_count, 2)

    def test_apply_initial_theme_plain_storage(self) -> None:
        class _Settings:
            theme = "dark"
            accent_color = "#123456"

        class _State:
            settings = _Settings()

        class _Storage:
            def is_encrypted(self) -> bool:
                return False

            def load(self):
                return _State()

        with mock.patch.object(theme, "setTheme") as set_theme, \
                mock.patch.object(theme, "setThemeColor") as set_color:
            result = theme.apply_initial_theme(_Storage())
        self.assertEqual(result, ("dark", "#123456"))
        set_theme.assert_called_once_with(Theme.DARK)
        set_color.assert_called_once_with("#123456")

    def test_apply_initial_theme_encrypted_storage_uses_defaults(self) -> None:
        class _Storage:
            def is_encrypted(self) -> bool:
                return True

            def load(self):  # pragma: no cover - must not be reached
                raise AssertionError("encrypted storage must not be loaded")

        with mock.patch.object(theme, "setTheme") as set_theme, \
                mock.patch.object(theme, "setThemeColor") as set_color:
            result = theme.apply_initial_theme(_Storage())
        self.assertEqual(result, ("system", theme.DEFAULT_ACCENT))
        set_theme.assert_called_once_with(Theme.AUTO)
        set_color.assert_called_once_with(theme.DEFAULT_ACCENT)


class _FakeListener:
    def __init__(self, parent=None):
        self.parent = parent
        self.started = False
        self.interrupted = False
        self.terminated = False
        self.deleted = False

    def start(self) -> None:
        self.started = True

    def requestInterruption(self) -> None:
        self.interrupted = True

    def terminate(self) -> None:
        self.terminated = True

    def deleteLater(self) -> None:
        self.deleted = True


class SystemThemeListenerSyncTest(unittest.TestCase):
    def tearDown(self) -> None:
        # Make sure no listener leaks between tests.
        theme.sync_system_theme_listener("dark")

    def test_system_mode_starts_listener_once(self) -> None:
        listener = theme.sync_system_theme_listener("system", None, _FakeListener)
        self.assertIsInstance(listener, _FakeListener)
        self.assertTrue(listener.started)
        # Re-sync in system mode keeps the same listener instance.
        again = theme.sync_system_theme_listener("system", None, _FakeListener)
        self.assertIs(again, listener)

    def test_leaving_system_mode_stops_listener(self) -> None:
        listener = theme.sync_system_theme_listener("system", None, _FakeListener)
        self.assertTrue(listener.started)
        result = theme.sync_system_theme_listener("dark")
        self.assertIsNone(result)
        self.assertIsNone(theme.system_theme_listener())
        self.assertTrue(listener.interrupted)
        self.assertTrue(listener.terminated)
        self.assertTrue(listener.deleted)


if __name__ == "__main__":
    unittest.main()
