from __future__ import annotations

import ctypes
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch


class _FakeFunction:
    def __call__(self, *args, **kwargs):
        return 0


class _FakeLibrary:
    def __getattr__(self, name: str):
        function = _FakeFunction()
        setattr(self, name, function)
        return function


class _FakeWindll:
    def __getattr__(self, name: str):
        library = _FakeLibrary()
        setattr(self, name, library)
        return library


if sys.platform == "win32":
    from xray_fluent.app_updater import AppUpdate
    from xray_fluent.ui.main_window import MainWindow
else:
    _original_windll = getattr(ctypes, "windll", None)
    ctypes.windll = _FakeWindll()  # type: ignore[attr-defined]
    try:
        from xray_fluent.app_updater import AppUpdate
        from xray_fluent.ui.main_window import MainWindow
    finally:
        if _original_windll is None:
            del ctypes.windll
        else:
            ctypes.windll = _original_windll  # type: ignore[attr-defined]


class _FakeSignal:
    def __init__(self) -> None:
        self.callback = None

    def disconnect(self) -> None:
        raise TypeError

    def connect(self, callback) -> None:
        self.callback = callback


class _FakeUpdatesPage:
    def __init__(self) -> None:
        self.download_btn = SimpleNamespace(clicked=_FakeSignal())
        self.available_version = ""

    def show_update_available(self, version: str) -> None:
        self.available_version = version


class _FakeButton:
    def __init__(self) -> None:
        self.text = ""

    def setText(self, text: str) -> None:
        self.text = text


class _FakeMessageBox:
    result = 0
    last = None

    def __init__(self, title: str, content: str, parent) -> None:
        self.title = title
        self.content = content
        self.parent_was_visible = parent.isVisible()
        self.yesButton = _FakeButton()
        self.cancelButton = _FakeButton()
        type(self).last = self

    def exec(self) -> int:
        return self.result


def _update() -> AppUpdate:
    return AppUpdate(
        version="0.4.67",
        tag="v0.4.67",
        download_url="https://example.invalid/ZapretKVN-windows-x64.zip",
        size=1,
        notes="",
        digest_sha256="0" * 64,
    )


class UpdateNotificationTests(unittest.TestCase):
    def test_silent_automatic_check_still_requests_update_dialog(self) -> None:
        page = _FakeUpdatesPage()
        window = SimpleNamespace(
            _update_in_progress=True,
            _pending_update=None,
            controller=SimpleNamespace(
                state=SimpleNamespace(settings=SimpleNamespace(allow_updates=True))
            ),
            updates_page=page,
            _start_update_download=Mock(),
            _show_update_available_dialog=Mock(),
        )
        update = _update()

        MainWindow._on_update_check_result(window, update, silent=True)

        self.assertFalse(window._update_in_progress)
        self.assertIs(window._pending_update, update)
        self.assertEqual(page.available_version, update.version)
        window._show_update_available_dialog.assert_called_once_with(
            update,
            open_updates_page=False,
        )

    def test_silent_up_to_date_check_does_not_repaint_updates_page(self) -> None:
        window = SimpleNamespace(
            _update_in_progress=True,
            updates_page=SimpleNamespace(show_up_to_date=Mock()),
            _show_status=Mock(),
        )

        MainWindow._on_update_check_result(window, None, silent=True)

        self.assertFalse(window._update_in_progress)
        window.updates_page.show_up_to_date.assert_not_called()
        window._show_status.assert_not_called()

    def test_active_update_proxy_url_uses_effective_runtime_port(self) -> None:
        window = SimpleNamespace(
            controller=SimpleNamespace(
                connected=True,
                get_effective_http_proxy_port=Mock(return_value=1401),
            )
        )

        proxy_url = MainWindow._active_update_proxy_url(window)

        self.assertEqual(proxy_url, "http://127.0.0.1:1401")

    def test_stale_checker_result_cannot_overwrite_current_check(self) -> None:
        current_checker = object()
        stale_checker = object()
        window = SimpleNamespace(
            _update_checker=current_checker,
            _update_in_progress=True,
            updates_page=SimpleNamespace(show_up_to_date=Mock()),
            _show_status=Mock(),
        )

        MainWindow._on_update_check_result(
            window,
            None,
            silent=False,
            checker=stale_checker,
        )

        self.assertTrue(window._update_in_progress)
        window.updates_page.show_up_to_date.assert_not_called()

    def test_hidden_window_is_shown_for_dialog_then_restored_on_later(self) -> None:
        events: list[str] = []

        class Window:
            updates_page = object()

            def __init__(self) -> None:
                self.visible = False

            def isVisible(self) -> bool:
                return self.visible

            def isMinimized(self) -> bool:
                return False

            def show(self) -> None:
                events.append("show")
                self.visible = True

            def showNormal(self) -> None:
                events.append("showNormal")
                self.visible = True

            def activateWindow(self) -> None:
                events.append("activate")

            def raise_(self) -> None:
                events.append("raise")

            def switchTo(self, page) -> None:
                events.append("switch")

            def hide(self) -> None:
                events.append("hide")
                self.visible = False

            def showMinimized(self) -> None:
                events.append("minimize")

            def _start_update_download(self, update: AppUpdate) -> None:
                events.append("download")

        window = Window()
        _FakeMessageBox.result = 0

        with patch("qfluentwidgets.MessageBox", _FakeMessageBox):
            MainWindow._show_update_available_dialog(
                window,
                _update(),
                open_updates_page=False,
            )

        box = _FakeMessageBox.last
        self.assertIsNotNone(box)
        self.assertTrue(box.parent_was_visible)
        self.assertEqual(box.title, "Доступно обновление")
        self.assertIn("Рекомендуется обновить приложение", box.content)
        self.assertEqual(box.yesButton.text, "Скачать и установить")
        self.assertEqual(box.cancelButton.text, "Позже")
        self.assertEqual(events, ["show", "activate", "raise", "hide"])
        self.assertFalse(window.visible)


if __name__ == "__main__":
    unittest.main()
