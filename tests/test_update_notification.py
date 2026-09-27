from __future__ import annotations

import ctypes
import inspect
from pathlib import Path
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
    from xray_fluent.updates.app_updater import AppUpdate
    from xray_fluent.ui.main_window import (
        APP_UPDATE_INITIAL_DELAY_MS,
        APP_UPDATE_INTERVAL_MS,
        MainWindow,
        _runtime_identity_log_line,
    )
else:
    _original_windll = getattr(ctypes, "windll", None)
    ctypes.windll = _FakeWindll()  # type: ignore[attr-defined]
    try:
        from xray_fluent.updates.app_updater import AppUpdate
        from xray_fluent.ui.main_window import (
            APP_UPDATE_INITIAL_DELAY_MS,
            APP_UPDATE_INTERVAL_MS,
            MainWindow,
            _runtime_identity_log_line,
        )
    finally:
        if _original_windll is None:
            del ctypes.windll
        else:
            ctypes.windll = _original_windll  # type: ignore[attr-defined]

from main import _runtime_identity_message, _setup_bootstrap_logging


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

        self.status = ""

    def show_update_available(self, version: str) -> None:
        self.available_version = version

    def set_app_status(self, text: str) -> None:
        self.status = text


class _FakeTimer:
    def __init__(self) -> None:
        self.interval = None
        self.active = False
        self.single_shot = None
        self.start_count = 0
        self.stop_count = 0

    def setSingleShot(self, value: bool) -> None:
        self.single_shot = value

    def setInterval(self, value: int) -> None:
        self.interval = value

    def start(self) -> None:
        self.active = True
        self.start_count += 1

    def stop(self) -> None:
        self.active = False
        self.stop_count += 1

    def isActive(self) -> bool:
        return self.active


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
    def test_runtime_identity_logs_version_executable_and_base_dir(self) -> None:
        from xray_fluent.constants import APP_VERSION, BASE_DIR

        startup_line = _runtime_identity_message()
        app_line = _runtime_identity_log_line()
        expected = (
            f"app_version={APP_VERSION} "
            f"executable={Path(sys.executable).resolve()} "
            f"base_dir={BASE_DIR.resolve()}"
        )

        self.assertIn(expected, startup_line)
        self.assertIn(f"[runtime] {expected}", app_line)
        self.assertIn("_runtime_identity_message()", inspect.getsource(_setup_bootstrap_logging))
        self.assertIn("_runtime_identity_log_line()", inspect.getsource(MainWindow.initialize))
        self.assertNotIn("token=", startup_line.lower())
        self.assertNotIn("token=", app_line.lower())

    def test_startup_update_timer_uses_one_timer_then_switches_to_30_minutes(self) -> None:
        timer = _FakeTimer()
        settings = SimpleNamespace(check_updates=True)
        window = SimpleNamespace(
            _app_update_timer=timer,
            _app_update_scheduler_ready=True,
            _quitting=False,
            controller=SimpleNamespace(
                state=SimpleNamespace(settings=settings),
            ),
            _check_updates=Mock(),
        )

        MainWindow._sync_app_update_timer(window, settings)
        self.assertEqual(timer.interval, APP_UPDATE_INITIAL_DELAY_MS)
        self.assertEqual(timer.start_count, 1)
        self.assertTrue(timer.active)

        # A second synchronisation while the initial timer is active must not
        # reset its deadline or create another timer.
        MainWindow._sync_app_update_timer(window, settings)
        self.assertEqual(timer.start_count, 1)

        MainWindow._on_app_update_timer_timeout(window)
        window._check_updates.assert_called_once_with(silent=True)
        self.assertEqual(timer.interval, APP_UPDATE_INTERVAL_MS)
        self.assertEqual(timer.start_count, 2)
        self.assertTrue(timer.active)

    def test_disabling_update_checks_stops_the_timer(self) -> None:
        timer = _FakeTimer()
        timer.active = True
        window = SimpleNamespace(
            _app_update_timer=timer,
            _quitting=False,
        )

        MainWindow._sync_app_update_timer(
            window,
            SimpleNamespace(check_updates=False),
        )

        self.assertFalse(timer.active)
        self.assertEqual(timer.stop_count, 1)

    def test_timer_callback_does_not_start_after_quit(self) -> None:
        timer = _FakeTimer()
        window = SimpleNamespace(
            _app_update_timer=timer,
            _app_update_scheduler_ready=True,
            _quitting=True,
            _check_updates=Mock(),
        )

        MainWindow._on_app_update_timer_timeout(window)

        window._check_updates.assert_not_called()
        self.assertEqual(timer.start_count, 0)

    def test_update_check_guard_rejects_a_concurrent_checker(self) -> None:
        window = SimpleNamespace(_update_in_progress=True)

        # This is the guard at the top of _check_updates; both the manual
        # button and the periodic timer use the same method.
        MainWindow._check_updates(window, silent=True)

        self.assertTrue(window._update_in_progress)

    def test_silent_update_error_is_logged_without_ui_notification(self) -> None:
        logger = Mock()
        page = SimpleNamespace(
            show_idle=Mock(),
            set_app_error=Mock(),
        )
        window = SimpleNamespace(
            _update_in_progress=True,
            controller=SimpleNamespace(_logger=logger),
            updates_page=page,
            _show_status=Mock(),
        )

        MainWindow._on_update_check_error(
            window,
            "Сервер обновлений временно не отвечает.",
            silent=True,
        )

        self.assertFalse(window._update_in_progress)
        logger.warning.assert_called_once()
        self.assertIn(
            "Фоновая проверка обновлений не выполнена",
            logger.warning.call_args.args[0],
        )
        page.show_idle.assert_not_called()
        page.set_app_error.assert_not_called()
        window._show_status.assert_not_called()

    def _check_result_window(self, block_reason: str = ""):
        return SimpleNamespace(
            _update_in_progress=True,
            _pending_update=None,
            controller=SimpleNamespace(
                state=SimpleNamespace(settings=SimpleNamespace(allow_updates=True)),
                _logger=Mock(),
            ),
            updates_page=_FakeUpdatesPage(),
            _start_update_download=Mock(),
            _auto_install_block_reason=Mock(return_value=block_reason),
        )

    def test_silent_check_installs_in_background_without_dialog(self) -> None:
        window = self._check_result_window()
        update = _update()

        with patch("qfluentwidgets.MessageBox") as box:
            MainWindow._on_update_check_result(window, update, silent=True)

        box.assert_not_called()
        self.assertFalse(window._update_in_progress)
        self.assertIs(window._pending_update, update)
        self.assertEqual(window.updates_page.available_version, update.version)
        window._start_update_download.assert_called_once_with(update, background=True)

    def test_blocked_auto_install_only_updates_page_status(self) -> None:
        window = self._check_result_window("установка не удалась уже 3 раза")

        MainWindow._on_update_check_result(window, _update(), silent=True)

        window._start_update_download.assert_not_called()
        self.assertIn("не удалась уже 3 раза", window.updates_page.status)
        # Кнопка страницы остаётся ручным путём в обход лимита.
        window.updates_page.download_btn.clicked.callback()
        window._start_update_download.assert_called_once_with(window._pending_update)

    def test_manual_check_installs_without_dialog_and_ignores_attempt_limit(self) -> None:
        window = self._check_result_window("установка не удалась уже 3 раза")
        update = _update()

        MainWindow._on_update_check_result(window, update, silent=False)

        window._auto_install_block_reason.assert_not_called()
        window._start_update_download.assert_called_once_with(update)

    def test_password_protection_blocks_silent_restart(self) -> None:
        window = SimpleNamespace(
            controller=SimpleNamespace(state=SimpleNamespace(security=SimpleNamespace(enabled=True)))
        )
        reason = MainWindow._auto_install_block_reason(window, _update())
        self.assertIn("защита паролем", reason)

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

    def _apply_window(self, *, busy: bool, deadline_passed: bool = False):
        downloader = SimpleNamespace(update=_update(), script_path=Path("C:/tmp/_update.ps1"))
        return SimpleNamespace(
            _quitting=False,
            _update_downloader=downloader,
            _update_apply_deadline=float("-inf") if deadline_passed else float("inf"),
            controller=SimpleNamespace(
                transition_busy=Mock(return_value=busy),
                connected=True,
                _desired_connected=True,
                _logger=Mock(),
            ),
            _quit_for_update=Mock(),
            _on_update_error=Mock(),
            _apply_downloaded_update=Mock(),
        )

    def test_downloaded_update_waits_for_running_transition(self) -> None:
        window = self._apply_window(busy=True)
        with patch("xray_fluent.ui.main_window.QTimer.singleShot") as single_shot, \
                patch("xray_fluent.ui.main_window.record_attempt") as record, \
                patch("xray_fluent.ui.main_window.launch_update_script") as launch:
            MainWindow._apply_downloaded_update(window)
        single_shot.assert_called_once()
        record.assert_not_called()
        launch.assert_not_called()
        window._quit_for_update.assert_not_called()

    def test_downloaded_update_records_attempt_before_launch_then_quits(self) -> None:
        for busy, deadline_passed in ((False, False), (True, True)):
            window = self._apply_window(busy=busy, deadline_passed=deadline_passed)
            order: list[str] = []
            with patch(
                "xray_fluent.ui.main_window.record_attempt",
                side_effect=lambda *a, **k: order.append("record"),
            ) as record, patch(
                "xray_fluent.ui.main_window.launch_update_script",
                side_effect=lambda *a, **k: order.append("launch"),
            ):
                MainWindow._apply_downloaded_update(window)
            self.assertEqual(order, ["record", "launch"])
            record.assert_called_once_with("0.4.67", reconnect=True)
            window._quit_for_update.assert_called_once()

    def test_failed_script_launch_keeps_app_running(self) -> None:
        window = self._apply_window(busy=False)
        with patch("xray_fluent.ui.main_window.record_attempt"), \
                patch("xray_fluent.ui.main_window.launch_update_script", side_effect=OSError("denied")):
            MainWindow._apply_downloaded_update(window)
        window._quit_for_update.assert_not_called()
        window._on_update_error.assert_called_once()

    def test_background_download_error_is_logged_without_toast(self) -> None:
        window = SimpleNamespace(
            _update_in_progress=True,
            _update_background=True,
            updates_page=SimpleNamespace(show_idle=Mock(), set_app_error=Mock()),
            controller=SimpleNamespace(_logger=Mock()),
            _show_status=Mock(),
        )
        MainWindow._on_update_error(window, "нет сети")
        self.assertFalse(window._update_in_progress)
        window._show_status.assert_not_called()
        window.controller._logger.warning.assert_called_once()

        window._update_background = False
        MainWindow._on_update_error(window, "нет сети")
        window._show_status.assert_called_once_with("error", "нет сети")

    def test_broken_archive_counts_as_attempt_but_network_error_does_not(self) -> None:
        for permanent in (True, False):
            window = SimpleNamespace(
                _update_in_progress=True,
                _update_background=True,
                _update_downloader=SimpleNamespace(update=_update(), failure_permanent=permanent),
                updates_page=SimpleNamespace(show_idle=Mock(), set_app_error=Mock()),
                controller=SimpleNamespace(_logger=Mock()),
                _show_status=Mock(),
            )
            with patch("xray_fluent.ui.main_window.record_attempt") as record:
                MainWindow._on_update_error(window, "ошибка")
            if permanent:
                record.assert_called_once_with("0.4.67", reconnect=False, restarting=False)
            else:
                record.assert_not_called()


class CoreUpdateStatusColorTests(unittest.TestCase):
    """«Актуален» у sing-box зелёный, как у Xray (раньше был серым)."""

    def _window(self):
        page = SimpleNamespace(
            set_singbox_error=Mock(), set_singbox_success=Mock(),
            set_singbox_status=Mock(), set_singbox_version=Mock(),
        )
        return SimpleNamespace(updates_page=page, logs_page=SimpleNamespace(append_line=Mock()))

    def test_up_to_date_and_updated_are_success(self) -> None:
        from xray_fluent.engines.singbox.core_updater import SingboxCoreUpdateResult

        for status in ("up_to_date", "updated"):
            window = self._window()
            MainWindow._on_singbox_update_result(
                window, SingboxCoreUpdateResult(status=status, message="m", current_version="1.14.1-extended-2.7.2")
            )
            window.updates_page.set_singbox_success.assert_called_once_with("m")
            window.updates_page.set_singbox_status.assert_not_called()

    def test_available_stays_neutral_and_error_is_error(self) -> None:
        from xray_fluent.engines.singbox.core_updater import SingboxCoreUpdateResult

        window = self._window()
        MainWindow._on_singbox_update_result(window, SingboxCoreUpdateResult(status="available", message="a"))
        window.updates_page.set_singbox_status.assert_called_once_with("a")
        window = self._window()
        MainWindow._on_singbox_update_result(window, SingboxCoreUpdateResult(status="error", message="e"))
        window.updates_page.set_singbox_error.assert_called_once_with("e")


if __name__ == "__main__":
    unittest.main()
