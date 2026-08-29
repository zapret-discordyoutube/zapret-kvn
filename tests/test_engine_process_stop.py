from __future__ import annotations

import shutil
import time
import unittest
from unittest.mock import Mock, patch

from PyQt6.QtCore import QCoreApplication, QProcess

from xray_fluent.application.async_steps import TransitionRunner
from xray_fluent.engines.singbox.manager import SingBoxManager
from xray_fluent.engines.tun2socks.manager import Tun2SocksManager
from xray_fluent.engines.xray.manager import XrayManager

_APP = QCoreApplication.instance() or QCoreApplication([])

_RUNNING = QProcess.ProcessState.Running
_NOT_RUNNING = QProcess.ProcessState.NotRunning


class XrayStopTests(unittest.TestCase):
    # После миграции на шаги (AC22) stop() гоняет stop_steps() через синхронный
    # драйвер; блокирующее ожидание живёт в async_steps.WaitProcessFinishedStep.
    def test_stop_kills_immediately_without_terminate(self) -> None:
        manager = XrayManager()
        fake = Mock()
        fake.state.return_value = _RUNNING
        manager._process = fake

        with patch(
            "xray_fluent.application.async_steps.wait_for_qprocess_finished",
            return_value=True,
        ) as wait_mock:
            self.assertTrue(manager.stop())

        fake.kill.assert_called_once_with()
        fake.terminate.assert_not_called()
        wait_mock.assert_called_once_with(fake, 2000)

    def test_stop_emits_perf_log_line(self) -> None:
        manager = XrayManager()
        fake = Mock()
        fake.state.return_value = _RUNNING
        manager._process = fake
        lines: list[str] = []
        manager.log_received.connect(lines.append)

        with patch(
            "xray_fluent.application.async_steps.wait_for_qprocess_finished",
            return_value=True,
        ):
            manager.stop()

        self.assertTrue(any(line.startswith("[xray-perf] stop:") for line in lines))


class XrayEnsurePortsTests(unittest.TestCase):
    def test_bindable_port_skips_netstat_diagnostics(self) -> None:
        manager = XrayManager()
        owner_lookup = Mock()
        manager._find_listening_port_owner = owner_lookup

        with patch(
            "xray_fluent.engines.xray.manager.is_tcp_port_bindable",
            return_value=True,
        ) as bind_mock:
            self.assertIsNone(manager._ensure_ports_available({10808: "SOCKS"}))

        bind_mock.assert_called_once_with("127.0.0.1", 10808)
        owner_lookup.assert_not_called()

    def test_busy_port_reports_owner_from_diagnostics(self) -> None:
        manager = XrayManager()
        manager._find_listening_port_owner = Mock(return_value=(4242, "other.exe"))

        with patch(
            "xray_fluent.engines.xray.manager.is_tcp_port_bindable",
            return_value=False,
        ):
            message = manager._ensure_ports_available({10808: "SOCKS"})

        self.assertIsNotNone(message)
        self.assertIn("10808", message)
        self.assertIn("other.exe", message)
        self.assertIn("4242", message)

    def test_busy_port_without_owner_still_reports_conflict(self) -> None:
        manager = XrayManager()
        manager._find_listening_port_owner = Mock(return_value=None)

        with patch(
            "xray_fluent.engines.xray.manager.is_tcp_port_bindable",
            return_value=False,
        ):
            message = manager._ensure_ports_available({10808: "SOCKS"})

        self.assertIsNotNone(message)
        self.assertIn("10808", message)

    def test_stale_xray_owner_is_killed_and_port_reprobed(self) -> None:
        manager = XrayManager()
        manager._find_listening_port_owner = Mock(return_value=(777, "xray.exe"))
        manager._kill_pid = Mock(return_value=True)

        with patch(
            "xray_fluent.engines.xray.manager.is_tcp_port_bindable",
            side_effect=[False, True],
        ), patch("xray_fluent.application.async_steps.sleep_with_events"):
            self.assertIsNone(manager._ensure_ports_available({10808: "SOCKS"}))

        manager._kill_pid.assert_called_once_with(777)


class XrayStopStepsAsyncTests(unittest.TestCase):
    """AC22: горячий путь stop_steps() работает через TransitionRunner без пампинга."""

    @unittest.skipIf(shutil.which("sleep") is None, "требуется бинарь sleep")
    def test_stop_steps_via_transition_runner_kills_real_process(self) -> None:
        manager = XrayManager()
        manager._process.setProgram("sleep")
        manager._process.setArguments(["5"])
        manager._process.start()
        self.assertTrue(manager._process.waitForStarted(3000))

        runner = TransitionRunner(manager.stop_steps())
        runner.start()

        deadline = time.monotonic() + 5.0
        while not runner.done and time.monotonic() < deadline:
            _APP.processEvents()
            time.sleep(0.002)

        self.assertTrue(runner.done)
        self.assertIs(runner.result, True)
        self.assertIsNone(runner.error)
        self.assertEqual(manager._process.state(), _NOT_RUNNING)


class Tun2SocksStopTests(unittest.TestCase):
    def test_stop_kills_immediately_without_terminate(self) -> None:
        manager = Tun2SocksManager()
        fake = Mock()
        fake.state.return_value = _RUNNING
        manager._process = fake
        manager._cleanup_routes = Mock()

        with patch(
            "xray_fluent.engines.tun2socks.manager.wait_for_qprocess_finished",
            return_value=True,
        ) as wait_mock:
            self.assertTrue(manager.stop())

        fake.kill.assert_called_once_with()
        fake.terminate.assert_not_called()
        wait_mock.assert_called_once_with(fake, 2000)
        manager._cleanup_routes.assert_called_once_with()


class SingBoxStopTests(unittest.TestCase):
    def test_stop_grace_is_at_most_500ms_before_kill(self) -> None:
        manager = SingBoxManager()
        fake = Mock()
        fake.state.side_effect = [_RUNNING, _NOT_RUNNING]
        manager._process = fake

        with patch(
            "xray_fluent.engines.singbox.manager.wait_for_qprocess_finished",
            side_effect=[False, True],
        ) as wait_mock:
            self.assertTrue(manager.stop())

        fake.terminate.assert_called_once_with()
        fake.kill.assert_called_once_with()
        timeouts = [call.args[1] for call in wait_mock.call_args_list]
        self.assertEqual(timeouts, [500, 2000])

    def test_stop_waits_for_tun_release_after_tun_session(self) -> None:
        manager = SingBoxManager()
        fake = Mock()
        fake.state.side_effect = [_RUNNING, _NOT_RUNNING]
        manager._process = fake
        manager._uses_tun = True

        with patch(
            "xray_fluent.engines.singbox.manager.wait_for_qprocess_finished",
            return_value=True,
        ), patch.object(SingBoxManager, "_wait_tun_released") as released_mock:
            self.assertTrue(manager.stop())

        released_mock.assert_called_once_with()


class SingBoxProxyReadinessTests(unittest.TestCase):
    def test_clash_api_port_is_the_proxy_readiness_contract(self) -> None:
        config = {
            "experimental": {
                "clash_api": {"external_controller": "127.0.0.1:19090"}
            }
        }
        self.assertEqual(SingBoxManager._extract_clash_api_port(config), 19090)

    def test_proxy_waits_for_clash_api_instead_of_process_age(self) -> None:
        manager = SingBoxManager()
        fake = Mock()
        fake.state.return_value = _RUNNING
        manager._process = fake

        with patch.object(manager, "_is_port_ready", side_effect=[False, False, True]), patch(
            "xray_fluent.engines.singbox.manager.sleep_with_events"
        ) as sleep_mock:
            self.assertTrue(
                manager._wait_until_proxy_ready(
                    {"experimental": {"clash_api": {"external_controller": "127.0.0.1:19090"}}},
                    max_wait=1.0,
                )
            )

        self.assertEqual(sleep_mock.call_count, 2)

    def test_proxy_readiness_timeout_stops_the_process(self) -> None:
        manager = SingBoxManager()
        fake = Mock()
        fake.state.return_value = _RUNNING
        manager._process = fake
        manager.stop = Mock(return_value=True)
        errors: list[str] = []
        manager.error.connect(errors.append)

        with patch.object(manager, "_is_port_ready", return_value=False):
            self.assertFalse(
                manager._wait_until_proxy_ready(
                    {"experimental": {"clash_api": {"external_controller": "127.0.0.1:19090"}}},
                    max_wait=0.0,
                )
            )

        manager.stop.assert_called_once_with(expected=True)
        self.assertTrue(manager.last_start_failure_retryable)
        self.assertTrue(any("19090" in message for message in errors))


if __name__ == "__main__":
    unittest.main()
