"""Field check #6 (2026-11-26): две редкие аварии 0.8.109, воспроизведённые на настоящих объектах.

* ``FileNotFoundError`` из ``_read_default_template_text`` (install eb00a3): подключение читало
  шаблон по умолчанию, даже когда рабочий конфиг уже лежит на диске и шаблон не нужен.
* ``RuntimeError`` из ``NetworkMonitor._check`` (три установки с 0.8.101): Qt удалил воркер
  (``deleteLater``), а ссылка на него ещё жила.

Имя начинается с ``test_p``: файл создаёт голый QCoreApplication и должен идти после ``test_app_*``.
"""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from PyQt6 import sip
from PyQt6.QtCore import QCoreApplication

from xray_fluent.application.controller import AppController
from xray_fluent.application.profile_service import ensure_active_config
from xray_fluent.constants import SINGBOX_DEFAULT_CONFIG_NAME, SINGBOX_TEMPLATES_DIR
from xray_fluent.network.network_monitor import NetworkMonitor, _FingerprintWorker

_APP = QCoreApplication.instance() or QCoreApplication([])


class MissingDefaultTemplateTests(unittest.TestCase):
    def _controller(self, config: Path) -> Mock:
        controller = Mock()
        controller._resolve_singbox_config_path.return_value = config
        controller._default_singbox_config_text.side_effect = FileNotFoundError("шаблон sing-box не найден")
        controller._default_singbox_template_path_for_config.return_value = None
        controller.state.settings.singbox_template_file = ""
        controller.state.settings.singbox_config_file = ""
        controller._normalize_singbox_template_relative_path.return_value = SINGBOX_DEFAULT_CONFIG_NAME
        controller._resolve_singbox_template_path.side_effect = ValueError("нет шаблона")
        return controller

    def test_existing_working_config_does_not_need_the_default_template(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / SINGBOX_DEFAULT_CONFIG_NAME
            # Настоящий шаблон, поставляемый с программой.
            shutil.copyfile(SINGBOX_TEMPLATES_DIR / SINGBOX_DEFAULT_CONFIG_NAME, config)
            controller = self._controller(config)

            self.assertEqual(ensure_active_config(controller, "singbox"), config)
            controller._default_singbox_config_text.assert_not_called()

    def test_no_config_and_no_template_still_says_what_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            controller = self._controller(Path(directory) / SINGBOX_DEFAULT_CONFIG_NAME)
            with self.assertRaises(FileNotFoundError):
                ensure_active_config(controller, "singbox")


class TransitionContextTests(unittest.TestCase):
    def test_the_config_scan_runs_only_when_no_node_is_selected(self) -> None:
        for method in ("_needs_transition", "_compute_transition_action"):
            with self.subTest(method=method):
                controller = Mock()
                controller._runtime_selected_node.return_value = object()
                controller._can_connect_without_selected_node.side_effect = FileNotFoundError("шаблон")
                controller._active_session = None
                controller._transition_signature.return_value = "sig"
                try:
                    getattr(AppController, method)(controller)
                except FileNotFoundError:
                    self.fail(f"{method} read the config although a node is selected")
                controller._can_connect_without_selected_node.assert_not_called()


class DeletedWorkerTests(unittest.TestCase):
    def test_check_survives_a_worker_qt_already_deleted(self) -> None:
        monitor = NetworkMonitor(provider=lambda: "x")
        self.monitor = monitor  # держим объект: иначе Qt удалит таймер раньше очистки
        worker = _FingerprintWorker(lambda: "x", monitor)
        monitor._worker = worker
        sip.delete(worker)  # то, что делает deleteLater(), но сразу
        with self.assertRaises(RuntimeError):
            worker.isRunning()  # воспроизведение: именно это падало в поле

        monitor._check()  # не бросает и запускает новый воркер

        self.assertIsNot(monitor._worker, worker)
        monitor.stop()

    def test_stop_survives_a_worker_qt_already_deleted(self) -> None:
        monitor = NetworkMonitor(provider=lambda: "x")
        worker = _FingerprintWorker(lambda: "x", monitor)
        monitor._worker = worker
        sip.delete(worker)

        monitor.stop()

        self.assertIsNone(monitor._worker)


if __name__ == "__main__":
    unittest.main()
