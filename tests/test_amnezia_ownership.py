from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from xray_fluent.application.controller import AppController
from xray_fluent.diagnostics.runtime_errors import RuntimeErrorJournal, core_failure


class AmneziaFailureOwnershipTests(unittest.TestCase):
    def test_cancelled_initial_readiness_never_commits_front(self):
        for stage in ("sidecar", "front", "dns"):
            for disconnect in (True, False):
                with self.subTest(stage=stage, disconnect=disconnect):
                    controller = Mock()
                    controller._transition_generation = 1
                    controller._desired_connected = True
                    controller._active_singbox_plan = None
                    plan = SimpleNamespace(amnezia_sidecar=SimpleNamespace(config={}),
                        hysteria_sidecar=None, xray_sidecar=None, provider_payload=None,
                        used_selected_node=True, clash_api_port=0, is_hybrid=False,
                        selected_outbound_tag="", singbox_config={})
                    def supersede(*_args):
                        if disconnect:
                            controller._desired_connected = False
                        else:
                            controller._transition_generation += 1
                        return True
                    controller._start_amnezia_manager.return_value = True
                    controller.singbox.start.return_value = True
                    controller.amnezia.verify_front_dns.return_value = True
                    operation = {"sidecar": controller._start_amnezia_manager,
                                 "front": controller.singbox.start,
                                 "dns": controller.amnezia.verify_front_dns}[stage]
                    operation.side_effect = supersede
                    self.assertFalse(AppController._start_singbox_runtime_plan(controller, plan))
                    self.assertIsNone(controller._active_singbox_plan)
                    controller.amnezia.stop.assert_called_once()
                    if stage == "sidecar":
                        controller.singbox.start.assert_not_called()
                    else:
                        controller.singbox.stop.assert_called_once()

    def controller(self):
        controller = Mock()
        controller.amnezia = object()
        controller._active_session = SimpleNamespace(sidecar_kind="amnezia")
        controller.runtime_errors = RuntimeErrorJournal()
        controller._desired_connected = True
        return controller

    def test_retired_failure_is_kept_without_changing_new_session_status(self):
        controller = self.controller()
        event = core_failure("amnezia", "process", "old process exited", session_generation=1)
        with patch("xray_fluent.application.controller.QTimer.singleShot") as timer:
            AppController._on_amnezia_failure(controller, object(), event)
        self.assertEqual(controller.runtime_errors.snapshot()[0].failure, event)
        controller._set_connection_status.assert_not_called()
        timer.assert_not_called()

    def test_queued_failure_cannot_close_a_replaced_session_or_manager(self):
        for replace in ("session", "manager", "disconnected"):
            with self.subTest(replace=replace):
                controller = self.controller()
                event = core_failure("amnezia", "process", "process exited")
                with patch("xray_fluent.application.controller.QTimer.singleShot") as timer:
                    AppController._on_amnezia_failure(controller, controller.amnezia, event)
                callback = timer.call_args.args[1]
                if replace == "manager":
                    controller.amnezia = object()
                elif replace == "session":
                    controller._active_session = SimpleNamespace(sidecar_kind="")
                else:
                    controller._active_session = None
                callback()
                controller._handle_unexpected_disconnect.assert_not_called()
                self.assertTrue(controller._desired_connected)

    def test_current_fatal_failure_closes_admission(self):
        controller = self.controller()
        with patch("xray_fluent.application.controller.QTimer.singleShot") as timer:
            AppController._on_amnezia_failure(
                controller, controller.amnezia, core_failure("amnezia", "process", "process exited"),
            )
        timer.call_args.args[1]()
        controller._handle_unexpected_disconnect.assert_called_once()
        self.assertFalse(controller._desired_connected)
