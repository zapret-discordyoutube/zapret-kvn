"""«Подобрать»: the runner against a fake controller, the transfer recorder and the trial layer."""

from __future__ import annotations

import io
import random
import socket
import time
import unittest
from types import SimpleNamespace

from PyQt6.QtCore import QCoreApplication, QObject, QTimer, pyqtSignal

from xray_fluent.application import masking_runtime
from xray_fluent.application.masking_tune_service import (
    TUNE_END_REASON,
    TUNE_REASON,
    MaskingTuneRunner,
    TuneDone,
    TuneFailed,
)
from xray_fluent.masking import codec, presets, tester
from xray_fluent.masking.model import INHERIT, OFF, MaskingSettings
from xray_fluent.network import masking_transfer

app = QCoreApplication.instance() or QCoreApplication([])

WG_OUTBOUND = {"type": "wireguard", "tag": "wg", "server": "1.2.3.4", "server_port": 51820}


def frozen() -> tuple[tester.Transfer, int]:
    samples = ((0, 0), (1000, 10 * 1024), (2000, 18 * 1024), (14000, 18 * 1024))
    return tester.Transfer(samples, tester.End.TIMEOUT, tester.TRANSFER_BYTES), 400


def clean() -> tuple[tester.Transfer, int]:
    samples = tuple((i * 500, tester.TRANSFER_BYTES * i // 4) for i in range(5))
    return tester.Transfer(samples, tester.End.COMPLETED, tester.TRANSFER_BYTES), 300


class FakeController:
    """Just the surface the runner touches; a requested transition settles on the next poll."""

    def __init__(self) -> None:
        self.connected = True
        self.node = SimpleNamespace(id="node-1", name="Финляндия", outbound=WG_OUTBOUND)
        self.state = SimpleNamespace(settings=SimpleNamespace(masking={}), selected_node_id="node-1")
        self.user_disconnects = 0
        self._transition_active = False
        self._transition_pending = False
        self._transition_scheduled = False
        self._desired_connected = True
        self._active_session = SimpleNamespace(tun_mode=False, http_port=10809)
        self.reasons: list[str] = []
        self.kept: list[tuple[str, object]] = []

    @property
    def selected_node(self):
        return self.node

    def _request_transition(self, reason: str) -> None:
        self.reasons.append(reason)
        self._transition_pending = True
        QTimer.singleShot(0, self._settle)

    def _settle(self) -> None:
        self._transition_pending = False
        self.connected = self._desired_connected

    def keep_masking_override(self, node_id: str, override) -> None:
        self.kept.append((node_id, override))


class FakeTransfer(QObject):
    measured = pyqtSignal(object)
    finished = pyqtSignal()

    def __init__(self, result) -> None:
        super().__init__()
        self._result = result

    def start(self) -> None:
        QTimer.singleShot(0, lambda: (self.measured.emit(self._result()), self.finished.emit()))


def run_until(predicate, seconds: float = 10.0) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        app.processEvents()
        time.sleep(0.001)
    raise AssertionError("runner did not settle")


class TuneRunnerTests(unittest.TestCase):
    def tearDown(self) -> None:
        masking_runtime.end_trial()

    def runner(self, controller: FakeController, on_transfer) -> MaskingTuneRunner:
        def factory(http_port):
            self.ports.append(http_port)
            return FakeTransfer(on_transfer)

        self.ports: list[int | None] = []
        return MaskingTuneRunner(
            controller, rng=random.Random(3), transfer_factory=factory,
            schedule=lambda ms, callback: QTimer.singleShot(0, callback), poll_ms=1,
        )

    @staticmethod
    def trial_override():
        return masking_runtime.settings_of(SimpleNamespace(masking={})).override_for("node-1")

    def test_run_ranks_a_clean_preset_above_a_frozen_baseline_and_restores(self) -> None:
        controller = FakeController()
        runner = self.runner(controller, lambda: frozen() if self.trial_override() == OFF else clean())
        runner.start()
        run_until(lambda: not runner.running)

        done = runner.state
        self.assertIsInstance(done, TuneDone)
        self.assertEqual("pass", done.ranked[0].verdict.kind)
        self.assertEqual(tester.BASELINE, done.ranked[-1].candidate)
        self.assertEqual("frozen", done.ranked[-1].verdict.kind)
        count = len(tester.candidates(_wg_shape()))
        self.assertEqual([TUNE_REASON] * count + [TUNE_END_REASON], controller.reasons)
        self.assertEqual({10809}, set(self.ports))
        self.assertEqual(INHERIT, self.trial_override(), "the trial is never left behind")

        best = done.ranked[0].candidate
        runner.keep(best)
        self.assertEqual([("node-1", best.override)], controller.kept)
        self.assertEqual(best.id, runner.state.kept)

    def test_user_switching_off_stops_and_never_reconnects(self) -> None:
        controller = FakeController()

        def transfer():
            controller.user_disconnects += 1
            controller._desired_connected = False
            return clean()

        runner = self.runner(controller, transfer)
        runner.start()
        run_until(lambda: not runner.running)
        self.assertEqual(TuneFailed("VPN выключен: подбор остановлен."), runner.state)
        self.assertEqual([TUNE_REASON], controller.reasons)

    def test_server_change_stops_and_restores(self) -> None:
        controller = FakeController()

        def transfer():
            controller.state.selected_node_id = "node-2"
            return clean()

        runner = self.runner(controller, transfer)
        runner.start()
        run_until(lambda: not runner.running)
        self.assertTrue(runner.state.message.startswith("Во время подбора VPN перешёл"))
        self.assertEqual(TUNE_END_REASON, controller.reasons[-1])

    def test_tun_mode_reads_without_the_http_inbound(self) -> None:
        controller = FakeController()
        controller._active_session = SimpleNamespace(tun_mode=True, http_port=10809)
        runner = self.runner(controller, clean)
        runner.start()
        run_until(lambda: not runner.running)
        self.assertEqual({None}, set(self.ports))

    def test_not_connected_does_nothing(self) -> None:
        controller = FakeController()
        controller.connected = False
        runner = self.runner(controller, clean)
        runner.start()
        self.assertIsInstance(runner.state, TuneFailed)
        self.assertEqual([], controller.reasons)


def _wg_shape():
    from xray_fluent.masking.apply import shape_of

    return shape_of(WG_OUTBOUND)


class TrialLayerTests(unittest.TestCase):
    def tearDown(self) -> None:
        masking_runtime.end_trial()

    def test_trial_reaches_settings_and_signature_only_while_it_runs(self) -> None:
        stored = SimpleNamespace(masking=codec.encode(MaskingSettings()))
        self.assertIsNone(masking_runtime.trial_signature())
        custom = tester.Candidate.of(presets.WIREGUARD_JUNK_ONLY).override
        masking_runtime.begin_trial("node-1", custom, "Только junk")
        self.assertTrue(masking_runtime.settings_of(stored).enabled)
        self.assertFalse(masking_runtime.stored_settings_of(stored).enabled)
        self.assertIn("node-1", masking_runtime.trial_signature())
        self.assertEqual("маскировка: подбор, вариант «Только junk»", masking_runtime.trial_log_line())
        masking_runtime.end_trial()
        self.assertFalse(masking_runtime.settings_of(stored).enabled)
        self.assertIsNone(masking_runtime.trial_log_line())


class FakeResponse(io.BytesIO):
    status = 206

    def __init__(self, data: bytes, error: BaseException | None = None):
        super().__init__(data)
        self._error = error

    def read(self, size: int = -1) -> bytes:
        chunk = super().read(size)
        if not chunk and self._error is not None:
            raise self._error
        return chunk


class FakeOpener:
    def __init__(self, response: FakeResponse):
        self.response = response
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        return self.response


class TransferTests(unittest.TestCase):
    def test_reads_the_target_with_range_and_browser_headers(self) -> None:
        opener = FakeOpener(FakeResponse(b"x" * (tester.TRANSFER_BYTES + 5000)))
        transfer, first = masking_transfer.run_transfer(opener, "https://example.test/f.bin")
        self.assertEqual(tester.End.COMPLETED, transfer.end)
        self.assertEqual(tester.TRANSFER_BYTES, transfer.total_bytes)
        self.assertIsNotNone(first)
        request, timeout = opener.requests[0]
        self.assertEqual(f"bytes=0-{tester.TRANSFER_BYTES - 1}", request.get_header("Range"))
        self.assertIn("Mozilla", request.get_header("User-agent"))
        self.assertGreater(timeout, tester.STALL_MS / 1000)

    def test_read_timeout_is_the_stall_and_early_close_is_fin(self) -> None:
        stalled = FakeOpener(FakeResponse(b"x" * 20000, socket.timeout("timed out")))
        transfer, _ = masking_transfer.run_transfer(stalled, "https://example.test/f.bin")
        self.assertEqual(tester.End.TIMEOUT, transfer.end)
        self.assertEqual(20000, transfer.total_bytes)
        short, _ = masking_transfer.run_transfer(FakeOpener(FakeResponse(b"x" * 1000)), "https://example.test/f.bin")
        self.assertEqual(tester.End.RESET, short.end)
        self.assertEqual(tester.End.RESET, masking_transfer.end_of(ConnectionResetError()))
        self.assertEqual(tester.End.ERROR, masking_transfer.end_of(ValueError("tls")))


if __name__ == "__main__":
    unittest.main()
