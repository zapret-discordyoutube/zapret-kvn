"""Гейт выпуска «без сигнала — ноль» (требование незаметности).

Полчаса обычной сессии — простой, браузер, загрузка, снова простой — не дают
ни одной проверки сервера: ни текущего (только по сигналу «запросы без
ответа»), ни других (только во время замены). Проверяется по журналу шлюза.
"""

from __future__ import annotations

import ctypes
import sys
import unittest
from unittest.mock import patch

from xray_fluent.network import probe_gate


def _worker_class():
    if sys.platform == "win32":
        from xray_fluent.diagnostics.live_metrics_worker import LiveMetricsWorker
        return LiveMetricsWorker
    original = getattr(ctypes, "windll", None)

    class _AnyLib:
        def __getattr__(self, name):
            lib = _AnyLib()
            setattr(self, name, lib)
            return lib

        def __call__(self, *args, **kwargs):
            return 0

    ctypes.windll = _AnyLib()  # type: ignore[attr-defined]
    try:
        from xray_fluent.diagnostics.live_metrics_worker import LiveMetricsWorker
    finally:
        if original is None:
            del ctypes.windll
        else:
            ctypes.windll = original  # type: ignore[attr-defined]
    return LiveMetricsWorker


def _session():
    """(секунда, down_bps, up_bps): 30 минут без признаков обрыва."""
    for second in range(1800):
        phase = (second // 120) % 4
        if phase == 0:
            yield second, 0.0, 0.0                    # простой
        elif phase == 1:
            yield second, 80_000.0, 3_000.0           # браузер: ответы идут
        elif phase == 2:
            yield second, 2_000_000.0, 40_000.0       # загрузка
        else:
            # keep-alive: редкие мелкие запросы, на которые приходит ответ
            yield second, (4_096.0 if second % 20 == 0 else 0.0), (300.0 if second % 20 == 0 else 0.0)


class SilenceScenarioTest(unittest.TestCase):
    def test_normal_session_sends_nothing_to_any_server(self) -> None:
        gate = probe_gate.ProbeGate()
        confirms: list[int] = []
        worker = _worker_class()(
            "xray.exe", 0, ping_host="203.0.113.10", ping_port=443,
            rtt_reader=lambda _a, _p: 55,
            link_confirmer=lambda: confirms.append(1) or True,
        )
        with patch.object(probe_gate, "GATE", gate):
            for second, down, up in _session():
                worker._watch_link(1000.0 + second, down, up)
        self.assertEqual(confirms, [])
        self.assertEqual(gate.journal(), ())
        self.assertEqual(worker._last_ping_ms, 55)  # задержка при этом видна


if __name__ == "__main__":
    unittest.main()
