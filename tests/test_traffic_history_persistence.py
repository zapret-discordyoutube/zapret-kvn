"""История трафика: запись через фонового писателя, закрытые сессии не перекодируются."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from xray_fluent.diagnostics import traffic_history
from xray_fluent.diagnostics.traffic_history import TrafficHistoryStorage


class TrafficHistoryPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.file = Path(tmp.name) / "traffic_history.json"
        patcher = mock.patch.object(traffic_history, "TRAFFIC_HISTORY_FILE", self.file)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_roundtrip_through_file(self) -> None:
        history = TrafficHistoryStorage(load=False)
        history.start_session("node A", "proxy")
        history.update_session({"chrome.exe": (100, 2000, "proxy")})
        history.end_session()
        history.start_session("node B", "tun")
        history.save_periodic()
        data = json.loads(self.file.read_text(encoding="utf-8"))
        self.assertEqual([s["node_name"] for s in data["sessions"]], ["node A", "node B"])
        reloaded = TrafficHistoryStorage()
        self.assertEqual(len(reloaded.get_sessions(1)), 2)
        self.assertEqual(reloaded.get_process_totals(1)["chrome.exe"]["download"], 2000)

    def test_writer_receives_payload_instead_of_sync_write(self) -> None:
        writer = mock.Mock()
        history = TrafficHistoryStorage(load=False)
        history.set_writer(writer)
        history.start_session("node", "proxy")
        writer.submit.assert_called_once()
        payload, passphrase = writer.submit.call_args.args
        self.assertEqual(passphrase, "")
        self.assertEqual(json.loads(payload)["sessions"][0]["node_name"], "node")
        self.assertFalse(self.file.exists())

    def test_closed_sessions_are_encoded_once(self) -> None:
        history = TrafficHistoryStorage(load=False)
        history.set_writer(mock.Mock())
        for index in range(3):
            history.start_session(f"n{index}", "proxy")
            history.end_session()
        history.start_session("open", "proxy")
        with mock.patch.object(traffic_history, "_compact_json", wraps=traffic_history._compact_json) as encode:
            history.save_periodic()
        # Только открытая сессия + daily_totals.
        self.assertEqual(encode.call_count, 2)


if __name__ == "__main__":
    unittest.main()
