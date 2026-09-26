"""Сбор трафика по процессам: состояние сессии ограничено живыми соединениями."""

from __future__ import annotations

import io
import json
import unittest
from unittest import mock

from xray_fluent.platform.windows import process_traffic_collector as collector


def _conn(cid: str, exe: str, up: int, down: int) -> dict:
    return {
        "id": cid, "upload": up, "download": down, "chains": ["proxy"],
        "metadata": {"processPath": f"C:/Apps/{exe}", "host": "example.com"},
    }


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _poll(connections: list[dict]):
    payload = json.dumps({"connections": connections}).encode()
    with mock.patch.object(collector.urllib.request, "urlopen", return_value=_Response(payload)):
        return {s.exe.lower(): s for s in collector.collect_process_stats()}


class BoundedCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        collector.reset_connection_tracking()

    def tearDown(self) -> None:
        collector.reset_connection_tracking()

    def test_closed_connections_leave_state_but_keep_bytes_and_count(self) -> None:
        _poll([_conn("a", "chrome.exe", 10, 100), _conn("b", "chrome.exe", 5, 50)])
        self.assertEqual(len(collector._conn_owner), 2)
        stats = _poll([_conn("b", "chrome.exe", 5, 60)])
        # «a» закрылось: его байты перешли в закрытые, а запись владельца удалена.
        self.assertEqual(set(collector._conn_owner), {"b"})
        self.assertEqual(stats["chrome.exe"].download, 160)
        stats = _poll([])
        self.assertEqual(collector._conn_owner, {})
        self.assertEqual(stats, {})
        stats = _poll([_conn("c", "chrome.exe", 1, 1)])
        self.assertEqual(stats["chrome.exe"].download, 161)

    def test_state_does_not_grow_with_connection_churn(self) -> None:
        for batch in range(200):
            _poll([_conn(f"{batch}-{i}", "app.exe", 1, 1) for i in range(20)])
        self.assertLessEqual(len(collector._conn_owner), 20)
        self.assertLessEqual(len(collector._conn_bytes), 20)
        self.assertEqual(collector._conn_total["app.exe"], 200 * 20)


if __name__ == "__main__":
    unittest.main()
