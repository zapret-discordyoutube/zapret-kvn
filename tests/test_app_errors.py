"""App errors not about a server (vpnbot «app_error live» 2026-11-20): codes, frames, the store and the sink."""

from __future__ import annotations

import re
import socket
import tempfile
import unittest
from pathlib import Path

from xray_fluent.client_reports import app_errors as a
from xray_fluent.client_reports.contract import AttemptDetails

FRAME = re.compile(r"^[A-Za-z0-9_$.<>-]{1,72}:[0-9]{1,6}$")
CODE = re.compile(r"^[a-z]{1,16}:[A-Za-z0-9_.-]{1,64}$")


class AppErrorTests(unittest.TestCase):
    def test_codes_and_frames_keep_the_contracts_shape_and_no_path(self) -> None:
        self.assertEqual("start:CORE_UNCLASSIFIED", a.code("start", "CORE_UNCLASSIFIED"))
        self.assertIsNone(a.code("Start", "x"))
        self.assertEqual("xray_fluent.application.controller",
                         a.module_of(r"C:\Users\Иван Петров\AppData\Local\ZapretKVN\xray_fluent\application\controller.py"))
        self.assertEqual("threading", a.module_of(r"C:\Python312\Lib\threading.py"))
        self.assertEqual("Foo.<module>:0", a.frame("Foo.<module>", None))
        try:
            {}["missing"]
        except KeyError as exc:
            error = a.crash_of(KeyError, exc.__traceback__)
        self.assertEqual(("crash", "crash:KeyError"), (error.step, error.code))
        self.assertTrue(error.frames and all(FRAME.match(item) for item in error.frames))
        self.assertRegex(error.frames[0], r"test_codes_and_frames_keep_the_contracts_shape_and_no_path:[0-9]+$")
        self.assertFalse(any("\\" in item or "/" in item or "Users" in item for item in error.frames))

    def test_start_subscription_and_transport_codes(self) -> None:
        self.assertEqual("port:bind", a.start_error_of(OSError("bind: address already in use")).code)
        self.assertEqual("start:failed", a.start_error_of(None).code)
        self.assertTrue(CODE.match(a.start_error_of(RuntimeError("something odd")).code))
        sub = a.subscription_error_of(503, None, True, "proxy")
        self.assertEqual(("sub:http_5xx", True, "proxy"), (sub.code, sub.subscription.ours, sub.subscription.route))
        self.assertEqual("timeout", a.transport_of(socket.timeout("timed out")))
        self.assertEqual("dns", a.transport_of(socket.gaierror(11001, "getaddrinfo failed")))
        self.assertEqual("refused", a.transport_of(ConnectionRefusedError(10061, "refused")))
        self.assertFalse(a.is_valid(a.AppError("start", "sub:timeout", subscription=a.SubscriptionFact(True, "direct"))))

    def test_the_record_carries_exactly_the_contracts_fields(self) -> None:
        record = a.AppErrorRecord(
            "ab" * 16, a.AppError("subscription", "sub:timeout", subscription=a.SubscriptionFact(False, "direct")), 2,
            1_763_640_000_000, "0.8.102", "v1.abc.def",
            AttemptDetails(server_ip="203.0.113.5", port=443, network_type="ethernet"),
        )
        item = a.record_json("0123456789abcdef0123456789abcdef", "zapret-kvn", "windows", record, "direct", -3_600_000)
        self.assertEqual({"kind", "schema", "install_id", "report_id", "app", "step", "code", "count", "occurred_at",
                          "sent_via", "network_token", "subscription", "network_type"}, set(item))
        self.assertEqual("2025-11-20T11:00:00Z", item["occurred_at"])
        self.assertEqual({"ours": False, "route": "direct"}, item["subscription"])

    def test_repeats_are_counted_and_a_code_goes_once_a_day(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            clock = [1_000_000_000]
            store = a.AppErrorStore(Path(folder) / "app-errors.json", lambda: clock[0])
            error = a.AppError("start", "start:failed")
            store.add(error, "0.8.102", "", AttemptDetails())
            store.add(error, "0.8.102", "", AttemptDetails())
            first = store.due(20)[0]
            self.assertEqual(2, first.count)
            store.add(error, "0.8.102", "", AttemptDetails())
            store.sent([first])
            self.assertEqual(1, store.size())
            self.assertEqual([], store.due(20))
            clock[0] += a.SEND_EVERY_MS
            later = store.due(20)
            self.assertEqual((1, True), (later[0].count, later[0].report_id != first.report_id))
            self.assertEqual(1, a.AppErrorStore(Path(folder) / "app-errors.json", lambda: clock[0]).size())

    def test_errors_noted_before_the_reporter_exist_go_when_it_does(self) -> None:
        got: list[a.AppError] = []
        a.set_sink(None)
        try:
            a.note(a.AppError("update", "update:net"))
            a.set_sink(got.append)
            a.note(a.AppError("storage", "storage:save"))
        finally:
            a.set_sink(None)
        self.assertEqual(["update:net", "storage:save"], [item.code for item in got])


if __name__ == "__main__":
    unittest.main()
