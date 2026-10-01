"""Subscription fetch races its routes under one deadline.

The direct route gets a short head start; after it the VPN proxy route runs in
parallel, so a silently blackholed subscription host costs about a second
instead of every per-operation timeout of the direct path.
"""

from __future__ import annotations

import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from xray_fluent.importer import subscription_http as sh
from xray_fluent.importer.subscription_http import (
    SUBSCRIPTION_PARSER_REVISION,
    SubscriptionFetchError,
    SubscriptionFetchResult,
    SubscriptionServerResponseError,
    fetch_subscription,
)


def _subscription() -> SimpleNamespace:
    return SimpleNamespace(
        url="https://sub.example/a",
        parser_revision=SUBSCRIPTION_PARSER_REVISION,
        etag="",
        last_modified="",
    )


class SubscriptionFetchRaceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.release = threading.Event()
        self.addCleanup(self.release.set)
        patcher = patch.object(sh, "PROXY_HEAD_START", 0.05)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _hang(self) -> None:
        self.release.wait(10)
        raise OSError("timed out")

    def test_proxy_wins_while_direct_route_hangs(self) -> None:
        proxied = SubscriptionFetchResult(data=b"ok", via_proxy=True)
        routes: list[bool] = []

        def fake(_sub, *, via_proxy, **_kw):
            if not via_proxy:
                self._hang()
            return proxied

        started = time.monotonic()
        with patch.object(sh, "_fetch_once", side_effect=fake):
            result = fetch_subscription(
                _subscription(), mode="auto", proxy_port=1080, on_route=routes.append
            )
        self.assertIs(result, proxied)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(routes, [False, True])
        self.assertGreater(result.elapsed, 0)

    def test_deadline_bounds_a_hanging_fetch(self) -> None:
        def fake(_sub, **_kw):
            self._hang()

        started = time.monotonic()
        with patch.object(sh, "_fetch_once", side_effect=fake):
            with self.assertRaisesRegex(SubscriptionFetchError, "не ответил"):
                fetch_subscription(_subscription(), mode="direct", deadline=0.2)
        self.assertLess(time.monotonic() - started, 2)

    def test_cancel_stops_waiting(self) -> None:
        cancel = threading.Event()

        def fake(_sub, **_kw):
            self._hang()

        threading.Timer(0.1, cancel.set).start()
        started = time.monotonic()
        with patch.object(sh, "_fetch_once", side_effect=fake):
            with self.assertRaisesRegex(SubscriptionFetchError, "отменено"):
                fetch_subscription(_subscription(), mode="direct", cancel=cancel)
        self.assertLess(time.monotonic() - started, 2)

    def test_direct_answer_outranks_proxy_refusal(self) -> None:
        direct = SubscriptionFetchResult(data=b"ok")

        def fake(_sub, *, via_proxy, **_kw):
            if via_proxy:
                raise SubscriptionServerResponseError("HTTP 403")
            time.sleep(0.3)
            return direct

        with patch.object(sh, "_fetch_once", side_effect=fake):
            result = fetch_subscription(_subscription(), mode="auto", proxy_port=1080)
        self.assertIs(result, direct)

    def test_proxy_refusal_reported_when_direct_stays_silent(self) -> None:
        def fake(_sub, *, via_proxy, **_kw):
            if via_proxy:
                raise SubscriptionServerResponseError("HTTP 403")
            self._hang()

        started = time.monotonic()
        with patch.object(sh, "_DIRECT_GRACE", 0.2), patch.object(
            sh, "_fetch_once", side_effect=fake
        ):
            with self.assertRaisesRegex(SubscriptionFetchError, "HTTP 403"):
                fetch_subscription(_subscription(), mode="auto", proxy_port=1080)
        self.assertLess(time.monotonic() - started, 2)

    def test_slow_body_is_cut_at_the_deadline(self) -> None:
        response = SimpleNamespace(read1=lambda _n: (time.sleep(0.05), b"x")[1])
        with self.assertRaises(TimeoutError):
            sh._read_body(response, 1024, time.monotonic() + 0.2)


if __name__ == "__main__":
    unittest.main()
