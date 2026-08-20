from __future__ import annotations

import unittest

from xray_fluent.models import Subscription, SubscriptionInfo
from xray_fluent.subscription_http import describe_http_failure
from xray_fluent.ui.subscriptions_page import _format_expire, _format_traffic


class HwidFailureTests(unittest.TestCase):
    def test_device_limit_is_explained(self) -> None:
        for header in ("x-hwid-max-devices-reached", "x-hwid-limit"):
            with self.subTest(header=header):
                message = describe_http_failure(404, {header: "true"})
                self.assertIn("лимит устройств", message.lower())
                self.assertNotIn("HTTP 404", message)

    def test_missing_hwid_is_explained(self) -> None:
        message = describe_http_failure(404, {"x-hwid-not-supported": "true"})
        self.assertIn("HWID", message)

    def test_header_case_is_ignored(self) -> None:
        message = describe_http_failure(404, {"X-Hwid-Max-Devices-Reached": "true"})
        self.assertIn("лимит устройств", message.lower())

    def test_plain_failure_keeps_status_code(self) -> None:
        self.assertEqual(describe_http_failure(503, {}), "HTTP 503")
        self.assertEqual(describe_http_failure(404, {"content-type": "text/plain"}), "HTTP 404")


class SubscriptionLimitFormatTests(unittest.TestCase):
    @staticmethod
    def _subscription(*, fetched: bool, **info) -> Subscription:
        subscription = Subscription(url="https://example.com/sub")
        subscription.info = SubscriptionInfo(**info)
        if fetched:
            subscription.last_success_at = "2026-08-12T00:00:00+00:00"
        return subscription

    def test_zero_expire_is_not_shown_as_1970(self) -> None:
        subscription = self._subscription(fetched=True, expire=0)
        rendered = _format_expire(subscription)
        self.assertNotIn("1970", rendered)
        self.assertEqual(rendered, "Бессрочно")

    def test_real_expire_is_a_date(self) -> None:
        subscription = self._subscription(fetched=True, expire=1_790_951_622)
        self.assertRegex(_format_expire(subscription), r"^\d{4}-\d{2}-\d{2}$")

    def test_unfetched_subscription_claims_nothing(self) -> None:
        subscription = self._subscription(fetched=False, expire=0)
        self.assertEqual(_format_expire(subscription), "—")
        self.assertEqual(_format_traffic(subscription), "—")

    def test_zero_total_means_unlimited(self) -> None:
        subscription = self._subscription(fetched=True, total=0, download=1024)
        self.assertIn("Безлимит", _format_traffic(subscription))

    def test_known_total_is_a_ratio(self) -> None:
        subscription = self._subscription(fetched=True, total=1024 * 1024, download=512 * 1024)
        rendered = _format_traffic(subscription)
        self.assertIn("/", rendered)
        self.assertNotIn("Безлимит", rendered)


if __name__ == "__main__":
    unittest.main()


class CheckResultPresentationTests(unittest.TestCase):
    """Проверка читает подписку и ничего не сохраняет, поэтому её результат
    нельзя показывать теми же счётчиками, что и результат обновления."""

    def test_check_reports_both_counts(self) -> None:
        from xray_fluent.models import SubscriptionUpdateResult

        result = SubscriptionUpdateResult(
            subscription_id="s1",
            success=True,
            message="Проверка успешна: в подписке серверов 42",
            check_only=True,
            source_count=42,
            stored_count=21,
        )

        self.assertTrue(result.check_only)
        self.assertNotEqual(result.source_count, result.stored_count)
        # Счётчики изменений у проверки бессмысленны и обязаны остаться нулевыми.
        self.assertEqual((0, 0, 0), (result.added, result.updated, result.removed))
