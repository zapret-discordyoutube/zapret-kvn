"""Подписка сервиса Zapret VPN: заголовок ответа, адрес без раскрытия, страна без GeoIP.

Решение владельца 2026-11-16: серверы сервиса (вход в России, выход в стране из имени)
показываются только флагом имени — без адреса и без страны по GeoIP адреса.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from xray_fluent.application import node_runtime_service
from xray_fluent.application.subscription_service import reconcile_subscription
from xray_fluent.importer.subscription_http import SERVICE_HEADER, SubscriptionFetchResult
from xray_fluent.importer.subscription_parser import parse_subscription_payload
from xray_fluent.profiles.models import AppState, Node, Subscription
from xray_fluent.ui import privacy

VLESS = "vless://11111111-1111-1111-1111-111111111111@203.0.113.5:443?security=tls#Velnor"


class ServiceSubscriptionTests(unittest.TestCase):
    def tearDown(self) -> None:
        privacy.set_service_subscriptions(())

    def test_header_marks_the_subscription_and_survives_a_round_trip(self) -> None:
        subscription = Subscription(id="sub", url="https://sub.example/token")
        state = AppState(subscriptions=[subscription])
        parsed = parse_subscription_payload(VLESS)

        reconcile_subscription(state, subscription, parsed, SubscriptionFetchResult(headers={SERVICE_HEADER: "1"}))
        self.assertTrue(subscription.service)
        self.assertTrue(Subscription.from_dict(subscription.to_dict()).service)

        # Заголовок пропал из ответа — подписка снова обычная.
        reconcile_subscription(state, subscription, parsed, SubscriptionFetchResult(headers={}))
        self.assertFalse(subscription.service)
        self.assertFalse(Subscription.from_dict({"id": "old"}).service)

    def test_service_node_address_is_never_revealed(self) -> None:
        service = Node(name="🇳🇱 Velnor", server="203.0.113.5", port=443, subscription_id="svc")
        plain = Node(name="Plain", server="198.51.100.7", port=443, subscription_id="other")
        privacy.set_service_subscriptions({"svc"})

        self.assertEqual(privacy.masked_endpoint(), privacy.node_endpoint_text(service, revealed=True))
        self.assertEqual("198.51.100.7:443", privacy.node_endpoint_text(plain, revealed=True))
        self.assertEqual(privacy.masked_endpoint(), privacy.node_endpoint_text(plain, revealed=False))

    def test_geoip_is_never_asked_for_service_nodes(self) -> None:
        service = Node(id="a", name="Velnor", server="203.0.113.5", port=443, subscription_id="svc", country_code="RU")
        state = AppState(subscriptions=[Subscription(id="svc", service=True)], nodes=[service])
        controller = SimpleNamespace(state=state, _country_resolver=None)

        with patch.object(node_runtime_service, "CountryResolver") as resolver:
            node_runtime_service.start_country_ip_resolution(controller)
        resolver.assert_not_called()
        self.assertEqual("", service.country_code)

        emitted = []
        controller.countries_changed = SimpleNamespace(emit=emitted.append)
        results = {"a": (node_runtime_service.endpoint_hosts(service), "RU")}
        node_runtime_service.on_countries_resolved(controller, results)
        self.assertEqual("", service.country_code)
        self.assertEqual([], emitted)


if __name__ == "__main__":
    unittest.main()
