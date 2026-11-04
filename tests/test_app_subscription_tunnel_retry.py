"""Подписка, не загрузившаяся без VPN, сама догружается через VPN после подключения.

Сценарий жалобы 31.10.2026: при запуске («подключаться после подписок») или с
выключенным VPN у обновления есть только прямой маршрут. Прямой путь молчит —
ядро отвечает ``browser-fetch: context deadline exceeded``, — и раньше этот
текст висел на подписке весь backoff (15/60/360 минут), хотя через VPN она
загружалась. Теперь отказ говорит, что случилось, а подключение VPN повторяет
обновление через туннель.

Настоящие AppController, SubscriptionUpdateWorker (поток), гонка маршрутов и
разбор подписки; подменены только сетевые границы: процесс browser-fetch
(прямой путь) и сокет urllib (путь через HTTP-порт VPN).

Префикс ``test_app_*``: модуль создаёт QApplication и должен идти раньше
tests/test_engine_process_stop.py (см. tests/test_app_nodes_page_view.py).
"""

from __future__ import annotations

import os
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QEventLoop, QTimer
from PyQt6.QtWidgets import QApplication

app = QApplication.instance() or QApplication([])

from xray_fluent.application.controller import AppController
from xray_fluent.application.subscription_service import AWAITING_NAME
from xray_fluent.importer import subscription_http as sh
from xray_fluent.network import browser_fetch
from xray_fluent.profiles.models import AppState, Subscription

_BODY = b"vless://00000000-0000-4000-8000-000000000001@203.0.113.10:443?encryption=none&security=tls&type=tcp#Node\n"
_shared: dict[str, AppController] = {}


def _controller() -> AppController:
    controller = _shared.get("controller")
    if controller is None:
        controller = AppController()
        controller.schedule_save = lambda: None  # type: ignore[method-assign]
        controller.save = lambda: None  # type: ignore[method-assign]
        controller._request_transition = lambda *_args, **_kw: None  # type: ignore[method-assign]
        # Определение стран серверов после загрузки — свой поток: тесту он не нужен
        # и под нагрузкой переживал бы выход процесса (QThread destroyed while running).
        controller._start_country_ip_resolution = lambda: None  # type: ignore[method-assign]
        _shared["controller"] = controller
    return controller


class _SilentDirectRoute:
    """Процесс browser-fetch, у которого прямой путь упирается в таймаут ядра."""

    def __init__(self) -> None:
        self.calls = 0

    def available(self) -> bool:
        return True

    def fetch(self, url, *, headers, timeout, max_bytes):
        self.calls += 1
        raise browser_fetch.BrowserFetchError("browser-fetch: context deadline exceeded")


class _Response:
    status = 200

    def __init__(self, url: str) -> None:
        self.headers = {"Content-Type": "text/plain"}
        self._url = url
        self._left = _BODY

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def geturl(self) -> str:
        return self._url

    def read1(self, size: int) -> bytes:
        chunk, self._left = self._left[:size], self._left[size:]
        return chunk


class _VpnHttpPort:
    """urllib через HTTP-порт VPN: запоминает порт и отдаёт тело подписки."""

    def __init__(self) -> None:
        self.ports: list[str] = []

    def build_opener(self, proxy_handler, *_handlers):
        port_holder = self

        class _Opener:
            def open(self, request, timeout):
                port_holder.ports.append(proxy_handler.proxies.get("https", ""))
                return _Response(request.full_url)

        return _Opener()


class _RetryCase(unittest.TestCase):
    """Общая подготовка: настоящий контроллер, прямой путь молчит, VPN-порт отдаёт подписку."""

    def setUp(self) -> None:
        self.controller = _controller()
        self.controller.state = AppState()
        self.controller.connected = False
        self.controller.locked = False
        self.subscription = Subscription(name="Sub", url="https://sub.example/token")
        self.controller.state.subscriptions = [self.subscription]
        self.direct = _SilentDirectRoute()
        self.vpn = _VpnHttpPort()
        patches = (
            patch.object(browser_fetch, "SERVICE", self.direct),
            patch.object(sh, "build_opener", self.vpn.build_opener),
            patch.object(self.controller, "get_effective_http_proxy_port", lambda: 1391),
        )
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        self.addCleanup(self._reset)

    def _reset(self) -> None:
        self.controller.connected = False
        self.controller.state = AppState()

    def _wait_finished(self) -> object:
        results: list[object] = []
        loop = QEventLoop()

        def done(result) -> None:
            results.append(result)
            loop.quit()

        self.controller.subscription_update_finished.connect(done)
        timer = QTimer()
        timer.setSingleShot(True)
        timer.timeout.connect(loop.quit)
        timer.start(10_000)
        loop.exec()
        timer.stop()
        self.controller.subscription_update_finished.disconnect(done)
        self.assertTrue(results, "обновление подписки не завершилось за 10 с")
        # Слот «поток завершился» приходит после результата: дождаться потока и доставить его.
        for worker in list(self.controller._subscription_workers.values()):
            self.assertTrue(worker.wait(5000), "поток обновления не завершился")
        deadline = time.monotonic() + 5
        while self.controller._subscription_workers and time.monotonic() < deadline:
            app.processEvents()
        self.assertEqual(self.controller._subscription_workers, {})
        return results[0]


class TunnelRetryTest(_RetryCase):
    def test_failure_without_vpn_is_plain_and_retried_through_vpn_on_connect(self) -> None:
        from xray_fluent.network import fetch_diagnosis as fd

        def offline_diagnose(host, port, *, tunnel_port, servers_available=True):
            # Без VPN: сервер молчит на TLS, контроль отвечает — проба сети не ходит наружу.
            self.assertIsNone(tunnel_port)
            return fd.judge(fd.Evidence(host, port, (fd.HostProbe(False, "tls", "timeout"), fd.HostProbe(True))))

        with patch.object(fd, "diagnose", offline_diagnose):
            self.assertTrue(self.controller.update_subscription(self.subscription.id))
            failed = self._wait_finished()
        self.assertFalse(failed.success)
        self.assertEqual(self.vpn.ports, [])  # VPN выключен: маршрута через него не было
        self.assertRegex(
            self.subscription.last_error,
            r"^Не удалось загрузить подписку\. Виноват: блокировка сети или провайдера \(вероятно\)\. "
            r"Где оборвалось: напрямую TCP есть, но рукопожатие TLS повисло.*"
            r"Через VPN не пробовали: он не подключён\.$",
        )
        self.assertTrue(self.subscription.retry_via_tunnel)
        self.assertIsNotNone(self.subscription.backoff_until)

        # VPN подключился — повтор сразу, мимо backoff.
        self.controller.connected = True
        self.controller.connection_changed.emit(True)
        retried = self._wait_finished()
        self.assertTrue(retried.success, getattr(retried, "message", ""))
        self.assertEqual(self.vpn.ports, ["http://127.0.0.1:1391"])
        self.assertEqual(self.subscription.last_error, "")
        self.assertFalse(self.subscription.retry_via_tunnel)
        self.assertIsNone(self.subscription.backoff_until)
        self.assertEqual(
            [node.server for node in self.controller.state.nodes if node.subscription_id == self.subscription.id],
            ["203.0.113.10"],
        )
        self.assertEqual(self.direct.calls, 2)  # прямой путь пробовали оба раза

    def test_check_without_vpn_does_not_turn_into_an_update(self) -> None:
        self.assertTrue(self.controller.check_subscription(self.subscription.id))
        self._wait_finished()
        self.assertFalse(self.subscription.retry_via_tunnel)
        self.controller.connected = True
        self.controller.connection_changed.emit(True)
        self.assertEqual(self.controller._subscription_workers, {})
        self.assertEqual(self.controller._subscription_update_queue, [])

    def test_no_retry_while_locked_or_without_vpn_port(self) -> None:
        self.subscription.retry_via_tunnel = True
        self.controller.connected = True
        self.controller.locked = True
        self.controller.connection_changed.emit(True)
        self.controller.locked = False
        with patch.object(self.controller, "get_effective_http_proxy_port", lambda: None):
            self.controller.connection_changed.emit(True)
        self.assertEqual(self.controller._subscription_workers, {})
        self.assertEqual(self.controller._subscription_update_queue, [])


class NewSubscriptionTest(_RetryCase):
    """Подписка, добавленная без VPN, не теряется: остаётся в списке и догружается через VPN.

    Раньше первая неудачная загрузка новой подписки её выбрасывала, хотя текст отказа обещал
    «приложение повторит загрузку само»: в списке не оставалось ничего, что можно повторить.
    """

    def setUp(self) -> None:
        super().setUp()
        self.controller.state = AppState()
        self.controller._pending_subscription_additions.clear()
        self.new = Subscription(name="", url="https://sub.example/new-token")

    @staticmethod
    def _tls_blocked_diagnose(host, port, *, tunnel_port, servers_available=True):
        from xray_fluent.network import fetch_diagnosis as fd

        direct = (fd.HostProbe(False, "tls", "timeout"), fd.HostProbe(True))
        return fd.judge(fd.Evidence(host, port, direct, None, servers_available=servers_available))

    def _add_and_fail(self) -> object:
        from xray_fluent.network import fetch_diagnosis as fd

        with patch.object(fd, "diagnose", self._tls_blocked_diagnose):
            self.assertTrue(self.controller.add_subscription(self.new))
            return self._wait_finished()

    def test_unreachable_new_subscription_is_kept_for_a_retry_through_the_vpn(self) -> None:
        failed = self._add_and_fail()

        self.assertFalse(failed.success)
        self.assertEqual([item.id for item in self.controller.state.subscriptions], [self.new.id])
        self.assertTrue(self.new.retry_via_tunnel)
        self.assertEqual(self.new.failure_count, 1)
        self.assertIsNotNone(self.new.backoff_until)
        self.assertEqual(self.new.name, AWAITING_NAME)
        self.assertEqual(self.controller._pending_subscription_additions, {})
        self.assertEqual(self.controller.state.nodes, [])

    def test_without_any_server_the_advice_asks_for_a_single_key(self) -> None:
        failed = self._add_and_fail()

        self.assertIn("добавьте любой одиночный ключ", failed.message)
        self.assertIn("не подписку", failed.message)
        self.assertIn("загрузится сама через этот сервер", failed.message)
        self.assertNotIn("Включите VPN", failed.message)

    def test_with_a_server_present_the_advice_is_to_connect_to_it(self) -> None:
        from xray_fluent.profiles.models import Node

        self.controller.state.nodes = [Node(name="one", link="vless://x", server="198.51.100.7")]
        failed = self._add_and_fail()

        self.assertIn("Подключитесь к любому серверу", failed.message)
        self.assertNotIn("одиночный ключ", failed.message)

    def test_kept_subscription_loads_through_the_vpn_gets_a_name_and_a_server(self) -> None:
        self._add_and_fail()

        self.controller.connected = True
        self.controller.connection_changed.emit(True)
        loaded = self._wait_finished()

        self.assertTrue(loaded.success, getattr(loaded, "message", ""))
        self.assertEqual(self.vpn.ports, ["http://127.0.0.1:1391"])
        # Название то же, что при обычном добавлении: заголовок из подписки, а у простого списка ссылок
        # парсер берёт его из адреса.
        self.assertEqual(self.new.name, "new-token")
        self.assertNotEqual(self.new.name, AWAITING_NAME)
        self.assertFalse(self.new.retry_via_tunnel)
        self.assertEqual(self.new.last_error, "")
        nodes = [node for node in self.controller.state.nodes if node.subscription_id == self.new.id]
        self.assertEqual([node.server for node in nodes], ["203.0.113.10"])
        self.assertEqual(self.controller.state.selected_node_id, nodes[0].id)

    def test_a_kept_subscription_does_not_replace_a_name_the_user_typed(self) -> None:
        self.new.name = "Моя подписка"
        self._add_and_fail()

        self.controller.connected = True
        self.controller.connection_changed.emit(True)
        self._wait_finished()

        self.assertEqual(self.new.name, "Моя подписка")

    def test_failure_that_is_not_about_the_vpn_route_still_drops_the_new_subscription(self) -> None:
        self.controller._pending_subscription_additions[self.new.id] = self.new
        results: list[object] = []
        self.controller.subscription_update_finished.connect(results.append)
        self.addCleanup(self.controller.subscription_update_finished.disconnect, results.append)

        self.controller._on_subscription_update_failed(self.new, "Сервер подписки ответил 404", False)

        self.assertEqual(self.controller.state.subscriptions, [])
        self.assertEqual(self.controller._pending_subscription_additions, {})
        self.assertFalse(results[0].success)

    def test_the_second_attempt_through_the_vpn_keeps_backing_off_instead_of_giving_up(self) -> None:
        self._add_and_fail()
        self.new.backoff_until = None  # пауза прошла
        self.assertTrue(self.new.retry_via_tunnel)

        from datetime import datetime, timezone

        from xray_fluent.application.subscription_service import subscription_due

        self.assertTrue(subscription_due(self.new, datetime.now(timezone.utc)))


if __name__ == "__main__":
    unittest.main()
