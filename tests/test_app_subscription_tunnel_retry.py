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


class TunnelRetryTest(unittest.TestCase):
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

    def test_failure_without_vpn_is_plain_and_retried_through_vpn_on_connect(self) -> None:
        self.assertTrue(self.controller.update_subscription(self.subscription.id))
        failed = self._wait_finished()
        self.assertFalse(failed.success)
        self.assertEqual(self.vpn.ports, [])  # VPN выключен: маршрута через него не было
        self.assertRegex(
            self.subscription.last_error,
            r"^Не удалось загрузить подписку напрямую: сервер не ответил за \d+ с\. "
            r"VPN не был подключён, через VPN не пробовали$",
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


if __name__ == "__main__":
    unittest.main()
