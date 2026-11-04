"""Физический отпечаток сети в TUN: разбор таблицы маршрутов, монитор и решения контроллера.

Имя начинается с ``test_n``: файл создаёт голый QCoreApplication и должен идти после ``test_app_*``
(см. tests/test_app_nodes_page_view.py).
"""

import unittest
from unittest.mock import Mock

from PyQt6.QtCore import QCoreApplication

from xray_fluent.application.controller import AppController
from xray_fluent.network.network_monitor import NetworkMonitor
from xray_fluent.network.physical_route import (
    PHYSICAL_PREFIX,
    has_network,
    is_physical_fingerprint,
    physical_fingerprint,
    tun_networks,
)

_APP = QCoreApplication.instance() or QCoreApplication([])

# Вывод ``route print -4 0.0.0.0`` на win10 (русская Windows): заголовки по-русски, строки числовые.
_SAMPLE = """\
===========================================================================
Список интерфейсов
 80...bc 24 11 03 a7 85 ......Red Hat VirtIO Ethernet Adapter
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 таблица маршрута
===========================================================================
Активные маршруты:
Сетевой адрес           Маска сети      Адрес шлюза       Интерфейс  Метрика
          0.0.0.0          0.0.0.0        10.20.0.1       10.20.0.20     15
===========================================================================
Постоянные маршруты:
  Отсутствует
"""

_TUN = tun_networks({"inbounds": [{"type": "tun", "address": ["172.19.0.1/30"]}]})


def _table(*rows: tuple[str, str, int]) -> str:
    lines = ["Активные маршруты:", "Сетевой адрес Маска сети Адрес шлюза Интерфейс Метрика"]
    lines += [f"          0.0.0.0          0.0.0.0  {gw:>14}  {ip:>14}  {metric}" for gw, ip, metric in rows]
    return "\n".join(lines) + "\n"


class PhysicalFingerprintTest(unittest.TestCase):
    def test_real_windows_sample_gives_gateway_and_interface(self) -> None:
        self.assertEqual(physical_fingerprint(_SAMPLE, _TUN), "phys:10.20.0.1>10.20.0.20")

    def test_our_tun_rows_are_left_out_so_the_adapter_does_not_change_the_fingerprint(self) -> None:
        without_tun = physical_fingerprint(_table(("192.168.1.1", "192.168.1.50", 25)), _TUN)
        with_tun = physical_fingerprint(
            _table(("192.168.1.1", "192.168.1.50", 25), ("172.19.0.2", "172.19.0.1", 1)), _TUN
        )
        self.assertEqual(without_tun, with_tun)

    def test_wifi_to_ethernet_changes_the_fingerprint(self) -> None:
        wifi = physical_fingerprint(_table(("192.168.1.1", "192.168.1.50", 35)), _TUN)
        cable = physical_fingerprint(_table(("10.0.0.1", "10.0.0.7", 25)), _TUN)
        self.assertNotEqual(wifi, cable)

    def test_row_order_does_not_matter(self) -> None:
        a = _table(("10.0.0.1", "10.0.0.7", 25), ("192.168.1.1", "192.168.1.50", 35))
        b = _table(("192.168.1.1", "192.168.1.50", 35), ("10.0.0.1", "10.0.0.7", 25))
        self.assertEqual(physical_fingerprint(a, _TUN), physical_fingerprint(b, _TUN))

    def test_no_default_route_is_an_empty_physical_set_not_a_plain_address(self) -> None:
        value = physical_fingerprint("Активные маршруты:\n", _TUN)
        self.assertEqual(value, PHYSICAL_PREFIX)
        self.assertFalse(has_network(value))

    def test_localized_on_link_gateway_words_are_accepted(self) -> None:
        for gateway in ("On-link", "Подключено", "On link"):
            text = f"          0.0.0.0          0.0.0.0  {gateway}  192.168.5.9  281\n"
            self.assertEqual(physical_fingerprint(text, _TUN), f"phys:{gateway}>192.168.5.9")

    def test_other_prefixes_and_noise_are_ignored(self) -> None:
        text = (
            "          0.0.0.0        128.0.0.0     172.19.0.2    172.19.0.1      1\n"
            "        127.0.0.0        255.0.0.0         On-link       127.0.0.1    331\n"
            "not a route row\n"
        )
        self.assertEqual(physical_fingerprint(text, _TUN), PHYSICAL_PREFIX)

    def test_kind_helpers(self) -> None:
        self.assertTrue(is_physical_fingerprint("phys:a>b"))
        self.assertFalse(is_physical_fingerprint("192.168.1.8"))
        self.assertTrue(has_network("192.168.1.8"))
        self.assertTrue(has_network("phys:a>b"))
        self.assertFalse(has_network("0.0.0.0"))
        self.assertFalse(has_network(""))


class TunNetworksTest(unittest.TestCase):
    def test_reads_address_list_string_and_legacy_field(self) -> None:
        config = {
            "inbounds": [
                {"type": "mixed", "address": ["10.1.1.1/24"]},
                {"type": "tun", "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"], "inet4_address": "172.20.0.1/30"},
                {"type": "tun", "address": "172.21.0.1/30"},
            ]
        }
        self.assertEqual([str(n) for n in tun_networks(config)], ["172.19.0.0/30", "172.20.0.0/30", "172.21.0.0/30"])

    def test_bad_input_gives_no_networks(self) -> None:
        self.assertEqual(tun_networks(None), [])
        self.assertEqual(tun_networks({"inbounds": "x"}), [])
        self.assertEqual(tun_networks({"inbounds": [{"type": "tun", "address": ["not-an-ip"]}]}), [])


class MonitorGuardsTest(unittest.TestCase):
    def _monitor(self) -> tuple[NetworkMonitor, list]:
        monitor = NetworkMonitor(provider=lambda: "x")
        self.monitor = monitor  # держим объект: иначе Qt удалит таймер раньше очистки
        monitor._timer.start()
        self.addCleanup(monitor._timer.stop)
        changes: list = []
        monitor.network_changed.connect(lambda old, new: changes.append((old, new)))
        return monitor, changes

    def test_change_inside_one_kind_is_emitted(self) -> None:
        monitor, changes = self._monitor()
        monitor._apply_fingerprint("phys:a>b")
        monitor._apply_fingerprint("phys:c>d")
        monitor._apply_fingerprint("192.168.1.8")
        monitor._apply_fingerprint("192.168.1.9")
        self.assertEqual(changes, [("phys:a>b", "phys:c>d"), ("192.168.1.8", "192.168.1.9")])

    def test_switch_between_kinds_is_not_a_network_change(self) -> None:
        monitor, changes = self._monitor()
        monitor._apply_fingerprint("192.168.1.8")
        monitor._apply_fingerprint("phys:a>b")  # сессия стала TUN
        monitor._apply_fingerprint("192.168.1.8")  # и обратно
        self.assertEqual(changes, [])

    def test_empty_reading_is_skipped_and_keeps_the_last_value(self) -> None:
        monitor, changes = self._monitor()
        monitor._apply_fingerprint("phys:a>b")
        monitor._apply_fingerprint("")
        monitor._apply_fingerprint("phys:a>b")
        self.assertEqual(changes, [])

    def test_provider_failure_is_reported_as_an_empty_reading(self) -> None:
        def broken() -> str:
            raise RuntimeError("boom")

        monitor = NetworkMonitor(provider=broken)
        seen: list = []
        from xray_fluent.network.network_monitor import _FingerprintWorker

        worker = _FingerprintWorker(broken)
        worker.result.connect(seen.append)
        worker.run()
        self.assertEqual(seen, [""])
        self.assertIsNotNone(monitor)


def _controller(*, tun: bool, connected: bool = True) -> Mock:
    controller = Mock()
    controller.state.settings.tun_mode = tun
    controller.state.settings.reconnect_on_network_change = True
    controller.connected = connected
    controller._desired_connected = connected
    controller._transition_active = False
    controller._disconnecting = False
    controller._retry_connect_on_network = False
    controller._active_tunnel_addresses.return_value = set()
    return controller


class ControllerDecisionTest(unittest.TestCase):
    def test_physical_change_in_tun_mode_reconnects(self) -> None:
        controller = _controller(tun=True)
        AppController._on_network_changed(controller, "phys:10.0.0.1>10.0.0.7", "phys:192.168.1.1>192.168.1.50")
        controller._request_transition.assert_called_once_with("network changed")

    def test_plain_change_in_tun_mode_is_still_ignored(self) -> None:
        controller = _controller(tun=True)
        AppController._on_network_changed(controller, "172.19.0.1", "172.19.0.1x")
        controller._request_transition.assert_not_called()

    def test_physical_change_in_tun_mode_waits_while_a_transition_runs(self) -> None:
        controller = _controller(tun=True)
        controller._transition_active = True
        AppController._on_network_changed(controller, "phys:a>b", "phys:c>d")
        controller._request_transition.assert_not_called()

    def test_physical_change_respects_the_reconnect_setting(self) -> None:
        controller = _controller(tun=True)
        controller.state.settings.reconnect_on_network_change = False
        AppController._on_network_changed(controller, "phys:a>b", "phys:c>d")
        controller._request_transition.assert_not_called()

    def test_lost_uplink_does_not_count_as_network_returned(self) -> None:
        controller = _controller(tun=True, connected=False)
        controller._retry_connect_on_network = True
        AppController._on_network_changed(controller, "phys:a>b", PHYSICAL_PREFIX)
        controller._request_transition.assert_not_called()
        self.assertTrue(controller._retry_connect_on_network)

    def test_returned_uplink_retries_a_failed_connect(self) -> None:
        controller = _controller(tun=True, connected=False)
        controller._desired_connected = False
        controller._retry_connect_on_network = True
        AppController._on_network_changed(controller, PHYSICAL_PREFIX, "phys:a>b")
        controller._request_transition.assert_called_once_with("network returned")


if __name__ == "__main__":
    unittest.main()
