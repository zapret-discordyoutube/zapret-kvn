"""AWG 3.0 на Windows обязан уходить с дефолтного bind ядра.

Дефолтный Windows-bind sing-box extended 2.6.5 (WinRingBind) обнуляет байты
1-3 каждого принятого UDP-пакета. У WireGuard и AWG 2.0 это безобидно, а у
AWG 3.0 эти байты входят в соль шифра защиты заголовка — ответ сервера
расшифровывается в мусор и молча отбрасывается. Ядро использует свободный
от дефекта ClientBind, если у endpoint'а задан detour.
"""
import unittest

from xray_fluent.engines.singbox.runtime_planner import (
    AWG3_DIRECT_DETOUR_TAG,
    endpoint_needs_windows_bind_workaround,
    ensure_awg3_windows_bind_workaround,
)

HPK = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY="


def _awg3_endpoint(**overrides):
    endpoint = {
        "type": "wireguard",
        "tag": "proxy",
        "amnezia": {"jc": 4, "s1": 41, "header_protection_key": HPK},
    }
    endpoint.update(overrides)
    return endpoint


class TestDetection(unittest.TestCase):
    def test_awg3_needs_workaround(self):
        self.assertTrue(endpoint_needs_windows_bind_workaround(_awg3_endpoint()))

    def test_awg2_and_plain_wireguard_do_not(self):
        awg2 = {"amnezia": {"jc": 4, "s1": 41, "i1": "<b 0xaa>"}}
        self.assertFalse(endpoint_needs_windows_bind_workaround(awg2))
        self.assertFalse(endpoint_needs_windows_bind_workaround({"type": "wireguard"}))
        self.assertFalse(endpoint_needs_windows_bind_workaround({"amnezia": {}}))

    def test_blank_key_is_not_generation3(self):
        self.assertFalse(
            endpoint_needs_windows_bind_workaround(
                {"amnezia": {"header_protection_key": "  "}}
            )
        )


class TestApplication(unittest.TestCase):
    def test_detour_and_direct_outbound_are_added(self):
        config = {"outbounds": [{"type": "direct", "tag": "direct"}]}
        endpoint = _awg3_endpoint()
        self.assertTrue(ensure_awg3_windows_bind_workaround(config, endpoint))
        self.assertEqual(endpoint["detour"], AWG3_DIRECT_DETOUR_TAG)
        tags = [item["tag"] for item in config["outbounds"]]
        self.assertIn(AWG3_DIRECT_DETOUR_TAG, tags)
        self.assertIn("direct", tags)

    def test_direct_outbound_is_not_duplicated(self):
        config = {"outbounds": []}
        for _ in range(3):
            ensure_awg3_windows_bind_workaround(config, _awg3_endpoint())
        matching = [
            item for item in config["outbounds"] if item["tag"] == AWG3_DIRECT_DETOUR_TAG
        ]
        self.assertEqual(len(matching), 1)

    def test_user_detour_is_preserved(self):
        config = {"outbounds": []}
        endpoint = _awg3_endpoint(detour="my-chain")
        self.assertFalse(ensure_awg3_windows_bind_workaround(config, endpoint))
        self.assertEqual(endpoint["detour"], "my-chain")
        self.assertEqual(config["outbounds"], [])

    def test_awg2_endpoint_is_untouched(self):
        config = {"outbounds": []}
        endpoint = {"amnezia": {"jc": 4}}
        self.assertFalse(ensure_awg3_windows_bind_workaround(config, endpoint))
        self.assertNotIn("detour", endpoint)
        self.assertEqual(config["outbounds"], [])


if __name__ == "__main__":
    unittest.main()
