from __future__ import annotations

import unittest

from xray_fluent.profiles.models import RoutingSettings

LEGACY_DNS_KEYS = (
    "dns_mode",
    "dns_bootstrap_server",
    "dns_bootstrap_type",
    "dns_proxy_server",
    "dns_proxy_type",
)


class RoutingSettingsLegacyDnsKeysTests(unittest.TestCase):
    """DNS живёт в активном JSON sing-box; в настройках приложения его нет."""

    def test_old_state_with_dead_dns_keys_still_loads(self) -> None:
        stored = {
            "mode": "rule",
            "direct_domains": ["example.ru"],
            "tun_default_outbound": "proxy",
            **{key: "builtin" for key in LEGACY_DNS_KEYS},
        }

        routing = RoutingSettings.from_dict(stored)

        self.assertEqual(routing.direct_domains, ["example.ru"])
        self.assertEqual(routing.tun_default_outbound, "proxy")
        for key in LEGACY_DNS_KEYS:
            self.assertFalse(hasattr(routing, key), msg=key)

    def test_settings_no_longer_write_dead_dns_keys(self) -> None:
        written = RoutingSettings().to_dict()

        for key in LEGACY_DNS_KEYS:
            self.assertNotIn(key, written)
        self.assertEqual(RoutingSettings.from_dict(written), RoutingSettings())


if __name__ == "__main__":
    unittest.main()
