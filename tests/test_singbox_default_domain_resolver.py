from __future__ import annotations

import unittest

from xray_fluent.engines.singbox.runtime_planner import (
    _ensure_default_domain_resolver,
    _validate_runtime_dns_contract,
)


def _dns(*tags: str) -> dict:
    return {"dns": {"servers": [{"tag": tag} for tag in tags]}}


class EnsureDefaultDomainResolverTests(unittest.TestCase):
    def test_injects_missing_resolver_preferring_proxy_dns(self) -> None:
        payload = _dns("bootstrap-dns", "proxy-dns")
        _ensure_default_domain_resolver(payload)
        self.assertEqual(payload["route"]["default_domain_resolver"], "proxy-dns")

    def test_falls_back_to_bootstrap_then_first_tag(self) -> None:
        boot = _dns("bootstrap-dns", "other")
        _ensure_default_domain_resolver(boot)
        self.assertEqual(boot["route"]["default_domain_resolver"], "bootstrap-dns")

        custom = _dns("my-dns", "second")
        _ensure_default_domain_resolver(custom)
        self.assertEqual(custom["route"]["default_domain_resolver"], "my-dns")

    def test_keeps_existing_valid_resolver(self) -> None:
        payload = _dns("proxy-dns", "bootstrap-dns")
        payload["route"] = {"default_domain_resolver": "bootstrap-dns"}
        _ensure_default_domain_resolver(payload)
        self.assertEqual(payload["route"]["default_domain_resolver"], "bootstrap-dns")

    def test_replaces_resolver_pointing_at_missing_tag(self) -> None:
        payload = _dns("proxy-dns")
        payload["route"] = {"default_domain_resolver": "ghost-dns"}
        _ensure_default_domain_resolver(payload)
        self.assertEqual(payload["route"]["default_domain_resolver"], "proxy-dns")

    def test_no_dns_servers_leaves_config_untouched(self) -> None:
        payload: dict = {"outbounds": []}
        _ensure_default_domain_resolver(payload)
        self.assertNotIn("route", payload)

    def test_validator_injects_resolver_for_imported_config(self) -> None:
        # An imported config that omits the resolver (works on Android/1.13, fatal
        # on Windows/1.14) must come out of validation with a valid resolver set.
        payload = {
            "dns": {"servers": [{"tag": "proxy-dns"}, {"tag": "bootstrap-dns"}]},
            "outbounds": [{"tag": "proxy", "type": "vless", "server": "example.com"}],
            "route": {"rules": []},
        }
        _validate_runtime_dns_contract(payload)
        self.assertEqual(payload["route"]["default_domain_resolver"], "proxy-dns")


if __name__ == "__main__":
    unittest.main()
