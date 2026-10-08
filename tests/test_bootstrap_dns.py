from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from xray_fluent.engines.singbox.runtime_planner import (
    parse_singbox_document,
    plan_singbox_runtime,
)
from xray_fluent.importer.link_parser import parse_single
from xray_fluent.network import bootstrap_dns
from xray_fluent.network.bootstrap_dns import (
    CACHE_MAX_AGE_SEC,
    BootstrapCache,
    BootstrapDnsError,
    BootstrapNameNotFound,
    build_query,
    parse_response,
    resolve_bootstrap,
    resolve_doh,
)


ROOT = Path(__file__).resolve().parents[1]
HY2 = "hy2://secret@vpn.example.com:443/?insecure=1&pinSHA256=" + "a" * 64


def _answer(query: bytes, records: list[tuple[int, bytes]], rcode: int = 0) -> bytes:
    header = struct.pack("!HHHHHH", 0, 0x8180 | rcode, 1, len(records), 0, 0)
    body = query[12:]
    for rtype, rdata in records:
        # Имя ответа — указатель сжатия на вопрос (0xC00C), как у реальных резолверов.
        body += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 60, len(rdata)) + rdata
    return header + body


class DnsWireTests(unittest.TestCase):
    def test_query_and_response_round_trip(self) -> None:
        query = build_query("VPN.Example.com.", 1)
        self.assertEqual(query[:2], b"\x00\x00")
        self.assertIn(b"\x03vpn\x07example\x03com\x00", query)
        rcode, addresses = parse_response(
            _answer(query, [(5, b"\xc0\x0c"), (1, bytes([203, 0, 113, 7])), (28, bytes(15) + b"\x01")])
        )
        self.assertEqual(rcode, 0)
        self.assertEqual(addresses, ["203.0.113.7", "::1"])

    def test_nxdomain_and_garbage(self) -> None:
        query = build_query("gone.example.com", 1)
        self.assertEqual(parse_response(_answer(query, [], rcode=3)), (3, []))
        with self.assertRaises(ValueError):
            parse_response(b"\x00\x01")


class ResolveDohTests(unittest.TestCase):
    def test_first_non_empty_answer_wins_and_failures_are_skipped(self) -> None:
        def lookup(server: str, host: str, timeout: float) -> set[str]:
            if server == "bad":
                raise OSError("reset")
            if server == "empty":
                return set()
            return {"203.0.113.7"}

        self.assertEqual(
            resolve_doh("vpn.example.com", servers=("bad", "empty", "good"), lookup=lookup),
            {"203.0.113.7"},
        )

    def test_name_missing_only_when_every_resolver_agrees(self) -> None:
        def missing(server: str, host: str, timeout: float) -> set[str]:
            raise BootstrapNameNotFound(host)

        def mixed(server: str, host: str, timeout: float) -> set[str]:
            if server == "a":
                raise BootstrapNameNotFound(host)
            raise OSError("timeout")

        with self.assertRaises(BootstrapNameNotFound):
            resolve_doh("gone.example.com", servers=("a", "b"), lookup=missing)
        with self.assertRaises(BootstrapDnsError) as caught:
            resolve_doh("vpn.example.com", servers=("a", "b"), lookup=mixed)
        self.assertNotIsInstance(caught.exception, BootstrapNameNotFound)


class ResolveBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "bootstrap-lkg.json"
        bootstrap_dns.configure_cache(self.path)
        self.addCleanup(bootstrap_dns.configure_cache, None)

    @staticmethod
    def _fail(_host: str) -> set[str]:
        raise OSError("unreachable")

    def test_literal_address_needs_no_lookup(self) -> None:
        result = resolve_bootstrap("203.0.113.9", doh=self._fail, system=self._fail)
        self.assertEqual((result.source, set(result.addresses)), ("literal", {"203.0.113.9"}))

    def test_trusted_answer_is_used_and_remembered(self) -> None:
        result = resolve_bootstrap(
            "vpn.example.com", doh=lambda _h: {"203.0.113.7"}, system=lambda _h: {"198.51.100.1"}
        )
        self.assertEqual((result.source, set(result.addresses)), ("doh", {"203.0.113.7"}))
        saved = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(saved["hosts"]["vpn.example.com"]["addresses"], ["203.0.113.7"])

    def test_system_answer_is_used_but_never_remembered(self) -> None:
        result = resolve_bootstrap("vpn.example.com", doh=self._fail, system=lambda _h: {"198.51.100.1"})
        self.assertEqual(result.source, "system")
        self.assertFalse(self.path.exists())

    def test_spoofed_nxdomain_falls_back_to_remembered_address(self) -> None:
        resolve_bootstrap("vpn.example.com", doh=lambda _h: {"203.0.113.7"}, system=self._fail)

        def provider_says_no(_host: str) -> set[str]:
            raise OSError(11001, "getaddrinfo failed")

        result = resolve_bootstrap("vpn.example.com", doh=self._fail, system=provider_says_no)
        self.assertEqual((result.source, set(result.addresses)), ("cache", {"203.0.113.7"}))

    def test_trusted_nxdomain_is_final(self) -> None:
        resolve_bootstrap("vpn.example.com", doh=lambda _h: {"203.0.113.7"}, system=self._fail)

        def gone(host: str) -> set[str]:
            raise BootstrapNameNotFound(host)

        with self.assertRaises(BootstrapNameNotFound):
            resolve_bootstrap("vpn.example.com", doh=gone, system=lambda _h: {"198.51.100.1"})

    def test_nothing_anywhere_raises(self) -> None:
        with self.assertRaises(OSError):
            resolve_bootstrap("vpn.example.com", doh=self._fail, system=self._fail)


class BootstrapCacheTests(unittest.TestCase):
    def test_entries_expire_and_bad_addresses_are_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            now = [1_000_000.0]
            cache = BootstrapCache(Path(directory) / "lkg.json", clock=lambda: now[0])
            cache.remember("VPN.Example.com.", ["203.0.113.7", "2001:db8::1"])
            self.assertEqual(cache.lookup("vpn.example.com"), ["203.0.113.7", "2001:db8::1"])
            now[0] += CACHE_MAX_AGE_SEC + 1
            self.assertEqual(cache.lookup("vpn.example.com"), [])

            (Path(directory) / "lkg.json").write_text(
                json.dumps({"hosts": {"x.example.com": {"addresses": ["0.0.0.0", "nope", "203.0.113.8"],
                                                        "saved_at": now[0]}}}),
                encoding="utf-8",
            )
            self.assertEqual(cache.lookup("x.example.com"), ["203.0.113.8"])

    def test_corrupt_file_is_treated_as_empty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lkg.json"
            path.write_text("{not json", encoding="utf-8")
            cache = BootstrapCache(path)
            self.assertEqual(cache.lookup("vpn.example.com"), [])
            cache.remember("vpn.example.com", ["203.0.113.7"])
            self.assertEqual(cache.lookup("vpn.example.com"), ["203.0.113.7"])


class PlannerBootstrapFallbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "bootstrap-lkg.json"
        self.addCleanup(bootstrap_dns.configure_cache, None)
        template = ROOT / "data" / "templates" / "sing-box" / "default.json"
        self.document = parse_singbox_document(template, template.read_text(encoding="utf-8"))
        # Нативный sing-box-узел с доменным адресом (не hysteria-sidecar).
        self.node = parse_single("trojan://secret@vpn.example.com:443?sni=vpn.example.com")

    def _plan(self) -> dict:
        return plan_singbox_runtime(self.document, self.node).singbox_config

    @staticmethod
    def _proxy(config: dict) -> dict:
        return next(o for o in config["outbounds"] if o.get("tag") == "proxy")

    def test_without_remembered_address_the_stock_chain_is_used(self) -> None:
        bootstrap_dns.configure_cache(self.path)
        config = self._plan()
        self.assertEqual(self._proxy(config)["domain_resolver"], "bootstrap-dns")
        tags = {server["tag"] for server in config["dns"]["servers"]}
        self.assertNotIn("app-bootstrap-lkg", tags)

    def test_remembered_address_backs_the_trusted_chain_without_system_dns(self) -> None:
        BootstrapCache(self.path).remember("vpn.example.com", ["203.0.113.7"])
        bootstrap_dns.configure_cache(self.path)
        config = self._plan()
        servers = {server["tag"]: server for server in config["dns"]["servers"]}

        self.assertEqual(self._proxy(config)["domain_resolver"], "app-node-bootstrap")
        self.assertEqual(servers["app-node-bootstrap"]["servers"], ["direct-doh", "app-bootstrap-lkg"])
        self.assertEqual(servers["app-node-bootstrap"]["strategy"], "sequential")
        self.assertEqual(servers["app-bootstrap-lkg"]["type"], "hosts")
        self.assertEqual(servers["app-bootstrap-lkg"]["predefined"], {"vpn.example.com": ["203.0.113.7"]})
        # Пользовательская цепочка не тронута.
        self.assertEqual(servers["bootstrap-dns"]["servers"], ["direct-doh", "local-system-dns"])

    def test_plan_is_stable_while_the_cache_is_refreshed_in_the_background(self) -> None:
        bootstrap_dns.configure_cache(self.path)
        first = self._plan()
        BootstrapCache(self.path).remember("vpn.example.com", ["203.0.113.7"])
        second = self._plan()
        # Имя TUN и порты случайны в каждом плане; сравниваем то, чем владеет DNS.
        self.assertEqual(second["dns"], first["dns"])
        self.assertEqual(self._proxy(second)["domain_resolver"], "bootstrap-dns")

    def test_config_without_trusted_chain_keeps_the_stock_resolver(self) -> None:
        BootstrapCache(self.path).remember("vpn.example.com", ["203.0.113.7"])
        bootstrap_dns.configure_cache(self.path)
        payload = json.loads(self.document.text)
        for server in payload["dns"]["servers"]:
            if server["tag"] == "direct-doh":
                server["tag"] = "my-doh"
            if server["tag"] == "bootstrap-dns":
                server["servers"] = ["my-doh", "local-system-dns"]
        document = parse_singbox_document(self.document.source_path, json.dumps(payload))
        config = plan_singbox_runtime(document, self.node).singbox_config
        self.assertEqual(self._proxy(config)["domain_resolver"], "bootstrap-dns")


class HybridAndAmneziaBootstrapTests(unittest.TestCase):
    """Гибридный режим и WG/AWG получают тот же доверенный путь, что и узел."""

    VLESS = (
        "vless://11111111-1111-1111-1111-111111111111@vless.example.com:443"
        "?type=xhttp&security=tls&sni=vless.example.com&path=%2F#hybrid"
    )

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "bootstrap-lkg.json"
        self.addCleanup(bootstrap_dns.configure_cache, None)
        template = ROOT / "data" / "templates" / "sing-box" / "default.json"
        self.document = parse_singbox_document(template, template.read_text(encoding="utf-8"))

    def _hybrid_plan(self):
        node = parse_single(self.VLESS)
        plan = plan_singbox_runtime(self.document, node)
        self.assertEqual(plan.outcome, "hybrid_xray_sidecar")
        return plan.singbox_config

    @staticmethod
    def _resolve_rules(config: dict) -> list[dict]:
        return [rule for rule in config["route"]["rules"] if rule.get("action") == "resolve"]

    def test_hybrid_without_remembered_address_adds_nothing(self) -> None:
        bootstrap_dns.configure_cache(self.path)
        self.assertEqual(self._resolve_rules(self._hybrid_plan()), [])

    def test_hybrid_server_resolves_through_the_trusted_chain(self) -> None:
        BootstrapCache(self.path).remember("vless.example.com", ["203.0.113.9"])
        bootstrap_dns.configure_cache(self.path)
        config = self._hybrid_plan()
        rules = config["route"]["rules"]
        protect = ["__app_hybrid_protect_in"]

        resolve = self._resolve_rules(config)
        self.assertEqual(
            resolve,
            [{"inbound": protect, "domain": ["vless.example.com"], "action": "resolve",
              "server": "app-node-bootstrap"}],
        )
        # resolve стоит перед правилом, отправляющим protect-inbound в direct:
        # иначе соединение ушло бы раньше, чем имя разрешится.
        self.assertLess(rules.index(resolve[0]), rules.index({"inbound": protect, "outbound": "direct"}))
        servers = {server["tag"]: server for server in config["dns"]["servers"]}
        self.assertEqual(servers["app-bootstrap-lkg"]["predefined"], {"vless.example.com": ["203.0.113.9"]})
        # Резолвер общего direct не тронут: он служит всем прямым доменам.
        direct = next(o for o in config["outbounds"] if o.get("tag") == "direct")
        self.assertEqual(direct["domain_resolver"], "bootstrap-dns")

    def test_amnezia_peer_name_is_replaced_before_the_core_starts(self) -> None:
        from unittest.mock import patch

        from xray_fluent.application.async_steps import run_steps_blocking
        from xray_fluent.engines.amnezia import manager

        payload = {"endpoint": {"peers": [
            {"address": "wg.example.com", "port": 51820},
            {"address": "203.0.113.5", "port": 51820},
            {"address": "dead.example.com", "port": 51820},
        ]}}

        def lookup(host: str) -> bootstrap_dns.BootstrapResolution:
            if host == "dead.example.com":
                raise OSError("no answer anywhere")
            return bootstrap_dns.BootstrapResolution(frozenset({"2001:db8::7", "203.0.113.7"}), "doh")

        with (
            patch.object(manager, "resolve_bootstrap", side_effect=lookup) as resolver,
            patch.object(manager, "register_server_aliases") as aliases,
        ):
            run_steps_blocking(manager.resolve_peers_steps(payload))

        peers = payload["endpoint"]["peers"]
        # IPv4 предпочитается: по нему ищется физический интерфейс.
        self.assertEqual(peers[0]["address"], "203.0.113.7")
        self.assertEqual(peers[1]["address"], "203.0.113.5")
        # Не удалось — имя остаётся, ядро делает прежнюю попытку само.
        self.assertEqual(peers[2]["address"], "dead.example.com")
        self.assertEqual([call.args[0] for call in resolver.call_args_list], ["wg.example.com", "dead.example.com"])
        aliases.assert_called_once()


class DiagnosticsTests(unittest.TestCase):
    def test_system_denial_is_told_apart_from_unreachable_dns(self) -> None:
        import socket

        def denies(*_args, **_kwargs):
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

        def windows_denies(*_args, **_kwargs):
            raise socket.gaierror(11001, "getaddrinfo failed")

        def unreachable(*_args, **_kwargs):
            raise socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")

        self.assertTrue(bootstrap_dns.system_denies_name("vpn.example.com", denies))
        self.assertTrue(bootstrap_dns.system_denies_name("vpn.example.com", windows_denies))
        self.assertFalse(bootstrap_dns.system_denies_name("vpn.example.com", unreachable))
        self.assertFalse(bootstrap_dns.system_denies_name("vpn.example.com", lambda *_a, **_k: [("ok",)]))

    def test_tampering_is_reported_once_per_session(self) -> None:
        seen: list[str] = []
        bootstrap_dns.set_tampering_listener(seen.append)
        self.addCleanup(bootstrap_dns.set_tampering_listener, None)
        bootstrap_dns._report_tampering("vpn.example.com")
        bootstrap_dns._report_tampering("other.example.com")
        self.assertEqual(seen, ["vpn.example.com"])

    def test_startup_notices_are_shown_once(self) -> None:
        from xray_fluent.application import startup_notices

        startup_notices.drain()
        startup_notices.add("warning", "раздел DNS изменён")
        startup_notices.add("warning", "раздел DNS изменён")
        self.assertEqual(startup_notices.drain(), [("warning", "раздел DNS изменён")])
        self.assertEqual(startup_notices.drain(), [])


if __name__ == "__main__":
    unittest.main()
