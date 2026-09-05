import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest

from PyQt6.QtCore import QCoreApplication

from xray_fluent.network import ping_worker
from xray_fluent.network import speed_test_worker
from xray_fluent.engines.singbox.config_builder import (
    is_singbox_endpoint_node,
    is_singbox_endpoint_outbound,
)
from xray_fluent.engines.singbox.runtime_planner import (
    classify_node_for_singbox,
    inspect_singbox_document_text,
    parse_singbox_document,
    plan_singbox_proxy_runtime,
    plan_singbox_runtime,
)
from xray_fluent.importer.link_parser import (
    parse_links_text,
    parse_single,
    validate_node_outbound,
)
from xray_fluent.profiles.models import Node


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "data" / "templates" / "sing-box" / "default.json"
SINGBOX_CORE = ROOT / "core" / "sing-box.exe"

_APP = QCoreApplication.instance() or QCoreApplication([])


FIXTURE_WG_CONF = """# my-wg-node
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.66.66.2/32, fd42:42:42::2/128
DNS = 1.1.1.1
MTU = 1380

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
PresharedKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=
Endpoint = wg.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""

FIXTURE_AWG_CONF = """[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.8.1.5/32
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 68
S2 = 149
H1 = 1004746675
H2 = 9077-9177
H3 = 4
H4 = 1234567890
I1 = <b 0xf6ab5b>

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.10:41820
AllowedIPs = 0.0.0.0/0
"""

FIXTURE_WG_CONF_PRIVATE_DNS = """[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.66.66.2/32
DNS = 10.64.0.1

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = wg.example.com:51820
AllowedIPs = 0.0.0.0/0
"""

FIXTURE_WG_CONF_PUBLIC_DNS = """[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.88.0.2/32
DNS = 9.9.9.9, 8.8.4.4, 1.1.1.1

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 198.51.100.7:51830
AllowedIPs = 0.0.0.0/0
"""

FIXTURE_WG_CONF_NO_DNS_NO_ADDRESS = """[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = wg.example.com:51820
AllowedIPs = 0.0.0.0/0
"""

FIXTURE_WG_ENDPOINT_JSON = (
    '{"endpoints": [{"type": "wireguard", "tag": "wg-json", "address": ["10.0.0.2/32"], '
    '"private_key": "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=", '
    '"peers": [{"address": "198.51.100.7", "port": 51820, '
    '"public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", '
    '"allowed_ips": ["0.0.0.0/0"]}]}]}'
)


def _load_module_by_path(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_runtime_introspection():
    path = ROOT / "xray_fluent" / "application" / "runtime_introspection.py"
    return _load_module_by_path("app_runtime_introspection", path)


def _load_node_service():
    # Пакет xray_fluent.application не импортируется под WSL (win_proc_monitor →
    # ctypes.windll), поэтому подменяем пакет пустым модулем и грузим node_service
    # по файлу с полным именем, чтобы работали относительные импорты.
    pkg_name = "xray_fluent.application"
    if pkg_name not in sys.modules:
        import xray_fluent  # noqa: F401

        package = types.ModuleType(pkg_name)
        package.__path__ = [str(ROOT / "xray_fluent" / "application")]
        sys.modules[pkg_name] = package
    path = ROOT / "xray_fluent" / "application" / "node_service.py"
    return _load_module_by_path(f"{pkg_name}.node_service", path)


def _parse_wg_node() -> Node:
    nodes, errors = parse_links_text(FIXTURE_WG_CONF)
    assert errors == []
    return nodes[0]


def _parse_awg_node() -> Node:
    nodes, errors = parse_links_text(FIXTURE_AWG_CONF)
    assert errors == []
    return nodes[0]


def _run_singbox_check(config: dict) -> subprocess.CompletedProcess:
    if os.name != "nt" and not shutil.which("wslpath"):
        raise unittest.SkipTest("Windows sing-box.exe cannot run on this host")
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=".json",
        dir=ROOT,
        delete=False,
    ) as handle:
        json.dump(config, handle)
        config_path = Path(handle.name)
    try:
        runtime_path = str(config_path)
        working_directory = str(SINGBOX_CORE.parent)
        if os.name != "nt" and shutil.which("wslpath"):
            runtime_path = subprocess.check_output(
                ["wslpath", "-w", runtime_path],
                text=True,
            ).strip()
            working_directory = subprocess.check_output(
                ["wslpath", "-w", working_directory],
                text=True,
            ).strip()
        return subprocess.run(
            [
                str(SINGBOX_CORE),
                "check",
                "-D",
                working_directory,
                "-c",
                runtime_path,
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
    finally:
        config_path.unlink(missing_ok=True)


class WireguardConfParsingTests(unittest.TestCase):
    def test_ac1_parses_plain_wireguard_conf(self) -> None:
        nodes, errors = parse_links_text(FIXTURE_WG_CONF)

        self.assertEqual(errors, [])
        self.assertEqual(len(nodes), 1)
        node = nodes[0]
        self.assertEqual(node.scheme, "wireguard")
        self.assertEqual(node.server, "wg.example.com")
        self.assertEqual(node.port, 51820)
        self.assertEqual(node.name, "my-wg-node")
        self.assertEqual(node.link, FIXTURE_WG_CONF)

        outbound = node.outbound
        self.assertEqual(outbound["type"], "wireguard")
        self.assertEqual(outbound["address"], ["10.66.66.2/32", "fd42:42:42::2/128"])
        self.assertEqual(outbound["private_key"], "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=")
        self.assertEqual(outbound["mtu"], 1380)
        self.assertIsInstance(outbound["mtu"], int)
        self.assertNotIn("dns", outbound)

        peers = outbound["peers"]
        self.assertEqual(len(peers), 1)
        peer = peers[0]
        self.assertEqual(peer["public_key"], "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=")
        self.assertEqual(peer["pre_shared_key"], "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=")
        self.assertEqual(peer["address"], "wg.example.com")
        self.assertEqual(peer["port"], 51820)
        self.assertIsInstance(peer["port"], int)
        self.assertEqual(peer["allowed_ips"], ["0.0.0.0/0", "::/0"])
        self.assertEqual(peer["persistent_keepalive_interval"], 25)
        self.assertIsInstance(peer["persistent_keepalive_interval"], int)
        self.assertNotIn("server", peer)
        self.assertNotIn("server_port", peer)
        self.assertNotIn("endpoint", peer)

    def test_ac2_parses_awg_conf_with_amnezia_types(self) -> None:
        nodes, errors = parse_links_text(FIXTURE_AWG_CONF)

        self.assertEqual(errors, [])
        self.assertEqual(len(nodes), 1)
        node = nodes[0]
        self.assertEqual(node.scheme, "awg")
        self.assertEqual(node.server, "203.0.113.10")
        self.assertEqual(node.port, 41820)
        self.assertEqual(node.name, "awg-203.0.113.10:41820")

        amnezia = node.outbound["amnezia"]
        self.assertEqual(amnezia["jc"], 5)
        self.assertIsInstance(amnezia["jc"], int)
        self.assertEqual(amnezia["jmin"], 50)
        self.assertIsInstance(amnezia["jmin"], int)
        self.assertEqual(amnezia["jmax"], 1000)
        self.assertIsInstance(amnezia["jmax"], int)
        self.assertEqual(amnezia["s1"], 68)
        self.assertIsInstance(amnezia["s1"], int)
        self.assertEqual(amnezia["s2"], 149)
        self.assertIsInstance(amnezia["s2"], int)
        self.assertEqual(amnezia["h1"], 1004746675)
        self.assertIsInstance(amnezia["h1"], int)
        self.assertEqual(amnezia["h2"], "9077-9177")
        self.assertIsInstance(amnezia["h2"], str)
        self.assertEqual(amnezia["h3"], 4)
        self.assertIsInstance(amnezia["h3"], int)
        self.assertEqual(amnezia["h4"], 1234567890)
        self.assertIsInstance(amnezia["h4"], int)
        self.assertEqual(amnezia["i1"], "<b 0xf6ab5b>")
        self.assertIsInstance(amnezia["i1"], str)

    def test_ac3_multiline_conf_is_not_split_per_line(self) -> None:
        nodes, errors = parse_links_text(FIXTURE_WG_CONF)
        self.assertEqual(errors, [])
        self.assertEqual(len(nodes), 1)

        padded = "\n\n" + FIXTURE_WG_CONF + "\n\n"
        padded_nodes, padded_errors = parse_links_text(padded)
        self.assertEqual(padded_errors, [])
        self.assertEqual(len(padded_nodes), 1)
        self.assertEqual(padded_nodes[0].scheme, nodes[0].scheme)
        self.assertEqual(padded_nodes[0].server, nodes[0].server)
        self.assertEqual(padded_nodes[0].port, nodes[0].port)
        self.assertEqual(padded_nodes[0].name, nodes[0].name)
        self.assertEqual(padded_nodes[0].outbound, nodes[0].outbound)

    def test_ac4_json_endpoint_import(self) -> None:
        nodes, errors = parse_links_text(FIXTURE_WG_ENDPOINT_JSON)
        self.assertEqual(errors, [])
        self.assertEqual(len(nodes), 1)
        node = nodes[0]
        self.assertEqual(node.server, "198.51.100.7")
        self.assertEqual(node.port, 51820)
        self.assertEqual(node.outbound["type"], "wireguard")

        inner = json.loads(FIXTURE_WG_ENDPOINT_JSON)["endpoints"][0]
        single = parse_single(json.dumps(inner))
        self.assertEqual(single.server, "198.51.100.7")
        self.assertEqual(single.port, 51820)
        self.assertEqual(single.outbound["type"], "wireguard")

    def test_ac5_wireguard_validation(self) -> None:
        node = _parse_wg_node()
        self.assertIsNone(validate_node_outbound(node))

        no_key = Node(name="wg", outbound={"type": "wireguard", "peers": node.outbound["peers"]})
        problem = validate_node_outbound(no_key)
        self.assertTrue(problem)
        self.assertIn("private_key", problem)

        no_peers = Node(
            name="wg",
            outbound={"type": "wireguard", "private_key": "x", "peers": []},
        )
        self.assertTrue(validate_node_outbound(no_peers))
        missing_peers = Node(name="wg", outbound={"type": "wireguard", "private_key": "x"})
        self.assertTrue(validate_node_outbound(missing_peers))

        bad_peer = Node(
            name="wg",
            outbound={
                "type": "wireguard",
                "private_key": "x",
                "peers": [{"address": "1.2.3.4", "port": 51820}],
            },
        )
        problem = validate_node_outbound(bad_peer)
        self.assertTrue(problem)
        self.assertIn("public_key", problem)

        bad_amnezia = Node(
            name="wg",
            outbound={
                "type": "wireguard",
                "private_key": "x",
                "peers": [
                    {"address": "1.2.3.4", "port": 51820, "public_key": "pk"}
                ],
                "amnezia": {"jc": "abc"},
            },
        )
        problem = validate_node_outbound(bad_amnezia)
        self.assertTrue(problem)
        self.assertIn("jc", problem)


class WireguardRuntimePlannerTests(unittest.TestCase):
    def _document(self):
        return parse_singbox_document(
            TEMPLATE_PATH,
            TEMPLATE_PATH.read_text(encoding="utf-8"),
        )

    def test_ac6_classification(self) -> None:
        self.assertEqual(classify_node_for_singbox(_parse_wg_node()), "amnezia_sidecar")
        self.assertEqual(classify_node_for_singbox(_parse_awg_node()), "amnezia_sidecar")
        self.assertNotEqual(classify_node_for_singbox(_parse_wg_node()), "hybrid_xray_sidecar")
        self.assertTrue(is_singbox_endpoint_node(_parse_awg_node()))
        self.assertTrue(is_singbox_endpoint_outbound(_parse_wg_node().outbound))

        vless = parse_single(
            "vless://2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365@example.com:443"
            "?type=tcp&security=tls#Regression"
        )
        self.assertEqual(classify_node_for_singbox(vless), "hybrid_xray_sidecar")
        hy2 = parse_single("hy2://secret@example.com:443/?sni=cdn.example.com&insecure=1&pinSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        self.assertEqual(classify_node_for_singbox(hy2), "hysteria_sidecar")

    def _assert_endpoint_plan(self, plan, *, expect_amnezia: bool) -> None:
        self.assertFalse(plan.singbox_config.get("endpoints"))
        self.assertEqual(plan.outcome, "amnezia_sidecar")
        self.assertEqual(plan.sidecar_kind, "amnezia")
        endpoint = plan.amnezia_sidecar.config["endpoint"]
        if expect_amnezia:
            self.assertEqual(endpoint["amnezia"]["h2"], "9077-9177")
        else:
            self.assertNotIn("amnezia", endpoint)
        proxy = next(item for item in plan.singbox_config["outbounds"] if item.get("tag") == "proxy")
        self.assertEqual(proxy["type"], "socks")
        self.assertEqual(proxy["server"], "127.0.0.1")
        self.assertGreaterEqual(len(proxy["password"]), 32)
        self.assertEqual(plan.singbox_config["route"]["final"], "proxy")

    def test_ac7_tun_plan_injects_endpoint_and_passes_check(self) -> None:
        for node, expect_amnezia in ((_parse_awg_node(), True), (_parse_wg_node(), False)):
            with self.subTest(scheme=node.scheme):
                plan = plan_singbox_runtime(self._document(), node)
                self._assert_endpoint_plan(plan, expect_amnezia=expect_amnezia)
                if not SINGBOX_CORE.is_file():
                    self.skipTest("bundled sing-box.exe is not present")
                result = _run_singbox_check(plan.singbox_config)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_ac8_proxy_plan_injects_endpoint_and_passes_check(self) -> None:
        for node, expect_amnezia in ((_parse_awg_node(), True), (_parse_wg_node(), False)):
            with self.subTest(scheme=node.scheme):
                plan = plan_singbox_proxy_runtime(
                    self._document(),
                    node,
                    allowed_proxy_ports={1390, 1391},
                )
                self._assert_endpoint_plan(plan, expect_amnezia=expect_amnezia)
                self.assertEqual((plan.socks_port, plan.http_port), (1390, 1391))
                self.assertEqual(
                    [
                        (item.get("type"), item.get("listen_port"))
                        for item in plan.singbox_config["inbounds"]
                        if item.get("type") in {"mixed", "http"}
                    ],
                    [("mixed", 1390), ("http", 1391)],
                )
                if not SINGBOX_CORE.is_file():
                    self.skipTest("bundled sing-box.exe is not present")
                result = _run_singbox_check(plan.singbox_config)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_ac9_proxy_endpoint_scan_and_introspection(self) -> None:
        document = {
            "endpoints": [
                {
                    "type": "wireguard",
                    "tag": "proxy",
                    "address": ["10.0.0.2/32"],
                    "private_key": "x",
                    "peers": [
                        {"address": "198.51.100.7", "port": 51820, "public_key": "pk"}
                    ],
                }
            ],
            "outbounds": [{"type": "direct", "tag": "direct"}],
        }
        state = inspect_singbox_document_text(TEMPLATE_PATH, json.dumps(document))
        self.assertTrue(state.has_proxy_outbound)

        introspection = _load_runtime_introspection()
        endpoint = json.loads(FIXTURE_WG_ENDPOINT_JSON)["endpoints"][0]
        self.assertEqual(
            introspection.infer_singbox_outbound_endpoint(endpoint),
            ("198.51.100.7", 51820),
        )
        self.assertEqual(
            introspection.infer_singbox_ping_target(document, None),
            ("198.51.100.7", 51820),
        )


class WireguardWorkerSafetyTests(unittest.TestCase):
    def test_ac10_ping_never_kills_endpoint_nodes(self) -> None:
        node = _parse_wg_node()
        self.assertIsNone(node.is_alive)

        original_tcp_ping = ping_worker.tcp_ping

        def _forbidden(*args, **kwargs):
            raise AssertionError("tcp_ping must not be called for endpoint nodes")

        ping_worker.tcp_ping = _forbidden
        try:
            ping_ms = ping_worker.ping_node(node)
            ping_worker.apply_ping_measurement(node, ping_ms)
        finally:
            ping_worker.tcp_ping = original_tcp_ping

        self.assertIsNone(node.ping_ms)
        self.assertIsNot(node.is_alive, False)

        # Регрессия: обычная нода с неудачным пингом по-прежнему помечается.
        plain = Node(name="plain", server="example.com", port=443)
        ping_worker.apply_ping_measurement(plain, None)
        self.assertIs(plain.is_alive, False)

    def test_ac11_speed_test_skips_endpoint_nodes_gracefully(self) -> None:
        node = _parse_wg_node()
        skip, message = speed_test_worker.should_skip_speed_test(node)
        self.assertTrue(skip)
        self.assertIn("пропущен", message)

        vless = parse_single(
            "vless://2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365@example.com:443"
            "?type=tcp&security=tls#Regression"
        )
        self.assertEqual(speed_test_worker.should_skip_speed_test(vless), (False, ""))

        original_builder = speed_test_worker.build_xray_config

        def _forbidden(*args, **kwargs):
            raise AssertionError("build_xray_config must not be called for endpoint nodes")

        speed_test_worker.build_xray_config = _forbidden
        skipped: list[tuple[str, str]] = []
        try:
            worker = speed_test_worker.SpeedTestWorker([node], xray_path="missing-xray.exe")
            worker.skipped.connect(lambda node_id, msg: skipped.append((node_id, msg)))
            worker.run()
        finally:
            speed_test_worker.build_xray_config = original_builder

        self.assertEqual(worker.completed_nodes, 1)
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0][0], node.id)
        self.assertIn("пропущен", skipped[0][1])
        self.assertIsNot(node.is_alive, False)


class _StubSignal:
    def emit(self, *args, **kwargs) -> None:
        return None


class _StubState:
    def __init__(self) -> None:
        self.nodes: list[Node] = []
        self.selected_node_id: str | None = None


class _StubController:
    def __init__(self) -> None:
        self.state = _StubState()
        self.nodes_changed = _StubSignal()
        self.selection_changed = _StubSignal()
        self.selected_node = None
        self._desired_connected = False

    def save(self) -> None:
        return None

    def _start_country_ip_resolution(self) -> None:
        return None

    def _request_transition(self, reason: str) -> None:
        return None


class WireguardDedupTests(unittest.TestCase):
    def test_ac12_empty_links_are_not_deduplicated(self) -> None:
        node_service = _load_node_service()
        controller = _StubController()

        first = Node(
            name="json-a",
            scheme="anytls",
            server="a.example.com",
            port=443,
            link="",
            outbound={"type": "anytls", "server": "a.example.com", "server_port": 443, "password": "a"},
        )
        second = Node(
            name="json-b",
            scheme="anytls",
            server="b.example.com",
            port=443,
            link="",
            outbound={"type": "anytls", "server": "b.example.com", "server_port": 443, "password": "b"},
        )

        original_parse = node_service.parse_links_text
        node_service.parse_links_text = lambda text: ([first, second], [])
        try:
            added, errors = node_service.import_nodes_from_text(controller, "two native json outbounds")
        finally:
            node_service.parse_links_text = original_parse

        self.assertEqual(errors, [])
        self.assertEqual(added, 2)
        self.assertEqual(len(controller.state.nodes), 2)

    def test_ac12_wireguard_conf_reimport_is_deduplicated(self) -> None:
        node_service = _load_node_service()
        controller = _StubController()

        added, errors = node_service.import_nodes_from_text(controller, FIXTURE_WG_CONF)
        self.assertEqual(errors, [])
        self.assertEqual(added, 1)

        added_again, errors_again = node_service.import_nodes_from_text(controller, FIXTURE_WG_CONF)
        self.assertEqual(errors_again, [])
        self.assertEqual(added_again, 0)
        self.assertEqual(len(controller.state.nodes), 1)


class WireguardDnsPreservationTests(unittest.TestCase):
    def test_user_dns_and_rules_survive_every_imported_profile(self):
        for fixture in (FIXTURE_WG_CONF_PRIVATE_DNS, FIXTURE_WG_CONF_PUBLIC_DNS,
                        FIXTURE_WG_ENDPOINT_JSON, FIXTURE_WG_CONF_NO_DNS_NO_ADDRESS):
            nodes, errors = parse_links_text(fixture)
            self.assertEqual(errors, [])
            raw = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
            before = json.loads(json.dumps(raw))
            for planner in (plan_singbox_runtime, plan_singbox_proxy_runtime):
                plan = planner(parse_singbox_document(TEMPLATE_PATH, json.dumps(raw)), nodes[0])
                self.assertEqual(raw, before)
                self.assertEqual(plan.singbox_config["dns"], raw["dns"])
                self.assertEqual(plan.singbox_config["route"]["rules"][1:], raw["route"]["rules"])
                self.assertNotIn("_dns", plan.amnezia_sidecar.config["endpoint"])
                self.assertNotIn("awg3-direct", json.dumps(plan.singbox_config))

    def test_amnezia_does_not_guess_a_gateway(self):
        raw = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
        plan = plan_singbox_runtime(parse_singbox_document(TEMPLATE_PATH, json.dumps(raw)), _parse_awg_node())
        self.assertEqual(plan.singbox_config["dns"], raw["dns"])
        self.assertNotIn("10.8.1.1", json.dumps(plan.singbox_config))
        dns_inbound = next(i for i in plan.singbox_config["inbounds"] if i.get("tag") == "__app_amnezia_dns")
        self.assertEqual(dns_inbound["listen"], "127.0.0.1")
        self.assertEqual(plan.amnezia_sidecar.config["dns_address"], f"127.0.0.1:{dns_inbound['listen_port']}")

    def test_import_keeps_explicit_dns_metadata_without_changing_active_json(self):
        node = parse_links_text(FIXTURE_WG_CONF_PUBLIC_DNS)[0][0]
        self.assertEqual(node.outbound["_dns"], ["9.9.9.9", "8.8.4.4", "1.1.1.1"])

    def test_non_endpoint_plans_keep_dns(self):
        node = parse_single("vless://2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365@example.com:443?type=tcp&security=tls")
        raw = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
        plan = plan_singbox_runtime(parse_singbox_document(TEMPLATE_PATH, json.dumps(raw)), node)
        self.assertEqual(plan.singbox_config["dns"], raw["dns"])


class AwgOddHexValidationTests(unittest.TestCase):
    """FAC5 — фикс P2: нечётная hex-длина в I1..I5/J1..J3 (problems.md)."""

    def _awg_node(self, **amnezia_overrides) -> Node:
        amnezia = {"jc": 5, "jmin": 50, "jmax": 1000}
        amnezia.update(amnezia_overrides)
        return Node(
            name="awg",
            outbound={
                "type": "wireguard",
                "private_key": "x",
                "peers": [{"address": "1.2.3.4", "port": 51820, "public_key": "pk"}],
                "amnezia": amnezia,
            },
        )

    def test_fac5_odd_hex_length_is_rejected(self) -> None:
        problem = validate_node_outbound(self._awg_node(i1="<b 0xf6ab5>"))
        self.assertEqual(problem, "AWG: нечётное число hex-символов в I1.")

        # j1-j3 удалены из схемы amnezia ядра 2.6.x: любое значение —
        # неподдерживаемый ключ ещё до проверки hex-тегов.
        problem = validate_node_outbound(
            self._awg_node(j2="<b 0xaa><b 0xbbb>")
        )
        self.assertIsNotNone(problem)
        self.assertIn("не поддерживается ядром", problem)

    def test_fac5_even_or_absent_hex_passes(self) -> None:
        self.assertIsNone(validate_node_outbound(self._awg_node(i1="<b 0xf6ab5b>")))
        self.assertIsNone(validate_node_outbound(self._awg_node()))
        # Значение без <b 0x...> тегов не трогаем.
        self.assertIsNone(validate_node_outbound(self._awg_node(i2="<c 100-500>")))
        # Конф из спеки (чётный hex) остаётся валидным.
        self.assertIsNone(validate_node_outbound(_parse_awg_node()))

    def test_fac5_odd_hex_from_conf_import(self) -> None:
        conf = FIXTURE_AWG_CONF.replace("I1 = <b 0xf6ab5b>", "I1 = <b 0xf6ab5>")
        nodes, errors = parse_links_text(conf)
        self.assertEqual(errors, [])
        problem = validate_node_outbound(nodes[0])
        self.assertEqual(problem, "AWG: нечётное число hex-символов в I1.")


class WireguardRegressionTests(unittest.TestCase):
    def test_ac13_existing_schemes_still_parse(self) -> None:
        links = (
            "vless://2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365@example.com:443?type=tcp&security=tls#V",
            "trojan://secret@example.com:443?security=tls#T",
            "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388#S",
            "hy2://secret@example.com:443/?sni=cdn.example.com&insecure=1&pinSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa#H",
        )
        expected = {"vless", "trojan", "ss", "hysteria2"}
        parsed = {parse_single(link).scheme for link in links}
        self.assertEqual(parsed, expected)


if __name__ == "__main__":
    unittest.main()
