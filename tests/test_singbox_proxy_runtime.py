import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from xray_fluent.engines.singbox.operations import restart_proxy_runtime, restart_runtime
from xray_fluent.engines.singbox.runtime_planner import (
    classify_node_for_singbox,
    parse_singbox_document,
    plan_singbox_proxy_runtime,
    plan_singbox_runtime,
)
from xray_fluent.constants import HYSTERIA_PATH_DEFAULT
from xray_fluent.engines.hysteria.manager import HysteriaManager
from xray_fluent.link_parser import parse_single
from xray_fluent.models import Node


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "data" / "templates" / "sing-box" / "default.json"


class SingboxProxyRuntimeTests(unittest.TestCase):
    def _build_plan(self, link: str):
        document = parse_singbox_document(
            TEMPLATE_PATH,
            TEMPLATE_PATH.read_text(encoding="utf-8"),
        )
        return plan_singbox_proxy_runtime(
            document,
            parse_single(link),
            allowed_proxy_ports={1390, 1391},
        )

    def _restart_controller(self, *, tun: bool):
        node = parse_single("hy2://secret@example.com:443/?insecure=1#one")
        tags = {node.id: "subscription/node"}
        plan = SimpleNamespace(
            used_selected_node=True,
            source_path=TEMPLATE_PATH,
            is_hybrid=False,
            selector_tags=tags,
            socks_port=1390,
            http_port=1391,
            singbox_config={},
            xray_sidecar=None,
            hysteria_sidecar=None,
            is_hysteria_sidecar=False,
            sidecar_kind="",
            proxy_ports_changed=False,
            hybrid_relay_selector_tags=(),
            hybrid_relay_selected_tag="",
        )
        controller = Mock()
        controller.selected_node = node
        controller.connected = True
        controller.state.settings.enable_system_proxy = False
        controller.singbox.is_running = False
        controller.xray.is_running = False
        controller.hysteria.is_running = False
        controller._start_singbox_runtime_plan.return_value = True
        controller._infer_singbox_ping_target.return_value = (node.server, node.port)
        controller._refresh_connected_state.return_value = (True, True)
        if tun:
            controller._plan_runtime_singbox.return_value = plan
        else:
            controller._plan_proxy_runtime_singbox.return_value = plan
        return controller, tags

    def test_proxy_restart_preserves_hot_switch_pool_in_session(self) -> None:
        controller, tags = self._restart_controller(tun=False)

        self.assertTrue(restart_proxy_runtime(controller, "test"))

        self.assertEqual(
            controller._capture_active_session.call_args.kwargs["outbound_pool_tags"],
            tags,
        )

    def test_tun_restart_preserves_hot_switch_pool_in_session(self) -> None:
        controller, tags = self._restart_controller(tun=True)

        self.assertTrue(restart_runtime(controller, "test"))

        self.assertEqual(
            controller._capture_active_session.call_args.kwargs["outbound_pool_tags"],
            tags,
        )

    def test_default_proxy_runtime_replaces_tun_with_public_proxy_inbounds(self) -> None:
        plan = self._build_plan(
            "hy2://secret@example.com:443/?sni=cdn.example.com&insecure=1"
        )

        self.assertEqual(plan.outcome, "hysteria_sidecar")
        self.assertEqual((plan.socks_port, plan.http_port), (1390, 1391))
        self.assertFalse(any(item.get("type") == "tun" for item in plan.singbox_config["inbounds"]))
        self.assertEqual(
            [
                (item.get("type"), item.get("listen"), item.get("listen_port"))
                for item in plan.singbox_config["inbounds"]
            ],
            [
                ("socks", "0.0.0.0", 1390),
                ("http", "0.0.0.0", 1391),
            ],
        )
        proxy = next(item for item in plan.singbox_config["outbounds"] if item.get("tag") == "proxy")
        self.assertEqual(proxy["type"], "socks")
        self.assertIsNotNone(plan.hysteria_sidecar)
        # Порт clash_api подбирается пробным bind'ом (19090 может быть в
        # excluded port range Windows), поэтому проверяем согласованность,
        # а не конкретное значение.
        self.assertGreater(plan.clash_api_port, 0)
        self.assertEqual(
            plan.singbox_config["experimental"]["clash_api"]["external_controller"],
            f"127.0.0.1:{plan.clash_api_port}",
        )

    def test_hysteria2_uses_official_sidecar_without_duplicating_uri_conversion(self) -> None:
        link = (
            "hy2://secret@example.com:443/?obfs=gecko&obfs-password=cover"
            "&pinSHA256=deadbeef&sni=cdn.example.com#Gecko"
        )
        document = parse_singbox_document(
            TEMPLATE_PATH,
            TEMPLATE_PATH.read_text(encoding="utf-8"),
        )
        node = parse_single(link)

        self.assertEqual(classify_node_for_singbox(node), "hysteria_sidecar")
        for plan in (
            plan_singbox_runtime(document, node),
            plan_singbox_proxy_runtime(document, node, allowed_proxy_ports={1390, 1391}),
        ):
            with self.subTest(mode="proxy" if plan.socks_port else "tun"):
                self.assertTrue(plan.is_hysteria_sidecar)
                self.assertIsNone(plan.xray_sidecar)
                self.assertIsNotNone(plan.hysteria_sidecar)
                sidecar = plan.hysteria_sidecar
                assert sidecar is not None
                self.assertEqual(sidecar.config["server"], link)
                self.assertEqual(
                    sidecar.config["socks5"],
                    {
                        "listen": f"127.0.0.1:{sidecar.relay_port}",
                        "username": sidecar.relay_username,
                        "password": sidecar.relay_password,
                        "disableUDP": False,
                    },
                )
                proxy = next(
                    item for item in plan.singbox_config["outbounds"] if item.get("tag") == "proxy"
                )
                self.assertEqual(proxy["type"], "socks")
                self.assertEqual(proxy["server"], "127.0.0.1")
                self.assertEqual(proxy["server_port"], sidecar.relay_port)
                self.assertEqual(proxy["username"], sidecar.relay_username)
                self.assertEqual(proxy["password"], sidecar.relay_password)
                self.assertFalse(
                    any(item.get("type") == "hysteria2" for item in plan.singbox_config["outbounds"])
                )
                rules = plan.singbox_config["route"]["rules"]
                self.assertEqual(
                    rules[0],
                    {
                        "process_path": [str(HYSTERIA_PATH_DEFAULT.resolve())],
                        "outbound": "direct",
                    },
                )

    def test_hysteria2_sidecar_adapts_legacy_uri_aliases_only_at_runtime(self) -> None:
        link = (
            "hy2://user%3Apass@[2001:db8::1]:443/?peer=cover.example"
            "&skip-cert-verify=yes&obfs=salamander&obfs_password=masking"
            "&mport=444,5000-5002&hop_interval=20s&pin_sha256=AA%3ABB"
            "&vendor=a%2Fb#Alias"
        )
        node = parse_single(link)

        plan = self._build_plan(link)
        sidecar = plan.hysteria_sidecar
        assert sidecar is not None

        self.assertEqual(node.link, link)
        self.assertIn("@[2001:db8::1]:444,5000-5002/", sidecar.config["server"])
        self.assertIn("vendor=a%2Fb", sidecar.config["server"])
        self.assertIn("sni=cover.example", sidecar.config["server"])
        self.assertIn("obfs-password=masking", sidecar.config["server"])
        self.assertEqual(
            sidecar.config["tls"],
            {
                "sni": "cover.example",
                "insecure": True,
                "pinSHA256": "AA:BB",
            },
        )
        self.assertEqual(
            sidecar.config["obfs"],
            {"type": "salamander", "salamander": {"password": "masking"}},
        )
        self.assertEqual(
            sidecar.config["transport"],
            {"type": "udp", "udp": {"hopInterval": "20s"}},
        )
        self.assertEqual(sidecar.config["quic"], {"disableChromeParrot": False})

    def test_hysteria2_canonical_sni_wins_without_rewriting_saved_uri(self) -> None:
        link = "hy2://secret@example.com:443/?sni=canonical.example&peer=alias.example"

        plan = self._build_plan(link)
        sidecar = plan.hysteria_sidecar
        assert sidecar is not None

        self.assertEqual(sidecar.config["server"], link)
        self.assertEqual(sidecar.config["tls"]["sni"], "canonical.example")

    def test_hysteria2_empty_sni_uses_nonempty_peer_runtime_alias(self) -> None:
        link = "hy2://secret@example.com:443/?sni=&peer=cover.example"

        plan = self._build_plan(link)
        sidecar = plan.hysteria_sidecar
        assert sidecar is not None

        self.assertEqual(sidecar.config["server"], link)
        self.assertEqual(sidecar.config["tls"]["sni"], "cover.example")

    def test_hysteria2_json_outbound_without_original_uri_stays_native(self) -> None:
        document = parse_singbox_document(
            TEMPLATE_PATH,
            TEMPLATE_PATH.read_text(encoding="utf-8"),
        )
        node = Node(
            scheme="hysteria2",
            server="example.com",
            port=443,
            outbound={
                "type": "hysteria2",
                "server": "example.com",
                "server_port": 443,
                "password": "secret",
                "obfs": {"type": "gecko", "password": "cover"},
            },
        )

        plan = plan_singbox_runtime(document, node)
        self.assertEqual(plan.outcome, "native_singbox")
        self.assertIsNone(plan.hysteria_sidecar)
        proxy = next(item for item in plan.singbox_config["outbounds"] if item.get("tag") == "proxy")
        self.assertEqual(proxy["type"], "hysteria2")

    def test_hysteria_log_redaction_never_exposes_share_uri(self) -> None:
        secret = "hy2://secret@example.com:443/?obfs=gecko&obfs-password=cover"
        redacted = HysteriaManager.redact_log_line(f"failed to use {secret}")
        self.assertNotIn("secret", redacted)
        self.assertNotIn("obfs-password", redacted)

    def test_clash_api_port_self_heals_when_default_is_taken(self) -> None:
        import socket

        from xray_fluent.constants import SINGBOX_CLASH_API_PORT

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
            blocker.bind(("127.0.0.1", SINGBOX_CLASH_API_PORT))
            plan = self._build_plan(
                "hy2://secret@example.com:443/?sni=cdn.example.com&insecure=1"
            )

        self.assertGreater(plan.clash_api_port, SINGBOX_CLASH_API_PORT)
        self.assertEqual(
            plan.singbox_config["experimental"]["clash_api"]["external_controller"],
            f"127.0.0.1:{plan.clash_api_port}",
        )

    def test_extended_core_accepts_new_protocol_proxy_plans(self) -> None:
        core = ROOT / "core" / "sing-box.exe"
        if not core.is_file():
            self.skipTest("bundled sing-box.exe is not present")
        if os.name != "nt" and not shutil.which("wslpath"):
            self.skipTest("Windows sing-box.exe cannot run on this host")

        links = (
            "hy2://secret@example.com:443/?sni=cdn.example.com&insecure=1",
            "hysteria://example.com:8443/?auth=secret&upmbps=50&downmbps=100&insecure=1",
            "tuic://2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365:hello@example.com:443?insecure=1",
            '{"type":"anytls","server":"example.com","server_port":443,'
            '"password":"secret","tls":{"enabled":true,"insecure":true}}',
        )

        for link in links:
            with self.subTest(link=link.split(":", 1)[0]):
                plan = self._build_plan(link)
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    suffix=".json",
                    dir=ROOT,
                    delete=False,
                ) as handle:
                    json.dump(plan.singbox_config, handle)
                    config_path = Path(handle.name)
                try:
                    runtime_path = str(config_path)
                    working_directory = str(core.parent)
                    if os.name != "nt" and shutil.which("wslpath"):
                        runtime_path = subprocess.check_output(
                            ["wslpath", "-w", runtime_path],
                            text=True,
                        ).strip()
                        working_directory = subprocess.check_output(
                            ["wslpath", "-w", working_directory],
                            text=True,
                        ).strip()
                    result = subprocess.run(
                        [
                            str(core),
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
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                finally:
                    config_path.unlink(missing_ok=True)

    def test_xray_only_transport_uses_sidecar_behind_singbox_proxy(self) -> None:
        document = parse_singbox_document(
            TEMPLATE_PATH,
            TEMPLATE_PATH.read_text(encoding="utf-8"),
        )
        node = Node(
            name="XHTTP fallback",
            scheme="vless",
            server="example.com",
            port=443,
            outbound={
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "example.com",
                            "port": 443,
                            "users": [{"id": "11111111-1111-1111-1111-111111111111"}],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": {"serverName": "example.com"},
                    "xhttpSettings": {"path": "/api"},
                },
            },
        )

        plan = plan_singbox_proxy_runtime(
            document,
            node,
            allowed_proxy_ports={1390, 1391},
        )

        self.assertTrue(plan.is_hybrid)
        self.assertIsNotNone(plan.xray_sidecar)
        self.assertEqual((plan.socks_port, plan.http_port), (1390, 1391))
        proxy = next(item for item in plan.singbox_config["outbounds"] if item.get("tag") == "proxy")
        self.assertEqual(proxy["type"], "selector")
        self.assertTrue(proxy["interrupt_exist_connections"])
        self.assertEqual(tuple(proxy["outbounds"]), plan.hybrid_relay_selector_tags)
        relay_outbounds = [
            item
            for item in plan.singbox_config["outbounds"]
            if item.get("tag") in plan.hybrid_relay_selector_tags
        ]
        self.assertEqual(len(relay_outbounds), 2)
        self.assertTrue(all(item["type"] == "socks" for item in relay_outbounds))
        self.assertTrue(
            all(item["server_port"] == plan.xray_sidecar.relay_port for item in relay_outbounds)
        )
        self.assertEqual(plan.xray_sidecar.config["outbounds"][0]["protocol"], "vless")

    def test_xray_sidecar_uses_os_assigned_ports_when_preferred_ranges_are_reserved(self) -> None:
        class ReservedRangeSocket:
            assigned_ports = iter((55000, 55001, 55002))

            def __init__(self, *_args, **_kwargs) -> None:
                self.port = 0

            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def bind(self, address) -> None:
                if int(address[1]) != 0:
                    raise OSError(10013, "Port range is reserved")
                self.port = next(self.assigned_ports)

            def getsockname(self):
                return ("127.0.0.1", self.port)

        document = parse_singbox_document(
            TEMPLATE_PATH,
            TEMPLATE_PATH.read_text(encoding="utf-8"),
        )
        node = parse_single(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443"
            "?type=xhttp&security=tls&sni=example.com&path=%2Fapi#XHTTP"
        )

        with patch(
            "xray_fluent.engines.singbox.runtime_planner.socket.socket",
            side_effect=ReservedRangeSocket,
        ):
            plan = plan_singbox_proxy_runtime(
                document,
                node,
                allowed_proxy_ports={1390, 1391},
            )

        self.assertTrue(plan.is_hybrid)
        self.assertIsNotNone(plan.xray_sidecar)
        self.assertEqual(plan.xray_sidecar.relay_port, 55000)
        self.assertEqual(plan.xray_sidecar.protect_port, 55001)
        self.assertEqual(plan.xray_sidecar.api_port, 55002)

    def test_xray_sidecar_port_failure_is_reported_as_planner_error(self) -> None:
        class UnavailableSocket:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def bind(self, _address) -> None:
                raise OSError(10013, "No local ports available")

        document = parse_singbox_document(
            TEMPLATE_PATH,
            TEMPLATE_PATH.read_text(encoding="utf-8"),
        )
        node = parse_single(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443"
            "?type=xhttp&security=tls&sni=example.com&path=%2Fapi#XHTTP"
        )

        with patch(
            "xray_fluent.engines.singbox.runtime_planner.socket.socket",
            side_effect=UnavailableSocket,
        ), self.assertRaisesRegex(ValueError, "гибридного режима sing-box \\+ Xray"):
            plan_singbox_proxy_runtime(
                document,
                node,
                allowed_proxy_ports={1390, 1391},
            )

    def test_vless_reality_stays_native_in_tun_and_proxy_modes(self) -> None:
        link = (
            "vless://11111111-1111-1111-1111-111111111111@reality.example:8443"
            "?type=tcp&encryption=none&security=reality"
            "&pbk=Ie4ld0x7PvMRA2idLXq58rXRhefsved2eKgqtBtS2Hg"
            "&fp=edge&sni=www.example.com&sid=0123456789abcdef&spx=%2F#Reality"
        )
        document = parse_singbox_document(
            TEMPLATE_PATH,
            TEMPLATE_PATH.read_text(encoding="utf-8"),
        )
        node = parse_single(link)

        self.assertEqual(classify_node_for_singbox(node), "native_singbox")
        self.assertEqual(node.outbound["streamSettings"]["realitySettings"]["spiderX"], "/")

        plans = (
            plan_singbox_runtime(document, node),
            plan_singbox_proxy_runtime(
                document,
                node,
                allowed_proxy_ports={1390, 1391},
            ),
        )
        for plan in plans:
            with self.subTest(mode="proxy" if plan.socks_port else "tun"):
                self.assertEqual(plan.outcome, "native_singbox")
                self.assertIsNone(plan.xray_sidecar)
                proxy = next(
                    item
                    for item in plan.singbox_config["outbounds"]
                    if item.get("tag") == "proxy"
                )
                self.assertEqual(proxy["type"], "vless")
                self.assertEqual(proxy["server"], "reality.example")
                self.assertEqual(proxy["server_port"], 8443)
                self.assertEqual(
                    proxy["tls"],
                    {
                        "enabled": True,
                        "server_name": "www.example.com",
                        "utls": {"enabled": True, "fingerprint": "edge"},
                        "reality": {
                            "enabled": True,
                            "public_key": "Ie4ld0x7PvMRA2idLXq58rXRhefsved2eKgqtBtS2Hg",
                            "short_id": "0123456789abcdef",
                        },
                    },
                )

    def test_vless_encryption_stays_native_in_tun_and_proxy_modes(self) -> None:
        encryption = (
            "mlkem768x25519plus.native.0rtt."
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        link = (
            "vless://11111111-1111-1111-1111-111111111111@reality.example:8443"
            f"?type=tcp&encryption={encryption}&security=reality"
            "&pbk=Ie4ld0x7PvMRA2idLXq58rXRhefsved2eKgqtBtS2Hg"
            "&fp=edge&sni=www.example.com&sid=0123456789abcdef&spx=%2F#Reality"
        )
        document = parse_singbox_document(
            TEMPLATE_PATH,
            TEMPLATE_PATH.read_text(encoding="utf-8"),
        )
        node = parse_single(link)

        user = node.outbound["settings"]["vnext"][0]["users"][0]
        self.assertEqual(user["encryption"], encryption)
        self.assertEqual(classify_node_for_singbox(node), "native_singbox")

        plans = (
            plan_singbox_runtime(document, node),
            plan_singbox_proxy_runtime(
                document,
                node,
                allowed_proxy_ports={1390, 1391},
            ),
        )
        for plan in plans:
            with self.subTest(mode="proxy" if plan.socks_port else "tun"):
                self.assertEqual(plan.outcome, "native_singbox")
                self.assertIsNone(plan.xray_sidecar)
                proxy = next(
                    item
                    for item in plan.singbox_config["outbounds"]
                    if item.get("tag") == "proxy"
                )
                self.assertEqual(proxy["encryption"], encryption)

if __name__ == "__main__":
    unittest.main()
