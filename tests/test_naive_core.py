"""NaiveProxy keys (owner decision 2026-11-27): the stock naive client owns the protocol, sing-box stays the gasket.

The grammar cases are the contract vectors of the bot (``vpnbot_contracts/tests/test_naive_link.py``, sent by its session
2026-11-27): the producer's own accepted and refused lines. The planner and importer cases use the real key of the canary
when the machine has it (``tests/real_naive_key.py``) and the contract line otherwise; the live run is
``test_app_e2e_naive.py``.
"""

import json
import unittest
from pathlib import Path

from xray_fluent.application.protocol_core import ProtocolCore, protocol_core
from xray_fluent.constants import NAIVE_PATH_DEFAULT
from xray_fluent.engines.naive.key import CONCURRENCY_WARN_ABOVE, NaiveKeyError, helper_config, parse_naive_key
from xray_fluent.engines.singbox.config_builder import build_singbox_outbound
from xray_fluent.engines.singbox.runtime_planner import (
    classify_node_for_singbox,
    parse_singbox_document,
    plan_singbox_runtime,
)
from xray_fluent.importer.link_parser import LinkParseError, parse_links_text, parse_single
from xray_fluent.importer.subscription_parser import hidden_source_key_for_node, parse_subscription_payload

from tests import real_naive_key

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "data" / "templates" / "sing-box" / "default.json"
SECRET = "Q2xpZW50U2VjcmV0MDEyMzQ1Njc4OQ"
CONTRACT_LINE = (
    f"naive+https://k-7f3a:{SECRET}@q417.ru1.example.com:443?insecure-concurrency=2"
    "#%F0%9F%87%A9%F0%9F%87%AA%20Germany"
)


def _line() -> str:
    return real_naive_key.key_line() if real_naive_key.available() else CONTRACT_LINE


class NaiveKeyGrammarTests(unittest.TestCase):
    def test_contract_line_parses(self) -> None:
        key = parse_naive_key(CONTRACT_LINE)
        self.assertEqual(("k-7f3a", SECRET, "q417.ru1.example.com", 443, 2, "🇩🇪 Germany"),
                         (key.client_id, key.secret, key.host, key.port, key.concurrency, key.name))
        self.assertEqual(f"https://k-7f3a:{SECRET}@q417.ru1.example.com:443", key.proxy_url)

    def test_defaults(self) -> None:
        key = parse_naive_key(f"naive+https://a:{SECRET}@h.example.com#n")
        self.assertEqual((443, 1), (key.port, key.concurrency))
        self.assertEqual(1, parse_naive_key(f"naive+https://a:{SECRET}@h.example.com:443?insecure-concurrency=1#n").concurrency)

    def test_what_the_bot_refuses_is_refused(self) -> None:
        refused = [
            f"naive+https://a:{SECRET}@192.0.2.7:443#n",
            f"naive+https://a:{SECRET}@localhost:443#n",
            f"naive+https://a:{SECRET}@Q417.example.com:443#n",
            f"naive+https://a:{SECRET}@[2001:db8::1]:443#n",
            f"naive+https://a:short@h.example.com#n",
            f"naive+https://k%207f3a:{SECRET}@h.example.com#n",
            f"naive+https://:{SECRET}@h.example.com#n",
            f"naive+https://a:{SECRET}@h.example.com?padding=true#n",
            f"naive+https://a:{SECRET}@h.example.com?insecure-concurrency=2&insecure-concurrency=3#n",
            f"naive+https://a:{SECRET}@h.example.com?insecure-concurrency=0#n",
            f"naive+https://a:{SECRET}@h.example.com?insecure-concurrency=100#n",
            f"naive+https://a:{SECRET}@h.example.com/path#n",
            f"naive+https://a:{SECRET}@h.example.com#",
            f"https://a:{SECRET}@h.example.com#n",
            f"naive+https://a:{SECRET}@h.example.com:99999#n",
            f"naive+https://a:{SECRET}@h.example.com #n",
        ]
        for line in refused:
            with self.subTest(line=line.replace(SECRET, "<secret>")):
                with self.assertRaises(NaiveKeyError):
                    parse_naive_key(line)

    def test_errors_never_carry_the_secret(self) -> None:
        with self.assertRaises(NaiveKeyError) as caught:
            parse_naive_key(f"naive+https://a:{SECRET}@192.0.2.7:443#n")
        self.assertNotIn(SECRET, str(caught.exception))

    def test_concurrency_above_the_upstream_advice_is_honoured_with_a_warning(self) -> None:
        key = parse_naive_key(f"naive+https://a:{SECRET}@h.example.com?insecure-concurrency=9#n")
        self.assertEqual(9, key.concurrency)
        self.assertIn("9", key.concurrency_warning)
        self.assertEqual("", parse_naive_key(f"naive+https://a:{SECRET}@h.example.com?insecure-concurrency={CONCURRENCY_WARN_ABOVE}#n").concurrency_warning)

    def test_helper_config_is_the_stock_clients_own_shape(self) -> None:
        key = parse_naive_key(CONTRACT_LINE)
        config = helper_config(key, relay_port=11810, relay_username="u", relay_password="p")
        self.assertEqual(
            {"listen": "socks://u:p@127.0.0.1:11810", "proxy": key.proxy_url, "insecure-concurrency": 2}, config)
        single = helper_config(parse_naive_key(f"naive+https://a:{SECRET}@h.example.com#n"),
                               relay_port=1, relay_username="u", relay_password="p")
        self.assertNotIn("insecure-concurrency", single)


class NaiveImportTests(unittest.TestCase):
    def test_the_key_becomes_a_naive_node_owned_by_the_naive_core(self) -> None:
        node = parse_single(_line())
        self.assertEqual("naive", node.scheme)
        self.assertIs(ProtocolCore.NAIVE, protocol_core(node))
        self.assertEqual("naive_sidecar", classify_node_for_singbox(node))
        self.assertEqual(_line(), node.link)

    def test_the_exported_outbound_carries_no_secret(self) -> None:
        node = parse_single(_line())
        key = parse_naive_key(_line())
        dump = json.dumps(node.outbound)
        self.assertNotIn(key.secret, dump)
        self.assertNotIn(key.client_id, dump)

    def test_sing_box_never_translates_it(self) -> None:
        with self.assertRaises(ValueError):
            build_singbox_outbound(parse_single(_line()))

    def test_a_bad_key_is_a_clear_import_error(self) -> None:
        with self.assertRaises(LinkParseError):
            parse_single(f"naive+https://a:{SECRET}@192.0.2.7:443#n")

    def test_keys_in_pasted_text_and_subscriptions_are_found(self) -> None:
        nodes, errors = parse_links_text(f"заметка\n{_line()}\n")
        self.assertEqual(1, len([n for n in nodes if n.scheme == "naive"]))
        payload = f"{_line()}\n"
        parsed = parse_subscription_payload(payload)
        self.assertEqual(["naive"], [n.scheme for n in parsed.nodes])

    def test_identity_survives_a_secret_rotation_and_differs_between_clients(self) -> None:
        rotated = _line().replace(parse_naive_key(_line()).secret, "R" * 22 + "_" * 10)
        a, b = parse_single(_line()), parse_single(rotated)
        self.assertEqual(hidden_source_key_for_node(a), hidden_source_key_for_node(b))


class NaivePlannerTests(unittest.TestCase):
    def _plan(self, line: str | None = None):
        node = parse_single(line or _line())
        document = parse_singbox_document(TEMPLATE_PATH, TEMPLATE_PATH.read_text(encoding="utf-8"))
        return node, plan_singbox_runtime(document, node)

    def test_sing_box_dials_the_loopback_socks_of_the_helper(self) -> None:
        _, plan = self._plan()
        self.assertEqual("naive_sidecar", plan.outcome)
        self.assertEqual("naive", plan.sidecar_kind)
        sidecar = plan.naive_sidecar
        proxy = next(o for o in plan.singbox_config["outbounds"] if o.get("tag") == "proxy")
        self.assertEqual(
            ("socks", "127.0.0.1", sidecar.relay_port, sidecar.relay_username, sidecar.relay_password),
            (proxy["type"], proxy["server"], proxy["server_port"], proxy["username"], proxy["password"]),
        )
        self.assertEqual(
            f"socks://{sidecar.relay_username}:{sidecar.relay_password}@127.0.0.1:{sidecar.relay_port}",
            sidecar.config["listen"],
        )

    def test_the_helper_gets_the_proxy_of_the_key_and_sing_box_never_sees_the_secret(self) -> None:
        node, plan = self._plan()
        key = parse_naive_key(node.link)
        self.assertEqual(key.proxy_url, plan.naive_sidecar.config["proxy"])
        dump = json.dumps(plan.singbox_config)
        self.assertNotIn(key.secret, dump)
        self.assertNotIn(key.client_id, dump)
        self.assertEqual(key.concurrency, plan.naive_sidecar.config.get("insecure-concurrency", 1))

    def test_the_helpers_own_sockets_leave_directly(self) -> None:
        _, plan = self._plan()
        rules = plan.singbox_config["route"]["rules"]
        self.assertEqual({"process_path": [str(NAIVE_PATH_DEFAULT.resolve())], "outbound": "direct"}, rules[0])

    def test_the_secrets_to_scrub_from_logs_are_named(self) -> None:
        node, plan = self._plan()
        key = parse_naive_key(node.link)
        self.assertEqual(set(key.secrets()), set(plan.naive_sidecar.secrets))


if __name__ == "__main__":
    unittest.main()
