"""«Мимо TUN»: addresses written into the TUN inbound of the user's own JSON (owner request 2026-11-27)."""

import copy
import json
import unittest
from pathlib import Path

from xray_fluent.singbox_config import tun_bypass

TEMPLATES = Path(__file__).resolve().parent.parent / "data" / "templates" / "sing-box"


def _template(name: str = "default.json") -> dict:
    return json.loads((TEMPLATES / name).read_text(encoding="utf-8"))


class ParseTests(unittest.TestCase):
    def test_addresses_and_subnets_in_any_separator(self) -> None:
        parsed = tun_bypass.parse_addresses("24.105.0.0/18, 137.221.106.5\n185.60.112.0/22;2a02:6ea0:c000::/36 # note")
        self.assertEqual([], parsed.errors)
        self.assertEqual(["24.105.0.0/18", "137.221.106.5/32", "185.60.112.0/22", "2a02:6ea0:c000::/36"], parsed.cidrs)

    def test_a_domain_is_refused_with_the_reason(self) -> None:
        parsed = tun_bypass.parse_addresses("eu.actual.battle.net")
        self.assertEqual([], parsed.cidrs)
        self.assertIn("IP-адрес, а не имя сайта", parsed.errors[0])

    def test_local_and_too_wide_prefixes_are_refused(self) -> None:
        for bad in ("0.0.0.0/0", "10.0.0.0/8", "192.168.1.5", "127.0.0.1", "169.254.1.1", "224.0.0.1", "8.0.0.0/7", "2000::/8"):
            with self.subTest(bad=bad):
                parsed = tun_bypass.parse_addresses(bad)
                self.assertEqual([], parsed.cidrs, bad)
                self.assertEqual(1, len(parsed.errors), bad)

    def test_a_broader_entry_swallows_the_narrower_ones(self) -> None:
        self.assertEqual(["24.105.0.0/18"], tun_bypass.parse_addresses("24.105.1.1 24.105.0.0/18 24.105.2.0/24 24.105.1.1").cidrs)

    def test_widening_makes_the_neighbouring_addresses_one_subnet(self) -> None:
        self.assertEqual(
            ["137.221.106.0/24", "185.60.112.0/24"],
            tun_bypass.widen_to_subnet(["137.221.106.5/32", "137.221.106.9/32", "185.60.112.3/32"]),
        )
        self.assertEqual(["24.105.0.0/18"], tun_bypass.widen_to_subnet(["24.105.0.0/18"]))


class DocumentTests(unittest.TestCase):
    def test_the_shipped_templates_have_a_tun_inbound_to_write_into(self) -> None:
        for path in sorted(TEMPLATES.glob("*.json")):
            with self.subTest(template=path.name):
                self.assertTrue(tun_bypass.tun_inbounds(json.loads(path.read_text(encoding="utf-8"))))

    def test_adding_writes_the_native_field_and_nothing_else_changes(self) -> None:
        document = _template()
        before = copy.deepcopy(document)
        added = tun_bypass.add_to_document(document, ["24.105.0.0/18", "137.221.106.5/32"])
        self.assertEqual(["24.105.0.0/18", "137.221.106.5/32"], added)
        inbound = tun_bypass.tun_inbounds(document)[0]
        self.assertEqual(["24.105.0.0/18", "137.221.106.5/32"], inbound["route_exclude_address"])
        del inbound["route_exclude_address"]
        self.assertEqual(before, document, "only the TUN inbound's exclusion list may change")

    def test_adding_again_is_a_no_op_and_keeps_the_users_own_entries(self) -> None:
        document = _template()
        tun_bypass.tun_inbounds(document)[0]["route_exclude_address"] = ["198.51.100.0/24"]
        tun_bypass.add_to_document(document, ["24.105.0.0/18"])
        self.assertEqual(["24.105.0.0/18", "198.51.100.0/24"], tun_bypass.current(document))
        self.assertEqual([], tun_bypass.add_to_document(document, ["24.105.0.0/18"]))
        self.assertEqual(["24.105.0.0/18", "198.51.100.0/24"], tun_bypass.current(document))

    def test_removing_some_or_all_and_the_empty_field_goes_away(self) -> None:
        document = _template()
        tun_bypass.add_to_document(document, ["24.105.0.0/18", "137.221.106.0/24"])
        self.assertEqual(["24.105.0.0/18"], tun_bypass.remove_from_document(document, ["24.105.0.0/18"]))
        self.assertEqual(["137.221.106.0/24"], tun_bypass.current(document))
        tun_bypass.remove_from_document(document)
        self.assertNotIn("route_exclude_address", tun_bypass.tun_inbounds(document)[0])

    def test_a_document_without_a_tun_inbound_is_refused_not_invented(self) -> None:
        document = {"inbounds": [{"type": "mixed", "tag": "mixed-in"}], "outbounds": []}
        with self.assertRaises(LookupError):
            tun_bypass.add_to_document(document, ["24.105.0.0/18"])
        self.assertEqual({"inbounds": [{"type": "mixed", "tag": "mixed-in"}], "outbounds": []}, document)

    def test_a_single_string_in_the_field_is_read_like_a_list(self) -> None:
        document = _template()
        tun_bypass.tun_inbounds(document)[0]["route_exclude_address"] = "198.51.100.0/24"
        self.assertEqual(["198.51.100.0/24"], tun_bypass.current(document))
        tun_bypass.add_to_document(document, ["24.105.0.0/18"])
        self.assertEqual(["24.105.0.0/18", "198.51.100.0/24"], tun_bypass.tun_inbounds(document)[0]["route_exclude_address"])


class SummaryTests(unittest.TestCase):
    def test_russian_plural_forms(self) -> None:
        words = {1: "адрес", 2: "адреса", 4: "адреса", 5: "адресов", 11: "адресов", 12: "адресов", 21: "адрес", 22: "адреса", 25: "адресов"}
        for count, word in words.items():
            with self.subTest(count=count):
                self.assertTrue(tun_bypass.summary([f"203.0.{i // 256}.{i % 256}/32" for i in range(count)]).startswith(f"{count} {word}:"))
        self.assertEqual("адресов нет", tun_bypass.summary([]))


WOW = "C:\\Program Files (x86)\\World of Warcraft\\"


class ProgramAddressTests(unittest.TestCase):
    CONNECTIONS = [
        (WOW + "_retail_\\Wow.exe", "137.221.106.5"),          # a realm server
        (WOW + "_retail_\\Wow.exe", "24.105.14.20"),           # another realm address
        (WOW + "Launcher.exe", "185.60.112.3"),                  # the launcher's own address
        (WOW + "_retail_\\Wow.exe", "192.168.1.1"),            # the router: local, never excluded
        (WOW + "_retail_\\Wow.exe", "127.0.0.1"),
        (WOW + "_retail_\\Wow.exe", "2a02:6ea0:c000::4"),      # IPv6
        ("C:\\Program Files\\Mozilla Firefox\\firefox.exe", "142.250.74.14"),  # not the game
        ("C:\\Program Files (x86)\\World of Warcraft Other\\x.exe", "203.0.113.9"),  # a sibling folder
    ]

    def test_a_folder_collects_every_process_under_it_and_only_them(self) -> None:
        addresses = tun_bypass.remote_addresses_of_programs(self.CONNECTIONS, [WOW])
        self.assertEqual(["24.105.14.20/32", "137.221.106.5/32", "185.60.112.3/32", "2a02:6ea0:c000::4/128"], addresses)

    def test_a_program_name_and_a_path_work_like_in_the_rule(self) -> None:
        self.assertEqual(
            ["24.105.14.20/32", "137.221.106.5/32", "2a02:6ea0:c000::4/128"],
            tun_bypass.remote_addresses_of_programs(self.CONNECTIONS, ["wow.exe"]),
        )
        self.assertEqual(
            ["185.60.112.3/32"],
            tun_bypass.remote_addresses_of_programs(self.CONNECTIONS, [WOW + "Launcher.exe"]),
        )

    def test_nothing_listed_or_nothing_connected_finds_nothing(self) -> None:
        self.assertEqual([], tun_bypass.remote_addresses_of_programs(self.CONNECTIONS, []))
        self.assertEqual([], tun_bypass.remote_addresses_of_programs([], [WOW]))
        self.assertEqual([], tun_bypass.remote_addresses_of_programs(self.CONNECTIONS, ["# a comment", "  "]))

    def test_what_is_found_can_be_added_as_it_is(self) -> None:
        document = _template()
        found = tun_bypass.remote_addresses_of_programs(self.CONNECTIONS, [WOW])
        tun_bypass.add_to_document(document, found)
        self.assertEqual(found, tun_bypass.current(document))
        self.assertEqual([], tun_bypass.parse_addresses("\n".join(found)).errors)


from tests.real_subscription import nodes_of, requires_real_subscription  # noqa: E402
from xray_fluent.engines.singbox.runtime_planner import parse_singbox_document, plan_singbox_runtime  # noqa: E402

TEMPLATE_PATH = TEMPLATES / "default.json"


@requires_real_subscription
class RuntimePlanTests(unittest.TestCase):
    """The real planner on the real template and a real node: the exclusion must reach the config sing-box runs."""

    def _plan(self, excluded: list[str]):
        document = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
        if excluded:
            tun_bypass.add_to_document(document, excluded)
        parsed = parse_singbox_document(TEMPLATE_PATH, json.dumps(document))
        return plan_singbox_runtime(parsed, nodes_of("vless")[0])

    def test_the_exclusion_reaches_the_runtime_tun_inbound(self) -> None:
        plan = self._plan(["137.221.106.0/24", "24.105.0.0/18"])
        tun = [item for item in plan.singbox_config["inbounds"] if item.get("type") == "tun"]
        self.assertEqual(1, len(tun))
        self.assertEqual(["24.105.0.0/18", "137.221.106.0/24"], tun[0]["route_exclude_address"])
        self.assertTrue(tun[0]["auto_route"], "the exclusion only means something with auto_route")

    def test_without_an_exclusion_the_runtime_tun_inbound_has_none(self) -> None:
        plan = self._plan([])
        tun = [item for item in plan.singbox_config["inbounds"] if item.get("type") == "tun"]
        self.assertNotIn("route_exclude_address", tun[0])


if __name__ == "__main__":
    unittest.main()
