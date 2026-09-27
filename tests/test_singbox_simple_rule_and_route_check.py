"""«Простое правило» и «Проверить сайт»: разбор строк v2rayN и порядок правил ядра.

Ядро здесь не запускается: наборы правил проверяет подставной matcher, команда
``sing-box rule-set match`` проверяется по аргументам.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from xray_fluent.application.route_check import RouteCheck, RuleSetMatcher, rule_set_match_command
from xray_fluent.singbox_config.route_explain import explain_route
from xray_fluent.singbox_config.simple_rule import BLOCK, build_rule, insert_index, normalize_domain

ROOT = Path(__file__).resolve().parents[1]
STOCK = json.loads((ROOT / "data" / "templates" / "sing-box" / "default.json").read_text(encoding="utf-8"))
SETS = {"geosite-category-ru", "geoip-ru", "geosite-ru-blocked", "geoip-ru-blocked"}


class SimpleRuleTests(unittest.TestCase):
    def test_plain_site_means_site_and_subdomains_like_v2rayn(self) -> None:
        result = build_rule("direct", "2ip.ru", "", "", SETS)
        self.assertEqual(result.rule, {"domain_suffix": ["2ip.ru"], "action": "route", "outbound": "direct"})

    def test_domains_are_normalized(self) -> None:
        self.assertEqual(normalize_domain("https://www.2IP.ru:443/path?q=1"), "2ip.ru")
        self.assertEqual(normalize_domain("*.example.com"), "example.com")
        self.assertEqual(normalize_domain("госуслуги.рф"), "xn--c1aapkosapc.xn--p1ai")
        self.assertEqual(normalize_domain("www.com"), "www.com")

    def test_v2rayn_prefixes_map_to_native_fields(self) -> None:
        rule = build_rule(
            "proxy",
            "domain:a.com\nfull:b.com\nkeyword:yt\nregexp:^c\\.\ngeosite:category-ru",
            "geoip:private\n1.2.3.4\n10.0.0.0/8\ngeoip:ru",
            "",
            SETS,
        ).rule
        self.assertEqual(rule["domain_suffix"], ["a.com"])
        self.assertEqual(rule["domain"], ["b.com"])
        self.assertEqual(rule["domain_keyword"], ["yt"])
        self.assertEqual(rule["domain_regex"], ["^c\\."])
        self.assertEqual(rule["rule_set"], ["geosite-category-ru", "geoip-ru"])
        self.assertTrue(rule["ip_is_private"])
        self.assertEqual(rule["ip_cidr"], ["1.2.3.4/32", "10.0.0.0/8"])
        self.assertEqual(rule["outbound"], "proxy")

    def test_sites_and_programs_become_or_not_and(self) -> None:
        rule = build_rule(BLOCK, "a.com", "", "chrome.exe\nC:\\Games\\g.exe", SETS).rule
        self.assertEqual(rule["type"], "logical")
        self.assertEqual(rule["mode"], "or")
        self.assertEqual(rule["action"], "reject")
        self.assertNotIn("outbound", rule)
        patterns = rule["rules"][1]["process_path_regex"]
        self.assertEqual(patterns, ["(?i)(^|[\\\\/])chrome\\.exe$", "(?i)^C:\\\\Games\\\\g\\.exe$"])

    def test_programs_match_without_case_and_get_exe(self) -> None:
        import re

        from xray_fluent.singbox_config.catalog import match_summary
        from xray_fluent.singbox_config.simple_rule import process_display, process_pattern

        pattern = process_pattern("telegram")
        self.assertTrue(re.search(pattern, "C:\\Users\\u\\AppData\\Telegram.exe"))
        self.assertFalse(re.search(pattern, "C:\\x\\notTelegram.exe"))
        self.assertEqual(process_display(pattern), "telegram.exe")
        spaced = process_pattern("Яндекс Музыка.exe")
        self.assertTrue(re.search(spaced, "D:\\Apps\\ЯНДЕКС МУЗЫКА.EXE"))
        rule = build_rule("direct", "", "", "telegram", SETS).rule
        self.assertEqual(match_summary(rule), "процессы: telegram.exe")

    def test_word_without_dot_is_a_keyword(self) -> None:
        rule = build_rule("proxy", "youtube", "", "", SETS).rule
        self.assertEqual(rule["domain_keyword"], ["youtube"])
        self.assertNotIn("domain_suffix", rule)

    def test_errors_block_the_rule(self) -> None:
        for sites, ips, message in (
            ("", "", "Укажите"),
            ("geosite:nope", "", "geosite-nope"),
            ("exa!mple.com", "", "Не похоже на адрес"),
            ("", "300.1.1.1", "IP-адрес"),
            ("regexp:(", "", "регулярном"),
        ):
            with self.subTest(sites=sites, ips=ips):
                result = build_rule("direct", sites, ips, "", SETS)
                self.assertIsNone(result.rule)
                self.assertTrue(any(message in error for error in result.errors), result.errors)

    def test_new_rule_goes_after_service_and_protective_rules(self) -> None:
        # sniff, hijack-dns, блок DoT 853, блок сервисов проверки IP — затем пользовательское.
        self.assertEqual(insert_index(STOCK["route"]["rules"]), 4)
        self.assertEqual(STOCK["route"]["rules"][4].get("outbound"), "direct")
        self.assertEqual(insert_index([]), 0)
        self.assertEqual(insert_index([{"domain": ["a"], "outbound": "direct"}, {"action": "sniff"}]), 0)


def _matcher(members: dict[str, set[str]]):
    def match(definition: dict, value: str) -> bool:
        return any(value == item or value.endswith("." + item) for item in members.get(definition["tag"], ()))

    return match


class ListValuesTests(unittest.TestCase):
    """«2ip.ru, 2ip.io» в одной строке — два домена, а не один с запятой."""

    def test_separators_split_only_token_fields(self) -> None:
        from xray_fluent.singbox_config.list_values import parse_list

        self.assertEqual(parse_list("domain_suffix", "2ip.ru, 2ip.io\nexample.com  ya.ru;vk.com")[0],
                         ["2ip.ru", "2ip.io", "example.com", "ya.ru", "vk.com"])
        self.assertEqual(parse_list("ip_cidr", "1.1.1.1, 10.0.0.0/8")[0], ["1.1.1.1", "10.0.0.0/8"])
        self.assertEqual(parse_list("port", "443, 80")[0], ["443", "80"])
        # Запятая бывает в regex, пробел — в имени файла.
        self.assertEqual(parse_list("domain_regex", "^a{2,3}$")[0], ["^a{2,3}$"])
        self.assertEqual(parse_list("process_name", "Яндекс Музыка.exe")[0], ["Яндекс Музыка.exe"])

    def test_domains_are_normalized_and_invalid_values_rejected(self) -> None:
        from xray_fluent.singbox_config.list_values import parse_list

        values, problems = parse_list("domain_suffix", "HTTPS://2IP.ru/path .only.sub.com госуслуги.рф")
        self.assertEqual(values, ["2ip.ru", ".only.sub.com", "xn--c1aapkosapc.xn--p1ai"])
        self.assertEqual(problems, [])
        self.assertTrue(parse_list("ip_cidr", "300.1.1.1")[1])
        self.assertTrue(parse_list("port_range", "1000-2000")[1])

    def test_stored_multi_value_strings_are_reported(self) -> None:
        from xray_fluent.singbox_config.list_values import value_problems

        self.assertTrue(value_problems("domain_suffix", ["2ip.ru, 2ip.io"]))
        self.assertEqual(value_problems("domain_suffix", ["2ip.ru"]), [])
        self.assertEqual(value_problems("domain_regex", ["a, b"]), [])

    def test_simple_form_splits_sites_by_spaces_too(self) -> None:
        rule = build_rule("direct", "2ip.ru 2ip.io\nregexp:^a{2, 3}$", "1.1.1.1 8.8.8.8", "", SETS).rule
        self.assertEqual(rule["domain_suffix"], ["2ip.ru", "2ip.io"])
        self.assertEqual(rule["domain_regex"], ["^a{2, 3}$"])
        self.assertEqual(rule["ip_cidr"], ["1.1.1.1/32", "8.8.8.8/32"])


class RouteExplainTests(unittest.TestCase):
    sets = staticmethod(_matcher({"geosite-category-ru": {"2ip.ru"}, "geoip-ru": {"95.1.1.1"}, "geosite-ru-blocked": {"youtube.com"}}))

    def explain(self, host: str, *, tun: bool = False, document: dict | None = None, resolve=None):
        return explain_route(document or STOCK, host, tun=tun, match_set=self.sets, resolve=resolve or (lambda _h: []))

    def test_first_match_wins_and_final_catches_the_rest(self) -> None:
        self.assertEqual(self.explain("youtube.com").target, "proxy")
        self.assertEqual(self.explain("ifconfig.me").target, "block")
        gov = self.explain("www.gosuslugi.ru")
        self.assertEqual((gov.target, gov.rule_index), ("direct", 5))
        other = self.explain("example.com")
        self.assertEqual((other.target, other.rule_index), ("proxy", None))

    def test_process_rule_is_reported_as_maybe_not_as_hit(self) -> None:
        verdict = self.explain("2ip.ru")
        self.assertEqual((verdict.target, verdict.rule_index), ("direct", 10))
        self.assertEqual([item.index for item in verdict.maybe], [4])
        self.assertIn("процессы", verdict.maybe[0].reason)

    def test_ip_rules_need_the_address_only_tun_has(self) -> None:
        document = {
            "route": {
                "rules": [{"action": "sniff"}, {"ip_cidr": ["95.0.0.0/8"], "outbound": "direct"}],
                "final": "proxy",
            }
        }
        resolve = lambda _host: ["95.1.1.1"]  # noqa: E731
        self.assertEqual(self.explain("site.ru", tun=False, document=document, resolve=resolve).target, "proxy")
        tun = self.explain("site.ru", tun=True, document=document, resolve=resolve)
        self.assertEqual((tun.target, tun.ips), ("direct", ["95.1.1.1"]))
        document["route"]["rules"].insert(1, {"action": "resolve"})
        self.assertEqual(self.explain("site.ru", tun=False, document=document, resolve=resolve).target, "direct")

    def test_domain_rules_in_tun_need_sniff(self) -> None:
        document = {"route": {"rules": [{"domain_suffix": ["a.com"], "outbound": "direct"}], "final": "proxy"}}
        verdict = self.explain("a.com", tun=True, document=document)
        self.assertEqual(verdict.target, "proxy")
        self.assertTrue(any("sniff" in note for note in verdict.notes))

    def test_logical_invert_and_unknown_set(self) -> None:
        document = {
            "route": {
                "rule_set": [{"tag": "remote", "type": "remote", "url": "https://x"}],
                "rules": [
                    {"type": "logical", "mode": "and", "rules": [{"domain_suffix": ["a.com"]}, {"port": [443]}],
                     "action": "reject"},
                    {"domain_suffix": ["b.com"], "invert": True, "outbound": "direct"},
                    {"rule_set": ["remote"], "outbound": "direct"},
                ],
                "final": "proxy",
            }
        }
        unknown = lambda _definition, _value: None  # noqa: E731
        run = lambda host: explain_route(document, host, tun=False, match_set=unknown)  # noqa: E731
        self.assertEqual(run("a.com").target, "reject")
        self.assertEqual(run("c.com").target, "direct")  # invert: всё, кроме b.com
        verdict = run("b.com")
        self.assertEqual(verdict.target, "proxy")
        self.assertEqual([item.index for item in verdict.maybe], [2])


class RuleSetMatchCommandTests(unittest.TestCase):
    def test_binary_format_is_explicit_and_path_is_core_relative(self) -> None:
        exe = Path("C:/app/core/sing-box.exe")
        command = rule_set_match_command(exe, STOCK["route"]["rule_set"][2], "2ip.ru")
        self.assertEqual(command[:5], [str(exe), "rule-set", "match", "-f", "binary"])
        self.assertEqual(Path(command[5]), exe.parent / "rule-set" / "geosite-category-ru.srs")
        self.assertIsNone(rule_set_match_command(exe, {"type": "remote", "url": "https://x"}, "a"))

    def test_matcher_reads_the_match_line_and_treats_errors_as_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exe = root / "sing-box.exe"
            exe.write_bytes(b"")
            (root / "set.srs").write_bytes(b"")
            calls: list[list[str]] = []

            def run(command):
                calls.append(command)
                value = command[-1]
                if value == "broken":
                    return subprocess.CompletedProcess(command, 1, b"", b"FATAL")
                hit = b"match rules.[0]: domain_suffix=<binary>" if value == "2ip.ru" else b""
                return subprocess.CompletedProcess(command, 0, b"", hit)

            matcher = RuleSetMatcher(exe, root, run)
            definition = {"tag": "s", "type": "local", "format": "binary", "path": "set.srs"}
            self.assertTrue(matcher(definition, "2ip.ru"))
            self.assertTrue(matcher(definition, "2ip.ru"))
            self.assertFalse(matcher(definition, "example.com"))
            self.assertIsNone(matcher(definition, "broken"))
            self.assertEqual(len(calls), 3)  # повтор из кэша
            inline = {"tag": "i", "type": "inline", "rules": [{"domain": ["x"]}]}
            matcher(inline, "x")
            self.assertEqual(calls[-1][4], "source")
            matcher.close()
            self.assertEqual(list(root.glob("route_check_*.json")), [])

    def test_check_without_core_still_answers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            check = RouteCheck(runtime_dir=Path(directory))
            try:
                verdict = check.check_blocking(None, json.dumps(STOCK), "ifconfig.me", tun=False)
            finally:
                check.shutdown()
        self.assertEqual(verdict.target, "block")


if __name__ == "__main__":
    unittest.main()
