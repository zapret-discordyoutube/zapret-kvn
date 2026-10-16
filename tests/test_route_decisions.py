"""Сводка решений маршрута для диагностики (VK/Яндекс уходили в туннель незаметно)."""

from __future__ import annotations

import unittest

from xray_fluent.diagnostics.export import route_history_entry
from xray_fluent.diagnostics.route_decisions import RouteDecisionLog, is_russian_site, route_of, site_of


def _conn(cid: str, host: str, chains: list[str], rule: str, process: str = "C:\\Apps\\Chrome.exe", ip: str = "") -> dict:
    return {
        "id": cid,
        "metadata": {"host": host, "destinationIP": ip, "processPath": process},
        "chains": chains,
        "rule": rule,
        "rulePayload": "",
    }


class RouteDecisionLogTests(unittest.TestCase):
    def test_site_is_registrable_part_or_ip(self) -> None:
        self.assertEqual(site_of("sun9-1.userapi.com"), "userapi.com")
        self.assertEqual(site_of("87.240.132.72"), "87.240.132.72")
        self.assertEqual(site_of("[2a02:6b8::2:242]"), "2a02:6b8::2:242")
        self.assertEqual(site_of(""), "")

    def test_russian_sites_include_services_on_foreign_domains(self) -> None:
        for site in ("ya.ru", "userapi.com", "vk.com", "xn--d1acufc.xn--p1ai"):
            self.assertTrue(is_russian_site(site), site)
        self.assertFalse(is_russian_site("youtube.com"))

    def test_route_is_proxy_for_any_proxy_hop(self) -> None:
        self.assertEqual(route_of(["__app_hybrid_relay_a", "proxy"]), "proxy")
        self.assertEqual(route_of(["direct"]), "direct")
        self.assertEqual(route_of([]), "unknown")

    def test_counts_distinct_connections_and_flags_russian_via_tunnel(self) -> None:
        log = RouteDecisionLog()
        log.begin_session("singbox node A")
        rule = "process_path_regex=[(?i)chrome.exe] => route(proxy)"
        batch = [
            _conn("1", "vk.com", ["proxy"], rule),
            _conn("2", "sun9-1.userapi.com", ["proxy"], rule),
            _conn("3", "youtube.com", ["proxy"], rule),
            _conn("4", "ya.ru", ["direct"], "rule_set=[geosite-category-ru geoip-ru] => route(direct)"),
        ]
        log.observe(batch)
        log.observe(batch)  # тот же опрос ещё раз: id уже учтены
        session = log.snapshot()["sessions"][-1]
        self.assertEqual(session["connections"], 4)
        self.assertEqual(session["russian_sites_via_tunnel"], 2)
        self.assertEqual({item["site"] for item in session["russian_via_tunnel"]}, {"vk.com", "userapi.com"})
        self.assertTrue(all(item["process"] == "chrome.exe" for item in session["entries"]))
        self.assertEqual(session["russian_via_tunnel"][0]["rule"], rule)

    def test_reconnect_keeps_the_previous_session(self) -> None:
        log = RouteDecisionLog(sessions=2)
        log.begin_session("first")
        log.observe([_conn("1", "vk.com", ["proxy"], "r")])
        log.begin_session("second")
        log.observe([_conn("1", "ya.ru", ["direct"], "r2")])  # тот же id в новом ядре — новое соединение
        sessions = log.snapshot()["sessions"]
        self.assertEqual([item["label"] for item in sessions], ["first", "second"])
        self.assertEqual(sessions[0]["russian_sites_via_tunnel"], 1)
        self.assertEqual(sessions[1]["connections"], 1)
        log.begin_session("third")
        self.assertEqual([item["label"] for item in log.snapshot()["sessions"]], ["second", "third"])

    def test_distinct_keys_are_bounded(self) -> None:
        log = RouteDecisionLog(max_keys=3)
        log.begin_session("s")
        log.observe([_conn(str(i), f"site{i}.com", ["proxy"], "r") for i in range(10)])
        session = log.snapshot()["sessions"][-1]
        self.assertEqual(session["distinct"], 3)
        self.assertEqual(session["dropped_distinct"], 7)
        self.assertEqual(session["connections"], 10)

    def test_long_rule_text_is_truncated(self) -> None:
        log = RouteDecisionLog()
        log.observe([_conn("1", "a.com", ["direct"], "domain_suffix=[" + "x" * 500 + "]")])
        rule = log.snapshot()["sessions"][-1]["entries"][0]["rule"]
        self.assertLessEqual(len(rule), 200)


class RouteHistoryTests(unittest.TestCase):
    def test_entry_takes_rules_and_final_from_snapshot(self) -> None:
        snapshot = {"captured_at": "t", "config": {"route": {"rules": [{"action": "sniff"}], "final": "proxy"}}}
        self.assertEqual(
            route_history_entry(snapshot),
            {"captured_at": "t", "route_rules": [{"action": "sniff"}], "route_final": "proxy"},
        )
        self.assertIsNone(route_history_entry(None))
        self.assertIsNone(route_history_entry({"config": {}}))


if __name__ == "__main__":
    unittest.main()
