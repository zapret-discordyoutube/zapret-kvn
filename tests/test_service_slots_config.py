"""Service slots written into the active sing-box JSON (owner decision 2026-11-16, docs/SERVICE_SLOTS.md)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from xray_fluent.slots import catalog
from xray_fluent.slots.config_writer import apply_slots, dns_tag, enabled_slots, selector_tag

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "data/templates/sing-box/default.json"
ALL = {catalog.YOUTUBE, catalog.AI, catalog.TELEGRAM}
# A Linux build of the same pinned core (Android's core build); the Windows gate checks with core/sing-box.exe.
LINUX_SINGBOX = ROOT.parent / "android/core-build/output/sing-box"


def template() -> dict:
    return json.loads(TEMPLATE.read_text(encoding="utf-8"))


def index_of(rules: list, predicate) -> int:
    return next(i for i, rule in enumerate(rules) if predicate(rule))


class SlotConfigWriterTests(unittest.TestCase):
    def test_ticking_youtube_writes_selector_rule_and_dns_in_the_right_place(self):
        source = template()
        result = apply_slots(source, {catalog.YOUTUBE})
        self.assertEqual(source, template(), "the input must not change")
        selector = next(o for o in result["outbounds"] if o["tag"] == selector_tag("youtube"))
        self.assertEqual(
            {"type": "selector", "tag": "zapret-slot-youtube", "outbounds": ["proxy"], "default": "proxy",
             "interrupt_exist_connections": True},
            selector,
        )
        rules = result["route"]["rules"]
        slot_rule = index_of(rules, lambda r: r.get("outbound") == "zapret-slot-youtube")
        first_proxy = index_of(rules, lambda r: r.get("outbound") == "proxy")
        ru_direct = index_of(rules, lambda r: "geoip-ru" in (r.get("rule_set") or []) and r.get("outbound") == "direct")
        hijack = index_of(rules, lambda r: r.get("action") == "hijack-dns")
        self.assertLess(hijack, slot_rule)
        self.assertLess(slot_rule, first_proxy, "before the always-proxy rules")
        self.assertLess(slot_rule, ru_direct, "a Russian address must not take YouTube out of the tunnel")
        self.assertEqual(list(catalog.YOUTUBE_DOMAINS), rules[slot_rule]["domain_suffix"])

        dns = result["dns"]
        tags = {s["tag"]: s for s in dns["servers"]}
        self.assertEqual("zapret-slot-youtube", tags["zapret-slot-dns-youtube-udp"]["detour"])
        self.assertEqual("zapret-slot-youtube", tags["zapret-slot-dns-youtube-tcp"]["detour"])
        self.assertEqual(["zapret-slot-dns-youtube-udp", "zapret-slot-dns-youtube-tcp"], tags["zapret-slot-dns-youtube"]["servers"])
        dns_rule = index_of(dns["rules"], lambda r: r.get("server") == dns_tag("youtube"))
        node_rule = index_of(dns["rules"], lambda r: r.get("server") == "proxy-dns")
        self.assertLess(dns_rule, node_rule)
        self.assertTrue(dns["rules"][dns_rule]["disable_cache"])

    def test_telegram_apps_names_and_ranges_are_separate_rules(self):
        # sing-box ANDs different fields inside one rule.
        rules = [r for r in apply_slots(template(), {catalog.TELEGRAM})["route"]["rules"]
                 if r.get("outbound") == "zapret-slot-telegram"]
        self.assertEqual([["process_name"], ["domain_suffix"], ["ip_cidr"]],
                         [[k for k in r if k not in ("action", "outbound")] for r in rules])

    def test_routing_order_is_apps_then_names_then_ranges_ai_first(self):
        rules = [r for r in apply_slots(template(), ALL)["route"]["rules"] if str(r.get("outbound")).startswith("zapret-slot-")]
        self.assertEqual(
            [("process_name", "ai"), ("process_name", "telegram"), ("domain_suffix", "ai"), ("domain_suffix", "youtube"),
             ("domain_suffix", "telegram"), ("ip_cidr", "telegram")],
            [(next(k for k in r if k not in ("action", "outbound")), r["outbound"].removeprefix("zapret-slot-")) for r in rules],
        )

    def test_idempotent_and_untick_restores_the_original(self):
        once = apply_slots(template(), ALL)
        self.assertEqual(once, apply_slots(once, ALL))
        self.assertEqual(template(), apply_slots(once, set()))
        only_ai = apply_slots(once, {catalog.AI})
        self.assertEqual({catalog.AI}, enabled_slots(only_ai))
        self.assertEqual(apply_slots(template(), {catalog.AI}), only_ai)

    def test_a_rule_the_user_moved_stays_where_the_user_put_it(self):
        config = apply_slots(template(), {catalog.YOUTUBE})
        rules = config["route"]["rules"]
        moved = rules.pop(index_of(rules, lambda r: r.get("outbound") == "zapret-slot-youtube"))
        rules.append(moved)
        again = apply_slots(config, {catalog.YOUTUBE})
        self.assertEqual("zapret-slot-youtube", again["route"]["rules"][-1]["outbound"])
        self.assertEqual(1, sum(r.get("outbound") == "zapret-slot-youtube" for r in again["route"]["rules"]))

    def test_user_blocks_are_never_removed(self):
        config = template()
        config["outbounds"].append({"type": "direct", "tag": "my-exit"})
        config["route"]["rules"].insert(3, {"domain_suffix": ["example.org"], "action": "route", "outbound": "my-exit"})
        result = apply_slots(apply_slots(config, ALL), set())
        self.assertEqual(config, result)

    def test_profile_with_its_own_dns_gets_no_slot_dns(self):
        config = template()
        for server in config["dns"]["servers"]:
            server.pop("detour", None)
        result = apply_slots(config, {catalog.YOUTUBE})
        self.assertEqual(config["dns"], result["dns"])
        self.assertIn("zapret-slot-youtube", {o["tag"] for o in result["outbounds"]})

    def test_enabled_slots_ignores_unknown_and_dns_tags(self):
        config = {"outbounds": [{"tag": "zapret-slot-youtube"}, {"tag": "zapret-slot-dns-ai"}, {"tag": "zapret-slot-x"}]}
        self.assertEqual({"youtube"}, enabled_slots(config))

    @unittest.skipUnless(LINUX_SINGBOX.is_file(), "Linux sing-box of the pinned core not available")
    def test_written_config_passes_the_pinned_core_check(self):
        # `sing-box check` proves the schema (field names, types, actions); member references resolve only at start.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            config = apply_slots(template(), ALL)
            # The rule-set files come with the build; the check needs only the structure, so they become inline
            # placeholders with the same tags.
            config["route"]["rule_set"] = [
                {"type": "inline", "tag": rule_set["tag"], "rules": [{"domain_suffix": ["placeholder.invalid"]}]}
                for rule_set in config["route"]["rule_set"]
            ]
            path.write_text(json.dumps(config), encoding="utf-8")
            done = subprocess.run([str(LINUX_SINGBOX), "check", "-c", str(path)], capture_output=True, text=True, timeout=60)
            self.assertEqual(0, done.returncode, done.stderr[-2000:])


if __name__ == "__main__":
    unittest.main()
