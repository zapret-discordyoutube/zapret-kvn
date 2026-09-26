"""Icons, illustrations and motion of the «Маршрутизация» pages."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import json
from pathlib import Path
import unittest

from PyQt6.QtCore import QCoreApplication, QEvent, QRectF
from PyQt6.QtGui import QColor, QImage, QPainter
from PyQt6.QtWidgets import QApplication

_app = QApplication.instance() or QApplication([])

import xray_fluent.ui  # noqa: E402,F401
from qfluentwidgets import FluentIcon as FIF, Theme, setTheme  # noqa: E402

from xray_fluent.ui.singbox import art  # noqa: E402
from xray_fluent.ui.singbox.visuals import (  # noqa: E402
    BLOCK,
    DIRECT,
    PROXY,
    Visual,
    outbound_visual,
    rule_outcomes,
    rule_visual,
    variant_icon,
)

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = json.loads((ROOT / "data" / "templates" / "sing-box" / "default.json").read_text(encoding="utf-8"))
_shared: dict[str, object] = {}


def _pump() -> None:
    for _ in range(3):
        QCoreApplication.processEvents()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


def _arts():
    if "arts" not in _shared:
        route = art.RouteMapArt()
        route.set_counts(2, 5, 2)
        scan = art.RuleScanArt()
        scan.set_rules([rule_visual(rule) for rule in TEMPLATE["route"]["rules"]])
        sets = art.RuleSetArt()
        sets.set_counts(4, 1, 0)
        dns = art.DnsArt()
        dns.set_servers(9)
        hub = art.OutboundHubArt()
        hub.set_outbounds([outbound_visual(item) for item in TEMPLATE["outbounds"]])
        _shared["arts"] = [route, scan, sets, dns, hub, art.TunnelArt(), art.JsonArt()]
    return _shared["arts"]


class VisualsTests(unittest.TestCase):
    def test_stock_rules_split_into_outcomes(self) -> None:
        self.assertEqual(rule_outcomes(TEMPLATE), (2, 5, 2))

    def test_user_outbounds_count_by_their_type(self) -> None:
        document = {
            "outbounds": [{"type": "direct", "tag": "lan"}, {"type": "block", "tag": "deny"}, {"type": "vless", "tag": "eu"}],
            "route": {"rules": [
                {"domain": ["a"], "outbound": "lan"},
                {"domain": ["b"], "outbound": "deny"},
                {"domain": ["c"], "outbound": "eu"},
                {"protocol": "dns", "action": "hijack-dns"},
            ]},
        }
        self.assertEqual(rule_outcomes(document), (1, 1, 1))

    def test_rule_tones_follow_outcome(self) -> None:
        self.assertEqual(rule_visual({"action": "route", "outbound": "proxy"}).tone, PROXY)
        self.assertEqual(rule_visual({"action": "route", "outbound": "direct"}).tone, DIRECT)
        self.assertEqual(rule_visual({"action": "reject"}).tone, BLOCK)
        self.assertEqual(variant_icon("outbound", "type", "urltest"), FIF.SPEED_HIGH)
        self.assertEqual(variant_icon("rule", "action", "sniff"), FIF.SEARCH)


class ArtTests(unittest.TestCase):
    def test_every_illustration_paints_in_both_themes(self) -> None:
        for theme in (Theme.LIGHT, Theme.DARK):
            setTheme(theme)
            for widget in _arts():
                for moment in (0.0, 0.7, 1.9, 3.1):
                    with self.subTest(art=type(widget).__name__, theme=theme, t=moment):
                        image = QImage(560, widget.height(), QImage.Format.Format_ARGB32)
                        image.fill(QColor(0, 0, 0, 0))
                        painter = QPainter(image)
                        widget.paint_art(painter, QRectF(0, 0, 560, widget.height()), moment)
                        painter.end()
                        drawn = sum(
                            1 for x in range(0, 560, 7) for y in range(0, widget.height(), 7)
                            if image.pixelColor(x, y).alpha() > 0
                        )
                        self.assertGreater(drawn, 20)
        setTheme(Theme.LIGHT)

    def test_hidden_illustrations_do_not_tick(self) -> None:
        widget = art.TunnelArt()
        self.assertFalse(widget.is_animating())
        widget.show()
        _pump()
        self.assertTrue(widget.is_animating())
        widget.hide()
        _pump()
        self.assertFalse(widget.is_animating())
        _shared["tunnel"] = widget

    def test_badge_paints_icon_tile(self) -> None:
        badge = art.KindBadge(size=34)
        badge.set_visual(Visual(FIF.VPN, PROXY), vivid=True)
        image = badge.grab().toImage()
        self.assertGreater(image.pixelColor(17, 4).alpha(), 0)
        _shared["badge"] = badge

    def test_pulse_dot_runs_only_while_active(self) -> None:
        dot = art.PulseDot()
        dot.set_active(True)
        dot.show()
        _pump()
        self.assertTrue(dot.isVisible())
        dot.set_active(False)
        self.assertFalse(dot.isVisible())
        _shared["dot"] = dot


if __name__ == "__main__":
    unittest.main()
