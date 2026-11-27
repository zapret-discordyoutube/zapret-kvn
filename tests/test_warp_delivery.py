"""The WARP account delivered in the subscription header (owner 2026-11-27, docs/WARP_ACCOUNT_DELIVERY.md).

The payload is a REAL one: the service's provisioning script (`scripts/warp_account_provision.py`) registered two devices at the
real Cloudflare API on 2026-11-27, the app code wrote the files from it, and the real core accepted both (WireGuard handshake
and MASQUE over HTTP/2, `warp=on` on Cloudflare's trace page).  The two devices were deleted afterwards: the keys in the fixture
open nothing, they only keep the real shape of the data.
"""

from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xray_fluent.network import warp_delivery, warp_masque_account, warp_registration  # noqa: E402

FIXTURE = ROOT / "tests/fixtures/real_warp_delivery_payload.json"


def _header(payload: dict) -> str:
    return base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()


class DeliveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.account = self.dir / "warp-entry-profile.json"

    def test_the_real_payload_makes_both_account_files_the_app_accepts(self) -> None:
        outcome = warp_delivery.apply({"Zapret-Warp-Account": _header(self.payload)}, self.dir)
        self.assertEqual("written", outcome.status)
        self.assertTrue(outcome.wrote_wireguard and outcome.wrote_masque)
        self.assertTrue(warp_registration.account_file_ready(self.account))
        self.assertTrue(warp_masque_account.ready(warp_masque_account.account_path(self.account)))
        # the files are exactly the documents of the payload (what the core reads)
        self.assertEqual(self.payload["wireguard"], json.loads(self.account.read_text(encoding="utf-8")))
        self.assertEqual(self.payload["masque"], json.loads(warp_masque_account.account_path(self.account).read_text(encoding="utf-8")))

    def test_the_header_name_is_not_case_sensitive_and_a_missing_header_does_nothing(self) -> None:
        self.assertEqual("none", warp_delivery.apply({"etag": "x"}, self.dir).status)
        self.assertFalse(self.account.exists())
        self.assertEqual("written", warp_delivery.apply({"zapret-warp-account": _header(self.payload)}, self.dir).status)

    def test_a_working_account_on_the_device_is_never_replaced(self) -> None:
        warp_delivery.apply({"zapret-warp-account": _header(self.payload)}, self.dir)
        mine = json.loads(self.account.read_text(encoding="utf-8"))
        mine["private_key"] = "device-own-key"
        self.account.write_text(json.dumps(mine), encoding="utf-8")
        other = json.loads(json.dumps(self.payload))
        other["wireguard"]["private_key"] = "another-key"
        outcome = warp_delivery.apply({"zapret-warp-account": _header(other)}, self.dir)
        self.assertEqual("kept", outcome.status)
        self.assertEqual("device-own-key", json.loads(self.account.read_text(encoding="utf-8"))["private_key"])

    def test_only_the_missing_half_is_filled(self) -> None:
        warp_delivery.apply({"zapret-warp-account": _header(self.payload)}, self.dir)
        warp_masque_account.account_path(self.account).unlink()
        outcome = warp_delivery.apply({"zapret-warp-account": _header(self.payload)}, self.dir)
        self.assertEqual(("written", False, True), (outcome.status, outcome.wrote_wireguard, outcome.wrote_masque))

    def test_replace_overwrites_once_per_distinct_payload(self) -> None:
        warp_delivery.apply({"zapret-warp-account": _header(self.payload)}, self.dir)
        newer = json.loads(json.dumps(self.payload))
        newer["replace"] = True
        newer["wireguard"]["private_key"] = "replacement-key"
        first = warp_delivery.apply({"zapret-warp-account": _header(newer)}, self.dir)
        self.assertEqual("written", first.status)
        self.assertEqual("replacement-key", json.loads(self.account.read_text(encoding="utf-8"))["private_key"])
        # the device later got another key of its own: the same replace payload does not overwrite it again
        self.account.write_text(json.dumps({**json.loads(self.account.read_text(encoding="utf-8")), "private_key": "later"}), encoding="utf-8")
        self.assertEqual("kept", warp_delivery.apply({"zapret-warp-account": _header(newer)}, self.dir).status)
        self.assertEqual("later", json.loads(self.account.read_text(encoding="utf-8"))["private_key"])

    def test_garbage_is_refused_and_writes_nothing(self) -> None:
        for value in ("%%%not base64%%%", base64.b64encode(b"not json").decode(), base64.b64encode(b'{"v":2}').decode(),
                      _header({"v": 1, "wireguard": {"private_key": "x"}, "masque": self.payload["masque"]}),
                      _header({"v": 1, "wireguard": self.payload["wireguard"], "masque": {"private_key": "x"}}),
                      "A" * (warp_delivery.MAX_HEADER_BYTES + 1)):
            outcome = warp_delivery.apply({"zapret-warp-account": value}, self.dir)
            self.assertEqual("invalid", outcome.status, outcome)
        self.assertEqual([], list(self.dir.iterdir()))

    def test_an_edge_remembered_for_the_old_account_is_forgotten_with_it(self) -> None:
        (self.dir / "warp-entry-profile.json.edge").write_text("162.159.192.1:2408", encoding="utf-8")
        warp_delivery.apply({"zapret-warp-account": _header(self.payload)}, self.dir)
        self.assertFalse((self.dir / "warp-entry-profile.json.edge").exists())


class SubscriptionHookTests(unittest.TestCase):
    """The hook in the subscription service: only the service's own replies deliver, on a full reply and on a 304."""

    def setUp(self) -> None:
        from unittest.mock import patch

        self.payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        patcher = patch("xray_fluent.constants.DATA_DIR", Path(self._tmp.name))
        patcher.start()
        self.addCleanup(patcher.stop)

    def _fetch(self, **headers):
        from types import SimpleNamespace

        return SimpleNamespace(headers=headers)

    def test_a_reply_of_the_service_delivers_and_another_providers_reply_does_not(self) -> None:
        from xray_fluent.application.subscription_service import learn_warp_account
        from xray_fluent.profiles.models import Subscription

        foreign = Subscription(id="s1", name="other", url="https://example.com/x")
        foreign.service = False
        self.assertEqual("none", learn_warp_account(foreign, self._fetch(**{"zapret-warp-account": _header(self.payload)})).status)
        self.assertEqual([], list(Path(self._tmp.name).iterdir()))
        ours = Subscription(id="s2", name="ours", url="https://example.com/y")
        ours.service = True
        outcome = learn_warp_account(ours, self._fetch(**{"zapret-warp-account": _header(self.payload)}))
        self.assertEqual("written", outcome.status)
        self.assertTrue(warp_registration.account_file_ready(Path(self._tmp.name) / "warp-entry-profile.json"))


if __name__ == "__main__":
    unittest.main()
