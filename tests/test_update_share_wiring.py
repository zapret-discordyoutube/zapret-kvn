from __future__ import annotations

"""Раздача обновлений в Zapret KVN: склейка с общим ядром (сама раздача проверена в Zapret 2 GUI)."""

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from xray_fluent.profiles.models import AppSettings
from xray_fluent.updates import share_wiring
from zapret_update import share_discover, share_service
from zapret_update.manifest import ManifestError


class WiringTests(unittest.TestCase):
    def setUp(self) -> None:
        for name, value in (("_service", None), ("_enabled", True), ("_internet", False), ("_book", None)):
            patcher = patch.object(share_wiring, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_service_is_built_for_this_product_with_its_own_port(self) -> None:
        service = share_wiring.default_service()
        self.assertIsInstance(service, share_service.SharingService)
        self.assertEqual(service._product, "zapret-kvn")
        self.assertEqual(service._discovery_port, share_discover.DISCOVERY_PORT_KVN)
        self.assertNotEqual(share_discover.DISCOVERY_PORT_KVN, share_discover.DISCOVERY_PORT_GUI)
        self.assertIs(share_wiring.default_service(), service)
        self.assertFalse(service.running)

    def test_setting_defaults_on_and_roundtrips(self) -> None:
        self.assertTrue(AppSettings().share_updates_lan)
        self.assertTrue(AppSettings.from_dict({}).share_updates_lan)
        off = AppSettings.from_dict(AppSettings(share_updates_lan=False).to_dict())
        self.assertFalse(off.share_updates_lan)

    def test_internet_sharing_is_off_by_default_and_roundtrips(self) -> None:
        self.assertFalse(AppSettings().share_updates_internet)
        self.assertFalse(AppSettings.from_dict({}).share_updates_internet)
        self.assertTrue(AppSettings.from_dict(AppSettings(share_updates_internet=True).to_dict()).share_updates_internet)
        self.assertFalse(share_wiring.is_internet_enabled())

    def test_service_has_an_internet_side_that_follows_its_own_flag(self) -> None:
        service = share_wiring.default_service()  # без зависания: у книги свой замок
        self.assertIsNotNone(service._internet)
        self.assertIs(service._internet_enabled, share_wiring.is_internet_enabled)

    def test_apply_setting_sets_both_flags(self) -> None:
        fake = SimpleNamespace(refresh=lambda: None)
        with patch.object(share_wiring, "default_service", return_value=fake):
            share_wiring.apply_setting(False, True, wait=True)
            self.assertEqual((share_wiring.is_enabled(), share_wiring.is_internet_enabled()), (False, True))
            share_wiring.apply_setting(True, wait=True)
            self.assertEqual((share_wiring.is_enabled(), share_wiring.is_internet_enabled()), (True, False))

    def test_internet_finder_exists_only_when_the_switch_is_on(self) -> None:
        self.assertIsNone(share_wiring.internet_finder("0.8.66"))
        with patch.object(share_wiring, "_internet", True):
            self.assertTrue(callable(share_wiring.internet_finder("0.8.66")))

    def test_registry_is_the_wait_address_without_the_wait_word(self) -> None:
        with patch("xray_fluent.updates.site_names.resolve", side_effect=lambda url: url):
            self.assertEqual(share_wiring.registry_bases(), ["https://git.zapret.moe/api/zapret/kvn"])
        with patch("xray_fluent.updates.site_names.resolve", return_value="https://x/other"):
            self.assertEqual(share_wiring.registry_bases(), [])

    def test_apply_setting_sets_the_flag_and_refreshes_in_the_background(self) -> None:
        refreshed = []
        fake = SimpleNamespace(refresh=lambda: refreshed.append(share_wiring.is_enabled()))
        with patch.object(share_wiring, "default_service", return_value=fake):
            share_wiring.apply_setting(False, wait=True)
            share_wiring.apply_setting(True, wait=True)
        self.assertEqual(refreshed, [False, True])

    def test_failure_inside_refresh_does_not_escape(self) -> None:
        def boom():
            raise RuntimeError("no network stack")

        with patch.object(share_wiring, "default_service", return_value=SimpleNamespace(refresh=boom)):
            with self.assertLogs(share_wiring._log, "WARNING"):
                share_wiring.apply_setting(True, wait=True)

    def test_missing_or_broken_installed_list_is_none(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertIsNone(share_wiring.installed_manifest(root))
            target = root.joinpath(*share_wiring.INSTALLED_LIST)
            target.parent.mkdir(parents=True)
            target.write_bytes(b'{"not": "signed"}')
            target.with_name(target.name + ".sig").write_bytes(b"bad")
            self.assertIsNone(share_wiring.installed_manifest(root))

    def test_lookup_names_the_newest_release_without_the_v_prefix(self) -> None:
        class Client:
            def __init__(self, _proxy):
                pass

            def fetch_release(self):
                return {"tag_name": "v0.8.66", "assets": [{"name": "x"}]}

        with patch("xray_fluent.updates.app_updater._ReleaseClient", Client):
            found = share_wiring._lookup("stable")
        self.assertEqual(found.release["version"], "0.8.66")
        self.assertEqual(found.error, "")

    def test_lookup_reports_a_failure_instead_of_raising(self) -> None:
        class Client:
            def __init__(self, _proxy):
                pass

            def fetch_release(self):
                raise OSError("no route")

        with patch("xray_fluent.updates.app_updater._ReleaseClient", Client):
            found = share_wiring._lookup("stable")
        self.assertIsNone(found.release)
        self.assertIn("no route", found.error)

    def test_fetch_downloads_list_and_signature_and_returns_their_bytes(self) -> None:
        asked = []

        class Client:
            def fetch_signed(self, url, limit):
                asked.append(url)
                return b"RAW" if url.endswith(".json") else b"SIG"

        release = {"version": "0.8.66", "client": Client(), "assets": [
            {"name": "update-manifest.json", "browser_download_url": "https://git.zapret.moe/zapretkvn/zapret-kvn/releases/download/v0.8.66/update-manifest.json"},
            {"name": "update-manifest.json.sig", "browser_download_url": "https://git.zapret.moe/zapretkvn/zapret-kvn/releases/download/v0.8.66/update-manifest.json.sig"},
        ]}
        fake = SimpleNamespace(version="0.8.66")
        with patch.object(share_wiring, "load_signed", return_value=fake) as verify, patch(
            "xray_fluent.updates.app_updater._is_trusted_release_url", return_value=True
        ):
            signed = share_wiring._fetch(release, channel="stable", current_version="0.8.66", allow_same=True)
        self.assertEqual((signed.raw, signed.signature, signed.manifest), (b"RAW", b"SIG", fake))
        self.assertEqual(len(asked), 2)
        self.assertTrue(verify.call_args.kwargs["allow_same"])

    def test_fetch_refuses_a_release_without_a_signed_list(self) -> None:
        with patch("xray_fluent.updates.app_updater._is_trusted_release_url", return_value=True):
            with self.assertRaises(ManifestError):
                share_wiring._fetch({"assets": [], "client": object()}, channel="stable", current_version="1", allow_same=True)


if __name__ == "__main__":
    unittest.main()
