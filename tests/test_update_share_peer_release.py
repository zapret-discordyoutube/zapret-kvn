from __future__ import annotations

"""Новая версия от соседей по интернету, когда сервер выпусков не ответил: те же проверки подписи."""

import base64
import hashlib
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from xray_fluent.updates import app_updater, share_wiring
from zapret_update import manifest, share_discover, share_internet, share_serve
from zapret_update.ed25519 import public_key_from_seed, sign_ed25519

SEED = hashlib.sha256(b"kvn test key").digest()
OTHER = hashlib.sha256(b"someone else").digest()
KEYS = {"kvn-test": public_key_from_seed(SEED)}
VERSION = "99.1.2.3"
ARCHIVE = "ZapretKVN-windows-x64-99.1.2.3.zip"


def _signed(version=VERSION, *, seed=SEED, product="zapret-kvn"):
    raw = manifest.dumps({
        "schema": 1, "product": product, "channel": "stable", "version": version, "created": int(time.time()),
        "key": "kvn-test", "files": [{"path": "ZapretKVN.exe", "size": 3, "sha256": "b" * 64, "zsize": 2}],
        "installer": {"name": ARCHIVE, "size": 777, "sha256": "a" * 64},
    })
    return raw, base64.b64encode(sign_ed25519(seed, raw)) + b"\n"


class PeerUpdateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._servers = []
        for name, value in (("TRUSTED_KEYS", KEYS), ("_internet", True), ("_book", None)):
            patcher = patch.object(share_wiring, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(share_wiring, "APP_VERSION", "0.8.66")
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(share_wiring, "registry_bases", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    def _neighbour(self, blob):
        server = share_serve.ShareServer(
            share_serve.InstalledFiles(Path(self._tmp.name), []), host="127.0.0.1", allow_loopback=True,
            manifest_provider=lambda: blob,
        )
        server.start()
        self.addCleanup(server.stop)
        neighbour = share_discover.Neighbour("127.0.0.1", server.port)
        patcher = patch.object(share_internet, "find_internet_neighbours", return_value=[neighbour])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_switch_off_means_no_search(self) -> None:
        with patch.object(share_wiring, "_internet", False), patch.object(share_internet, "find_internet_neighbours") as find:
            self.assertIsNone(share_wiring.update_from_peers())
        find.assert_not_called()

    def test_update_is_built_from_the_verified_list_with_our_own_release_address(self) -> None:
        self._neighbour(_signed())
        update = share_wiring.update_from_peers()
        self.assertEqual((update.version, update.tag), (VERSION, f"v{VERSION}"))
        self.assertEqual((update.size, update.digest_sha256), (777, "a" * 64))
        self.assertTrue(update.download_url.startswith("https://git.zapret.moe/"))
        self.assertTrue(update.download_url.endswith(f"/v{VERSION}/{ARCHIVE}"))
        self.assertEqual([(item.path, item.sha256) for item in update.files], [("ZapretKVN.exe", "b" * 64)])
        self.assertEqual(update.manifest.version, VERSION)

    def test_forged_old_or_foreign_lists_give_nothing(self) -> None:
        for blob in (
            _signed(seed=OTHER),  # подпись чужим ключом
            _signed("0.8.66"),  # не новее установленной
            _signed("0.8.1"),  # старее
            _signed(product="zapret-gui"),  # чужой продукт
            (_signed()[0].replace(b"99.1.2.3", b"99.9.9.9"), _signed()[1]),  # подмена после подписи
        ):
            with self.subTest(blob=blob[0][:40]):
                self._neighbour(blob)
                self.assertIsNone(share_wiring.update_from_peers())

    def test_neighbour_serves_our_own_signed_list_from_the_installed_files(self) -> None:
        with patch.object(share_wiring, "BASE_DIR", Path(self._tmp.name)):
            self.assertIsNone(share_wiring.manifest_blob())
            target = Path(self._tmp.name).joinpath(*share_wiring.INSTALLED_LIST)
            target.parent.mkdir(parents=True)
            target.write_bytes(b"LIST")
            target.with_name(target.name + ".sig").write_bytes(b"SIG")
            self.assertEqual(share_wiring.manifest_blob(), (b"LIST", b"SIG"))


class FindAvailableUpdateHookTests(unittest.TestCase):
    def _client(self, *, fails):
        class Client:
            def __init__(self, _proxy):
                pass

            def fetch_release(self):
                if fails:
                    raise OSError("blocked")
                return {"tag_name": "v0.8.66", "assets": []}  # не новее: «обновлений нет»

        return Client

    def test_peers_are_asked_only_when_the_release_server_failed(self) -> None:
        sentinel = SimpleNamespace(version="9.9.9")
        with patch.object(app_updater, "_ReleaseClient", self._client(fails=True)), patch.object(
            share_wiring, "update_from_peers", return_value=sentinel
        ) as peers:
            self.assertIs(app_updater._find_available_update(), sentinel)
        peers.assert_called_once_with()
        with patch.object(app_updater, "_ReleaseClient", self._client(fails=False)), patch.object(
            share_wiring, "update_from_peers"
        ) as peers:
            self.assertIsNone(app_updater._find_available_update())
        peers.assert_not_called()

    def test_without_peers_the_original_error_is_kept(self) -> None:
        for peers in (lambda: None, lambda: (_ for _ in ()).throw(RuntimeError("no peers"))):
            with patch.object(app_updater, "_ReleaseClient", self._client(fails=True)), patch.object(
                share_wiring, "update_from_peers", peers
            ):
                with self.assertRaises(OSError):
                    app_updater._find_available_update()


if __name__ == "__main__":
    unittest.main()
