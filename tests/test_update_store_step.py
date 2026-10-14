from __future__ import annotations

"""Лестница загрузки обновления: хранилище с заплатками → куски архива → архив целиком."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from xray_fluent.updates import app_updater
from zapret_update import manifest as update_manifest


def _manifest(*, with_store: bool):
    return update_manifest.parse({
        "schema": 1, "product": "zapret-kvn", "channel": "stable", "version": "9.9.9", "created": 1, "key": "k",
        "files": [{"path": "ZapretKVN.exe", "size": 3, "sha256": "a" * 64, "zsize": 2 if with_store else 0}],
    })


class StoreStepTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.app = Path(self._tmp.name) / "app"
        self.app.mkdir()

    def _downloader(self, manifest):
        update = app_updater.AppUpdate("9.9.9", "v9.9.9", "https://git.zapret.moe/x.zip", 100, "", "b" * 64, (), manifest)
        return app_updater.UpdateDownloader(update, app_dir=self.app)

    def test_release_without_a_store_skips_the_step(self) -> None:
        with patch("zapret_update.fetch.fetch_plan") as fetch:
            self.assertIsNone(self._downloader(_manifest(with_store=False))._try_store())
        fetch.assert_not_called()

    def test_store_builds_the_new_version_tree(self) -> None:
        tree = self.app / "data" / "runtime" / "app_update" / "store-9.9.9" / "tree"

        def build(planned, *, root, ready, stage_dir):
            stage_dir.mkdir(parents=True)
            (stage_dir / "ZapretKVN.exe").write_bytes(b"new")
            return stage_dir

        with patch("zapret_update.fetch.fetch_plan", return_value={}) as fetch, patch(
            "zapret_update.stage.build_stage", side_effect=build
        ):
            self.assertEqual(self._downloader(_manifest(with_store=True))._try_store(), tree)
        # Скачанное лежит в постоянной папке: после перезапуска загрузка продолжится.
        self.assertEqual(fetch.call_args.kwargs["work_dir"], tree.parent)
        self.assertIn("zapretkvn/generic/zapret-kvn-store/1/", fetch.call_args.kwargs["sources"][0].url_for("x.zst"))

    def test_failed_store_hands_over_to_the_next_step(self) -> None:
        from zapret_update.fetch import FetchError

        with patch("zapret_update.fetch.fetch_plan", side_effect=FetchError("нет сети")):
            self.assertIsNone(self._downloader(_manifest(with_store=True))._try_store())

    def test_store_comes_before_archive_pieces(self) -> None:
        downloader = self._downloader(_manifest(with_store=True))
        order = []
        downloader._try_store = lambda: order.append("store") or None
        downloader._try_delta = lambda work_dir: order.append("delta") or None
        downloader._fetch = lambda archive: (order.append("zip"), (_ for _ in ()).throw(app_updater.DownloadFailed("стоп")))
        with patch.object(app_updater, "_purge_stale_update_dirs"):
            downloader.run()
        self.assertEqual(order, ["store", "delta", "zip"])
