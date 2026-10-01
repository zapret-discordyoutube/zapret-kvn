from __future__ import annotations

import json
import unittest
from unittest.mock import patch
import urllib.error

from xray_fluent.updates import app_updater
from xray_fluent.network.http_utils import HttpFetchError, HttpResponseData


def _response(payload: bytes, url: str) -> HttpResponseData:
    return HttpResponseData(payload, url, 200, "proxy")


class AppUpdateCheckTests(unittest.TestCase):
    def test_release_client_uses_active_proxy_and_bounded_retry_policy(self) -> None:
        payload = json.dumps({"tag_name": "v0.4.86", "assets": []}).encode()
        with patch.object(
            app_updater,
            "fetch_bytes",
            return_value=_response(payload, app_updater.FORGEJO_RELEASE_API),
        ) as fetch:
            result = app_updater._ReleaseClient(
                "http://127.0.0.1:1391"
            ).fetch_release()

        self.assertEqual(result["tag_name"], "v0.4.86")
        kwargs = fetch.call_args.kwargs
        self.assertEqual(kwargs["proxy_url"], "http://127.0.0.1:1391")
        self.assertEqual(kwargs["attempts_per_route"], 2)
        self.assertTrue(kwargs["prefer_proxy"])
        self.assertEqual(kwargs["max_bytes"], 1024 * 1024)
        self.assertEqual(kwargs["fallback_http_statuses"], frozenset({451}))

    def test_checksum_sidecar_uses_same_transport_and_size_limit(self) -> None:
        asset_name = "ZapretKVN-v9.9.9-windows-x64.zip"
        asset_url = (
            "https://git.zapret.moe/zapretkvn/zapret-kvn/"
            f"releases/download/v9.9.9/{asset_name}"
        )
        checksum_url = asset_url + ".sha256"
        metadata = {
            "tag_name": "v9.9.9",
            "assets": [
                {"name": asset_name, "browser_download_url": asset_url, "size": 10},
                {"name": asset_name + ".sha256", "browser_download_url": checksum_url},
            ],
        }
        digest = "a" * 64
        responses = [
            _response(json.dumps(metadata).encode(), app_updater.FORGEJO_RELEASE_API),
            _response((digest + "  " + asset_name).encode(), checksum_url),
        ]

        with patch.object(app_updater, "fetch_bytes", side_effect=responses) as fetch:
            update = app_updater._find_available_update("http://127.0.0.1:1391")

        self.assertIsNotNone(update)
        self.assertEqual(update.digest_sha256, digest)
        self.assertEqual(fetch.call_args_list[1].kwargs["max_bytes"], 16 * 1024)
        self.assertEqual(
            fetch.call_args_list[1].kwargs["proxy_url"],
            "http://127.0.0.1:1391",
        )

    def test_untrusted_release_api_redirect_is_rejected(self) -> None:
        payload = json.dumps({"tag_name": "v0.4.86", "assets": []}).encode()
        with patch.object(
            app_updater,
            "fetch_bytes",
            return_value=_response(payload, "https://example.com/releases/latest"),
        ):
            with self.assertRaisesRegex(ValueError, "недоверенный"):
                app_updater._ReleaseClient().fetch_release()

    def test_network_exhaustion_has_friendly_error_without_raw_urllib(self) -> None:
        error = HttpFetchError((TimeoutError("handshake timed out"),))
        message = app_updater._describe_update_check_error(error, has_proxy=False)

        self.assertIn("временно не отвечает", message)
        self.assertNotIn("urllib", message)
        self.assertNotIn("handshake", message)

    def test_451_without_proxy_recommends_connecting(self) -> None:
        cause = urllib.error.HTTPError(
            app_updater.FORGEJO_RELEASE_API,
            451,
            "Unavailable For Legal Reasons",
            {},
            None,
        )
        message = app_updater._describe_update_check_error(
            HttpFetchError((cause,)),
            has_proxy=False,
        )

        self.assertIn("Подключитесь к серверу", message)
        self.assertNotIn("Unavailable", message)

    def test_update_checker_emits_friendly_network_error(self) -> None:
        checker = app_updater.UpdateChecker()
        emitted: list[str] = []
        checker.error.connect(emitted.append)

        with (
            patch.object(
                app_updater,
                "_find_available_update",
                side_effect=HttpFetchError((TimeoutError("handshake timed out"),)),
            ),
            patch.object(app_updater._log, "warning"),
        ):
            checker.run()

        self.assertEqual(len(emitted), 1)
        self.assertIn("временно не отвечает", emitted[0])
        self.assertNotIn("handshake", emitted[0])


if __name__ == "__main__":
    unittest.main()


class UpdateDownloaderTests(unittest.TestCase):
    """Загрузчик отдаёт установщику распакованную сборку или внятный отказ."""

    def _downloader(self, files: dict[str, str], *, digest: str | None = None):
        import hashlib
        import io
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as bundle:
            for name, text in files.items():
                bundle.writestr(name, text)
        payload = buffer.getvalue()
        update = app_updater.AppUpdate(
            version="9.9.9",
            tag="v9.9.9",
            download_url="https://git.zapret.moe/zapretkvn/zapret-kvn/releases/download/v9.9.9/a.zip",
            size=len(payload),
            notes="",
            digest_sha256=hashlib.sha256(payload).hexdigest() if digest is None else digest,
        )
        downloader = app_updater.UpdateDownloader(update)
        downloader._download = lambda archive, proxy_url: archive.write_bytes(payload)
        self.errors: list[str] = []
        downloader.error.connect(self.errors.append)
        return downloader

    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        patcher = patch.object(app_updater.tempfile, "gettempdir", return_value=self._tmp.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(
            app_updater.tempfile, "mkdtemp",
            side_effect=lambda prefix: self._make_work_dir(prefix),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _make_work_dir(self, prefix: str) -> str:
        from pathlib import Path

        path = Path(self._tmp.name) / f"{prefix}test"
        path.mkdir()
        return str(path)

    def test_valid_archive_becomes_a_prepared_update(self) -> None:
        downloader = self._downloader({"ZapretKVN/ZapretKVN.exe": "exe", "ZapretKVN/core/xray.exe": "x"})
        downloader.run()
        self.assertEqual(self.errors, [])
        prepared = downloader.prepared
        self.assertEqual(prepared.version, "9.9.9")
        self.assertTrue((prepared.source_dir / "ZapretKVN.exe").is_file())
        self.assertEqual(prepared.source_dir.name, "ZapretKVN")
        self.assertEqual(prepared.source_dir.parent.parent, prepared.work_dir)
        # Архив после распаковки не нужен.
        self.assertFalse((prepared.work_dir / "update.zip").exists())

    def test_wrong_checksum_is_a_permanent_failure_and_leaves_nothing_behind(self) -> None:
        downloader = self._downloader({"ZapretKVN/ZapretKVN.exe": "exe"}, digest="0" * 64)
        downloader.run()
        self.assertIsNone(downloader.prepared)
        self.assertTrue(downloader.failure_permanent)
        self.assertEqual(self.errors, ["Контрольная сумма архива не совпадает"])
        self.assertEqual(list(__import__("pathlib").Path(self._tmp.name).iterdir()), [])

    def test_archive_without_the_application_is_rejected(self) -> None:
        downloader = self._downloader({"readme.txt": "nothing here"})
        downloader.run()
        self.assertIsNone(downloader.prepared)
        self.assertTrue(downloader.failure_permanent)

    def test_network_failure_is_not_permanent(self) -> None:
        downloader = self._downloader({"ZapretKVN/ZapretKVN.exe": "exe"})

        def offline(archive, proxy_url):
            raise OSError("no route")

        downloader._download = offline
        downloader.run()
        self.assertIsNone(downloader.prepared)
        self.assertFalse(downloader.failure_permanent)
        self.assertEqual(len(self.errors), 1)
