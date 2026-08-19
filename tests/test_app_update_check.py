from __future__ import annotations

import json
import unittest
from unittest.mock import patch
import urllib.error

from xray_fluent import app_updater
from xray_fluent.http_utils import HttpFetchError, HttpResponseData


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
