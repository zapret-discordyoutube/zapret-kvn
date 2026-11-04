from __future__ import annotations

import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from xray_fluent.network.http_utils import HttpFetchError
from xray_fluent.updates import app_updater as au

GITHUB_PAYLOAD = {
    "tag_name": "v0.8.99",
    "assets": [
        {"name": "ZapretKVN-windows-x64.zip", "size": 1234, "digest": "sha256:" + "ab" * 32,
         "browser_download_url": "https://github.com/zapret-discordyoutube/zapret-kvn/releases/download/v0.8.99/ZapretKVN-windows-x64.zip"},
        {"name": "release-manifest.json", "size": 10, "digest": "",
         "browser_download_url": "https://github.com/zapret-discordyoutube/zapret-kvn/releases/download/v0.8.99/release-manifest.json"},
        {"name": "../evil", "size": 1, "digest": "", "browser_download_url": "https://evil.example/x"},
    ],
}


def reply(url: str, data: bytes = b"{}") -> SimpleNamespace:
    return SimpleNamespace(data=data, final_url=url, status=200, route="direct")


class NormalizeTests(unittest.TestCase):
    def test_github_release_becomes_a_forgejo_shaped_one_that_passes_the_trust_checks(self) -> None:
        release = au.normalize_github_release(GITHUB_PAYLOAD)
        self.assertEqual(release["tag_name"], "v0.8.99")
        names = [asset["name"] for asset in release["assets"]]
        self.assertEqual(names, ["ZapretKVN-windows-x64.zip", "release-manifest.json"])  # «../evil» отброшен
        for asset in release["assets"]:
            self.assertTrue(au._is_trusted_release_url(asset["browser_download_url"]), asset)
        self.assertEqual(release["assets"][0]["digest"], "sha256:" + "ab" * 32)

    def test_the_download_step_maps_the_normalized_url_back_to_github(self) -> None:
        url = au.normalize_github_release(GITHUB_PAYLOAD)["assets"][0]["browser_download_url"]
        self.assertEqual(
            au.github_asset_url(url),
            "https://github.com/zapret-discordyoutube/zapret-kvn/releases/download/v0.8.99/ZapretKVN-windows-x64.zip",
        )

    def test_bad_tags_are_rejected(self) -> None:
        for tag in ("", "v1/../x", "a/b"):
            with self.assertRaises(ValueError):
                au.normalize_github_release({"tag_name": tag, "assets": []})

    def test_only_githubs_own_https_hosts_are_trusted_for_files(self) -> None:
        good = (
            "https://github.com/zapret-discordyoutube/zapret-kvn/releases/download/v1/a.zip",
            "https://objects.githubusercontent.com/x/y",
            "https://release-assets.githubusercontent.com/x",
        )
        bad = (
            "http://github.com/a", "https://github.com.evil.example/a", "https://evil.example/github.com",
            "https://user:pw@github.com/a", "https://github.com:8443/a", "https://githubusercontent.com/a",
        )
        for url in good:
            self.assertTrue(au.is_trusted_github_file_url(url), url)
        for url in bad:
            self.assertFalse(au.is_trusted_github_file_url(url), url)


class ClientFallbackTests(unittest.TestCase):
    def client(self, handler):
        client = au._ReleaseClient(None)
        client._mirrors.hosts = lambda: ["git.zapret.moe"]
        client._mirrors.note_failure = lambda host, exc: None
        client._mirrors.forget = lambda: None
        client._fetch = lambda request, *, max_bytes: handler(request.full_url)
        return client

    def test_release_comes_from_github_when_every_mirror_is_down(self) -> None:
        seen: list[str] = []

        def handler(url: str):
            seen.append(url)
            if "api.github.com" in url:
                return reply(url, json.dumps(GITHUB_PAYLOAD).encode())
            raise HttpFetchError((OSError("tls reset"),))

        client = self.client(handler)
        release = client.fetch_release()
        self.assertEqual(release["tag_name"], "v0.8.99")
        self.assertTrue(client.github_fallback)
        self.assertTrue(any("git.zapret.moe" in url for url in seen))  # зеркала спрашивались первыми
        self.assertIn(au.GITHUB_RELEASE_API, seen)

    def test_mirror_answer_is_used_without_touching_github(self) -> None:
        seen: list[str] = []

        def handler(url: str):
            seen.append(url)
            return reply("https://git.zapret.moe/api/v1/repos/zapretkvn/zapret-kvn/releases/latest", b'{"tag_name":"v1.0.0","assets":[]}')

        client = self.client(handler)
        self.assertEqual(client.fetch_release()["tag_name"], "v1.0.0")
        self.assertFalse(client.github_fallback)
        self.assertFalse(any("api.github.com" in url for url in seen))

    def test_both_down_raises_the_mirror_error_not_a_github_one(self) -> None:
        def handler(url: str):
            raise HttpFetchError((OSError("down"),))

        client = self.client(handler)
        with self.assertRaises(HttpFetchError):
            client.fetch_release()
        self.assertFalse(client.github_fallback)

    def test_github_garbage_does_not_pass(self) -> None:
        def handler(url: str):
            if "api.github.com" in url:
                return reply(url, b'["not", "an", "object"]')
            raise HttpFetchError((OSError("down"),))

        client = self.client(handler)
        with self.assertRaises(HttpFetchError):
            client.fetch_release()

    def test_signed_files_go_to_github_first_after_a_github_release_and_to_forgejo_first_otherwise(self) -> None:
        forgejo = "https://git.zapret.moe/zapretkvn/zapret-kvn/releases/download/v0.8.99/release-manifest.json"
        github = "https://github.com/zapret-discordyoutube/zapret-kvn/releases/download/v0.8.99/release-manifest.json"
        for from_github, expected_first in ((True, github), (False, forgejo)):
            seen: list[str] = []

            def handler(url: str, _seen=seen):
                _seen.append(url)
                if len(_seen) == 1:
                    raise HttpFetchError((OSError("down"),))
                return reply(url, b"signed")

            client = self.client(handler)
            client.github_fallback = from_github
            self.assertEqual(client.fetch_signed(forgejo, 1000), b"signed")
            self.assertEqual(seen[0], expected_first)
            self.assertEqual(len(seen), 2)  # первый отказ — второй путь отдал файл

    def test_a_redirect_to_a_foreign_host_is_refused(self) -> None:
        forgejo = "https://git.zapret.moe/zapretkvn/zapret-kvn/releases/download/v0.8.99/release-manifest.json"
        client = self.client(lambda url: reply("https://evil.example/payload"))
        with self.assertRaises(ValueError):
            client.fetch_signed(forgejo, 1000)


if __name__ == "__main__":
    unittest.main()
