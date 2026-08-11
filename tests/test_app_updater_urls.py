import unittest

from xray_fluent.app_updater import _is_trusted_release_url


class AppUpdaterUrlPolicyTests(unittest.TestCase):
    def test_accepts_only_own_forgejo_release_assets(self) -> None:
        # Canonical owner and the legacy pre-rename owner are both trusted.
        accepted = (
            "https://git.zapret.moe/zapretkvn/"
            "zapret-kvn/releases/download/v0.4.79/"
            "ZapretKVN-v0.4.79-windows-x64.zip",
            "https://git.zapret.moe/zapretdiscordyoutube/"
            "zapret-kvn/releases/download/v0.4.76/"
            "ZapretKVN-v0.4.76-windows-x64.zip",
        )
        for url in accepted:
            with self.subTest(url=url):
                self.assertTrue(_is_trusted_release_url(url))

    def test_rejects_other_hosts_and_repository_paths(self) -> None:
        rejected = (
            "http://git.zapret.moe/zapretdiscordyoutube/"
            "zapret-kvn/releases/download/v0.4.76/file.zip",
            "https://example.com/zapretdiscordyoutube/"
            "zapret-kvn/releases/download/v0.4.76/file.zip",
            "https://git.zapret.moe/other/zapret-kvn/"
            "releases/download/v0.4.76/file.zip",
            "https://git.zapret.moe/zapretdiscordyoutube/"
            "zapret-kvn/archive/v0.4.76.zip",
        )
        for url in rejected:
            with self.subTest(url=url):
                self.assertFalse(_is_trusted_release_url(url))


if __name__ == "__main__":
    unittest.main()
