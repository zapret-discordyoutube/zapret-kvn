"""Страница «О нас»: бот сверху, каналы и главные ресурсы, каждая ссылка открывается."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import unittest
from unittest import mock

from PyQt6.QtWidgets import QApplication

_app = QApplication.instance() or QApplication([])

from qfluentwidgets import PushButton  # noqa: E402

from xray_fluent.ui.about_us import links  # noqa: E402
from xray_fluent.ui.about_us.page import AboutUsPage  # noqa: E402


class AboutUsLinksTests(unittest.TestCase):
    def test_bot_stands_first_then_channels_then_resources(self) -> None:
        self.assertEqual(links.ALL[0], links.BOT)
        self.assertEqual(links.ALL[1:], (*links.CHANNELS, *links.RESOURCES))

    def test_channels_are_the_four_telegram_links_in_order(self) -> None:
        self.assertEqual(
            [item.url for item in links.CHANNELS],
            [
                "https://t.me/bypassblock",
                "https://t.me/vpndiscordyooutube",
                "https://t.me/runetvpnyoutubediscord",
                "https://t.me/zastogram",
            ],
        )

    def test_resources_cover_wiki_git_and_both_backup_lists(self) -> None:
        urls = [item.url for item in links.RESOURCES]
        self.assertTrue(any(url.endswith("?s=wiki") for url in urls))
        self.assertTrue(any(url.endswith("?s=git") for url in urls))
        self.assertTrue(any(url.startswith("https://docs.google.com/document/d/") for url in urls))
        self.assertTrue(any(url.startswith("https://gist.github.com/") for url in urls))

    def test_every_link_is_unique_https_and_has_text(self) -> None:
        self.assertEqual(len(links.ALL), len({item.url for item in links.ALL}))
        for item in links.ALL:
            self.assertTrue(item.url.startswith("https://"), item.url)
            self.assertTrue(item.title.strip() and item.subtitle.strip(), item.url)


class AboutUsPageTests(unittest.TestCase):
    def test_page_has_one_button_per_link_in_order_and_each_opens_its_url(self) -> None:
        page = AboutUsPage()
        buttons = page.findChildren(PushButton)
        self.assertEqual([b.text() for b in buttons], [item.title for item in links.ALL])
        opened: list[str] = []
        with mock.patch("xray_fluent.ui.about_us.page.webbrowser.open", side_effect=opened.append):
            for button in buttons:
                button.click()
        self.assertEqual(opened, [item.url for item in links.ALL])


if __name__ == "__main__":
    unittest.main()
