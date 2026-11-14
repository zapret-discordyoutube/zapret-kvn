"""Страница «О нас»: бот сверху, каналы и главные ресурсы, каждая ссылка открывается."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import re
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

from PyQt6.QtCore import QSize
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QApplication

_app = QApplication.instance() or QApplication([])

from qfluentwidgets import PushButton  # noqa: E402

from xray_fluent.ui.about_us import icons, links  # noqa: E402
from xray_fluent.ui.about_us.page import AboutUsPage, brand_qicon  # noqa: E402


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


def _near(color: QColor, hex_color: str, tolerance: int = 3) -> bool:
    """Края значка сглажены: при округлении прозрачности канал уходит на 1-2 единицы."""
    expected = QColor(hex_color)
    return (
        abs(color.red() - expected.red()) <= tolerance
        and abs(color.green() - expected.green()) <= tolerance
        and abs(color.blue() - expected.blue()) <= tolerance
    )


class BrandIconTests(unittest.TestCase):
    def test_every_link_names_a_known_logo_by_the_service_it_points_to(self) -> None:
        for item in links.ALL:
            self.assertIn(item.icon, icons.ALL, item.url)
            if item.url.startswith("https://t.me/"):
                expected = "telegram"
            elif item.url.startswith("https://gist.github.com/"):
                expected = "github"
            elif item.url.startswith("https://docs.google.com/"):
                expected = "googledocs"
            elif item.url.endswith("?s=git"):
                expected = "git"
            elif item.url.endswith("?s=wiki"):
                expected = "book"
            else:  # pragma: no cover - a new service needs its own rule here
                self.fail(f"no logo rule for {item.url}")
            self.assertEqual(item.icon, expected, item.url)

    def test_every_logo_is_valid_svg_24_by_24_with_real_path_data(self) -> None:
        for key, icon in icons.ALL.items():
            root = ET.fromstring(icon.svg("#ffffff"))
            self.assertTrue(root.tag.endswith("svg"), key)
            self.assertEqual(root.get("viewBox"), "0 0 24 24", key)
            paths = [el for el in root.iter() if el.tag.endswith("path")]
            self.assertEqual(len(paths), 1, key)
            self.assertGreater(len(paths[0].get("d")), 200, key)

    def test_brand_logos_keep_their_color_and_monochrome_ones_follow_the_fill(self) -> None:
        self.assertEqual(icons.TELEGRAM.brand, "#26A5E4")
        self.assertEqual(icons.GOOGLEDOCS.brand, "#4285F4")
        self.assertEqual(icons.GIT.brand, "#F05032")
        self.assertIn('fill="#26A5E4"', icons.TELEGRAM.svg("#ffffff"))
        self.assertIn('fill="#ffffff"', icons.GITHUB.svg("#ffffff"))
        self.assertIn('fill="#ffffff"', icons.BOOK.svg("#ffffff"))
        # На кнопке акцента всё красится одним цветом, иначе синий Telegram пропал бы.
        self.assertIn('fill="#ffffff"', icons.TELEGRAM.svg("#ffffff", mono=True))

    def test_no_emoji_in_link_texts(self) -> None:
        emoji = re.compile("[\U0001F000-\U0001FAFF\u2600-\u27BF\uFE0F\u200D]")
        for item in links.ALL:
            self.assertIsNone(emoji.search(item.title), item.title)
            self.assertIsNone(emoji.search(item.subtitle), item.subtitle)

    def test_icons_really_paint_pixels_in_their_own_color(self) -> None:
        for item in links.ALL:
            image = brand_qicon(item.icon).pixmap(QSize(48, 48)).toImage()
            painted = [
                QColor(image.pixel(x, y))
                for x in range(image.width())
                for y in range(image.height())
                if QColor.fromRgba(image.pixel(x, y)).alpha() > 200
            ]
            self.assertGreater(len(painted), 200, item.title)
        telegram = brand_qicon("telegram").pixmap(QSize(48, 48)).toImage()
        opaque = [
            QColor.fromRgba(telegram.pixel(x, y))
            for x in range(48)
            for y in range(48)
            if QColor.fromRgba(telegram.pixel(x, y)).alpha() > 200
        ]
        self.assertTrue(all(_near(c, "#26A5E4") for c in opaque))

    def test_icon_on_the_accent_button_is_white(self) -> None:
        image = brand_qicon("telegram", on_accent=True).pixmap(QSize(48, 48)).toImage()
        opaque = [
            QColor.fromRgba(image.pixel(x, y))
            for x in range(48)
            for y in range(48)
            if QColor.fromRgba(image.pixel(x, y)).alpha() > 200
        ]
        self.assertGreater(len(opaque), 200)
        self.assertTrue(all(_near(c, "#ffffff") for c in opaque))


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

    def test_every_button_shows_a_logo_not_an_empty_icon(self) -> None:
        page = AboutUsPage()
        for button, item in zip(page.findChildren(PushButton), links.ALL):
            self.assertFalse(button.icon().isNull(), item.title)
            self.assertFalse(button.icon().pixmap(QSize(24, 24)).isNull(), item.title)


if __name__ == "__main__":
    unittest.main()
