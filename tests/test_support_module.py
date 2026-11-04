from __future__ import annotations

import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QCoreApplication, QEventLoop, QTimer

from xray_fluent.support import bundle as support_bundle
from xray_fluent.support import site as support_site
from xray_fluent.support.service import SupportAction, prepare_support

app = QCoreApplication.instance() or QCoreApplication([])

MIRROR_URL = "https://cwdnvtsqdc.zapret.moe/zapretkvn/zapret-kvn/issues/new"


def make_zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("meta.json", "{}")
    return path


class RedactionTests(unittest.TestCase):
    def test_windows_user_name_urls_and_secrets_are_removed(self) -> None:
        text = (
            r"open C:\Users\Ivan Petrov\AppData\x and C:\Users\Ivan\data"
            " fetch https://sub.example.com/abc123token/path "
            "token=SECRETVALUE password: hunter2 uuid=11111111-2222"
        )
        cleaned = support_bundle.redact_support_text(text)
        for leaked in ("Ivan", "abc123token", "SECRETVALUE", "hunter2", "11111111-2222"):
            self.assertNotIn(leaked, cleaned)
        self.assertIn(r"C:\Users\<user>", cleaned)
        self.assertIn("<URL скрыт>", cleaned)


class BundleTests(unittest.TestCase):
    def test_only_allowlisted_logs_enter_the_archive_and_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logs = root / "logs"
            logs.mkdir()
            (logs / "update.log").write_text(r"swap C:\Users\Ivan\app token=ABC", encoding="utf-8")
            (logs / "startup.log").write_text("started\n", encoding="utf-8")
            (logs / "private_dump.log").write_text("DO NOT SHIP", encoding="utf-8")
            archive_path = make_zip(root / "diagnostics.zip")
            bundle = support_bundle.append_support_files(archive_path, logs, mirror_tag="cw***.za***.moe:443#abc123")
            self.assertEqual(sorted(bundle.included), ["startup.log", "update.log"])
            self.assertIn("update_error.log", bundle.missing)
            with zipfile.ZipFile(archive_path) as archive:
                names = set(archive.namelist())
                self.assertEqual(names, {"meta.json", "logs/update.log", "logs/startup.log", "support.json"})
                body = archive.read("logs/update.log").decode()
                self.assertNotIn("Ivan", body)
                self.assertNotIn("ABC", body)
                info = json.loads(archive.read("support.json"))
            self.assertEqual(info["support_format"], 1)
            self.assertEqual(info["mirror"], "cw***.za***.moe:443#abc123")
            self.assertEqual(info["log_files"], ["update.log", "startup.log"])

    def test_big_log_is_cut_to_its_tail_without_a_torn_first_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logs = root / "logs"
            logs.mkdir()
            line = "строка журнала номер %06d\n"
            body = "".join(line % number for number in range(30000))
            (logs / "update.log").write_text(body, encoding="utf-8")
            archive_path = make_zip(root / "d.zip")
            support_bundle.append_support_files(archive_path, logs)
            with zipfile.ZipFile(archive_path) as archive:
                tail = archive.read("logs/update.log").decode()
            self.assertLessEqual(len(tail.encode()), support_bundle.MAX_TAIL_BYTES)
            self.assertTrue(tail.splitlines()[0].startswith("строка журнала номер"))
            self.assertTrue(tail.splitlines()[-1].endswith("029999"))


class SiteTests(unittest.TestCase):
    def test_open_mirror_is_used_when_it_proved_itself(self) -> None:
        with patch.object(support_site.site_names, "resolve", lambda url: MIRROR_URL), patch.object(
            support_site.site_names, "proven", lambda: True
        ):
            self.assertEqual(support_site.support_url(), MIRROR_URL)

    def test_entry_page_is_the_page_when_no_mirror_answered_the_app(self) -> None:
        with patch.object(support_site.site_names, "resolve", lambda url: "https://git2.zapret.moe/x"), patch.object(
            support_site.site_names, "proven", lambda: False
        ):
            url = support_site.support_url()
        self.assertEqual(url, support_site.entry_page_url())
        self.assertTrue(url.startswith("https://script.google.com/macros/s/"))
        self.assertIn("?s=git&p=zapretkvn/zapret-kvn/issues/new", url)
        self.assertNotIn("format=json", url)
        self.assertNotIn("github.com", url)

    def test_entry_page_is_also_used_when_discovery_itself_fails(self) -> None:
        def broken(url):
            raise OSError("network down")

        with patch.object(support_site.site_names, "resolve", broken):
            self.assertEqual(support_site.support_url(), support_site.entry_page_url())

    def test_github_is_never_a_support_page(self) -> None:
        self.assertFalse(hasattr(support_site, "GITHUB_SUPPORT_URL"))
        self.assertTrue(support_site.CANONICAL_SUPPORT_URL.endswith(support_site.SUPPORT_PATH))

    def test_entry_page_url_keeps_a_custom_path_and_drops_the_leading_slash(self) -> None:
        url = support_site.entry_page_url("/zapretkvn/zapret-kvn/issues")
        self.assertTrue(url.endswith("?s=git&p=zapretkvn/zapret-kvn/issues"), url)


class PrepareTests(unittest.TestCase):
    def test_support_json_names_the_mirror_only_masked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "logs").mkdir()
            archive_path = make_zip(root / "d.zip")
            result = prepare_support(archive_path, root / "logs", url_resolver=lambda: MIRROR_URL)
            self.assertEqual(result.url, MIRROR_URL)
            with zipfile.ZipFile(archive_path) as archive:
                info = json.loads(archive.read("support.json"))
            self.assertNotIn("cwdnvtsqdc", info["mirror"])
            self.assertIn("#", info["mirror"])


class ActionTests(unittest.TestCase):
    def run_action(self, **overrides):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "logs").mkdir()
            events: list[tuple] = []
            archive_path = make_zip(root / "d.zip")
            action = SupportAction(
                overrides.get("build_zip", lambda: archive_path),
                root / "logs",
                open_url=lambda url: events.append(("open", url)),
                reveal_file=lambda path: events.append(("reveal", Path(path).name)),
                url_resolver=overrides.get("url_resolver", lambda: MIRROR_URL),
            )
            loop = QEventLoop()
            action.finished_ok.connect(lambda result: (events.append(("ok", result.url)), loop.quit()))
            action.failed.connect(lambda message: (events.append(("failed", message)), loop.quit()))
            QTimer.singleShot(8000, loop.quit)
            started = action.start()
            if started:
                loop.exec()
                while action.running:
                    app.processEvents()
            return started, events

    def test_click_reveals_the_archive_then_opens_the_mirror_page(self) -> None:
        started, events = self.run_action()
        self.assertTrue(started)
        self.assertEqual([event[0] for event in events], ["reveal", "open", "ok"])
        self.assertEqual(events[0][1], "d.zip")
        self.assertEqual(events[1][1], MIRROR_URL)

    def test_failed_archive_build_is_reported_and_nothing_opens(self) -> None:
        def boom() -> Path:
            raise RuntimeError("disk full")

        started, events = self.run_action(build_zip=boom)
        self.assertFalse(started)
        self.assertEqual([event[0] for event in events], ["failed"])
        self.assertIn("disk full", events[0][1])

    def test_resolver_crash_is_reported_not_swallowed_silently(self) -> None:
        def crash() -> str:
            raise RuntimeError("boom")

        started, events = self.run_action(url_resolver=crash)
        self.assertTrue(started)
        self.assertEqual(events[0][0], "failed")
        self.assertIn("boom", events[0][1])
        self.assertNotIn("open", [event[0] for event in events])


if __name__ == "__main__":
    unittest.main()
