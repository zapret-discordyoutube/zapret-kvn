"""Патч browser-fetch доходит до релизного sing-box.exe.

Без запуска Go: патч только добавляет файлы (ложится на любую серию — и на
Windows-набор, и поверх Android 0001–0006), сборщик применяет его и гоняет
Go-тесты, провенанс хранит sha256, отпечаток кэша бандла ядер меняется при
правке патча — иначе гейт win10 переиспользовал бы старый sing-box.exe.
"""
from __future__ import annotations

from pathlib import Path
import re
import shutil
import tempfile
import unittest

from scripts.core_bundle_fingerprint import fingerprint

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "core-patches/browser-fetch.patch"
BUILDER = ROOT / "scripts/build_singbox_front.py"


class BrowserFetchPatchTests(unittest.TestCase):
    def test_patch_only_adds_files(self) -> None:
        text = PATCH.read_text(encoding="utf-8")
        touched = re.findall(r"^diff --git a/(\S+) b/", text, re.MULTILINE)
        self.assertEqual(sorted(touched), [
            "cmd/sing-box/cmd_tools_browser_fetch.go",
            "common/browserfetch/browserfetch.go",
            "common/browserfetch/browserfetch_stub.go",
            "common/browserfetch/dns_answer.go",
            "common/browserfetch/engine_other.go",
            "common/browserfetch/engine_unix.go",
            "common/browserfetch/socket_control_unix.go",
            "common/browserfetch/types.go",
            "common/browserfetch/zapret_browserfetch_test.go",
            "common/browserfetch/zapret_socket_control_test.go",
            "experimental/libbox/browser_fetch.go",
        ])
        self.assertEqual(len(re.findall(r"^new file mode", text, re.MULTILINE)), len(touched))
        self.assertNotRegex(text, r"(?m)^-(?!--)")

    def test_chromium_stack_and_https_only_are_kept(self) -> None:
        text = PATCH.read_text(encoding="utf-8")
        self.assertIn("github.com/sagernet/cronet-go", text)
        self.assertIn("SetEnableHTTP2(true)", text)
        self.assertIn("only https is allowed", text)
        self.assertIn("ChromeUserAgent(engine.Version())", text)
        # Android: без JavaVM системный DNS Chromium роняет процесс — свой DNS.
        self.assertIn("SetDNSServerOverride", text)
        # Окна HTTP/2 не трогаем: свои значения (как у naive) поменяли бы отпечаток.
        self.assertNotIn("SetHTTP2Options", text)
        # Путь загрузки тела в cronet-go падает SIGSEGV — тела отклоняются.
        self.assertIn("request bodies are not supported", text)
        self.assertNotIn("NewUploadDataProvider", text)
        # Имена — своим DoH тем же движком: на Windows локальный DNS-сервер,
        # подкоманда ставит TrustedDoH (иначе хост подписки — системным DNS).
        self.assertIn("SetResolver(browserfetch.TrustedDoH)", text)
        self.assertIn("listenLocalDNS", text)

    def test_builder_applies_tests_and_records_the_patch(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        self.assertIn('BROWSER_FETCH_PATCH = "browser-fetch.patch"', text)
        self.assertIn("'./common/browserfetch'", text)
        self.assertIn('"browser_fetch_patch_sha256"', text)
        self.assertIn("assert_browser_fetch_command(output)", text)

    def test_patch_edit_changes_the_core_bundle_fingerprint(self) -> None:
        lock = ROOT / "scripts/core-lock.windows-x64.json"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "scripts", root / "scripts")
            shutil.copytree(ROOT / "core-patches", root / "core-patches")
            shutil.copytree(ROOT / "runtime/amnezia", root / "runtime/amnezia")
            before = fingerprint(root, root / "scripts" / lock.name)
            patch = root / "core-patches/browser-fetch.patch"
            patch.write_text(patch.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            self.assertNotEqual(fingerprint(root, root / "scripts" / lock.name), before)


if __name__ == "__main__":
    unittest.main()
