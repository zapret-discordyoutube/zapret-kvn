from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
import zipfile

from xray_fluent.engines.singbox.core_updater import (
    ASSET_PATTERN,
    _install,
    is_newer,
    parse_version,
    resolve_release,
)


class SingboxCoreVersionTests(unittest.TestCase):
    """Тег несёт две версии сразу: ядра и набора расширений. Сравнивать нужно
    обе, иначе обновление внутри одной версии ядра осталось бы незамеченным."""

    def test_both_parts_of_the_tag_are_compared(self) -> None:
        self.assertEqual((1, 13, 18, 2, 6, 5), parse_version("v1.13.18-extended-2.6.5"))
        self.assertTrue(is_newer("v1.13.18-extended-2.6.5", "v1.13.14-extended-2.5.2"))
        # Ядро то же, расширения новее.
        self.assertTrue(is_newer("v1.13.18-extended-2.6.6", "v1.13.18-extended-2.6.5"))
        self.assertFalse(is_newer("v1.13.18-extended-2.6.5", "v1.13.18-extended-2.6.5"))
        self.assertFalse(is_newer("v1.13.14-extended-2.5.2", "v1.13.18-extended-2.6.5"))

    def test_unreadable_release_never_counts_as_newer(self) -> None:
        self.assertIsNone(parse_version("nightly"))
        self.assertFalse(is_newer("nightly", "v1.13.18-extended-2.6.5"))
        # Неизвестная установленная версия не мешает предложить обновление.
        self.assertTrue(is_newer("v1.13.18-extended-2.6.5", ""))

    def test_only_the_windows_purego_archive_is_accepted(self) -> None:
        self.assertTrue(ASSET_PATTERN.match("sing-box-1.13.18-extended-2.6.5-windows-amd64-purego.zip"))
        self.assertFalse(ASSET_PATTERN.match("sing-box-1.13.18-extended-2.6.5-linux-amd64.tar.gz"))
        self.assertFalse(ASSET_PATTERN.match("sing-box-1.13.18-extended-2.6.5-windows-arm64-purego.zip"))


class SingboxCoreInstallTests(unittest.TestCase):
    def test_install_replaces_the_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "core" / "sing-box.exe"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"old")

            archive = root / "core.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("sing-box-1.13.18/sing-box.exe", b"new")

            _install(archive, target)

            self.assertEqual(b"new", target.read_bytes())
            self.assertFalse((target.parent / "sing-box.exe.new").exists())

    def test_archive_without_the_executable_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "sing-box.exe"
            target.write_bytes(b"old")
            archive = root / "core.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("readme.txt", b"nothing here")

            with self.assertRaises(RuntimeError):
                _install(archive, target)
            # Прежнее ядро обязано остаться на месте.
            self.assertEqual(b"old", target.read_bytes())


if __name__ == "__main__":
    unittest.main()
