"""Гонка семейств WG/AWG в zapret-amnezia.exe — та же, что в ядре Android (патч 0021).

Первое рукопожатие уходит на IPv6 и IPv4 сразу, сессия остаётся на семействе,
которое ответило. Код решения один на обе платформы: копия на Windows отличается
только именем пакета и шапкой, а raceAddresses не нужен (адреса даёт приложение).
"""
from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WINDOWS_COPY = ROOT / "runtime/amnezia/family_race.go"
ANDROID_PATCH = ROOT.parent / "android/core-patches/0021-wireguard-family-race.patch"
ANDROID_FILE = "transport/wireguard/family_race.go"


def _new_file(text: str, name: str) -> str:
    match = re.search(rf"^diff --git a/{re.escape(name)} b/.*?(?=^diff --git |\Z)", text, re.MULTILINE | re.DOTALL)
    assert match, name
    return "\n".join(line[1:] for line in match.group(0).splitlines() if line.startswith("+") and not line.startswith("+++"))


def _body(source: str) -> str:
    """Код после строки package, без raceAddresses."""
    lines = source.splitlines()
    start = next(index for index, line in enumerate(lines) if line.startswith("package ")) + 1
    body = "\n".join(lines[start:])
    cut = body.find("// raceAddresses picks")
    return (body[:cut] if cut >= 0 else body).strip()


class AmneziaFamilyRaceTests(unittest.TestCase):
    def test_windows_copy_is_the_android_race(self) -> None:
        if not ANDROID_PATCH.is_file():
            self.skipTest("android repository is not next to windows")
        android = _new_file(ANDROID_PATCH.read_text(encoding="utf-8"), ANDROID_FILE)
        windows = WINDOWS_COPY.read_text(encoding="utf-8")
        normalize = lambda text: text.replace(  # noqa: E731
            "off on mobile semantics), so the bind sends to targets() instead of the\n// engine's destination.",
            "off: main calls DisableSomeRoamingForBrokenMobileSemantics), so the bind\n// sends to targets() instead of the engine's destination.",
        )
        self.assertEqual(_body(windows), normalize(_body(android)))

    def test_helper_reports_only_the_family(self) -> None:
        main = (ROOT / "runtime/amnezia/main.go").read_text(encoding="utf-8")
        emit = main[main.index('j.emit("address_family"'):]
        emit = emit[: emit.index("\n")]
        self.assertIn('"family": family', emit)
        self.assertNotIn("address.String()", emit)


if __name__ == "__main__":
    unittest.main()
