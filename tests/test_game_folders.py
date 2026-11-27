"""A game is many processes: one rule on its folder covers all of them (owner request 2026-11-27, World of Warcraft)."""

import re
import unittest

from xray_fluent.platform.windows.running_programs import ProgramGroup, group_programs, install_root
from xray_fluent.singbox_config.simple_rule import build_rule, is_folder_entry, process_display, process_pattern
from xray_fluent.ui.singbox.running_programs_dialog import group_caption

WOW = "C:\\Program Files (x86)\\World of Warcraft\\"
WOW_PROCESSES = (
    "C:\\Program Files (x86)\\World of Warcraft\\_retail_\\Wow.exe",
    "C:\\Program Files (x86)\\World of Warcraft\\_retail_\\WowVoiceProxy.exe",
    "C:\\Program Files (x86)\\World of Warcraft\\Launcher.exe",
    "C:\\Program Files (x86)\\World of Warcraft\\_retail_\\Errors\\BlizzardError.exe",
    "c:\\program files (x86)\\world of warcraft\\_classic_\\WowClassic.exe",
)
NOT_WOW = (
    "C:\\Program Files (x86)\\World of Warcraft Other\\x.exe",
    "C:\\Program Files (x86)\\World of Warcraft",
    "C:\\Program Files (x86)\\Battle.net\\Battle.net.exe",
    "D:\\Games\\World of Warcraft\\_retail_\\Wow.exe",
)


class FolderRuleTests(unittest.TestCase):
    def test_a_folder_line_is_recognised(self) -> None:
        for line in (WOW, WOW.rstrip("\\") + "\\*", "C:/Games/WoW/", "C:/Games/WoW/*", f'"{WOW}"'):
            with self.subTest(line=line):
                self.assertTrue(is_folder_entry(line))
        for line in ("Wow.exe", "C:\\Games\\game.exe", "chrome"):
            with self.subTest(line=line):
                self.assertFalse(is_folder_entry(line))

    def test_one_folder_rule_matches_every_process_under_it(self) -> None:
        pattern = re.compile(process_pattern(WOW))
        for path in WOW_PROCESSES:
            with self.subTest(path=path):
                self.assertTrue(pattern.search(path))

    def test_it_does_not_match_a_sibling_with_a_longer_name_or_the_bare_folder(self) -> None:
        pattern = re.compile(process_pattern(WOW))
        for path in NOT_WOW:
            with self.subTest(path=path):
                self.assertFalse(pattern.search(path))

    def test_forward_slashes_and_a_star_give_the_same_rule(self) -> None:
        self.assertEqual(process_pattern("C:\\Games\\WoW\\"), process_pattern("C:/Games/WoW/*"))

    def test_the_rule_reads_back_as_the_folder(self) -> None:
        self.assertEqual(WOW, process_display(process_pattern(WOW)))

    def test_a_file_rule_is_unchanged(self) -> None:
        self.assertEqual("C:\\Games\\game.exe", process_display(process_pattern("C:\\Games\\game.exe")))
        self.assertEqual("chrome.exe", process_display(process_pattern("chrome.exe")))

    def test_the_folder_goes_into_the_built_rule(self) -> None:
        result = build_rule("direct", "", "", WOW + "\nBattle.net.exe", set(), except_russian=False)
        self.assertIsNotNone(result.rule, result.errors)
        self.assertEqual(2, len(result.rule["process_path_regex"]))


class InstallRootTests(unittest.TestCase):
    def test_every_wow_process_has_one_install_folder(self) -> None:
        self.assertEqual({WOW.lower()}, {install_root(path).lower() for path in WOW_PROCESSES})

    def test_known_launchers_and_stores(self) -> None:
        cases = {
            "C:\\Program Files (x86)\\Battle.net\\Battle.net.exe": "C:\\Program Files (x86)\\Battle.net\\",
            "C:\\ProgramData\\Battle.net\\Agent\\Agent.exe": "C:\\ProgramData\\Battle.net\\",
            "D:\\SteamLibrary\\steamapps\\common\\Dota 2\\game\\bin\\dota2.exe": "D:\\SteamLibrary\\steamapps\\common\\Dota 2\\",
            "D:\\Games\\Cyberpunk 2077\\bin\\x64\\Cyberpunk2077.exe": "D:\\Games\\Cyberpunk 2077\\",
            "E:\\Riot Games\\VALORANT\\live\\VALORANT.exe": "E:\\Riot Games\\",
            "C:\\Users\\me\\AppData\\Local\\Discord\\app-1.0\\Discord.exe": "C:\\Users\\me\\AppData\\Local\\Discord\\",
        }
        for path, root in cases.items():
            with self.subTest(path=path):
                self.assertEqual(root, install_root(path))

    def test_system_and_unreadable_paths_are_skipped(self) -> None:
        for path in ("C:\\Windows\\System32\\svchost.exe", "svchost.exe", "", "C:\\x.exe",
                     "C:\\Users\\me\\AppData\\Local\\Microsoft\\Teams\\a.exe", "C:\\Users\\me\\Downloads\\a.exe"):
            with self.subTest(path=path):
                self.assertIsNone(install_root(path))

    def test_the_busiest_folder_comes_first(self) -> None:
        groups = group_programs(WOW_PROCESSES + ("C:\\Program Files (x86)\\Battle.net\\Battle.net.exe",
                                                  "C:\\Windows\\explorer.exe"))
        self.assertEqual("World of Warcraft", groups[0].name)
        self.assertEqual(len(WOW_PROCESSES), groups[0].processes)
        self.assertEqual(["World of Warcraft", "Battle.net"], [group.name for group in groups])

    def test_the_picked_folder_covers_the_scanned_processes(self) -> None:
        root = group_programs(WOW_PROCESSES)[0].root
        pattern = re.compile(process_pattern(root))
        self.assertTrue(all(pattern.search(path) for path in WOW_PROCESSES))


class CaptionTests(unittest.TestCase):
    def test_russian_plural_forms(self) -> None:
        words = {1: "процесс", 2: "процесса", 4: "процесса", 5: "процессов", 11: "процессов", 12: "процессов",
                 21: "процесс", 22: "процесса", 25: "процессов", 100: "процессов", 101: "процесс"}
        for count, word in words.items():
            with self.subTest(count=count):
                self.assertEqual(f"Игра — {count} {word}", group_caption(ProgramGroup("C:\\Игра\\", "Игра", count)))


if __name__ == "__main__":
    unittest.main()
