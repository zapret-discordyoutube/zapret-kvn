"""Патч поиска процесса-владельца в sing-box доходит до релизной сборки.

Проверяется связка без запуска Go: патч затрагивает только Windows-поиск,
сборщик применяет его и прогоняет Go-тесты, провенанс хранит sha256 патча,
а отпечаток кэша бандла ядер меняется при правке патча или его теста —
иначе гейт win10 переиспользовал бы старый sing-box.exe без исправления.
"""
from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.core_bundle_fingerprint import fingerprint

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from scripts import build_singbox_front as builder  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "core-patches/singbox-process-lookup-cache.patch"
GO_TEST = ROOT / "core-patches/singbox_process_lookup_test.go"


class SingboxProcessLookupPatchTests(unittest.TestCase):
    def test_patch_touches_only_windows_process_lookup(self):
        touched = re.findall(r"^diff --git a/(\S+) b/", PATCH.read_text(encoding="utf-8"), re.MULTILINE)
        self.assertEqual(
            sorted(touched),
            ["common/process/searcher_windows.go", "common/process/zapret_pid_table_cache.go"],
        )

    def test_cache_constants_respect_port_reuse_bound(self):
        text = PATCH.read_text(encoding="utf-8")
        ttl = re.search(r"pidTableSnapshotTTL\s*=\s*(\d+)\s*\*\s*time\.Millisecond", text)
        interval = re.search(r"pidTableMinRefreshInterval\s*=\s*(\d+)\s*\*\s*time\.Millisecond", text)
        self.assertIsNotNone(ttl)
        self.assertIsNotNone(interval)
        self.assertLessEqual(int(ttl.group(1)), 500)
        self.assertLessEqual(int(interval.group(1)), 50)

    def test_builder_applies_patch_runs_go_tests_and_records_provenance(self):
        builder_text = (ROOT / "scripts/build_singbox_front.py").read_text(encoding="utf-8")
        for fragment in (
            'PROCESS_LOOKUP_PATCH = "singbox-process-lookup-cache.patch"',
            "apply_process_lookup_patch(source, process_patch)",
            "assert_process_lookup_patch_needed(source, dependency)",
            "singbox_process_lookup_test.go",
            "'./common/process', '-run', '^TestZapret'",
            '"process_lookup_patch_sha256": sha256(process_patch)',
        ):
            self.assertIn(fragment, builder_text)
        self.assertTrue(GO_TEST.read_text(encoding="utf-8").startswith("package process"))

    def test_core_bundle_cache_key_tracks_patch_and_go_test(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            for name in (
                "build_core_bundle.ps1", "build_singbox_front.py", "prepare_sing_udp_patch.py",
                "core_bundle_fingerprint.py", "core-lock.windows-x64.json",
            ):
                shutil.copyfile(ROOT / "scripts" / name, root / "scripts" / name)
            shutil.copytree(ROOT / "core-patches", root / "core-patches")
            shutil.copytree(ROOT / "runtime/amnezia", root / "runtime/amnezia")
            previous = fingerprint(root)
            for name in (
                "core-patches/singbox-process-lookup-cache.patch",
                "core-patches/singbox_process_lookup_test.go",
            ):
                path = root / name
                path.write_bytes(path.read_bytes() + b"\n")
                current = fingerprint(root)
                self.assertNotEqual(previous, current, name)
                previous = current

    def test_real_patch_pins_full_upstream_base(self):
        text = PATCH.read_text(encoding="utf-8")
        self.assertIn(
            "diff --git a/common/process/searcher_windows.go b/common/process/searcher_windows.go\n"
            "index f011765705450e2c5150406f6573c3f4418ef021..",
            text,
        )
        # Our own patched searcher must not look like an upstream fix, or the
        # staleness guard would stop every build.
        added = "\n".join(line[1:] for line in text.splitlines() if line.startswith("+") and not line.startswith("+++"))
        searcher_part = added.split("package process", 2)[1]
        for marker in builder.UPSTREAM_OWNER_LOOKUP_MARKERS:
            self.assertNotIn(marker, searcher_part)

    def test_real_patch_applies_to_pinned_sources_from_go_cache(self):
        cache = Path.home() / "go/pkg/mod/github.com"
        singbox = cache / "shtorm-7/sing-box-extended@v1.14.1-extended-2.7.2"
        sing = cache / "shtorm-7/sing@v0.9.0-beta.4-extended-1.2.1"
        if not (singbox / "common/process/searcher_windows.go").is_file() or not sing.is_dir():
            self.skipTest("pinned sing-box sources are not in the local Go module cache")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            shutil.copytree(singbox / "common/process", source / "common/process")
            (source / "common/process").chmod(0o755)  # the Go module cache is read-only
            for path in (source / "common/process").iterdir():
                path.chmod(0o644)
            builder.apply_process_lookup_patch(source, PATCH)
            builder.assert_process_lookup_patch_needed(source, sing)
            self.assertIn("pidTableCache", (source / "common/process/searcher_windows.go").read_text(encoding="utf-8"))


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


class ProcessLookupStalenessGuardTests(unittest.TestCase):
    """Сборка останавливается, если upstream поменял поиск процесса или уже исправил его."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="zk-process-patch-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        repo = self.tmp / "repo"
        (repo / "common/process").mkdir(parents=True)
        searcher = repo / "common/process/searcher_windows.go"
        # Байты, а не write_text: на Windows текстовый режим пишет CRLF, и хеш
        # фикстуры не совпал бы с тем, что вернёт git show.
        searcher.write_bytes(b"package process\n\nfunc lookup() uint32 {\n\treturn scanWholeTable()\n}\n")
        _git(repo, "init", "-q")
        _git(repo, "add", "-A")
        _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base")
        searcher.write_bytes(b"package process\n\nfunc lookup() uint32 {\n\treturn cachedTable()\n}\n")
        (repo / "common/process/zapret_pid_table_cache.go").write_bytes(b"package process\n")
        _git(repo, "add", "-N", "common/process/zapret_pid_table_cache.go")
        self.patch = self.tmp / builder.PROCESS_LOOKUP_PATCH
        self.patch.write_text("Описание патча перед diff игнорируется git apply.\n\n" + _git(repo, "diff", "--full-index"), encoding="utf-8", newline="\n")
        self.source = self.tmp / "source"
        (self.source / "common/process").mkdir(parents=True)
        (self.source / "common/process/searcher_windows.go").write_bytes(subprocess.run(
            ["git", "show", "HEAD:common/process/searcher_windows.go"], cwd=repo, check=True, capture_output=True
        ).stdout)

    def test_pristine_upstream_is_patched(self):
        builder.apply_process_lookup_patch(self.source, self.patch)
        self.assertIn("cachedTable", (self.source / "common/process/searcher_windows.go").read_text(encoding="utf-8"))
        self.assertTrue((self.source / "common/process/zapret_pid_table_cache.go").is_file())

    def test_changed_upstream_searcher_stops_build(self):
        path = self.source / "common/process/searcher_windows.go"
        path.write_text(path.read_text(encoding="utf-8") + "\n// upstream change\n", encoding="utf-8", newline="\n")
        with self.assertRaises(builder.StaleProcessLookupPatch) as caught:
            builder.apply_process_lookup_patch(self.source, self.patch)
        message = str(caught.exception)
        self.assertIn("upstream изменил поиск процесса", message)
        self.assertIn("перенесите патч", message)
        self.assertIn("удалите", message)
        self.assertNotIn("cachedTable", path.read_text(encoding="utf-8"))

    def test_upstream_adding_our_file_stops_build(self):
        (self.source / "common/process/zapret_pid_table_cache.go").write_text("package process\n", encoding="utf-8", newline="\n")
        with self.assertRaisesRegex(builder.StaleProcessLookupPatch, "upstream изменил поиск процесса"):
            builder.apply_process_lookup_patch(self.source, self.patch)

    def test_upstream_owner_lookup_fix_marks_patch_stale(self):
        dependency = self.tmp / "sing"
        (dependency / "common/winiphlpapi").mkdir(parents=True)
        helper = dependency / "common/winiphlpapi/helper.go"
        helper.write_text("package winiphlpapi\n\nfunc FindPid() {}\n", encoding="utf-8", newline="\n")
        builder.assert_process_lookup_patch_needed(self.source, dependency)
        helper.write_text("package winiphlpapi\n\nfunc FindSocketOwner() {}\n", encoding="utf-8", newline="\n")
        with self.assertRaisesRegex(builder.StaleProcessLookupPatch, "вероятно, устарел"):
            builder.assert_process_lookup_patch_needed(self.source, dependency)

    def test_own_files_do_not_trigger_the_staleness_marker(self):
        (self.source / "common/process/zapret_pid_table_cache.go").write_text(
            "package process\n// shares one fetch, like singleflight\n", encoding="utf-8", newline="\n")
        builder.assert_process_lookup_patch_needed(self.source)


if __name__ == "__main__":
    unittest.main()
