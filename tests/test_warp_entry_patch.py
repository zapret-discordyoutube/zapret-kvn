"""Core patch warp-entry-profile (WARP as the entry hop, owner decision 2026-11-25) reaches the release sing-box.exe.

The patch gives the `warp` endpoint a tunnel `mtu`, a private account file `profile.cache_path`, and the account's assigned
address as the default peer.  It is the same code as Android core patch 0022; only the context lines of endpoint.go differ,
because Android applies patch 0005 first.
"""
from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
PATCH = ROOT / "core-patches/warp-entry-profile.patch"
BUILDER = ROOT / "scripts/build_singbox_front.py"
ANDROID_PATCH = ROOT.parent / "android/core-patches/0022-warp-mtu-and-profile-cache.patch"

EDITED = ["option/cloudflare.go", "option/warp.go", "protocol/warp/endpoint.go"]
ADDED = [
    "protocol/warp/peer_endpoint.go",
    "protocol/warp/peer_endpoint_test.go",
    "protocol/warp/profile_cache.go",
    "protocol/warp/profile_cache_test.go",
]


def _new_file(text: str, name: str) -> str:
    match = re.search(rf"^diff --git a/{re.escape(name)} b/.*?(?=^diff --git |\Z)", text, re.MULTILINE | re.DOTALL)
    assert match, name
    return "\n".join(line[1:] for line in match.group(0).splitlines() if line.startswith("+") and not line.startswith("+++"))


class WarpEntryPatchTests(unittest.TestCase):
    def test_patch_edits_only_the_warp_endpoint_and_its_options(self) -> None:
        text = PATCH.read_text(encoding="utf-8")
        touched = re.findall(r"^diff --git a/(\S+) b/", text, re.MULTILINE)
        self.assertEqual(sorted(set(touched) - set(ADDED)), EDITED)
        self.assertEqual(sorted(set(touched) & set(ADDED)), ADDED)
        self.assertEqual(len(re.findall(r"^new file mode", text, re.MULTILINE)), len(ADDED))
        # apply_exact_patch needs full 40-character index lines
        self.assertEqual(len(re.findall(r"^index [0-9a-f]{40}\.\.[0-9a-f]{40}", text, re.MULTILINE)), len(touched))

    def test_new_go_files_are_the_same_as_android(self) -> None:
        if not ANDROID_PATCH.is_file():
            self.skipTest("android repository is not next to windows")
        android = ANDROID_PATCH.read_text(encoding="utf-8")
        windows = PATCH.read_text(encoding="utf-8")
        for name in ADDED:
            self.assertEqual(_new_file(windows, name), _new_file(android, name), name)

    def test_profile_file_is_private_and_mtu_is_bounded(self) -> None:
        text = PATCH.read_text(encoding="utf-8")
        self.assertIn("0o600", text)
        self.assertIn("minTunnelMTU     = 1280", text)
        self.assertIn("maxTunnelMTU     = 1420", text)

    def test_builder_applies_tests_and_records_the_patch(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        self.assertIn('WARP_ENTRY_PATCH = "warp-entry-profile.patch"', text)
        self.assertIn("apply_exact_patch(source, warp_patch", text)
        self.assertIn("'./protocol/warp'", text)
        self.assertIn('"warp_entry_patch_sha256"', text)
        # before the sing dependency is replaced, like the other source patches
        self.assertLess(text.index("apply_exact_patch(source, warp_patch"), text.index("prepare(source, stage"))

    def test_patch_applies_to_the_pinned_source_after_the_other_patches(self) -> None:
        from test_kvn_desync_patch import _pinned_source

        source = _pinned_source()
        if source is None or shutil.which("git") is None:
            self.skipTest("pinned sing-box module is not in the Go module cache")
        from build_singbox_front import apply_exact_patch, apply_process_lookup_patch

        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory) / "source"
            shutil.copytree(source, tree)
            for path in tree.rglob("*"):
                path.chmod(0o755 if path.is_dir() else 0o644)
            patches = ROOT / "core-patches"
            for name in ("singbox-dns-fallback-warning.patch", "browser-fetch.patch"):
                subprocess.run(["git", "apply", str(patches / name)], cwd=tree, check=True)
            apply_process_lookup_patch(tree, patches / "singbox-process-lookup-cache.patch")
            apply_exact_patch(tree, patches / "kvn-desync.patch", what="маршрутные опции", port_hint="тест")
            apply_exact_patch(tree, patches / "address-family-memory.patch", what="набор адресов сервера", port_hint="тест")
            apply_exact_patch(tree, PATCH, what="endpoint WARP", port_hint="тест")
            self.assertTrue((tree / "protocol/warp/profile_cache.go").is_file())
            self.assertIn("tunnelMTU", (tree / "protocol/warp/endpoint.go").read_text(encoding="utf-8"))


RECOVERY = ROOT / "core-patches/warp-entry-recovery.patch"
ANDROID_RECOVERY = ROOT.parent / "android/core-patches/0023-warp-start-recovery.patch"
RECOVERY_ADDED = ["protocol/warp/recovery.go", "protocol/warp/recovery_test.go"]


class WarpRecoveryPatchTests(unittest.TestCase):
    def test_patch_edits_only_the_warp_endpoint_and_adds_the_recovery(self) -> None:
        text = RECOVERY.read_text(encoding="utf-8")
        touched = re.findall(r"^diff --git a/(\S+) b/", text, re.MULTILINE)
        self.assertEqual(sorted(touched), sorted(["protocol/warp/endpoint.go", *RECOVERY_ADDED]))
        self.assertEqual(len(re.findall(r"^index [0-9a-f]{40}\.\.[0-9a-f]{40}", text, re.MULTILINE)), len(touched))

    def test_new_go_files_are_the_same_as_android(self) -> None:
        if not ANDROID_RECOVERY.is_file():
            self.skipTest("android repository is not next to windows")
        android = ANDROID_RECOVERY.read_text(encoding="utf-8")
        windows = RECOVERY.read_text(encoding="utf-8")
        for name in RECOVERY_ADDED:
            self.assertEqual(_new_file(windows, name), _new_file(android, name), name)

    def test_recovery_is_bounded_and_keeps_the_users_explicit_address(self) -> None:
        text = RECOVERY.read_text(encoding="utf-8")
        self.assertIn("startAttempts = 4", text)
        self.assertIn("probeTimeout = 4 * time.Second", text)
        self.assertIn("is the user's choice and is never rotated", text)
        self.assertIn('fallbackAddress = "162.159.192.1"', text)

    def test_builder_applies_the_recovery_after_the_profile_patch_and_records_it(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        self.assertIn('WARP_RECOVERY_PATCH = "warp-entry-recovery.patch"', text)
        self.assertIn('"warp_recovery_patch_sha256"', text)
        self.assertLess(text.index("apply_exact_patch(source, warp_patch"), text.index("apply_exact_patch(source, recovery_patch"))
        self.assertLess(text.index("apply_exact_patch(source, recovery_patch"), text.index("prepare(source, stage"))

    def test_patch_applies_after_the_profile_patch(self) -> None:
        from test_kvn_desync_patch import _pinned_source

        source = _pinned_source()
        if source is None or shutil.which("git") is None:
            self.skipTest("pinned sing-box module is not in the Go module cache")
        from build_singbox_front import apply_exact_patch

        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory) / "source"
            shutil.copytree(source, tree)
            for path in tree.rglob("*"):
                path.chmod(0o755 if path.is_dir() else 0o644)
            apply_exact_patch(tree, PATCH, what="endpoint WARP", port_hint="тест")
            apply_exact_patch(tree, RECOVERY, what="старт endpoint WARP", port_hint="тест")
            self.assertIn("startVerified", (tree / "protocol/warp/endpoint.go").read_text(encoding="utf-8"))


INTERFACE = ROOT / "core-patches/warp-entry-interface-update.patch"
ANDROID_INTERFACE = ROOT.parent / "android/core-patches/0024-warp-forward-interface-update.patch"
INTERFACE_ADDED = ["protocol/warp/interface_update.go", "protocol/warp/interface_update_test.go"]


class WarpInterfaceUpdatePatchTests(unittest.TestCase):
    def test_patch_only_adds_the_forwarding_and_its_test(self) -> None:
        text = INTERFACE.read_text(encoding="utf-8")
        touched = re.findall(r"^diff --git a/(\S+) b/", text, re.MULTILINE)
        self.assertEqual(sorted(touched), sorted(INTERFACE_ADDED))
        self.assertEqual(len(re.findall(r"^new file mode", text, re.MULTILINE)), len(INTERFACE_ADDED))
        self.assertEqual(len(re.findall(r"^index [0-9a-f]{40}\.\.[0-9a-f]{40}", text, re.MULTILINE)), len(touched))

    def test_new_go_files_are_the_same_as_android(self) -> None:
        if not ANDROID_INTERFACE.is_file():
            self.skipTest("android repository is not next to windows")
        android = ANDROID_INTERFACE.read_text(encoding="utf-8")
        windows = INTERFACE.read_text(encoding="utf-8")
        for name in INTERFACE_ADDED:
            self.assertEqual(_new_file(windows, name), _new_file(android, name), name)

    def test_forwarding_waits_for_the_started_inner_endpoint(self) -> None:
        text = INTERFACE.read_text(encoding="utf-8")
        self.assertIn("func (w *Endpoint) InterfaceUpdated(ctx context.Context)", text)
        self.assertIn("case <-w.await:", text)

    def test_builder_applies_the_patch_after_the_recovery_and_records_it(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        self.assertIn('WARP_INTERFACE_PATCH = "warp-entry-interface-update.patch"', text)
        self.assertIn('"warp_interface_patch_sha256"', text)
        self.assertLess(text.index("apply_exact_patch(source, recovery_patch"), text.index("apply_exact_patch(source, interface_patch"))
        self.assertLess(text.index("apply_exact_patch(source, interface_patch"), text.index("prepare(source, stage"))


CANDIDATES = ROOT / "core-patches/warp-entry-candidates.patch"
ANDROID_CANDIDATES = ROOT.parent / "android/core-patches/0025-warp-candidates.patch"
CANDIDATES_FILES = [
    "protocol/warp/edge_memory.go",
    "protocol/warp/edge_memory_test.go",
    "protocol/warp/endpoint.go",
    "protocol/warp/recovery.go",
    "protocol/warp/recovery_test.go",
]


class WarpCandidatesPatchTests(unittest.TestCase):
    """Eight start candidates and the edge memory (owner 2026-11-26): the same code as Android 0025."""

    def test_patch_touches_only_the_warp_package_files(self) -> None:
        text = CANDIDATES.read_text(encoding="utf-8")
        touched = re.findall(r"^diff --git a/(\S+) b/", text, re.MULTILINE)
        self.assertEqual(sorted(touched), sorted(CANDIDATES_FILES))
        # full-index lines: apply_exact_patch refuses a patch that does not name the exact blobs it changes
        self.assertEqual(len(re.findall(r"^index [0-9a-f]{40}\.\.[0-9a-f]{40}", text, re.MULTILINE)), len(touched))

    def test_new_go_files_are_the_same_as_android(self) -> None:
        if not ANDROID_CANDIDATES.is_file():
            self.skipTest("android repository is not next to windows")
        android = ANDROID_CANDIDATES.read_text(encoding="utf-8")
        windows = CANDIDATES.read_text(encoding="utf-8")
        for name in ("protocol/warp/edge_memory.go", "protocol/warp/edge_memory_test.go"):
            self.assertEqual(_new_file(windows, name), _new_file(android, name), name)

    def test_the_candidates_are_real_literal_edges_that_real_warp_answered(self) -> None:
        text = CANDIDATES.read_text(encoding="utf-8")
        for edge in ("188.114.97.1", "188.114.99.1", "188.114.96.1", "188.114.98.1"):
            self.assertIn(edge, text)
        # 162.159.193.1 and 204.1 did not answer the real handshake on any port (win10 sweep, 2026-11-26)
        for notedge in ('{"162.159.193.1"', '{"162.159.204.1"'):
            self.assertNotIn(notedge, text)

    def test_builder_applies_the_patch_after_the_interface_patch_and_records_it(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        self.assertIn('WARP_CANDIDATES_PATCH = "warp-entry-candidates.patch"', text)
        self.assertIn('"warp_candidates_patch_sha256"', text)
        self.assertLess(text.index("apply_exact_patch(source, interface_patch"), text.index("apply_exact_patch(source, candidates_patch"))
        self.assertLess(text.index("apply_exact_patch(source, candidates_patch"), text.index("prepare(source, stage"))


MASQUE = ROOT / "core-patches/warp-entry-masque.patch"
ANDROID_MASQUE = ROOT.parent / "android/core-patches/0026-warp-masque-fallback.patch"
MASQUE_FILES = [
    "option/warp.go",
    "protocol/masque/account_file.go",
    "protocol/masque/outbound.go",
    "protocol/warp/edge_memory.go",
    "protocol/warp/edge_memory_test.go",
    "protocol/warp/endpoint.go",
    "protocol/warp/interface_update.go",
    "protocol/warp/recovery.go",
    "protocol/warp/recovery_test.go",
    "protocol/warp/transport.go",
    "protocol/warp/transport_test.go",
]


class WarpMasquePatchTests(unittest.TestCase):
    """MASQUE as the way in where WireGuard is cut (owner 2026-11-26, mobile data): the same code as Android 0026."""

    def test_patch_touches_only_the_hop_files(self) -> None:
        text = MASQUE.read_text(encoding="utf-8")
        touched = re.findall(r"^diff --git a/(\S+) b/", text, re.MULTILINE)
        self.assertEqual(sorted(touched), sorted(MASQUE_FILES))
        self.assertEqual(len(re.findall(r"^index [0-9a-f]{40}\.\.[0-9a-f]{40}", text, re.MULTILINE)), len(touched))

    def test_new_go_files_are_the_same_as_android(self) -> None:
        if not ANDROID_MASQUE.is_file():
            self.skipTest("android repository is not next to windows")
        android = ANDROID_MASQUE.read_text(encoding="utf-8")
        windows = MASQUE.read_text(encoding="utf-8")
        for name in ("protocol/warp/transport.go", "protocol/warp/transport_test.go", "protocol/masque/account_file.go"):
            self.assertEqual(_new_file(windows, name), _new_file(android, name), name)

    def test_both_masque_transports_and_the_runtime_rotation_are_there(self) -> None:
        text = MASQUE.read_text(encoding="utf-8")
        for marker in ("transportMasqueQUIC", "transportMasqueHTTP2", "slowDial", "func (w *Endpoint) rotate()", "NoMasque"):
            self.assertIn(marker, text)

    def test_builder_applies_the_patch_after_the_candidates_patch_and_records_it(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        self.assertIn('WARP_MASQUE_PATCH = "warp-entry-masque.patch"', text)
        self.assertIn('"warp_masque_patch_sha256"', text)
        self.assertLess(text.index("apply_exact_patch(source, candidates_patch"), text.index("apply_exact_patch(source, masque_patch"))
        self.assertLess(text.index("apply_exact_patch(source, masque_patch"), text.index("prepare(source, stage"))


MASQUE_TIMING = ROOT / "core-patches/warp-entry-masque-timing.patch"
ANDROID_MASQUE_TIMING = ROOT.parent / "android/core-patches/0027-warp-masque-timing.patch"
MASQUE_TIMING_FILES = [
    "protocol/warp/endpoint.go",
    "protocol/warp/recovery.go",
    "protocol/warp/transport.go",
    "protocol/warp/transport_test.go",
]


class WarpMasqueTimingPatchTests(unittest.TestCase):
    """The dead tunnel is replaced without a 30 s wait and a MASQUE account still to be registered gets 20 s (Android 0027)."""

    def test_patch_touches_only_the_hop_files(self) -> None:
        text = MASQUE_TIMING.read_text(encoding="utf-8")
        touched = re.findall(r"^diff --git a/(\S+) b/", text, re.MULTILINE)
        self.assertEqual(sorted(touched), sorted(MASQUE_TIMING_FILES))
        self.assertEqual(len(re.findall(r"^index [0-9a-f]{40}\.\.[0-9a-f]{40}", text, re.MULTILINE)), len(touched))

    def test_the_start_probe_leaves_no_quiet_period_and_the_first_account_probe_is_long(self) -> None:
        text = MASQUE_TIMING.read_text(encoding="utf-8")
        for marker in ("func (w *Endpoint) adopt(", "w.lastSuccess = time.Time{}", "masqueFirstProbeTimeout = 20 * time.Second"):
            self.assertIn(marker, text)

    def test_the_hunks_are_the_same_as_android(self) -> None:
        if not ANDROID_MASQUE_TIMING.is_file():
            self.skipTest("android repository is not next to windows")
        android = ANDROID_MASQUE_TIMING.read_text(encoding="utf-8")
        windows = MASQUE_TIMING.read_text(encoding="utf-8")
        for needle in ("masqueFirstProbeTimeout", "func (w *Endpoint) adopt(", "TestTheStartProbePassingGivesNoQuietPeriod"):
            self.assertEqual(needle in android, needle in windows, needle)

    def test_builder_applies_the_patch_after_the_masque_patch_and_records_it(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        self.assertIn('WARP_MASQUE_TIMING_PATCH = "warp-entry-masque-timing.patch"', text)
        self.assertIn('"warp_masque_timing_patch_sha256"', text)
        self.assertLess(text.index("apply_exact_patch(source, masque_patch"), text.index("apply_exact_patch(source, masque_timing_patch"))
        self.assertLess(text.index("apply_exact_patch(source, masque_timing_patch"), text.index("prepare(source, stage"))


MASQUE_SNI = ROOT / "core-patches/warp-entry-masque-sni.patch"
ANDROID_MASQUE_SNI = ROOT.parent / "android/core-patches/0028-warp-masque-sni.patch"
MASQUE_SNI_FILES = [
    "protocol/warp/edge_memory.go",
    "protocol/warp/edge_memory_test.go",
    "protocol/warp/recovery.go",
    "protocol/warp/recovery_test.go",
    "protocol/warp/transport.go",
    "protocol/warp/transport_test.go",
]


class WarpMasqueSniPatchTests(unittest.TestCase):
    """MASQUE presents a decoy TLS server name, HTTP/2 before QUIC (owner 2026-11-26; Android 0028)."""

    def test_patch_touches_only_the_hop_files(self) -> None:
        text = MASQUE_SNI.read_text(encoding="utf-8")
        touched = re.findall(r"^diff --git a/(\S+) b/", text, re.MULTILINE)
        self.assertEqual(sorted(touched), sorted(MASQUE_SNI_FILES))
        self.assertEqual(len(re.findall(r"^index [0-9a-f]{40}\.\.[0-9a-f]{40}", text, re.MULTILINE)), len(touched))

    def test_decoy_names_come_before_cloudflares_own_and_http2_before_quic(self) -> None:
        text = MASQUE_SNI.read_text(encoding="utf-8")
        self.assertIn('var masqueDecoys = []string{"www.cloudflare.com", "yandex.ru"}', text)
        self.assertLess(text.index("{transport: transportMasqueHTTP2, sni: masqueDecoys[0]}"), text.index("{transport: transportMasqueQUIC, sni: masqueDecoys[0]}"))
        self.assertLess(text.index("{transport: transportMasqueQUIC, sni: masqueDecoys[0]}"), text.index("{transport: transportMasqueHTTP2},"))

    def test_the_candidate_code_is_the_same_as_android(self) -> None:
        if not ANDROID_MASQUE_SNI.is_file():
            self.skipTest("android repository is not next to windows")
        android = ANDROID_MASQUE_SNI.read_text(encoding="utf-8")
        windows = MASQUE_SNI.read_text(encoding="utf-8")
        for needle in ("masqueDecoys", "func tlsOptions(", "TestADecoyNameIsOnlyThePresentedServerName"):
            self.assertEqual(needle in android, needle in windows, needle)

    def test_builder_applies_the_patch_after_the_timing_patch_and_records_it(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        self.assertIn('WARP_MASQUE_SNI_PATCH = "warp-entry-masque-sni.patch"', text)
        self.assertIn('"warp_masque_sni_patch_sha256"', text)
        self.assertLess(text.index("apply_exact_patch(source, masque_timing_patch"), text.index("apply_exact_patch(source, masque_sni_patch"))
        self.assertLess(text.index("apply_exact_patch(source, masque_sni_patch"), text.index("prepare(source, stage"))


if __name__ == "__main__":
    unittest.main()
