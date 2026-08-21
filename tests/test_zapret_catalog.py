"""Catalog, blob registry and default-preset contracts (AC1-AC8)."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from xray_fluent.zapret_blobs import (
    BLOB_REGISTRY,
    BUILTIN_BLOBS,
    LUA_EXTENSION_FUNCS,
    blob_arguments,
    blob_names_in_args,
    lua_init_arguments,
    missing_blob_files,
    unresolved_blob_names,
)
from xray_fluent.zapret_manager import DEFAULT_PRESET_NAME, ZapretManager
from xray_fluent.zapret_target import load_strategy_catalog

_ROOT = Path(__file__).resolve().parents[1]
_LUA_DIR = _ROOT / "zapret" / "lua"


class CatalogVolumeTests(unittest.TestCase):
    def test_catalog_carries_the_full_upstream_set(self) -> None:
        self.assertGreaterEqual(len(load_strategy_catalog("tcp")), 385)
        self.assertGreaterEqual(len(load_strategy_catalog("udp")), 60)

    def test_local_overlay_entries_stay_loadable(self) -> None:
        tcp = load_strategy_catalog("tcp")
        udp = load_strategy_catalog("udp")
        for strategy_id in ("alt9", "tls_fake_badseq", "multisplit_pos1"):
            self.assertIn(strategy_id, tcp)
        for strategy_id in ("general_bf_32", "fake_zero", "fake_default_quic"):
            self.assertIn(strategy_id, udp)

    def test_metadata_fields_are_parsed(self) -> None:
        entry = load_strategy_catalog("tcp")["alt9"]
        self.assertEqual(entry.author, "loop-uh")
        self.assertEqual(entry.label, "recommended")
        self.assertEqual(entry.label_title, "Рекомендуется")
        self.assertTrue(entry.description)

    def test_repeat_load_is_served_from_cache(self) -> None:
        first = load_strategy_catalog("tcp")
        self.assertIs(load_strategy_catalog("tcp"), first)

    def test_cache_is_invalidated_when_a_catalog_file_changes(self) -> None:
        """A shared cache that never expires would freeze edited catalogs."""

        from xray_fluent import zapret_target

        path = zapret_target._CATALOG_ROOT / "tcp.local.txt"
        before = load_strategy_catalog("tcp")
        original = path.read_bytes()
        try:
            path.write_bytes(
                original + b"\n[cache_probe_entry]\nname = cache probe\n--lua-desync=multisplit:pos=1\n"
            )
            after = load_strategy_catalog("tcp")
            self.assertIn("cache_probe_entry", after)
            self.assertNotIn("cache_probe_entry", before)
        finally:
            path.write_bytes(original)
            load_strategy_catalog("tcp")
        self.assertNotIn("cache_probe_entry", load_strategy_catalog("tcp"))

    def test_rejected_entries_are_reported_not_swallowed(self) -> None:
        """A silently vanishing strategy is the failure mode this replaced."""

        from xray_fluent import zapret_target

        path = zapret_target._CATALOG_ROOT / "tcp.local.txt"
        original = path.read_bytes()
        try:
            path.write_bytes(original + b"\n[reject_probe]\nname = reject probe\n--wf-tcp-out=443\n")
            with self.assertLogs("xray_fluent.zapret_target", level="WARNING") as captured:
                catalog = load_strategy_catalog("tcp")
            self.assertNotIn("reject_probe", catalog)
            self.assertTrue(any("reject_probe" in line for line in captured.output))
        finally:
            path.write_bytes(original)
            load_strategy_catalog("tcp")

    def test_labels_cover_the_upstream_vocabulary(self) -> None:
        labels = {entry.label for entry in load_strategy_catalog("tcp").values()}
        self.assertTrue({"recommended", "experimental", "stock"} <= labels)


class BlobRegistryTests(unittest.TestCase):
    def test_every_catalog_blob_name_resolves(self) -> None:
        for transport in ("tcp", "udp"):
            for entry in load_strategy_catalog(transport).values():
                with self.subTest(strategy=entry.strategy_id):
                    self.assertEqual(unresolved_blob_names(entry.blob_dependencies), ())

    def test_every_registry_file_is_shipped(self) -> None:
        self.assertEqual(missing_blob_files(), ())

    def test_dependencies_come_from_arguments_not_only_metadata(self) -> None:
        args = ("--lua-desync=fake:blob=stun_pat:repeats=6",)
        self.assertEqual(blob_names_in_args(args), ("stun_pat",))

    def test_inline_hex_and_builtins_are_never_declared(self) -> None:
        args = (
            "--lua-desync=fake:blob=0x00:payload=all",
            "--lua-desync=fake:blob=fake_default_tls",
        )
        self.assertEqual(blob_names_in_args(args), ())
        for builtin in BUILTIN_BLOBS:
            self.assertNotIn(builtin, BLOB_REGISTRY)

    def test_pattern_style_references_are_detected(self) -> None:
        args = (
            "--lua-desync=fakemultisplit:fake_blob=tls_google:seqovl_pattern=tls7",
        )
        self.assertEqual(set(blob_names_in_args(args)), {"tls_google", "tls7"})

    def test_blob_arguments_are_deduplicated(self) -> None:
        self.assertEqual(
            blob_arguments(("tls_google", "tls_google")),
            ("--blob=tls_google:@bin/tls_clienthello_www_google_com.bin",),
        )


class LuaExtensionTests(unittest.TestCase):
    def test_extension_map_matches_the_shipped_lua_sources(self) -> None:
        """The map is static for speed; the shipment is the source of truth."""

        pattern = re.compile(r"^function\s+([a-z0-9_]+)\s*\(\s*ctx\s*,\s*desync\s*\)", re.M)
        owners: dict[str, set[str]] = {}
        for path in _LUA_DIR.glob("*.lua"):
            for match in pattern.finditer(path.read_text(encoding="utf-8", errors="replace")):
                owners.setdefault(match.group(1), set()).add(path.name)
        for func, lua_file in LUA_EXTENSION_FUNCS.items():
            with self.subTest(func=func):
                self.assertIn(lua_file, owners.get(func, set()))

    def test_every_catalog_function_is_available(self) -> None:
        pattern = re.compile(r"^function\s+([a-z0-9_]+)\s*\(\s*ctx\s*,\s*desync\s*\)", re.M)
        defined: set[str] = set()
        for path in _LUA_DIR.glob("*.lua"):
            defined |= set(pattern.findall(path.read_text(encoding="utf-8", errors="replace")))
        used: set[str] = set()
        for transport in ("tcp", "udp"):
            for entry in load_strategy_catalog(transport).values():
                used |= {
                    match.group(1)
                    for arg in entry.args
                    for match in re.finditer(r"--lua-desync=([a-z0-9_]+)", arg)
                }
        self.assertEqual(used - defined, set())

    def test_extension_lua_init_is_emitted_for_extension_strategies(self) -> None:
        args = ("--lua-desync=fakemultisplit:fake_blob=tls_google:pos=1",)
        self.assertEqual(lua_init_arguments(args), ("--lua-init=@lua/fakemultisplit.lua",))

    def test_core_only_strategy_needs_no_extension(self) -> None:
        self.assertEqual(lua_init_arguments(("--lua-desync=multisplit:pos=1",)), ())


class DefaultPresetTests(unittest.TestCase):
    def test_default_preset_is_available(self) -> None:
        self.assertEqual(ZapretManager.default_preset(), DEFAULT_PRESET_NAME)

    def test_default_preset_falls_back_to_any_present_preset(self) -> None:
        real = ZapretManager.preset_path

        def only_missing_default(name: str):
            path = real(name)
            return path if name != DEFAULT_PRESET_NAME else Path("/nonexistent/none.txt")

        ZapretManager.preset_path = staticmethod(only_missing_default)
        try:
            fallback = ZapretManager.default_preset()
        finally:
            ZapretManager.preset_path = staticmethod(real)
        self.assertTrue(fallback)
        self.assertNotEqual(fallback, DEFAULT_PRESET_NAME)

    def test_preset_listing_survives_unreadable_files(self) -> None:
        from unittest import mock

        from xray_fluent import zapret_manager

        broken = zapret_manager.PRESETS_DIR / "zz-unreadable-probe.txt"
        broken.write_text("# Preset: probe\n--new\n", encoding="utf-8")
        real_read_text = Path.read_text

        def refuse_probe(self, *args, **kwargs):
            # chmod(0o000) does not make a file unreadable on Windows, so the
            # failure is injected instead of relying on POSIX permissions.
            if self.name == broken.name:
                raise OSError(13, "Permission denied")
            return real_read_text(self, *args, **kwargs)

        try:
            with mock.patch.object(Path, "read_text", refuse_probe):
                names = {info.name for info in ZapretManager.list_preset_infos()}
        finally:
            broken.unlink()
        self.assertNotIn("zz-unreadable-probe", names)
        self.assertIn(DEFAULT_PRESET_NAME, names)


if __name__ == "__main__":
    unittest.main()
