"""Central winws2 blob and lua-extension registry.

winws2 resolves ``blob=<name>`` references inside ``--lua-desync`` arguments
against ``--blob=<name>:<source>`` definitions that must be present in the
global part of the command line.  Upstream zapret spreads those definitions
across every preset file; keeping a single registry here means a strategy
imported from the catalog stays runnable regardless of which preset hosts it.
"""

from __future__ import annotations

import re
from typing import Iterable

from ...constants import BASE_DIR

_BIN_DIR = BASE_DIR / "zapret" / "bin"
_LUA_DIR = BASE_DIR / "zapret" / "lua"

#: Blob name -> ``--blob=`` source, either ``@bin/<file>`` or an inline hex literal.
BLOB_REGISTRY: dict[str, str] = {
    "discord_active": "@bin/ACTIVE_DISCORD_UDP.bin",
    "dtls_w3": "@bin/dtls_clienthello_w3_org.bin",
    "fake_dbankcloud": "@bin/quic_initial_dbankcloud_ru.bin",
    "fake_http_max": "@bin/tls_clienthello_max_ru.bin",
    "fake_quic": "@bin/fake_quic.bin",
    "fake_quic_1": "@bin/fake_quic_1.bin",
    "fake_quic_2": "@bin/fake_quic_2.bin",
    "fake_quic_3": "@bin/fake_quic_3.bin",
    "fake_stun": "@bin/stun.bin",
    "fake_stun_as_tls": "@bin/stun.bin",
    "fake_tls": "@bin/fake_tls_1.bin",
    "fake_tls_1": "@bin/fake_tls_1.bin",
    "fake_tls_2": "@bin/fake_tls_2.bin",
    "fake_tls_3": "@bin/fake_tls_3.bin",
    "fake_tls_4": "@bin/fake_tls_4.bin",
    "fake_tls_5": "@bin/fake_tls_5.bin",
    "fake_tls_6": "@bin/fake_tls_6.bin",
    "fake_tls_7": "@bin/fake_tls_7.bin",
    "fake_tls_8": "@bin/fake_tls_8.bin",
    "game_active": "@bin/ACTIVE_GAME_UDP.bin",
    "http_max": "@bin/tls_clienthello_max_ru.bin",
    "http_req": "@bin/http_iana_org.bin",
    "quic1": "@bin/quic_1.bin",
    "quic2": "@bin/quic_2.bin",
    "quic3": "@bin/quic_3.bin",
    "quic4": "@bin/quic_4.bin",
    "quic5": "@bin/quic_5.bin",
    "quic6": "@bin/quic_6.bin",
    "quic7": "@bin/quic_7.bin",
    "quic_4pda": "@bin/quic_initial_4pda.to.bin",
    "quic_google": "@bin/quic_initial_www_google_com.bin",
    "quic_test": "@bin/quic_test_00.bin",
    "quic_vk": "@bin/quic_initial_vk_com.bin",
    "stun2": "@bin/stun2.bin",
    "stun_pat": "@bin/stun.bin",
    "syn_packet": "@bin/syn_packet.bin",
    "syndata3": "@bin/tls_clienthello_3.bin",
    "tls1": "@bin/tls_clienthello_1.bin",
    "tls10": "@bin/tls_clienthello_10.bin",
    "tls11": "@bin/tls_clienthello_11.bin",
    "tls12": "@bin/tls_clienthello_12.bin",
    "tls13": "@bin/tls_clienthello_13.bin",
    "tls14": "@bin/tls_clienthello_14.bin",
    "tls17": "@bin/tls_clienthello_17.bin",
    "tls18": "@bin/tls_clienthello_18.bin",
    "tls2": "@bin/tls_clienthello_2.bin",
    "tls2n": "@bin/tls_clienthello_2n.bin",
    "tls3": "@bin/tls_clienthello_3.bin",
    "tls4": "@bin/tls_clienthello_4.bin",
    "tls5": "@bin/tls_clienthello_5.bin",
    "tls6": "@bin/tls_clienthello_6.bin",
    "tls7": "@bin/tls_clienthello_7.bin",
    "tls8": "@bin/tls_clienthello_8.bin",
    "tls9": "@bin/tls_clienthello_9.bin",
    "tls_4pda": "@bin/tls_clienthello_4pda_to.bin",
    "tls_deepseek": "@bin/tls_clienthello_chat_deepseek_com.bin",
    "tls_google": "@bin/tls_clienthello_www_google_com.bin",
    "tls_gosuslugi": "@bin/tls_clienthello_gosuslugi_ru.bin",
    "tls_iana": "@bin/tls_clienthello_iana_org.bin",
    "tls_max": "@bin/tls_clienthello_max_ru.bin",
    "tls_sber": "@bin/tls_clienthello_sberbank_ru.bin",
    "tls_sber_v2": "@bin/tls_clienthello_sberbank_ru_v2.bin",
    "tls_stun": "@bin/stun.bin",
    "tls_vk": "@bin/tls_clienthello_vk_com.bin",
    "tls_vk_kyber": "@bin/tls_clienthello_vk_com_kyber.bin",
    "zero256": "@bin/zero_256.bin",
    "fake_default_udp": "0x00000000000000000000000000000000",
    "hex_00": "0x00",
    "hex_0e0e0f0e": "0x0E0E0F0E",
    "hex_0f0e0e0f": "0x0F0E0E0F",
    "hex_0f0f0f0f": "0x0F0F0F0F",
    "tls_zero4": "0x00000000",
    "zero64": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
}

#: Names the engine provides on its own.  Declaring them breaks winws2 startup.
BUILTIN_BLOBS = frozenset({
    "fake_default_tls",
    "fake_default_quic",
    "fake_default_http",
    "fake_unknown_256",
    "fake_zero64",
})

#: Always loaded, in this order, before any strategy argument.
CORE_LUA_FILES: tuple[str, ...] = ("zapret-lib.lua", "zapret-antidpi.lua")

#: desync function -> lua file that defines it, for functions living outside the core.
#: ``tests/test_zapret_blobs.py`` re-derives this map from the shipped lua sources.
LUA_EXTENSION_FUNCS: dict[str, str] = {
    "discord_ecn_exploit": "custom_funcs.lua",
    "discord_router_alert": "custom_funcs.lua",
    "discord_timestamp_travel": "custom_funcs.lua",
    "discord_ultimate_combo": "custom_funcs.lua",
    "discord_urgent_sni": "custom_funcs.lua",
    "discord_window_collapse": "custom_funcs.lua",
    "fakemultidisorder": "fakemultidisorder.lua",
    "fakemultisplit": "fakemultisplit.lua",
    "hostfakesplit_multi": "zapret-multishake.lua",
    "multisplit_tls": "custom_funcs.lua",
    "tls_aggressive": "custom_funcs.lua",
    "tls_disorder_gentle": "custom_funcs.lua",
    "tls_fake_disorder_gentle": "custom_funcs.lua",
    "tls_fake_flood": "custom_funcs.lua",
    "tls_fake_simple": "custom_funcs.lua",
    "tls_fake_split": "custom_funcs.lua",
    "tls_multisplit_sni": "custom_funcs.lua",
    "tls_split_gentle": "custom_funcs.lua",
}

# ``fake_blob=`` and ``fakedsplit_pattern=`` are covered by the two alternatives
# below because both end in ``blob=`` / ``pattern=`` respectively.
_BLOB_REFERENCE_RE = re.compile(r"(?:blob|pattern)=([A-Za-z0-9_]+)")
_DESYNC_FUNC_RE = re.compile(r"--lua-desync=([a-z0-9_]+)", re.IGNORECASE)


def blob_names_in_args(args: Iterable[str]) -> tuple[str, ...]:
    """Blob names a strategy actually references, in first-seen order.

    The catalog's own ``blobs =`` metadata is unreliable — 14 names used by
    winws2 arguments are never declared there — so dependencies are derived
    from the arguments themselves.  Inline ``0x…`` literals need no definition.
    """

    found: dict[str, None] = {}
    for argument in args:
        for name in _BLOB_REFERENCE_RE.findall(str(argument)):
            if name.lower().startswith("0x") or name in BUILTIN_BLOBS:
                continue
            found.setdefault(name, None)
    return tuple(found)


def blob_argument(name: str) -> str | None:
    """``--blob=`` definition for one name, or None when it is not resolvable."""

    source = BLOB_REGISTRY.get(name)
    return f"--blob={name}:{source}" if source else None


def blob_arguments(names: Iterable[str]) -> tuple[str, ...]:
    """``--blob=`` definitions for every resolvable name, deduplicated."""

    seen: dict[str, None] = {}
    for name in names:
        argument = blob_argument(name)
        if argument:
            seen.setdefault(argument, None)
    return tuple(seen)


def unresolved_blob_names(names: Iterable[str]) -> tuple[str, ...]:
    """Names that are neither engine builtins nor present in the registry."""

    return tuple(
        name for name in dict.fromkeys(names)
        if name not in BLOB_REGISTRY and name not in BUILTIN_BLOBS
    )


def missing_blob_files() -> tuple[str, ...]:
    """Registry entries whose backing ``@bin`` file is absent from the shipment."""

    missing = []
    for name, source in sorted(BLOB_REGISTRY.items()):
        if not source.startswith("@bin/"):
            continue
        if not (_BIN_DIR / source.removeprefix("@bin/")).is_file():
            missing.append(name)
    return tuple(missing)


def lua_files_for_args(args: Iterable[str]) -> tuple[str, ...]:
    """Extension lua files required by the desync functions used in ``args``."""

    seen: dict[str, None] = {}
    for argument in args:
        for func in _DESYNC_FUNC_RE.findall(str(argument)):
            lua_file = LUA_EXTENSION_FUNCS.get(func.lower())
            if lua_file and (_LUA_DIR / lua_file).is_file():
                seen.setdefault(lua_file, None)
    return tuple(seen)


def lua_init_arguments(args: Iterable[str]) -> tuple[str, ...]:
    """``--lua-init=`` arguments needed on top of the core ones for ``args``."""

    return tuple(f"--lua-init=@lua/{name}" for name in lua_files_for_args(args))
