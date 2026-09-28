"""winws2 strategy catalogs and the rule chosen for the selected server.

A strategy is only the ``--lua-desync=`` body of a winws2 profile; where it is
applied (IP, transport, ports) comes from :mod:`.endpoint`.  Catalogs are the
vendored upstream ``<transport>.txt`` plus local ``<transport>.local.txt``
overrides under ``zapret/strategy_catalogs/winws2``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Iterable, Mapping

from ...constants import BASE_DIR
from ...profiles.models import ZapretTargetSettings
from .blobs import BUILTIN_BLOBS, blob_names_in_args
from .endpoint import ServerEndpoint, Transport

log = logging.getLogger(__name__)

_CATALOG_ROOT = BASE_DIR / "zapret" / "strategy_catalogs" / "winws2"

CUSTOM_STRATEGY_ID = "custom"

#: Catalog labels, ordered from most to least battle-tested.
STRATEGY_LABELS: tuple[str, ...] = (
    "recommended", "stable", "stock", "game", "experimental", "caution",
)
STRATEGY_LABEL_TITLES: dict[str, str] = {
    "recommended": "Рекомендуется",
    "stable": "Стабильная",
    "stock": "Штатная",
    "game": "Для игр",
    "experimental": "Экспериментальная",
    "caution": "Осторожно",
}


@dataclass(frozen=True, slots=True)
class Strategy:
    strategy_id: str
    transport: Transport
    name: str
    args: tuple[str, ...]
    description: str = ""
    blob_dependencies: tuple[str, ...] = ()
    author: str = ""
    label: str = ""

    @property
    def label_title(self) -> str:
        return STRATEGY_LABEL_TITLES.get(self.label, self.label)

    @property
    def is_pass(self) -> bool:
        return self.args == PASS_ARGS

    @property
    def search_haystack(self) -> str:
        return " ".join(
            (self.strategy_id, self.name, self.description, self.author, self.label, *self.args)
        ).casefold()


PASS_ARGS = ("--lua-desync=pass",)


def pass_strategy(transport: Transport) -> Strategy:
    """Leave the server's packets alone even if the preset would touch them."""

    return Strategy("pass", transport, "не трогать", PASS_ARGS)


#: Arguments a strategy may hold.  All of them act inside the one profile they
#: are placed in; profile separators, filters, capture and blob definitions
#: belong to the app (``--new``, ``--filter-*``, ``--wf-*``, ``--blob``).
#: ``--payload`` / ``--*-range`` switch what the following ``--lua-desync``
#: lines apply to — composite catalog strategies are built from them.
STRATEGY_ARGUMENTS = ("--lua-desync=", "--payload=", "--out-range=", "--in-range=")


def validate_custom_strategy(text: str) -> tuple[str, ...]:
    """Strategy lines: see :data:`STRATEGY_ARGUMENTS`; ``#`` starts a comment."""

    args: list[str] = []
    for raw in str(text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        prefix = next((item for item in STRATEGY_ARGUMENTS if line.startswith(item)), "")
        if not prefix or not line[len(prefix):].strip() or any(char.isspace() for char in line):
            raise ValueError(
                "Разрешены только строки --lua-desync=, --payload=, --out-range=, "
                "--in-range= и комментарии"
            )
        args.append(line)
    if not any(arg.startswith("--lua-desync=") for arg in args):
        raise ValueError("Стратегия не содержит ни одной строки --lua-desync")
    return tuple(args)


# ── catalog files ────────────────────────────────────────────────────────


def _entry(
    strategy_id: str, transport: Transport, metadata: dict[str, str], args: tuple[str, ...],
) -> Strategy:
    # ``blobs =`` metadata is incomplete upstream, so declared names are only a
    # hint — the authoritative set comes from the arguments themselves.
    declared = (item.strip() for item in metadata.get("blobs", "").split(","))
    dependencies = dict.fromkeys(
        name for name in declared
        if name and name not in BUILTIN_BLOBS and not name.lower().startswith("0x")
    )
    dependencies.update(dict.fromkeys(blob_names_in_args(args)))
    return Strategy(
        strategy_id=strategy_id,
        transport=transport,
        name=metadata.get("name", strategy_id),
        description=metadata.get("description", ""),
        args=args,
        blob_dependencies=tuple(dependencies),
        author=metadata.get("author", ""),
        label=metadata.get("label", "").strip().lower(),
    )


def _parse_catalog(path: Path, transport: Transport) -> dict[str, Strategy]:
    """``[id]`` sections of ``key = value`` metadata and ``--lua-desync`` lines."""

    if not path.is_file():
        return {}
    sections: list[tuple[str, dict[str, str], list[str]]] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            sections.append((line[1:-1].strip(), {}, []))
        elif not sections:
            continue
        elif line.startswith("--"):
            sections[-1][2].append(line)
        elif "=" in line:
            key, value = line.split("=", 1)
            sections[-1][1][key.strip().lower()] = value.strip()

    result: dict[str, Strategy] = {}
    rejected: list[str] = []
    for strategy_id, metadata, lines in sections:
        if not strategy_id or not lines:
            continue
        try:
            args = validate_custom_strategy("\n".join(lines))
        except ValueError as exc:
            rejected.append(f"{strategy_id}: {exc}")
            continue
        result[strategy_id] = _entry(strategy_id, transport, metadata, args)
    if rejected:
        log.warning(
            "Каталог %s: пропущено записей — %d (%s)",
            path.name, len(rejected), "; ".join(rejected[:5]),
        )
    return result


def _catalog_paths(transport: Transport) -> tuple[Path, ...]:
    """Vendored upstream catalog first, local overrides second."""

    return (
        _CATALOG_ROOT / f"{transport}.txt",
        _CATALOG_ROOT / f"{transport}.local.txt",
    )


def _catalog_signature(paths: Iterable[Path]) -> tuple[tuple[str, int, int], ...]:
    signature = []
    for path in paths:
        try:
            stat = path.stat()
        except OSError:
            continue
        signature.append((path.name, stat.st_mtime_ns, stat.st_size))
    return tuple(signature)


_CATALOG_CACHE: dict[
    Transport, tuple[tuple[tuple[str, int, int], ...], Mapping[str, Strategy]]
] = {}


def load_strategy_catalog(transport: Transport) -> Mapping[str, Strategy]:
    """Merged catalog for one transport, cached on file mtime/size, read-only."""

    paths = _catalog_paths(transport)
    signature = _catalog_signature(paths)
    cached = _CATALOG_CACHE.get(transport)
    if cached is not None and cached[0] == signature:
        return cached[1]
    merged: dict[str, Strategy] = {}
    for path in paths:
        merged.update(_parse_catalog(path, transport))
    catalog = MappingProxyType(merged)
    _CATALOG_CACHE[transport] = (signature, catalog)
    return catalog


# ── the rule for the selected server ─────────────────────────────────────


def chosen_strategy(settings: ZapretTargetSettings, kind: str) -> Strategy:
    """The strategy the user picked for a server kind (whether on or off).

    Raises ``ValueError`` for an own strategy that does not validate or an id
    missing from the catalog.
    """

    transport: Transport = "tcp" if kind == "tcp" else "udp"
    strategy_id = settings.strategy_id(kind)
    if strategy_id == CUSTOM_STRATEGY_ID:
        return Strategy(
            CUSTOM_STRATEGY_ID, transport, "своя стратегия",
            validate_custom_strategy(settings.custom_args(kind)),
        )
    entry = load_strategy_catalog(transport).get(strategy_id)
    if entry is None:
        raise ValueError(f"Стратегия «{strategy_id}» не найдена в каталоге")
    return entry


def server_strategy(settings: ZapretTargetSettings, endpoint: ServerEndpoint) -> Strategy | None:
    """What winws2 does with the selected server's own packets.

    * bypass on — the chosen strategy;
    * bypass off, UDP server — ``pass``: preset fakes must not reach a QUIC or
      WireGuard tunnel;
    * bypass off, TCP server — ``None``: no own rule, the preset decides.
    """

    if settings.enabled(endpoint.kind):
        return chosen_strategy(settings, endpoint.kind)
    if endpoint.transport == "udp":
        return pass_strategy("udp")
    return None
