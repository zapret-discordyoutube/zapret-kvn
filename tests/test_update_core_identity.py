from __future__ import annotations

"""Копия общего ядра обновления не правилась в обход исходника в Zapret 2 GUI."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_core_copy_matches_its_recorded_hash() -> None:
    spec = importlib.util.spec_from_file_location("sync_update_core", ROOT / "scripts" / "sync_update_core.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    recorded = (module.TARGET / module.HASH_FILE).read_text(encoding="ascii").strip()

    # Упал — копию правили здесь. Правьте ядро в Zapret 2 GUI и перенесите его
    # сюда командой python3 scripts/sync_update_core.py.
    assert recorded == module.core_hash(module.TARGET)
