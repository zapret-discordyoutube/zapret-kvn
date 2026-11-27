"""The real NaiveProxy test key of the vpnbot canary as test data (owner decision 2026-11-25: tests run on real data).

The file ``~/.config/kvn-test-naive-key`` (override: ``KVN_TEST_NAIVE_KEY``; on CT 201 also ``-win``) holds ONE key line
issued by the naive bot session for a synthetic test person (it expires by itself). Nothing here prints or logs the line:
tests assert on shapes and results only. Without the file the dependent tests skip, which is an honest "unproven".
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path

_CANDIDATES = (
    Path.home() / ".config" / "kvn-test-naive-key",
    Path.home() / ".config" / "kvn-test-naive-key-win",
)


def key_path() -> Path | None:
    override = os.environ.get("KVN_TEST_NAIVE_KEY")
    if override:
        return Path(override)
    return next((path for path in _CANDIDATES if path.is_file()), None)


def available() -> bool:
    path = key_path()
    return path is not None and path.is_file()


def key_line() -> str:
    path = key_path()
    if path is None:
        raise unittest.SkipTest("no real NaiveProxy test key here (KVN_TEST_NAIVE_KEY or ~/.config/kvn-test-naive-key)")
    return path.read_text(encoding="utf-8").strip()


requires_real_key = unittest.skipUnless(available(), "no real NaiveProxy test key here")
