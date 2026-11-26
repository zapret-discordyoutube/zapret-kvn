"""The real test person of vpnbot as test data (owner decision 2026-11-25: tests run on real data only).

The file ``~/.config/kvn-test-subscription`` (override: ``KVN_TEST_SUBSCRIPTION``) holds one JSON object: the two live
subscription URLs of the test person and the text of its AmneziaWG config.  The apps import the URLs themselves, so this
module fetches them exactly as the app does and parses the answers with the app's own importer.  Nothing here prints or
logs a value of the file or of an imported node: tests assert on shapes and counts only.

Without the file (a machine that has no access to the test person) the dependent tests skip:
a skipped test is an honest "unproven", an invented configuration would only prove that the test agrees with itself.
"""

from __future__ import annotations

import json
import os
import unittest
import urllib.request
from functools import lru_cache
from pathlib import Path

from xray_fluent.importer.link_parser import parse_single
from xray_fluent.importer.subscription_parser import parse_subscription_payload
from xray_fluent.profiles.models import Node

# The same relative place on both machines that run the tests: CT 201 (/root/.config/...) and the win10 VM
# (C:\Users\privacy\.config\...), where the release gate runs them.
DEFAULT_PATH = Path.home() / ".config" / "kvn-test-subscription"


def subscription_path() -> Path:
    return Path(os.environ.get("KVN_TEST_SUBSCRIPTION", str(DEFAULT_PATH)))


def available() -> bool:
    return subscription_path().is_file()


requires_real_subscription = unittest.skipUnless(
    available(), "no real test subscription here (KVN_TEST_SUBSCRIPTION or ~/.config/kvn-test-subscription)"
)


@lru_cache(maxsize=1)
def _document() -> dict:
    return json.loads(subscription_path().read_text(encoding="utf-8"))


def _fetch(url: str) -> list[Node]:
    request = urllib.request.Request(url, headers={"User-Agent": "ZapretKVN"})
    with urllib.request.urlopen(request, timeout=30) as reply:  # noqa: S310 - the test person's own https URL
        body = reply.read()
        headers = dict(reply.headers)
    return parse_subscription_payload(body, headers=headers, source_url=url).nodes


@lru_cache(maxsize=1)
def all_nodes() -> tuple[Node, ...]:
    """Every server of the test person: VLESS (Reality), Hysteria2 and the AmneziaWG key, parsed by the app."""
    document = _document()
    nodes: list[Node] = []
    nodes += _fetch(document["vless_subscription_url"])
    nodes += _fetch(document["hysteria2_subscription_url"])
    nodes.append(parse_single(document["awg_conf"]))
    return tuple(nodes)


def nodes_of(scheme: str) -> list[Node]:
    return [node for node in all_nodes() if node.scheme == scheme]
