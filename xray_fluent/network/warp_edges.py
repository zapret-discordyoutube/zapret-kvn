"""Other WARP edges the service sends in the subscription header ``zapret-warp-edges`` (owner 2026-11-27).

New Cloudflare edges that work at some provider are found without an app release when the service hands them over: the header
holds base64 of ``{"v":1,"edges":[{"transport","address","port"?,"sni"?}]}``.  The checked list is kept next to the account file
(``warp-entry-profile.json.edges``) and the hop's plan puts it into the ``extra_edges`` option of the ``warp`` endpoint (core
patch warp-entry-extra-edges), where the core tries those edges right after the account's own first two addresses.  The rules are
the core's own (a literal IP, a known transport, a TLS name of letters, digits, dots and hyphens, at most 16): a list that comes
from the network must never be able to break a start, so everything unusable is dropped silently.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Mapping

HEADER = "zapret-warp-edges"
MAX_EDGES = 16
MAX_HEADER_BYTES = 32 * 1024
TRANSPORTS = ("wireguard", "masque-http2", "masque-quic")
_SNI = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def edges_path(profile: str | os.PathLike[str]) -> Path:
    return Path(str(profile) + ".edges")


def valid(edges: Any) -> list[dict[str, Any]]:
    """The usable edges of a decoded list, in order, duplicates dropped, at most MAX_EDGES."""
    out: list[dict[str, Any]] = []
    if not isinstance(edges, list):
        return out
    for edge in edges:
        if len(out) >= MAX_EDGES:
            break
        if not isinstance(edge, dict):
            continue
        transport, address = edge.get("transport"), edge.get("address")
        if transport not in TRANSPORTS or not isinstance(address, str):
            continue
        try:
            ipaddress.ip_address(address)  # a literal IP only: no attempt may need DNS
        except ValueError:
            continue
        port = edge.get("port", 0)
        if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
            continue
        sni = edge.get("sni", "")
        if sni and (transport == "wireguard" or not isinstance(sni, str) or not _SNI.match(sni)):
            continue
        item: dict[str, Any] = {"transport": transport, "address": address}
        if port:
            item["port"] = port
        if sni:
            item["sni"] = sni
        if item not in out:
            out.append(item)
    return out


def load(profile: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """The edges kept for this account; a missing or broken file is no list at all."""
    try:
        return valid((json.loads(edges_path(profile).read_text(encoding="utf-8")) or {}).get("edges"))
    except (OSError, ValueError, AttributeError):
        return []


def apply(headers: Mapping[str, str], directory: str | os.PathLike[str]) -> str:
    """Take the list from the headers: none (no header), invalid, same, written.  An empty valid list removes the file."""
    value = next((v for k, v in headers.items() if k.lower() == HEADER), None)
    if value is None or not value.strip():
        return "none"
    if len(value) > MAX_HEADER_BYTES:
        return "invalid"
    try:
        document = json.loads(base64.b64decode(value.strip(), validate=True).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return "invalid"
    if not isinstance(document, dict) or document.get("v") != 1 or not isinstance(document.get("edges"), list):
        return "invalid"
    edges = valid(document["edges"])
    target = edges_path(Path(directory) / "warp-entry-profile.json")
    if not edges:
        try:
            target.unlink()
            return "written"
        except OSError:
            return "same"
    text = json.dumps({"v": 1, "edges": edges}, separators=(",", ":"))
    try:
        if target.read_text(encoding="utf-8") == text:
            return "same"
    except OSError:
        pass
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".warp-edges-", dir=str(target.parent))
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return "written"
