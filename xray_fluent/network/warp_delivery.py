"""The WARP account the service hands over in the subscription (owner decision 2026-11-27, docs/WARP_ACCOUNT_DELIVERY.md).

A provider that blocks the Cloudflare registration API, and the entry servers too, leaves the app with nothing to register
through.  The service registers the accounts itself and sends them in the response header ``zapret-warp-account`` (also on a
304): base64 of a JSON with the two files the core reads (``warp-entry-profile.json`` and its ``.masque`` account).  This module
checks the payload with the same rules the core's loaders apply and writes the files, only where an account is missing (a
working account on the device is never replaced, unless the payload says ``"replace": true`` and is a new one).  Nothing from the
payload is ever logged: it holds private keys and device tokens.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from . import warp_masque_account, warp_registration

HEADER = "zapret-warp-account"
SCHEMA = 1
#: A payload is about 1.5 KB; anything much larger is not one.
MAX_HEADER_BYTES = 32 * 1024
ACCOUNT_FILE = "warp-entry-profile.json"
#: The digest of the last payload applied: a "replace" payload overwrites once per distinct payload.
DELIVERED_FILE = ACCOUNT_FILE + ".delivered"


@dataclass(frozen=True)
class Outcome:
    #: none (no header), invalid, kept (accounts already there), written
    status: str
    detail: str = ""
    wrote_wireguard: bool = False
    wrote_masque: bool = False


def _header(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None


def _wireguard_ok(document: object) -> bool:
    """What `warp_registration.account_file_ready` requires of the file."""
    if not isinstance(document, dict):
        return False
    interface = document.get("interface") or {}
    addresses = interface.get("addresses") if isinstance(interface, dict) else None
    return bool(
        document.get("private_key")
        and document.get("peers")
        and isinstance(addresses, dict)
        and addresses.get("v4")
    )


def _masque_ok(document: object) -> bool:
    """What `warp_masque_account.ready` requires of the file."""
    return isinstance(document, dict) and all(
        isinstance(document.get(key), str) and document.get(key) for key in ("private_key", "endpoint_pub_key", "ipv4")
    )


def _write(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".warp-delivered-", dir=str(path.parent))
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(document, stream, separators=(",", ":"))
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def apply(headers: Mapping[str, str], directory: str | os.PathLike[str]) -> Outcome:
    """Take the accounts from the subscription's headers into the app's data folder."""
    value = _header(headers, HEADER)
    if value is None:
        return Outcome("none")
    if len(value) > MAX_HEADER_BYTES:
        return Outcome("invalid", "the header is too large")
    try:
        payload = json.loads(base64.b64decode(value.strip(), validate=True).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return Outcome("invalid", "the header is not base64 of JSON")
    if not isinstance(payload, dict) or payload.get("v") != SCHEMA:
        return Outcome("invalid", "unknown schema")
    wireguard, masque = payload.get("wireguard"), payload.get("masque")
    if not _wireguard_ok(wireguard) or not _masque_ok(masque):
        return Outcome("invalid", "the payload lacks an account")
    base = Path(directory)
    account = base / ACCOUNT_FILE
    masque_file = warp_masque_account.account_path(account)
    digest = hashlib.sha256(value.strip().encode("ascii", "ignore")).hexdigest()
    delivered = base / DELIVERED_FILE
    try:
        replace = bool(payload.get("replace")) and delivered.read_text(encoding="ascii").strip() != digest
    except OSError:
        replace = bool(payload.get("replace"))
    wrote_wireguard = wrote_masque = False
    if replace or not warp_registration.account_file_ready(account):
        _write(account, wireguard)
        wrote_wireguard = True
    if replace or not warp_masque_account.ready(masque_file):
        _write(masque_file, masque)
        wrote_masque = True
    if wrote_wireguard or wrote_masque:
        # an edge remembered for the old account says nothing about the new one
        try:
            os.unlink(str(account) + ".edge")
        except OSError:
            pass
        delivered.write_text(digest, encoding="ascii")
        return Outcome("written", "", wrote_wireguard, wrote_masque)
    return Outcome("kept")
