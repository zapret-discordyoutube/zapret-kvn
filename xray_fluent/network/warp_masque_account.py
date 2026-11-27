"""The MASQUE account for the WARP entry hop, registered by the app itself (owner 2026-11-26, "WARP does not work on mobile data").

Where a network cuts WireGuard after its first packets the core falls back to Cloudflare's MASQUE tunnel (core patches
`warp-entry-masque.patch` and `warp-entry-masque-timing.patch`).  That tunnel needs a second account: a device and an ECDSA
key recorded at Cloudflare's API.  The core can register it itself, but with the one HTTPS request a network may reset or
slow down (the field diagnostic of Android 0.6.62: the core's request was cancelled after 7 s).  So the app does here what
`warp_registration.py` does for the WireGuard account: the same routes, the ClientHello cut into pieces included, and keeps
the answer in `<account file>.masque`, in the format the core reads (private, mode of the account file).  The core finds it
and asks the API for nothing.

Two requests: the device (POST, a throwaway WireGuard key; the answer holds the id and the token) and the MASQUE key
(PATCH `/reg/<id>`, the token of the device).  Blocking: call it from a worker thread.  Only the route and the outcome are
logged, never an address or a key.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import warp_registration

KEY_TYPE = "secp256r1"
TUNNEL_TYPE = "masque"
#: The MASQUE endpoint over HTTP/2, the core's own default (`cloudflare.DefaultEndpointH2V4`).
DEFAULT_H2_V4 = "162.159.198.2"
#: After a failure the routes are skipped this long: the core copes with its own request and the connect must not wait.
RETRY_S = 600.0

_failed_at = -1e9


@dataclass(frozen=True)
class Outcome:
    ok: bool
    route: str
    detail: str
    elapsed_ms: int = 0


def account_path(wireguard_account: str | os.PathLike[str]) -> Path:
    return Path(str(wireguard_account) + ".masque")


def ready(path: str | os.PathLike[str]) -> bool:
    """The file is there and holds what the core's loader requires (`protocol/masque/account_file.go`)."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return all(data.get(key) for key in ("private_key", "endpoint_pub_key", "ipv4"))
    except (OSError, ValueError, AttributeError):
        return False


def new_key() -> tuple[bytes, bytes]:
    """A P-256 key pair: the private half as SEC1 DER (Go's `x509.ParseECPrivateKey`), the public as X.509 SPKI DER."""
    key = ec.generate_private_key(ec.SECP256R1())
    private = key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return private, public


def host_of(endpoint: str) -> str:
    """`162.159.198.2:0` -> `162.159.198.2`, `[2606:4700::1]:0` -> `2606:4700::1`."""
    text = (endpoint or "").strip()
    if not text:
        return ""
    if text.startswith("["):
        return text[1:].partition("]")[0]
    return text.partition(":")[0] if text.count(":") == 1 else text


def write_account(path: str | os.PathLike[str], private_sec1: bytes, device_id: str, token: str, profile: dict) -> None:
    config = profile.get("config") or {}
    peers = config.get("peers") or []
    if not peers:
        raise ValueError("the answer holds no peer")
    peer = peers[0]
    endpoint = peer.get("endpoint") or {}
    addresses = (config.get("interface") or {}).get("addresses") or {}
    if not peer.get("public_key") or not addresses.get("v4"):
        raise ValueError("the answer holds no MASQUE account")
    document = {
        "private_key": base64.b64encode(private_sec1).decode(),
        "endpoint_v4": host_of(endpoint.get("v4", "")),
        "endpoint_v6": host_of(endpoint.get("v6", "")),
        "endpoint_h2_v4": DEFAULT_H2_V4,
        "endpoint_h2_v6": "",
        "endpoint_pub_key": peer["public_key"],
        "license": (profile.get("account") or {}).get("license", ""),
        "id": device_id,
        "access_token": token,
        "ipv4": addresses["v4"],
        "ipv6": addresses.get("v6", ""),
    }
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".masque-account-", dir=str(target.parent))
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(document, stream, separators=(",", ":"))
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


Requester = Callable[..., bytes]


def ensure(
    wireguard_account: str | os.PathLike[str],
    *,
    addresses: Callable[[], list[str]] | None = None,
    timeout: float = 8.0,
    budget: float = 25.0,
    requester: Requester | None = None,
    proxy_url: str | None = None,
) -> Outcome:
    """Make sure `<account>.masque` exists, registering it over the routes of `warp_registration.routes`.

    `proxy_url` set means "through that proxy only" (the VPN of a connect that runs without the hop, owner 2026-11-27:
    break through once, then reuse the account): one route, no back-off to honour, none recorded."""
    global _failed_at
    if proxy_url:
        def send(address, body, fragmented, limit, **kwargs):  # noqa: ANN001, ANN202 - same shape as `_exchange`
            return warp_registration._through_proxy(body, proxy_url, limit, **kwargs)
    else:
        send = requester or warp_registration._exchange
    target = account_path(wireguard_account)
    if ready(target):
        return Outcome(True, "cached", "account file is there")
    started = time.monotonic()

    def took() -> int:
        return int((time.monotonic() - started) * 1000)

    if not proxy_url and started - _failed_at < RETRY_S:
        return Outcome(False, "skipped", "the routes failed a moment ago")
    routes = [("vpn", None, False)] if proxy_url else warp_registration.routes(addresses)

    def over_routes(first: tuple | None, step: Callable[[str | None, bool, float], dict]):
        ordered = ([first] if first else []) + [route for route in routes if route != first]
        for route in ordered:
            remaining = budget - (time.monotonic() - started)
            if remaining < 2.0:
                return None
            try:
                return route, step(route[1], route[2], min(timeout, remaining / 2))
            except Exception:  # noqa: BLE001 - every route fails in its own way; the next one is tried
                continue
        return None

    _, wireguard_public = warp_registration._new_key()
    device_body = warp_registration._registration_body(wireguard_public)

    def register(address, fragmented, limit):
        answer = json.loads(send(address, device_body, fragmented, limit).decode("utf-8"))
        if not answer.get("id") or not answer.get("token"):
            raise ValueError("the answer holds no device")
        return answer

    registered = over_routes(None, register)
    if registered is None:
        if not proxy_url:
            _failed_at = time.monotonic()
        return Outcome(False, "none", f"no route registered the device in {budget:g} s", took())
    device = registered[1]
    private, public = new_key()
    body = json.dumps(
        {"key": base64.b64encode(public).decode(), "key_type": KEY_TYPE, "tunnel_type": TUNNEL_TYPE, "name": "PC"},
        separators=(",", ":"),
    ).encode()

    def enroll(address, fragmented, limit):
        return json.loads(
            send(
                address, body, fragmented, limit,
                method="PATCH", path=f"{warp_registration.API_PATH}/{device['id']}", token=device["token"],
            ).decode("utf-8")
        )

    enrolled = over_routes(registered[0], enroll)
    if enrolled is None:
        if not proxy_url:
            _failed_at = time.monotonic()
        return Outcome(False, registered[0][0], f"the MASQUE key was not accepted in {budget:g} s", took())
    try:
        write_account(target, private, device["id"], device["token"], enrolled[1])
    except Exception as error:  # noqa: BLE001
        return Outcome(False, enrolled[0][0], warp_registration._short(error), took())
    return Outcome(True, enrolled[0][0], "registered", took())


def forget_failure() -> None:
    """Tests only: forget a recent failure."""
    global _failed_at
    _failed_at = -1e9
