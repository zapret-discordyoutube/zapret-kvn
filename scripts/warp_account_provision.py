#!/usr/bin/env python3
"""Make the WARP accounts of one person on the SERVER side, for delivery in the subscription (docs/WARP_ACCOUNT_DELIVERY.md).

Owner decision 2026-11-27: a provider that blocks the Cloudflare registration API (by its TLS name) leaves the apps
without a WARP account, and a provider that blocks our entry servers leaves them without a connection to register
through.  The service registers the accounts itself, from its own network, and hands them to the app in a response
header of the subscription (`zapret-warp-account`).  The app writes them as its own account files and the core uses them.

Self-contained on purpose (the bot vendors this file): Python 3.9+, the `cryptography` package, nothing else.  It prints no
key and no token.  Each person needs ONE `provision()` (two devices at Cloudflare: one for WireGuard, one for MASQUE):
two people must never share an account (one WireGuard key on two machines flaps the tunnel).

    payload = provision()                 # {"v": 1, "wireguard": {...}, "masque": {...}}
    value = header_value(payload)         # the value of the response header, ASCII, about 3 KB
    delete_devices(payload)               # when the person goes away: frees the devices at Cloudflare

Cloudflare answers 429 when one address registers many devices in a short time: space the calls (a minute apart is safe),
and keep a small pool of ready payloads rather than registering on the request path.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import secrets
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

API = "https://api.cloudflareclient.com/v0a4471/reg"
HEADER_NAME = "zapret-warp-account"
SCHEMA = 1
# The MASQUE edge over HTTP/2, the core's own default (cloudflare.DefaultEndpointH2V4).
MASQUE_H2_V4 = "162.159.198.2"
_HEADERS = {
    "User-Agent": "WARP for Android",
    "CF-Client-Version": "a-6.35-4471",
    "Content-Type": "application/json",
}


def _call(method: str, url: str, body: bytes | None = None, token: str | None = None, timeout: float = 20.0) -> dict:
    headers = dict(_HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as reply:  # noqa: S310 - fixed https URL
        raw = reply.read(1 << 20)
    return json.loads(raw.decode("utf-8")) if raw.strip() else {}


def _wireguard_key() -> tuple[str, str]:
    key = X25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(private).decode(), base64.b64encode(public).decode()


def _registration_body(public_key: str) -> bytes:
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
    return json.dumps(
        {
            "key": public_key, "install_id": "", "fcm_token": "", "tos": now, "model": "PC",
            "serial_number": secrets.token_hex(8), "os_version": "", "key_type": "curve25519",
            "tunnel_type": "wireguard", "locale": "en-US",
        },
        separators=(",", ":"),
    ).encode()


def register_wireguard(timeout: float = 20.0) -> tuple[dict, dict]:
    """The WireGuard account: the document the core reads as its profile cache, and the device (id, token) to delete later."""
    private, public = _wireguard_key()
    answer = _call("POST", API, _registration_body(public), timeout=timeout)
    config = answer.get("config") or {}
    interface, peers = config.get("interface") or {}, config.get("peers") or []
    if not (interface.get("addresses") or {}).get("v4") or not peers:
        raise ValueError("the answer holds no WireGuard account")
    return {"private_key": private, "interface": interface, "peers": peers}, {"id": answer.get("id", ""), "token": answer.get("token", "")}


def _host_of(endpoint: str) -> str:
    text = (endpoint or "").strip()
    if not text:
        return ""
    if text.startswith("["):
        return text[1:].partition("]")[0]
    return text.partition(":")[0] if text.count(":") == 1 else text


def register_masque(timeout: float = 20.0) -> tuple[dict, dict]:
    """The MASQUE account (an ECDSA P-256 key enrolled on a fresh device): the document of the core's `account_file.go`."""
    _, throwaway = _wireguard_key()
    device = _call("POST", API, _registration_body(throwaway), timeout=timeout)
    device_id, token = device.get("id", ""), device.get("token", "")
    if not device_id or not token:
        raise ValueError("the answer holds no device")
    key = ec.generate_private_key(ec.SECP256R1())
    private = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    body = json.dumps(
        {"key": base64.b64encode(public).decode(), "key_type": "secp256r1", "tunnel_type": "masque", "name": "PC"},
        separators=(",", ":"),
    ).encode()
    profile = _call("PATCH", f"{API}/{device_id}", body, token=token, timeout=timeout)
    config = profile.get("config") or {}
    peers = config.get("peers") or []
    addresses = (config.get("interface") or {}).get("addresses") or {}
    if not peers or not peers[0].get("public_key") or not addresses.get("v4"):
        raise ValueError("the answer holds no MASQUE account")
    endpoint = peers[0].get("endpoint") or {}
    document = {
        "private_key": base64.b64encode(private).decode(),
        "endpoint_v4": _host_of(endpoint.get("v4", "")),
        "endpoint_v6": _host_of(endpoint.get("v6", "")),
        "endpoint_h2_v4": MASQUE_H2_V4,
        "endpoint_h2_v6": "",
        "endpoint_pub_key": peers[0]["public_key"],
        "license": (profile.get("account") or {}).get("license", ""),
        "id": device_id,
        "access_token": token,
        "ipv4": addresses["v4"],
        "ipv6": addresses.get("v6", ""),
    }
    return document, {"id": device_id, "token": token}


def provision(timeout: float = 20.0) -> dict:
    """Both accounts of one person.  The payload holds secrets: store it like a subscription key, never log it."""
    wireguard, wireguard_device = register_wireguard(timeout)
    masque, masque_device = register_masque(timeout)
    return {
        "v": SCHEMA,
        "wireguard": wireguard,
        "masque": masque,
        # not sent to the app (it has no use for them): kept by the service to delete the devices later
        "_devices": [wireguard_device, masque_device],
    }


def header_value(payload: dict) -> str:
    """The value of the `zapret-warp-account` header: base64 of the JSON, without the service-only fields."""
    public = {key: value for key, value in payload.items() if not key.startswith("_")}
    return base64.b64encode(json.dumps(public, separators=(",", ":")).encode("utf-8")).decode("ascii")


def delete_devices(payload: dict, timeout: float = 20.0) -> int:
    """Remove the person's devices at Cloudflare; returns how many were removed (a refusal of one does not stop the rest)."""
    removed = 0
    for device in payload.get("_devices") or []:
        if not device.get("id") or not device.get("token"):
            continue
        try:
            _call("DELETE", f"{API}/{device['id']}", token=device["token"], timeout=timeout)
            removed += 1
        except (urllib.error.URLError, ValueError, OSError):
            continue
    return removed


if __name__ == "__main__":  # a manual check: registers two devices, prints only sizes, deletes them
    result = provision()
    print("header bytes:", len(header_value(result)), "devices deleted:", delete_devices(result))
