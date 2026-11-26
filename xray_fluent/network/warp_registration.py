"""Registration of the WARP account by the app itself (owner decision 2026-11-25).

The WARP entry hop needs a Cloudflare account (a private key and what Cloudflare assigns to it).  The core registers one
by itself on the first start, but on some networks the provider resets that one HTTPS request to the Cloudflare API
(field report 2026-11-25: `wsarecv: An existing connection was forcibly closed by the remote host` at the API address),
and without the account the hop never starts.  The app therefore registers the account first and writes the file the
core reads (`profile.cache_path`, core patch `warp-entry-profile.patch`), so the core finds it and never calls the API.

Routes, in this order (blocking, worker thread only):

1. the plain request;
2. the same request with the TLS ClientHello cut into small TCP segments inside the server name, which a censor that
   matches the name in the first segment does not see (the same idea as the app's masking «TLS fragment»);
3. both of the above for every other address of the API host (the trusted DoH of the app resolves them);
4. through the VPN that is already up (`proxy_url`): the caller uses it only as the last resort, because that connection
   shows the VPN server's address to the provider once.

Only the file the core expects is written: `{"private_key", "interface", "peers"}`; nothing is logged but the route and
the outcome.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import datetime as _dt
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import tempfile
import time
from typing import Callable
from urllib.request import Request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

API_HOST = "api.cloudflareclient.com"
API_PATH = "/v0a4471/reg"
API_PORT = 443
HEADERS = {
    "User-Agent": "WARP for Android",
    "CF-Client-Version": "a-6.35-4471",
    "Content-Type": "application/json; charset=UTF-8",
}
# The API host's addresses seen in the field, tried after what DoH resolves (a censor may block one of them only).
KNOWN_ADDRESSES = ("162.159.137.105", "162.159.138.105", "8.6.112.0", "8.47.69.0")
MAX_RESPONSE = 64 * 1024
# Where inside the ClientHello the first segment ends: in the middle of the server name.
_SPLIT_INTO_NAME = 3


@dataclass(frozen=True)
class Outcome:
    ok: bool
    route: str  # the route that worked, or the last one tried
    detail: str  # a short reason without addresses or secrets


def account_file_ready(path: str | os.PathLike[str]) -> bool:
    """The file is there and holds a whole account (what the core's loader requires)."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return bool(
            data.get("private_key")
            and data.get("peers")
            and (data.get("interface") or {}).get("addresses", {}).get("v4")
        )
    except (OSError, ValueError, AttributeError):
        return False


def ensure_account(
    path: str | os.PathLike[str],
    *,
    addresses: Callable[[], list[str]] | None = None,
    proxy_url: str | None = None,
    timeout: float = 8.0,
    budget: float = 30.0,
) -> Outcome:
    """Make sure the account file exists, registering a new account over the routes above.

    `proxy_url` set means "register through that proxy only" (the last resort, see the module doc).

    `budget` is the most this call may take in all, whatever the routes do (field report 2026-11-26, Windows 0.8.121:
    on a network that blocks the API every route ran into its own timeout, together longer than the 60 s the connect
    allows for this step, so the connect failed outright instead of going on without the hop)."""
    if account_file_ready(path):
        return Outcome(True, "cached", "account file is there")
    started = time.monotonic()
    private, public = _new_key()
    body = _registration_body(public)
    if proxy_url:
        routes: list[tuple[str, Callable[[float], bytes]]] = [("vpn", lambda t: _through_proxy(body, proxy_url, t))]
    else:
        routes = []
        found: list[str] = []
        try:
            found = list(addresses()) if addresses else []
        except Exception:  # noqa: BLE001 - a resolver failure only means fewer routes
            found = []
        targets: list[str | None] = [None]  # None: let the system resolve the host
        for address in [*found, *KNOWN_ADDRESSES]:
            if address not in targets:
                targets.append(address)
        for index, target in enumerate(targets):
            label = "api" if index == 0 else f"api-{index}"
            for fragmented in (False, True):
                name = f"{label}{'-fragmented' if fragmented else ''}"
                routes.append((name, lambda limit, t=target, f=fragmented: _exchange(t, body, f, limit)))
    last = Outcome(False, "none", "no route tried")
    for name, send in routes:
        remaining = budget - (time.monotonic() - started)
        if remaining < 2.0:
            last = Outcome(False, name, f"time budget of {budget:g} s is used up")
            break
        try:
            # A route may need two timeouts (connect, then the whole exchange): never more than what is left.
            raw = send(min(timeout, remaining / 2))
            _write_account(path, private, raw)
            return Outcome(True, name, "registered")
        except Exception as error:  # noqa: BLE001 - every route fails in its own way; the next one is tried
            last = Outcome(False, name, _short(error))
    return last


def routes(addresses: Callable[[], list[str]] | None = None) -> list[tuple[str, str | None, bool]]:
    """The routes to the API in the order they are tried: (name, address or None for the system's, cut ClientHello)."""
    found: list[str] = []
    try:
        found = list(addresses()) if addresses else []
    except Exception:  # noqa: BLE001 - a resolver failure only means fewer routes
        found = []
    targets: list[str | None] = [None]
    for address in [*found, *KNOWN_ADDRESSES]:
        if address not in targets:
            targets.append(address)
    out: list[tuple[str, str | None, bool]] = []
    for index, target in enumerate(targets):
        label = "api" if index == 0 else f"api-{index}"
        for fragmented in (False, True):
            out.append((f"{label}{'-fragmented' if fragmented else ''}", target, fragmented))
    return out


def _new_key() -> tuple[str, str]:
    key = X25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(private).decode(), base64.b64encode(public).decode()


def _registration_body(public_key: str) -> bytes:
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
    return json.dumps(
        {
            "key": public_key,
            "install_id": "",
            "fcm_token": "",
            "tos": now,
            "model": "PC",
            "serial_number": secrets.token_hex(8),
            "os_version": "",
            "key_type": "curve25519",
            "tunnel_type": "wireguard",
            "locale": "en-US",
        },
        separators=(",", ":"),
    ).encode()


def _write_account(path: str | os.PathLike[str], private_key: str, raw: bytes) -> None:
    config = (json.loads(raw.decode("utf-8")) or {}).get("config") or {}
    interface = config.get("interface") or {}
    peers = config.get("peers") or []
    if not (interface.get("addresses") or {}).get("v4") or not peers:
        raise ValueError("the answer holds no account")
    document = {"private_key": private_key, "interface": interface, "peers": peers}
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".warp-profile-", dir=str(target.parent))
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


def _through_proxy(body: bytes, proxy_url: str, timeout: float) -> bytes:
    from .http_utils import fetch_bytes

    request = Request(f"https://{API_HOST}{API_PATH}", data=body, headers=dict(HEADERS), method="POST")
    return fetch_bytes(request, timeout=timeout, max_bytes=MAX_RESPONSE, proxy_url=proxy_url, prefer_proxy=True,
                       attempts_per_route=1).data


def _exchange(
    address: str | None,
    body: bytes,
    fragmented: bool,
    timeout: float,
    *,
    method: str = "POST",
    path: str = API_PATH,
    token: str | None = None,
) -> bytes:
    """One HTTPS request to the API, the ClientHello optionally cut into pieces; returns the body of the 200 answer.

    The registration is a POST to `/reg`; the MASQUE key of `warp_masque_account.py` is a PATCH to `/reg/<id>` with the
    token of the device."""
    deadline = time.monotonic() + timeout * 2
    sock = socket.create_connection((address or API_HOST, API_PORT), timeout=timeout)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = ssl.create_default_context().wrap_bio(incoming, outgoing, server_hostname=API_HOST)
        first = True
        while True:
            try:
                tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                _flush(sock, outgoing, split=fragmented and first)
                first = False
                _feed(sock, incoming, deadline)
        _flush(sock, outgoing, split=False)
        request = (
            f"{method} {path} HTTP/1.1\r\nHost: {API_HOST}\r\n"
            + "".join(f"{key}: {value}\r\n" for key, value in HEADERS.items())
            + (f"Authorization: Bearer {token}\r\n" if token else "")
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode() + body
        tls.write(request)
        _flush(sock, outgoing, split=False)
        received = b""
        while len(received) <= MAX_RESPONSE:
            try:
                chunk = tls.read(4096)
            except ssl.SSLWantReadError:
                _flush(sock, outgoing, split=False)
                if not _feed(sock, incoming, deadline):
                    break
                continue
            except ssl.SSLZeroReturnError:
                break
            if not chunk:
                break
            received += chunk
        return _body_of_200(received)
    finally:
        sock.close()


def _flush(sock: socket.socket, outgoing: ssl.MemoryBIO, *, split: bool) -> None:
    data = outgoing.read()
    if not data:
        return
    if split:
        cut = _name_offset(data)
        sock.sendall(data[:cut])
        time.sleep(0.05)  # a separate TCP segment, not merged by the stack
        sock.sendall(data[cut:])
    else:
        sock.sendall(data)


def _name_offset(client_hello: bytes) -> int:
    """A few bytes into the server name; the middle of the record when the name is not found."""
    position = client_hello.find(API_HOST.encode())
    if position > 0:
        return position + _SPLIT_INTO_NAME
    return max(1, len(client_hello) // 2)


def _feed(sock: socket.socket, incoming: ssl.MemoryBIO, deadline: float) -> bool:
    if time.monotonic() > deadline:
        raise TimeoutError("no answer in time")
    data = sock.recv(16384)
    if not data:
        incoming.write_eof()
        return False
    incoming.write(data)
    return True


def _body_of_200(raw: bytes) -> bytes:
    head, _, rest = raw.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].split(b" ")
    if len(status) < 2 or status[1] != b"200":
        raise ValueError(f"API answered {status[1].decode(errors='replace') if len(status) > 1 else 'nothing'}")
    lowered = head.lower()
    if b"transfer-encoding: chunked" in lowered:
        out, data = b"", rest
        while data:
            size_line, _, data = data.partition(b"\r\n")
            size = int(size_line.split(b";")[0] or b"0", 16)
            if size == 0:
                break
            out += data[:size]
            data = data[size + 2:]
        return out
    return rest


def _short(error: BaseException) -> str:
    text = f"{type(error).__name__}: {error}"
    return text[:160]
