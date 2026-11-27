# WARP account delivery in the subscription (owner decision 2026-11-27)

## Why

The WARP entry hop needs a Cloudflare WARP account on the device. The app used to register it itself at
`api.cloudflareclient.com`, and a provider that blocks that name (field reports of 2026-11-26/27, mobile data) leaves the app
without an account. Registering through the VPN does not help a person whose provider also blocks the entry servers (no VPN
connection, so nothing to register through). The service therefore registers the accounts from its own network and hands
them to the app in a response header of the subscription. A subscription that the app can download is enough.

Cloudflare's registration API cannot be fronted (checked 2026-11-27 against the real API: any TLS name other than
`api.cloudflareclient.com` gets 401/403, there is no ECH record), so server-side registration is the way that does not
depend on the person's network.

## Contract

Response header of the service subscription (the answers that already carry `zapret-vpn-service`), on **200 and on 304**
(the apps keep the ETag; a cached subscription must still deliver the account, like `zapret-server-ids` does):

```
zapret-warp-account: <base64 of UTF-8 JSON>
```

The JSON (schema 1), exactly the two files the core reads (`scripts/warp_account_provision.py` produces it):

```
{"v": 1,
 "wireguard": {"private_key": "<base64 x25519>", "interface": {...}, "peers": [...]},
 "masque":    {"private_key": "<base64 SEC1 DER>", "endpoint_v4": "...", "endpoint_v6": "...", "endpoint_h2_v4": "...",
               "endpoint_h2_v6": "", "endpoint_pub_key": "<PEM>", "license": "...", "id": "...", "access_token": "...",
               "ipv4": "...", "ipv6": "..."}}
```

- One payload per **person** (subscription), stable between requests: the same value on every request until the service
  replaces it. Two people never share a payload (a WireGuard key on two machines flaps the tunnel).
- About 1.5 KB base64 (header limit of nginx is 8 KB per header line by default: check the proxy in front of the bot).
- The header is simply **absent** when the person has no payload yet (the app then registers itself as before).
- The app only fills a MISSING account: a working account on the device is never replaced by the header. To replace a
  broken account the service sends `"replace": true` inside the JSON (the app then overwrites once per distinct payload).
- The payload holds secrets (private keys, device tokens): store it like the subscription key, never log it, never put it in
  a URL. The subscription itself is already secret-bearing.

## What the service does

1. `scripts/warp_account_provision.py` (self-contained: Python 3.9+, `cryptography`) registers two devices at Cloudflare
   (WireGuard + MASQUE) and returns the payload; `header_value()` makes the header value; `delete_devices()` frees the
   devices when the person goes away. Checked against the real API on 2026-11-27 (header 1472 bytes, both deleted).
2. Cloudflare answers 429 when one address registers many devices in a short time: pace the calls (a minute apart is safe)
   and keep a pool of ready payloads (registering on the request path would make the subscription slow and fail under a
   burst). Spread over several egress addresses of the service if the pool must grow fast.
3. Attach the payload to the person at the first subscription request after it exists (or at issue time), store it in the
   service database, send the same header on every later answer.
4. Optional: when a person's subscription is revoked, call `delete_devices(payload)`.

## What the apps do (this repository and the Android one)

- Windows `network/warp_delivery.py`, Android `config/WarpAccountDelivery.kt`: decode, validate (the same checks the core's
  loaders make), write `warp-entry-profile.json` and `warp-entry-profile.json.masque` atomically in the app's data folder,
  only when the account is missing. The hop stays opt-in (the setting "Вход через WARP").
- Verified on real data: an account made by the real API through `warp_account_provision.py`, applied by the app code, was
  accepted by the real core (WireGuard handshake and MASQUE over HTTP/2, `warp=on` on Cloudflare's trace page).

## Phase 2 (not built): remote edge list

New WARP edges, ports and names that work on some provider can be found without an app release if the service sends
them too: a second header `zapret-warp-edges` with JSON `{"v":1,"wireguard":[["ip",port],...],"masque":[{"address":"...",
"transport":"h2|quic","sni":"..."}]}`. The core needs an option for extra candidates first (a core patch); the field
names above are reserved for it.
