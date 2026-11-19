# Connection reports for status.zapret.moe

Owner decisions of 15–19.11.2026 (programme «honest coverage», stage S4). The status page checks
the service's servers from Russian datacenters and home scanners; none of them sees the filter of a
particular home provider. Real connection attempts of Zapret KVN from Russian home networks are the
third source: a server is shown as reachable or not from homes only when at least 3 installs on at
least 2 networks (ASNs) reported the same within 24 hours. Android does the same
(`android/docs/CLIENT_REPORTS.md`); both follow vpnbot `client_reports/contract.py`, schema 1.

## What is sent

One report per finished connect or server switch (`connect`, `reconnect`, `tun_hot_swap`,
`proxy_hot_swap` transitions) to a server of the service's own subscription (the reply carries
`zapret-vpn-service`), to `POST https://reports.zapret.moe/v1/reports`:

- `server_id`, `product` — from the `zapret-server-ids` header of the subscription reply (unpadded
  base64url of zlib-compressed JSON `{"<link name>": {"server_id", "product"}}`, ≤ 14 336 chars;
  inflated at most 512 KB), stored as `Subscription.server_ids` and matched by the node's
  `provider_name` and link scheme (Trojan/Shadowsocks/VMess lines of the VLESS subscription are product
  `vless`). vpnbot sends the header on a 304 too, so an unchanged subscription still refreshes the map.
  Relay rows «… через Россию» are not in the header. No entry — no report; the id is never guessed.
- `outcome` `connected` / `failed` / `cancelled`, the failed step (resolve → connect → handshake → auth
  → tunnel → request), a short code, elapsed ms, attempt time, app name/version/platform, a random
  `install_id` (`data/client-reports/install-id`, not tied to the account), `sent_via`, `network_token`.

No account, key, address or domain; other providers' servers are never reported.

## When a report is honest

- Hysteria 2 and AmneziaWG/WireGuard: a successful transition already means the engine proved the
  server at start (functional HTTPS probe / authenticated handshake) → `connected`.
- VLESS (Xray sidecar): Xray starting proves nothing about the server, so after a successful connect
  the reporter makes one HTTPS request (`generate_204`, `socks_probe.HTTPS_ENDPOINTS`, first answer
  wins) through the Xray relay SOCKS inbound — the same path as the user's traffic, bypassing sing-box
  routing — and reports `connected` or `failed` at `request` (owner decision 19.11.2026).
- A failure is reported only with the native core's own code for that server (Hysteria
  `last_failure_code`: `TARGET_AUTH_REJECTED` → auth, TLS/pin/obfs → handshake, `TARGET_NETWORK_TIMEOUT`
  → handshake `udp_no_answer`, …). Local failures (`LOCAL_*`, TUN, admin rights) give no report.
- A transition superseded by a newer request is `cancelled`.

## How it is sent

`xray_fluent/client_reports/`: `contract.py` holds every decision (contract, header, classifier,
queue, token, send policy; tested in `tests/test_client_reports.py`), `reporter.py` only the network.
No prompt, no setting, no timers: a daemon thread runs when a report is queued and once at start.
A batch (≤ 50) goes directly first (urllib without proxy, so the ingest sees the network itself),
then through the app's local HTTP proxy when connected. `GET /v1/network?install_id=…` is asked only
directly; Windows has no stable handle of the physical network, so the token is renewed after an hour
and attached only while younger than two hours. 202 removes the batch, 400/413 drop it, 429/5xx keep
it until the next report. Queue: `data/client-reports/queue.jsonl` (≤ 500, a week at most).

## Seeing it act

The log file has `[client-report]` lines: the VLESS check result, each queued report and each batch
(`batch N (direct) -> HTTP 202`).

## Known limits

- AmneziaWG/WireGuard failures are not reported on Windows: the engine gives no failure code, and a
  failed start without one cannot be told from a local failure.
- The `resolve` step is not reported yet; slots (YouTube, Telegram, AI) produce no reports.
