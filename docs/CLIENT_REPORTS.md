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
  Relay rows «… через Россию» are not in the header. No entry — reported as `foreign` (below); the id is never guessed.
- `outcome` `connected` / `failed` / `cancelled`, the failed step (resolve → connect → handshake → auth
  → tunnel → request), a short code, elapsed ms, attempt time, app name/version/platform, a random
  `install_id` (`data/client-reports/install-id`, not tied to the account), `sent_via`, `network_token`.

No account, key or domain.

Schema 2 (owner decisions 2026-11-19, live at the receiver since 16:07 UTC) adds, all optional and
written only when known (a bad value drops out instead of losing the report, `AttemptDetails.cleaned`):

- `server_ip` (the address the start connected to, or the one the path check probed) and `port`;
  `transport` (`tcp`, `ws`, `grpc`, `xhttp`, `quic`, `udp`, …) and `security` (`reality`, `tls`, `none`);
- `network_type` (`wifi`, `cellular`, `ethernet`, `other`) (not sent on Windows yet);
- `settings`: `mode` (`tun`/`proxy` of the live session), `masking` (`on`/`off`); `dns`, `quic_blocked` and `ipv6` live in the native JSON templates and are left unknown;
- `versions`: `os` (`platform.version()`), `xray`, `singbox`, `hysteria` asked once per app run from the cores themselves (`<core> version`).

The receiver stores the sender's IP and its /24 (IPv4) or /48 (IPv6) for `sent_via: direct` reports
only; tunnel reports store neither. Everything is kept 90 days.

Foreign servers (not from the service's subscriptions) get the path check on screen, and their failure is
reported by itself (owner 2026-11-19: «send everything we possibly can automatically, even without the
button», own servers in full, address included): `foreign` {`host`, `protocol`, `name`} replaces
`server_id`/`product` (exactly one of the two, or the receiver refuses), with the server's `server_ip` and
`port`. The name loses Unicode control/format characters and is cut to 64 code points (flags survive);
the host is lower-cased, an IPv6 zone is never sent. The receiver keeps them in its own table, never in
our servers' verdict or ranking.

`report_id` (vpnbot «report_id live», 2026-11-19): 32 lowercase hex characters from the system's secure random
source, made once when the attempt is recorded and kept in the device queue (key `r`), so every re-send of the
same attempt carries the same id and vpnbot stores the first copy only. Queue lines written before carry none and
go out without it. The 202 reply also says how many were `repeated`; a 400 for a re-send older than 7 days drops it.

`via` (vpnbot, 2026-11-19): a «… через Россию» line's header entry is `{"relay_of": "<target id>", "product",
"via": "<10 hex>"}` with no `server_id`, so a parser that does not know relay lines (0.6.39 / 0.8.94 and older)
skips it instead of counting the attempt against the target. A server's own line stays `{"server_id", "product"}`;
any other shape (`server_id` together with `via` or `relay_of`, a relay without a readable key) is skipped. The
report of a relay attempt carries `server_id` = the `relay_of` value and top-level `via` (queue key `w`), never with
`foreign`; vpnbot keeps such attempts out of the target's own verdict and shows them as a separate path. For about
an hour on 2026-11-19 vpnbot sent the interim shape `{"server_id", "product", "via"}`, which the older apps stored
as the target itself, so the stored map got a format marker (`"server_ids_format": 2` in the subscription record): a map without it is dropped once and the
backfill below learns it again from the header. The network value of `/v1/network` became v2 the same evening (it signs the
address the ingest saw); v1 values are no longer placed in any network, so the cache file is `network-token-2` and
an updated app asks a fresh one.

Catalogue ids (`zapret-server-ids`) come only with a reply of the service subscription. A subscription fetched
before the header existed (2026-11-19 13:07 UTC) keeps no ids, and then no report can name its servers: the
owner's own PC, with subscription auto-update off, sent none. So once per run the app checks each service
subscription without ids once, only for the header; the server list is not changed (Windows: a check-only
fetch, `_learn_missing_server_ids`; Android: `ServerIdBackfill`, the body is dropped). Log line:
`[client-report] … has no server ids: one check for the header` / `client-report: подписка сервиса без id серверов`.

## When a report is honest

- Hysteria 2 and AmneziaWG/WireGuard: a successful transition already means the engine proved the
  server at start (functional HTTPS probe / authenticated handshake) → `connected`.
- VLESS (Xray sidecar): Xray starting proves nothing about the server, so after a successful connect
  the reporter makes one HTTPS request (`generate_204`, `socks_probe.HTTPS_ENDPOINTS`, first answer
  wins) through the Xray relay SOCKS inbound — the same path as the user's traffic, bypassing sing-box
  routing — and reports `connected` or `failed` at `request` (owner decision 19.11.2026).
- A failure is reported with the native core's own code for that server (Hysteria
  `last_failure_code`: `TARGET_AUTH_REJECTED` → auth, TLS/pin/obfs → handshake, `TARGET_NETWORK_TIMEOUT`
  → handshake `udp_no_answer`, …; AmneziaWG stage `handshake_readiness` → `udp_no_answer`) or with the path
  check's verdict (below). Every other failure is reported too: local ones (`LOCAL_*`, TUN, admin rights) and
  ones without any code go as `local_*` (owner 2026-11-19, a Hysteria failure on his screen never reached the
  panel).
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

TUN mode (found in the ingest data 2026-11-19): Windows has no per-socket bypass of the TUN, so a "direct" request
follows the user's routing and may leave from the VPN server; the ingest then recorded the server's country (rows
`direct` with DE/SE/KZ for servers in those countries). With a TUN session up (`direct_is_direct` is false) the
reporter therefore sends only via the tunnel (`sent_via=tunnel`; through the session's local HTTP inbound, or,
without one, a request the TUN captures itself) and never asks `GET /v1/network`. The token is asked while
requests are really direct: at app start, at the start of a connection (before the TUN comes up) and after a
disconnect (`prefetch_token`). Proxy mode is unaffected: there urllib without a proxy is really direct.

## Ingest names and small requests (owner 2026-11-19)

`reports.zapret.moe` alone is usually cut in Russia: the whole zone `zapret.moe` is filtered by name (SNI).
The ingest is therefore also served under random names of the zapret-links pool (service `reports`, a bridge
in CT 204 to the same ingest; the visitor goes on in `CF-Connecting-IP`, so the ingest still sees the
sender's network). The app keeps a fixed seed (`INGEST_SEED`: the two pool names of the release day, which
zapret-links never removes, and `reports.zapret.moe` last) and learns more from the shared feed:
`services.reports.hosts` of the zapret-links entry pages (script.google.com `?format=json` and the GitHub
gist, both hard to block). A name is accepted only under `domains` of the same document. The feed is asked
on a send, never by a timer: when the names are older than a day, or when none answered (at most once an
hour); `data/client-reports/ingest-hosts` keeps them.

Each send tries up to 4 names per path (directly, then through the tunnel), in a shuffled order that
alternates domains, with names silent in the last 30 minutes at the end. One request is one batch on its
own new connection (`Connection: close`) with a body of at most 8 KB (`MAX_BODY_BYTES`): the TSPU freezes
a TCP connection to part of the foreign networks after ~25 packets both ways (~16 KB), counted per
connection, and a TLS handshake plus 8 KB and the answer stay near 15 packets. A long queue goes as several
small requests. The log line names the domain and the size: `batch 3, 1180 B (direct, osjcpjzipyb.click) -> HTTP 202`.

## Path check after a failure (owner 2026-11-19)

After a failed attempt the app checks where the path to the server is closed and swaps one thing at each
step (pure decision `client_reports/diagnosis.py`, network `client_reports/probe.py`, the same steps and codes on both platforms):

1. Control: TCP to our pool front (the ingest names, a Russian AS). No answer means the PC's own network
   is down (captive portal, no internet): no verdict at all.
2. DNS: the system resolver against our DoH for the server name. `dns_nxdomain` (every DoH says the name does
   not exist), `dns_no_answer`, `dns_poisoned` (no common address). Named only when nothing below is closed:
   the app connects by the DoH address, so a poisoned system DNS alone does not stop it.
3. TCP to IP:port, then the same IP on 443: `port_blocked` (443 answers, even with a reset), `ip_blocked`
   (both silent), `tcp_reset` (a reset proves the address is alive), `tcp_timeout` (443 not tried).
4. TLS: one ClientHello (`diagnosis.client_hello`, byte-identical on both platforms, only the first answer byte is read)
   with the real name on the server IP, then a neutral name (ya.ru, vk.com or www.gosuslugi.ru, open even
   under white lists) on the same IP, then the real name on our front: `sni_blocked`,
   `sni_blocked_everywhere`, `tls_blocked`. Any TLS record is an answer (a server that dislikes the name
   sends an alert, Reality forwards it to its sample site). On the swapped probes only silence is a filter:
   our front and many servers close the connection without an answer for a name that is not theirs
   (seen 2026-11-19), so a reset there proves nothing.
5. UDP servers (Hysteria 2, WireGuard/AWG): only whether the IP is alive, by TCP 443 (silence →
   `ip_blocked`); the protocol verdict stays with the core's own code.
6. Freeze: after a successful check, at most once per server per 10 minutes, the app reads up to 64 KB of the
   speed-test file (`fra.download.datapacket.com`, not Russian, so "Russia directly" routing cannot take it
   past the server) through the session. A stall between 1 000 and 24 000 bytes (the TSPU freezes a TCP
   connection after ~25 packets, ~16 KB) turns the report into `failed` at `request` with `freeze_16k`:
   such a server passes the small check but sites do not open.

The check runs only after a failure, at most once per server per 10 minutes, in the background (one pass
takes 1–40 s). The verdict refines the report (`AttemptClassifier.classify(facts, diagnosis)`), and makes a
report out of a failure that had no core code (Xray, no evidence) when it proves a block; a failure that is
not about the server (`LOCAL_*`, lost network) never becomes a server failure. The screen shows one Russian
line («Проверка пути: …», `describe`) for any server, ours or not; it contains no address.

## Every failure is sent by itself; «Отправить отчёт» (owner 2026-11-19)

Every failed attempt is written and sent without asking (owner 2026-11-19): a failure that is not about the
server goes as `failed` at `connect` with `detail` `local_<code>`, `local_network` or `local_unknown`; vpnbot
keeps `local_*` out of the server verdict and ranking. Servers of the user's own go as `foreign` (see «What is
sent»).

The button «Отправить отчёт» next to the error stays for a user who wants to send it himself: it sends the queue
at once (the report is normally already written; it never writes a second one). The note under it says «Отчёт
отправлен» or «Отчёт в очереди, отправим при первой связи».

Windows has no per-socket bypass of the TUN: the path check runs only while no TUN session is up (after a
failed connect the session is gone; a failed switch that kept a TUN session is not checked). The freeze is
measured through the session's local HTTP inbound. The dashboard shows the line and the button under the
error status (`DashboardPage.set_failure_report`, fed by `AppController.failure_report_changed`).

## Seeing it act

The log file has `[client-report]` lines: the VLESS check result, each queued report and each batch
(`batch N (direct) -> HTTP 202`), the path check (`path check -> handshake/sni_blocked (control=… tcp=…)`,
no addresses), the freeze measure and each button press.

## Test runs send nothing (2026-11-19)

The environment variable `ZAPRET_KVN_CLIENT_REPORTS=off` turns the reporter off for a process: nothing is
written to the queue, no token is asked and nothing is sent; the notice and the path check still work. The
release gate sets it around the test run (`scripts/release_windows_gate.ps1`), because the e2e tests drive the
real controller against local test servers: the 0.8.97 gate had put the foreign rows «A-works» and
«B-udp-lost» into the production store. The log says `[client-report] off (ZAPRET_KVN_CLIENT_REPORTS=off)`.
Reporter unit tests pass `enabled=True`, so they keep working with the variable set.

## Known limits

- AmneziaWG/WireGuard failures other than a silent handshake have no core code: they are reported only when
  the path check proves a block.
- The `resolve` step comes only from the path check (`dns_*`); slots (YouTube, Telegram, AI) produce no reports.
