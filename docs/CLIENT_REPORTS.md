# Connection reports for status.zapret.moe

Owner decisions of 15–19.11.2026 (programme «honest coverage», stage S4). The status page checks
the service's servers from Russian datacenters and home scanners; none of them sees the filter of a
particular home provider. Real connection attempts of Zapret KVN from Russian home networks are the
third source: a server is shown as reachable or not from homes only when at least 3 installs on at
least 2 networks (ASNs) reported the same within 24 hours. Android does the same
(`android/docs/CLIENT_REPORTS.md`); both follow vpnbot `client_reports/contract.py`, schema 3 since 2026-11-19.

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
- `outcome` `connected` / `failed` / `cancelled`, elapsed ms, attempt time, app name/version/platform, a random
  `install_id` (`data/client-reports/install-id`, not tied to the account), `sent_via`, `network_token`.

Schema 3 (vpnbot «schema 3 live» 2026-11-19 21:37 UTC; owner: analytics live in vpnbot, the apps are open
source): the app sends facts, never a verdict. `failed_step` and `detail` are gone; instead:

- `carrier` (`tcp`/`udp`): what the core's first hop to the server runs over (`checks.carrier_of`: UDP for
  Hysteria 2, TUIC, WireGuard/AWG, mKCP and QUIC transports, XHTTP whose ALPN is only `h3`);
- `core_code`: the core's own code when it has the contract's shape `^(TARGET|LOCAL)_[A-Z0-9_]{1,48}$`
  (`CORE_UNCLASSIFIED`, `TRANSITION_*` are left out), or `NETWORK_LOST`;
- `checks` {probe: {`r`, `ms`[, `b`][, `same`]}}: every probe the app ran (below), by its wire name, what came
  back (`answered`, `timeout`, `reset` = RST/EOF after the connection was up, `refused` = RST to SYN, `unknown`,
  `nxdomain` for DNS), its time in ms and, for a flow probe, the bytes read; absent = not run.

vpnbot judges every report by its verdict tables and answers each batch with `verdicts[i]` {`detail`, `level`,
`confidence`, `text`} in batch order (`contract.parse_reply`). A queue line written by an older version (with
`failed_step`/`detail`) still goes out as schema 2, which vpnbot keeps admitting.

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
  routing — and reports `connected`, or `failed` with the no-data checks (below) (owner decision 19.11.2026).
- A failure carries the native core's own code (Hysteria `last_failure_code`; AmneziaWG stage
  `handshake_readiness` → `TARGET_NETWORK_TIMEOUT`). Every failure is reported, with or without a code
  (owner 2026-11-19, a Hysteria failure on his screen never reached the panel); vpnbot keeps `LOCAL_*` and
  `NETWORK_LOST` out of the server's verdict.
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

The owner asked three times that the check stay quiet on the wire: «always do it randomly so TSPU doesn't notice,
and not make unnecessary requests to the servers»; «make sure there are no unnecessary checks that could trigger
DPI»; «check as rarely as possible and only if it's really necessary». Offered a design with no probe outside
the tunnel at all, he chose to keep these rare minimal probes (2026-11-19). So (`client_reports/probe.py`, the
same ladder on Android):

- No hand-made packet goes on the wire. TLS probes use the system's TLS stack (OpenSSL here), the ClientHello of
  countless ordinary programs, never one that could become this app's fingerprint; a certificate (trusted or
  not) or an alert from the server is an answer. There is no QUIC probe.
- No probe when the core's code already proves the server answered (`TARGET_AUTH_REJECTED`, `_CONNECTION_REFUSED`,
  `_CONNECTION_CLOSED`, `_OBFS_REJECTED`, `_TLS_*`, `_PIN_MISMATCH`, `_DESTINATION_UNREACHABLE`), for `LOCAL_*`
  and `NETWORK_LOST`, and never for a server that works.
- Rarely: one check per server (its name and its IP: rows sharing an address share it) a day, one per install in
  ten minutes (`PATH_CHECK_PER_SERVER_MS`, `PATH_CHECK_PER_INSTALL_MS`), so clicking through servers probes at
  most one. vpnbot sums the reports of every install, so a rare check loses little.
- Random gaps of 150–700 ms between probes; neutral names drawn from a pool on each run.

The ladder, each step only while it can still change the answer:

1. `control_front`: TCP to our pool front. Silent → `control_neutral` (TCP and TLS to a neutral Russian name:
   ya.ru, vk.com, www.gosuslugi.ru, ozon.ru, www.wildberries.ru) and stop: the server is never touched.
2. The address the start itself used; without one `dns_doh` (our resolver, encrypted), and `dns_system` (the
   server's name in plaintext) only when DoH did not answer.
3. TCP lines: `tcp_target`; silent and the port is not 443 → `tcp_443`; answered and TLS → `tls_real`; no
   answer → `tls_neutral` (a neutral name on the same address and port). The real name is never sent to our
   front.
4. UDP lines (Hysteria 2, WireGuard/AWG): no probe of the server; the core's own handshake already was one.

Inside the tunnel anything is invisible to DPI as a separate probe:

- `flow` after a success on a TCP line, at most once per server in 6 hours: up to 64 KB of the speed-test file
  (`fra.download.datapacket.com`, not Russian) through the session; `b` is the bytes before a stall.
- Tunnel up, no data (the VLESS relay check got nothing): `tunnel_a` (a connectivity-check name by the literal
  address our DoH gave, so no DNS in the tunnel) and `tunnel_b` (the same by name, DNS through the tunnel) via the
  relay, and `direct_a`/`direct_b` (the same two directly) only when requests are really direct. No probe of the
  server's path then: the tunnel proved it.
  Results (`no_data_result`, vpnbot 2026-11-19): the core's local SOCKS inbound accepts the connection before the
  core dials anything, so a RST or EOF through it is `reset` (the core dropped the flow), never `refused`; the local
  inbound itself refusing is `unknown`. Directly `refused` is only a RST to the SYN. A failed name lookup is
  `timeout` after 5 s without an answer, `unknown` when quicker.
- `health` (vpnbot 2026-11-20): the relay check itself (`probe_relay` → `relay_health`) as a probe, sent on every
  such failure without a core code, with the first copy and outside the rarity limits (it moves no extra traffic).
  `r` is `timeout` when every endpoint stayed silent, `reset` when any endpoint's flow was dropped, `unknown` when
  the failures prove nothing (local inbound refusal, a non-HTTP answer); `ms` is how long the app waited. Switch:
  `checks.HEALTH_LIVE`, on since vpnbot «health live» 2026-11-20 09:26 UTC (rules version 2).

## Completion: the failure at once, the checks after (vpnbot «completion live» 2026-11-19 22:16 UTC)

A failure that will be checked goes at once as schema 3 with `complete: false` and what the core knows, so the
panel sees it without waiting and the attempt is placed in the network it was made from. After the check the
same report goes whole: the same `report_id`, `attempted_at` and server, `complete: true`, with the checks; vpnbot
replaces the waiting copy. An unsent first copy gives way to its completion in the queue (one line per
`report_id`). A failure with no check goes once, without `complete`. If no completion arrives in 5 minutes, the
panel says «Проверка пути: не завершилась».


## The ingest's clock and refused batches (vpnbot 2026-11-20)

The ingest takes `attempted_at` from now − 7 days to now + 10 minutes of its own clock. A device clock running ahead
had whole batches refused as `client_report_invalid_attempted_at` (Windows 0.8.94–0.8.99), and the app's own freshness
check can never notice it because it uses the same clock. So the app learns the ingest's clock from the `Date` header
of every ingest reply (`contract.ReportClock`) and, when the offset is over 60 s, sends `attempted_at` in the ingest's time; a
refusal right after the offset was learnt is sent once more. A report already accepted keeps the offset it was
accepted with, so its completion copy carries the very same `attempted_at`.

The ingest validates a batch as a whole and names no index, so a refused batch (400, 413) is split in halves until
the refused report stands alone (`contract.deliver`, at most 16 extra requests); only that report is dropped, never its
neighbours.


## App errors not about a server (vpnbot «app_error live» 2026-11-20)

Errors that are not about any server go in the same batches as `"kind": "app_error"`, schema 1: a step (`start`,
`subscription`, `update`, `permission`, `crash`, `storage`), a code `prefix:value`, how often it happened since the last
send (`count`) and when the first was (`occurred_at`, in the ingest's time like `attempted_at`). A crash carries only its
frames (`Class.method:line` / `module.function:line`, innermost first, at most 16): never the message, a path, an
address or a URL; vpnbot groups crashes itself. A subscription failure says only whether the link is our service's
(`ours`) and which way it was fetched (`route`). The same error while unsent adds to its count; one code is sent at most
once a day per app version (`app_errors.AppErrorStore`), so a broken install does not flood. Errors during an attempt on a chosen server
(LOCAL_*, NETWORK_LOST) stay in the server's report. Sources: an uncaught exception in the main or any thread (`sys.excepthook`, `threading.excepthook`); a start that failed before a server was chosen; a subscription fetch that failed (`sub:http_4xx|http_5xx|timeout|dns|tls|refused|reset|unreachable|parse`); a failed update (`update:<code>` of the updater); TUN without administrator rights (`perm:not_admin`); a profile store that could not be read or written (`storage:load|save`).

## The notice shows vpnbot's verdict

The line under the error status is vpnbot's `text` for this report, as is (the app keeps no rule and no verdict
text): a preliminary one after the first copy, the final one after the completion. While the check runs it says
«Проверяем, где закрыт путь до сервера…»; until an answer arrives (the report is queued, or the ingest is cut)
«Разбор сбоя появится, когда отчёт дойдёт до сервиса.» (`reporter.WAITING_TEXT`).

## Every failure is sent by itself; «Отправить отчёт» (owner 2026-11-19)

Every failed attempt is written and sent without asking (owner 2026-11-19): a failure that is not about the
server goes with its raw `LOCAL_*` code or `NETWORK_LOST`, which vpnbot keeps out of the server verdict and
ranking. Servers of the user's own go as `foreign` (see «What is sent»).

The button «Отправить отчёт» next to the error stays for a user who wants to send it himself: it sends the queue
at once (the report is normally already written; it never writes a second one). The note under it says «Отчёт
отправлен» or «Отчёт в очереди, отправим при первой связи».

Windows has no per-socket bypass of the TUN: the path check runs only while no TUN session is up (after a
failed connect the session is gone; a failed switch that kept a TUN session is not checked). The freeze is
measured through the session's local HTTP inbound. The dashboard shows the line and the button under the
error status (`DashboardPage.set_failure_report`, fed by `AppController.failure_report_changed`).

## Seeing it act

The log file has `[client-report]` lines: the VLESS check result, each queued report and each batch
(`batch N (direct) -> HTTP 202`), the first copy and the completion (`hipnl/vless failed TARGET_…, 4 checks,
completion`), the path check (`path check -> control_front=answered/41ms tcp_target=timeout/4000ms …`, no
addresses), vpnbot's verdict (`verdict: sni_blocked (sni, proven)`), the flow measure and each button press.

## Test runs send nothing (2026-11-19)

The environment variable `ZAPRET_KVN_CLIENT_REPORTS=off` turns the reporter off for a process: nothing is
written to the queue, no token is asked and nothing is sent; the notice and the path check still work. The
release gate sets it around the test run (`scripts/release_windows_gate.ps1`), because the e2e tests drive the
real controller against local test servers: the 0.8.97 gate had put the foreign rows «A-works» and
«B-udp-lost» into the production store. The log says `[client-report] off (a run from source or
ZAPRET_KVN_CLIENT_REPORTS=off)`. Reporter unit tests pass `enabled=True`, so they keep working with the variable set.

Since 2026-11-21 only the shipped app sends at all: `reports_enabled()` is false for any run from source
(`sys.frozen` unset), whatever the environment says. Two test processes had still reached production on 2026-11-20
with app errors of the dev tree (0.8.101 and 0.8.102 rows with empty core versions): one long test process gathers
app errors before any reporter exists (`app_errors._early`) and hands them to the first real controller, so a
single process without the variable was enough. `tests/conftest.py` also sets the variable and clears the sink
after each pytest test.

## Known limits

- AmneziaWG/WireGuard failures other than a silent handshake have no core code; UDP lines get no path probe, so
  vpnbot judges them by the code and by comparing installs.
- The check slots live in memory: an app restart starts the day again.
- Slots (YouTube, Telegram, AI) produce no reports.
