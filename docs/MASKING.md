# Masking («Маскировка»)

Owner request 2026-11-15, plan approved 2026-11-16. Off by default: with the master switch off the
runtime plans and the transition signatures are exactly what they were before.

## Who owns what (native cores, sing-box is the gasket)

| Section | Native core | What the app writes (to a runtime copy of the node) |
|---|---|---|
| WireGuard masking | Amnezia runtime (`runtime/amnezia`) | `jc`, `jmin`, `jmax`, `i1`..`i5` in the endpoint's `amnezia` object |
| Xray shaping | Xray sidecar | `mux` on the outbound, `xmux` in XHTTP settings (inside `extra` when present), `finalmask.tcp` fragment |
| TLS fragment | sing-box (Trojan, VMess, AnyTLS, HTTP, ShadowTLS) | `tls.fragment`, `tls.record_fragment`, `tls.fragment_fallback_delay` |
| Packet tricks | sing-box front, socket to the VLESS server | route options `tls_spoof` / `kvn_desync` (see below) |
| Hysteria2 | official Hysteria | nothing: obfs is part of the link |

H1-H4/S1-S4 are never touched (they must equal the server). Junk and I1-I5 are sent by the
initiator only, so they work with a plain WireGuard server.

## Code

- `xray_fluent/masking/` (pure, no Qt): `model`, `codec` (JSON shared byte for byte with Android
  `MaskingCodec`), `merge` (global + per-server override by `node.id`), `wireguard`/`xray`/`singbox`
  rules and emitters (limits cite the pinned cores), `presets`, `choices` (what the controls show and
  write), `tester` (freeze verdict, candidates, plan, ranking), `apply`.
- `xray_fluent/application/masking_runtime.py`: masked COPIES of the selected node and the pool nodes
  for both sing-box planners, and of the Xray pool outbounds; the stored nodes are never edited.
- `AppSettings.masking` holds the codec document. The transition signature includes it only while
  masking is on, so users who never enable it get no extra reconnect after an update.
- One `[masking] маскировка: …` log line at each sing-box start (proxy, TUN, transport switch).
- UI: Settings -> group «Маскировка» (presets per section, «Свои значения» = the whole set as JSON
  with core validation); node list -> «Ещё» -> «Маскировка» for the selected servers.

## «Подобрать» (the tester)

- Decisions in `xray_fluent/masking/tester.py` (same as Android): candidates (baseline «Без
  маскировки», the server's own set, fitting presets), the plan (2 transfers per candidate, jittered
  pauses, one target), `judge` (control = the run itself) and the freeze verdict.
- `application/masking_runtime.py`: `begin_trial`/`end_trial`, the in-memory candidate; `settings_of`
  (what a connect runs with) applies it, `stored_settings_of` (what the UI and writes use) never does.
  While a trial runs the transition signature carries `masking_trial`, so every candidate really
  rebuilds the session; without a trial the signature is unchanged.
- `application/masking_tune_service.py` `MaskingTuneRunner` (GUI thread, QTimer + worker only): per
  candidate sets the trial, `_request_transition("masking tune")`, waits until the coordinator is idle
  and connected (45 s), checks the selected node, runs the transfers (`TransferWorker`: the session's
  HTTP inbound, or plain in TUN), then drops the trial and requests `masking tune end`. Counts
  `controller.user_disconnects` so a VPN the user switched off is never switched back on.
  «Оставить» = `controller.keep_masking_override`.
- `network/masking_transfer.py`: 256 KB (`Range`) of `SPEED_TEST_DEFAULT_URL`, browser User-Agent, read
  timeout 12 s, cap 40 s, sampler thread every 0.5 s.
- UI: Settings -> «Маскировка» -> «Подобрать для текущего сервера» -> `ui/masking_tune_dialog.py`.
- Log: `[masking] маскировка: подбор, вариант «…»` at every trial connect.

## «Пакеты-обманки» (desync, VLESS over TCP)

The Xray sidecar dials every server through sing-box (`sockopt.dialerProxy` -> protect inbound ->
`direct`), so the server socket belongs to the sing-box front and the tricks are route options of
that route, one `route-options` rule per server (`masking/desync.py`, inserted just before the
protect route by `runtime_planner._ensure_hybrid_desync_routes`, matched by the server's name and
its known addresses):

| Method | Windows engine | Route option |
|---|---|---|
| «Обманка» (`fake`) | sing-box `tls_spoof` over the WinDivert driver (owner 2026-11-16) | `tls_spoof: <fake SNI>`, `tls_spoof_method: wrong-sequence` |
| «Беспорядок» (`disorder`), «Разрез» (`split`) | `common/kvndesync`, core patch `core-patches/kvn-desync.patch` (same engine as Android 0017) | `kvn_desync: "<method>:<split_at>"` |
| OOB | not on Windows (validation error) | — |

- The Xray emitter puts the plan on the masked outbound copy under `__kvn_desync`; the planner takes
  it off before the config reaches Xray (a raw Xray config strips it and the log says so).
- The Windows decoy carries a wrong TCP sequence number, so the server drops it whatever the TTL:
  `fakeTtl` stays in the shared format but is not used here (one «Обманка» preset instead of
  Android's TTL 3 / TTL 5).
- Patch: `kvndesync/socket_windows.go` sets `IP_TTL` / `IPV6_UNICAST_HOPS` and waits until the
  piece left the host by `SIO_TCP_INFO` `BytesOut` (50 ms cap); five upstream files gain the
  `kvn_desync` route option. `build_singbox_front.py` applies it only onto the exact pinned blobs and
  runs `go test ./common/kvndesync ./route/rule`.
- Lab (win10, 2026-11-16, through the VM's router): disorder at SNI ~310 ms handshake (Windows'
  300 ms minimum RTO: the TTL 1 piece died at the first router and was resent with the normal TTL),
  split 5 ms; `tls_spoof` capture (pktmon): a `vk.com` decoy ClientHello 304 bytes before the real
  sequence goes out first, the handshake succeeds.

### Zapret and WinDivert while the tricks run (owner 2026-11-16)

- One desync per flow: for a server with its own tricks, `ServerBypass` makes the winws2 rule
  `pass` («не трогать») and bypass is not required for it; winws2 is never started just for that.
  Log: `[zapret] у сервера свои пакеты-обманки маскировки: …`.
- WinDivert unloaded and available: sing-box installs the driver as service `WinDivert` from its own
  copy and marks it for deletion, but the driver stays loaded after the last handle closes. After a
  sing-box process whose config opened WinDivert exited (disconnect, reconnect with spoofing off,
  app exit, crash before the next start), `SingBoxManager._release_windivert_steps` runs
  `engines/windivert_release.py`: stop the `WinDivert` service unless a known WinDivert user runs
  (winws/winws2 of any folder, GoodbyeDPI). Log: `[masking] WinDivert выгружен, драйвер свободен` or
  why it was kept.
- The bundled Zapret's `Monkey64.sys` is byte-identical to sing-box's `WinDivert64.sys` 2.2.2 and is
  installed as service `Monkey` on the same device `\\.\WinDivert`: either program uses the driver
  the other loaded. win10 check 2026-11-16: spoof loads `WinDivert`; winws2 starts on it; release is
  refused while winws2 runs; without it the service is gone; winws2 then loads `Monkey` itself and
  sing-box spoof works on that driver too.

Note: the Xray sidecar dials through `sockopt.dialerProxy` (the local protect relay), so finalmask
fragment pauses reach sing-box's direct connection, but segment boundaries are not guaranteed;
fragment stays an experiment behind the tester.
