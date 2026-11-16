# Masking («Маскировка»)

Owner request 2026-11-15, plan approved 2026-11-16. Off by default: with the master switch off the
runtime plans and the transition signatures are exactly what they were before.

## Who owns what (native cores, sing-box is the gasket)

| Section | Native core | What the app writes (to a runtime copy of the node) |
|---|---|---|
| WireGuard masking | Amnezia runtime (`runtime/amnezia`) | `jc`, `jmin`, `jmax`, `i1`..`i5` in the endpoint's `amnezia` object |
| Xray shaping | Xray sidecar | `mux` on the outbound, `xmux` in XHTTP settings (inside `extra` when present), `finalmask.tcp` fragment |
| TLS fragment | sing-box (Trojan, VMess, AnyTLS, HTTP, ShadowTLS) | `tls.fragment`, `tls.record_fragment`, `tls.fragment_fallback_delay` |
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

Note: the Xray sidecar dials through `sockopt.dialerProxy` (the local protect relay), so finalmask
fragment pauses reach sing-box's direct connection, but segment boundaries are not guaranteed;
fragment stays an experiment behind the tester.
