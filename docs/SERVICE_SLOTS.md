# Service slots on Windows (design draft, 2026-11-16)

Status (2026-11-16): phases 1-5 in code, not yet released or tried on win10. Modules: `xray_fluent/slots/`
(`catalog.py`, `config_writer.py`, `runtime_plan.py`, `assigner.py`, `rescue.py`),
`application/slot_runtime_service.py`, `ui/service_slots_card.py`; tests `tests/test_service_slots_*.py` (51).

## Owner decisions (2026-11-16)

1. Windows gets slots, generated behind an explicit switch (AskUserQuestion, option "Generate behind a switch").
2. "Each service has its own logic, because it is slightly different, although not always": one shared slot base
   (routing, selector, failover, marks) plus a per-service policy only where the service really differs (YouTube:
   slow-video rescue, dead-cluster tracker, proven servers; AI: names resolved through the slot's server; Telegram:
   its own server).
3. "On Windows it must be made for beginners, so it is convenient to use": one plain option per service with working
   defaults; the slot picks its server itself; a pin is optional. No JSON knowledge needed.
4. "I quickly picked the option, and the program put everything into the config itself": ticking a service WRITES the
   slot selector and the slot rules into the active native sing-box JSON. They are visible and editable on the
   «Маршрутизация» pages; unticking removes exactly what the app wrote.

5. Helpers (2026-11-16): «one per server» — a slot may use any server; each distinct Hysteria2 server in use runs its
   own `hysteria.exe` (up to 4), VLESS shares the one Xray sidecar.
6. Scope of the first release (2026-11-16): «all three at once» — YouTube, AI and Telegram slots together.
7. Place (2026-11-16): a card «Серверы по сервисам» on the main page under the server card: a tick per service and
   «Авто» or a pinned server, as on the phone.

Point 4 is what keeps slots inside the routing contract: the active raw JSON stays the source of truth, the change is
a user action from the GUI (like the existing "restore stock" actions), and nothing is injected at launch.

## What Windows has today (survey 2026-11-16, file:line from that day)

- One routing exit: the template's `proxy` outbound. The runtime replaces it (`engines/singbox/runtime_planner.py`
  ~433-500): a `selector` tagged `proxy` over the local provider `__app_nodes` when the selected server runs on
  sing-box itself, otherwise the single native outbound.
- Only servers whose core is sing-box go into that provider. VLESS, VMess and Trojan go to ONE Xray sidecar (hybrid mode: `proxy`
  becomes a selector over two loopback SOCKS relays into Xray, `runtime_planner.py` ~715-890, the Xray pool and its
  balancer in `outbound_pool_service.py`). Hysteria2 goes to ONE `hysteria.exe` sidecar behind a SOCKS relay. AWG to
  Amnezia. The controller owns one manager of each (`controller.py` ~415-418).
- Hot switch: Clash API `select_singbox_outbound(api_port, "proxy", tag)` (`selector_api.py`), Xray balancer override;
  `transition_engine.py` picks proxy_update / tun_hot_swap / proxy_hot_swap / reconnect.
- YouTube: `diagnostics/dead_video_cluster.py` (pure) feeds `smart_switch_service.py`, which switches the MAIN server.
  There is no per-service server.
- Templates: `data/templates/sing-box/default.json` sends the YouTube names (googlevideo.com, youtube.com, ...) to
  `proxy`; no Telegram or AI rules; `final` is `proxy`.

## Model

The slot model is the same as Android's (pure, tested, no Qt): `SlotSpec(id, title, matchers, pool, pin, policy)`.
Built-in slots: `youtube`, `ai`, `telegram`; everything unmatched stays on `proxy` (the main server). Matchers on
Windows are `process_name` (YouTube desktop clients are browsers, so YouTube matches by domain; Telegram Desktop and
forks by process name and the Telegram IP ranges; AI by domain: chatgpt.com, openai.com, claude.ai, anthropic.com,
gemini.google.com, ...). A browser tab on YouTube is caught by domain, which is the main Windows case.

## What the app writes into the active sing-box JSON when a slot is ticked

```json
{"type": "selector", "tag": "zapret-slot-youtube", "outbounds": ["proxy"], "default": "proxy",
 "interrupt_exist_connections": true}
```

and one route rule, placed right after the always-proxy names and before the RU-direct rules:

```json
{"domain_suffix": ["googlevideo.com", "youtube.com", "youtu.be", "ytimg.com", "ggpht.com",
  "youtube-nocookie.com", "youtubei.googleapis.com"], "action": "route", "outbound": "zapret-slot-youtube"}
```

- At rest the selector has only `proxy`, so the file is valid on its own; the runtime adds the server pool
  (`providers: ["__app_nodes"]`) at launch, the same app-owned contract as the `proxy` replacement.
- Apps, names and IP ranges are separate rules (sing-box ANDs different fields inside one rule), in the order AI,
  YouTube, Telegram, as on Android.
- Tags starting with `zapret-slot-` are app-written; untick removes exactly those blocks (and nothing the user wrote).
- `default: proxy` keeps the slot working when the app is not running its slot logic (the slot simply follows the
  main server): the JSON is valid and safe on its own.
- The slot's DNS rule (names resolved through the slot's server, Android 0.6.2 lesson: a googlevideo address chosen by
  one node can be unreachable from another) is written the same way, only when the profile's DNS goes through the node.
- Template sync: these are user-made edits of `outbounds` / `route` / `dns`, so the update merge keeps them verbatim.

## The hard part: several native-core helpers at once

A slot on a different server than the main one needs that server's native core to carry traffic at the same time:

| Slot server's core | What it needs |
|---|---|
| sing-box (Shadowsocks, SOCKS, HTTP, ...) | nothing new: it is already a member of `__app_nodes` |
| Xray (VLESS, VMess, Trojan; Reality / XHTTP) | the same ONE Xray sidecar, one more loopback relay inbound per slot routed to that server's outbound |
| Hysteria2 | one more `hysteria.exe` per distinct Hysteria2 server in use (up to 4 with 3 slots) |
| AWG (Amnezia) | one more Amnezia instance per distinct server (heaviest; WireGuard adapters) |

Each helper ends in a loopback SOCKS relay that becomes a provider member `__app_nodes/node_<hash>`, so the slot
selector switches it with the same Clash API call as the main server. This keeps the architecture basis: every protocol
on its own native core, sing-box only routes.

## Phase 3 plan: how a slot reaches its server at runtime (2026-11-16, after reading the launch path)

Facts: the provider file `__app_nodes` (`constants.SINGBOX_PROVIDER_FILE`) is written once at launch
(`controller.py` ~1377) and holds every sing-box-core server of the pool; it is built only when the MAIN server is a
sing-box-core server (`runtime_planner._plan_runtime_outbound` ~433-490). Helpers: one `HysteriaManager`
(`controller.py` ~417), one Xray sidecar, one Amnezia.

Plan:

1. **One stable relay per slot.** When a slot is ticked, the runtime adds a loopback SOCKS outbound
   `zapret-slot-relay-<id>` (own port and one-session credentials, like the Hysteria sidecar's `proxy` relay) and makes
   it a member of the slot selector. Behind it runs the slot server's own native core: `hysteria.exe` for Hysteria2,
   `xray.exe` for VLESS, Amnezia for AWG (owner 2026-11-16: «one per server»). Changing the slot's server to another
   server of the same kind restarts only that helper on the same port: sing-box is not restarted and the main traffic
   is not touched. (Change against the first draft: VLESS gets its own Xray per slot instead of a second inbound in the
   main Xray sidecar, so a slot move never restarts the main server's helper.)
2. **sing-box-core servers need no helper:** the provider is built whenever slots are on (not only when the main
   server is a sing-box-core one) and the slot selector gets `providers: ["__app_nodes"]`; a move is one Clash API
   `select` on the slot selector.
3. **Members of a slot selector at runtime:** `proxy` (follow the main server), the slot relay, the provider. The
   selected member is pinned through the Clash API before TUN/system proxy is exposed, as for `proxy` today.
4. **Planner output:** `SlotRuntimePlan(slot_id, member_tag, helper: kind + node + relay port/credentials | None)`,
   a pure function with tests; the controller owns the helpers' lifecycle (start after sing-box, stop with the session,
   health like the main Hysteria sidecar).
5. **Assignment** (which server per slot): pure, as on Android (`SlotPlanner`): pin first, then servers that worked
   for the service (speed history), avoid the main server and other slots while the pool allows, skip servers that
   failed recently. The slot's failover and the YouTube rescue (dead cluster, slow video) move the SLOT, not the main
   server, when the YouTube slot is on.

## Phases

1. Pure slot module + tests (spec, assignment from the pool, pin, failure marks) shared in idea with Android.
2. JSON writer: tick/untick writes/removes the `zapret-slot-*` blocks; tests for order, idempotence, user-edited JSON
   kept, `sing-box check` on the result.
3. Helpers: per-slot Xray relay inbound; then extra Hysteria sidecars; AWG last or never.
4. Runtime: per-slot selection through the Clash API, per-slot failover, YouTube rescue and dead-cluster tracker on the
   YouTube slot instead of the main server.
5. UI: one card «Серверы по сервисам» with an option per service, «Авто» or a pinned server.
6. Release, wiki guide (Zapret/premium.md, premium/apps.md), screenshots on win10.

## What is built (2026-11-16)

- **Card** «Серверы по сервисам» on the main page (`ServiceSlotsCard`): a switch per service, «Авто» or a pinned
  server, «сейчас: …» while connected. A switch calls `AppController.set_service_slots`, which writes the slot blocks
  with `apply_slots` and saves through `apply_singbox_config_text` (the routing editor's own path: validation, save,
  reconnect when connected); the editor page reloads the saved JSON. Pins live in `AppSettings.service_slot_pins`.
- **Launch:** `_plan_runtime_singbox` / `_plan_proxy_runtime_singbox` call `_attach_slot_plans`: `assign_slots` (pin
  first, then the best free server: alive, faster, lower ping; never the main server or another slot's while the pool
  allows; AWG skipped) and `attach_service_slots` (relay per slot, provider members when the main server is a
  sing-box-core one, a native out otherwise, the helpers' `process_path -> direct`).
- **Helpers:** `SlotRuntimeService` starts after sing-box is up and stops on `singbox.stopped`. Each helper runs from
  its own executable copy `data/runtime/slots/<core>-slot-<id>.exe` with its own config (the Hysteria and Xray managers
  got `exe_path` / `config_file`): the main sidecars' orphan cleanup kills by executable path and their stale-config
  cleanup globs by name, so with the shared defaults a slot helper would kill or delete the main one's. A helper that
  does not start leaves its slot on `proxy`, is logged, and that server is skipped for the slot until the app restarts
  or the user pins it again.
- **Masking:** a slot's Xray helper gets «Маскировка» of its server like the main path (mux, XHTTP connection
  rotation, fragmentation: `helper_config(helper, masking)` masks the pool outbound); packet tricks are a sing-box
  route option of the main path's server socket, so the carried plan is dropped and the log says
  `[slots] <id>: маскировка: пакеты-обманки маскировки у сервера слота не применяются`. Hysteria2 and sing-box-core
  slot servers are not masked (masking has nothing for them).
- **Hot moves:** every slot has a stable loopback relay, so moving a slot to a Hysteria2 or VLESS server only starts a
  helper behind the same port, and moving to a provider server is one Clash API `select`; sing-box is not restarted
  and other apps are not touched. A pin that needs a restart (a sing-box-core server outside the provider) reconnects.
- **YouTube rescue:** with the YouTube slot on, a dead YouTube cache cluster (`dead_video_cluster.py`) moves the
  YouTube slot (`slots/rescue.py`: best free hot-reachable server, the dead one remembered, 90 s cooldown, back to the
  main server when nothing is free) instead of switching the main server; honours «авто-переключение» and «переключение
  при низкой скорости», not «сервер выбран вручную» (that is the main server's pick). Log `[slots] youtube: кластер …
  не отвечает на A, слот YouTube -> B`; status «… YouTube переведён на B, остальные программы не тронуты.
  Перезапустите видео …».
- **Live e2e on win10 (2026-11-16, source ff37b8c):** headless AppController in proxy mode against five
  loopback servers of the real cores (three `hysteria.exe server` with a self-signed certificate and
  `pinSHA256`, two `xray.exe` VLESS over TCP). Main server hy1. Ticking the three services gave AI -> hy2,
  YouTube -> hy3 (both `hysteria-slot-*.exe`) and Telegram -> vl1 (`xray-slot-telegram.exe`), each selector
  on its own relay. Through the local SOCKS: YouTube 204, ChatGPT 200, Telegram 200, Wikipedia 200. Each
  Hysteria server saw exactly one client, so every service really used its own server. Pinning YouTube to
  vl2 while connected moved it Hysteria -> Xray behind the same relay, with the same sing-box PID and no
  reconnect, and traffic kept flowing. Disconnect left no slot helper running. Not covered: real
  censorship and the provider-member path (no sing-box-only server in the set).
- **Not yet:** slow-video rescue (Windows has no slow-video detector, only dead clusters), AWG slot servers (`slot_capable` keeps them out of the card list, and an old AWG pin falls back with the reason «серверы AmneziaWG для сервисов пока не поддерживаются»), a speed
  history per service, per-slot traffic on the card, the e2e against real vpnbot nodes (vpnbot test account pending).
