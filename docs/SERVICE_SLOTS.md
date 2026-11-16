# Service slots on Windows (design draft, 2026-11-16)

Status: phases 1-2 in code (`xray_fluent/slots/catalog.py`, `config_writer.py`, tests
`tests/test_service_slots_config.py`), not wired to the UI or runtime yet. Android has had slots since 0.5.52 / 0.6.x (`android/docs/SERVICE_SLOTS.md`, read its
"Owner decisions" and the field sections first). Read the workspace `AGENTS.md` section "Architecture basis: native
cores, sing-box is the gasket" and the skill `zapret-kvn-json-routing` before changing this design.

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
- Only servers whose core is sing-box go into that provider. VLESS goes to ONE Xray sidecar (hybrid mode: `proxy`
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
| sing-box (Trojan, Shadowsocks, VMess, ...) | nothing new: it is already a member of `__app_nodes` |
| Xray (VLESS Reality / XHTTP) | the same ONE Xray sidecar, one more loopback relay inbound per slot routed to that server's outbound |
| Hysteria2 | one more `hysteria.exe` per distinct Hysteria2 server in use (up to 4 with 3 slots) |
| AWG (Amnezia) | one more Amnezia instance per distinct server (heaviest; WireGuard adapters) |

Each helper ends in a loopback SOCKS relay that becomes a provider member `__app_nodes/node_<hash>`, so the slot
selector switches it with the same Clash API call as the main server. This keeps the architecture basis: every protocol
on its own native core, sing-box only routes.

## Phases

1. Pure slot module + tests (spec, assignment from the pool, pin, failure marks) shared in idea with Android.
2. JSON writer: tick/untick writes/removes the `zapret-slot-*` blocks; tests for order, idempotence, user-edited JSON
   kept, `sing-box check` on the result.
3. Helpers: per-slot Xray relay inbound; then extra Hysteria sidecars; AWG last or never.
4. Runtime: per-slot selection through the Clash API, per-slot failover, YouTube rescue and dead-cluster tracker on the
   YouTube slot instead of the main server.
5. UI: one card «Серверы по сервисам» with an option per service, «Авто» or a pinned server.
6. Release, wiki guide (Zapret/premium.md, premium/apps.md), screenshots on win10.
