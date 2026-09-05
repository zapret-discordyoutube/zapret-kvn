# Protocol runtimes and original errors

The transport owner is fixed on both platforms: VLESS → official Xray core,
Hysteria2 → official Hysteria core, remaining protocols → sing-box. The only
routing, DNS and TUN owner on both platforms is sing-box. Its active native JSON
owns domain rules and geosite-derived native `.srs` rule sets in both proxy and
TUN modes. Xray and Hysteria implement only the selected proxy transport, never
a second routing policy. Core selection is not a
capability probe or an automatic fallback between protocol implementations.

Protocol adapters retain the original imported URI. Xray needs native JSON,
so its adapter translates the URI at that boundary; it must not translate it
through sing-box first. On Android the cores are embedded libraries behind
the same outbound interface; sing-box owns the only TUN and protected sockets.

Legacy Windows Xray-front and tun2socks selections migrate to sing-box. Existing
raw Xray configuration files are retained, not translated or overwritten. Auto
connect is disabled during that migration: users must review their sing-box
rules before explicitly reconnecting. Existing sing-box users keep auto connect.

## Errors

`xray_fluent/application/runtime-errors.json` and Android's
`app/src/main/resources/runtime-errors.json` are the same catalog. An error is
evidence first: component, operation stage, original message, session generation
and a target identity only when the producer can prove it. The catalog supplies
classification, never replacement prose. Unknown messages remain visible.

The error journal is separate from bounded traffic/debug logs. It retains each
distinct error during the application process lifetime and counts repeats.
The UI and diagnostic export use this journal without the traffic-log limit.
Passwords, private keys, tokens and credential-bearing URIs are redacted.
Release verification must exercise real producer → observer → journal → UI/
export boundaries; direct reducer tests alone do not verify this contract.

## Android audit observations

The existing Hysteria adapter emits `server certificate SHA-256 mismatch` but
the old Android classifier required the substring `pin`. It therefore lost
the security classification and could show the subsequent generic HTTPS failure
as VPN-200. The shared catalog covers the adapter and official executable texts.

The protected domain UDP dialer returns a NAT wrapper that loses the numeric
sender address (`127.0.0.1:port` becomes `:port`). A loopback boundary test
reproduces this. A local official Hysteria plain handshake and TCP echo still
pass through that wrapper, so this is not proof of the reported device failure.
Android ADB is currently unavailable; no device reproduction has been claimed.
